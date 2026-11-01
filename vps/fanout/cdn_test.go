package main

import (
	"encoding/json"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCDNEmptyRecordsMarshalAsArray(t *testing.T) {
	n, _, _ := rollbackFixture(t)
	if got := n.CDNRecords(); got == nil || len(got) != 0 {
		t.Fatalf("empty CDN records should be a non-nil empty slice, got %#v", got)
	}
	data, err := json.Marshal(n.CDNRecords())
	if err != nil || string(data) != "[]" {
		t.Fatalf("empty CDN API must serialize as [], got %q (%v)", data, err)
	}
}

func cdnFixture() *nativeInbound {
	return &nativeInbound{
		ID: 1, Port: 30017, Protocol: "vless", Network: "ws", Security: "tls",
		HostDirect: true, Manual: true, Enable: true, Host: "cdn.example.com",
		Path: "/edge", TLS: &tlsConfig{ServerName: "cdn.example.com",
			CertFile: "/tmp/origin.crt", KeyFile: "/tmp/origin.key"},
		CDN: &cdnConfig{Domain: "cdn.example.com", EdgePort: 443,
			Entries: []cdnEntry{{Address: "104.16.1.1", Verified: true}}},
		Clients: []nativeClient{{ID: rollbackFixtureClientID, Enable: true}},
	}
}

func TestCDNInputValidation(t *testing.T) {
	for _, name := range []string{"cdn.example.com", "edge-1.test.net"} {
		if !validCDNDomain(name) {
			t.Fatalf("valid domain rejected: %s", name)
		}
	}
	for _, name := range []string{"localhost", "127.0.0.1", "cdn.example.com.", "x..com", "-cdn.example.com", "a_b.com"} {
		if validCDNDomain(name) {
			t.Fatalf("invalid domain accepted: %s", name)
		}
	}
	for _, p := range []string{"/", "/cdn", "/some%2Fpath"} {
		if !validCDNPath(p) {
			t.Fatalf("valid path rejected: %s", p)
		}
	}
	for _, p := range []string{"", "edge", "/a\r\nInjected: yes", "/a b", "/a?foo=bar", "/a#frag", "/a\\b", strings.Repeat("x", 2049)} {
		if validCDNPath(p) {
			t.Fatalf("invalid path accepted: %q", p)
		}
	}
	for _, port := range []int{443, 2053, 2083, 2087, 2096, 8443} {
		if !validCDNEdgePort(port) {
			t.Fatalf("Cloudflare HTTPS port rejected: %d", port)
		}
	}
	for _, port := range []int{80, 8080, 8444, 0} {
		if validCDNEdgePort(port) {
			t.Fatalf("non-HTTPS edge port accepted: %d", port)
		}
	}
	for _, address := range []string{"localhost", "127.0.0.1", "10.0.0.1", "fe80::1"} {
		if validCDNEdge(address) {
			t.Fatalf("internal edge accepted: %s", address)
		}
	}
}

func TestCDNInboundRulesAndStoreValidation(t *testing.T) {
	good := cdnFixture()
	if err := validateCDNInbound(good); err != nil {
		t.Fatal(err)
	}
	st := &nativeStore{NextID: 2, Inbounds: []*nativeInbound{good}}
	if err := validateNativeStore(st); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*nativeInbound){
		"wrong protocol":  func(i *nativeInbound) { i.Protocol = "vmess" },
		"wrong transport": func(i *nativeInbound) { i.Network = "tcp" },
		"no TLS":          func(i *nativeInbound) { i.Security = "none" },
		"self signed":     func(i *nativeInbound) { i.TLS.SelfSigned = true },
		"wrong host":      func(i *nativeInbound) { i.Host = "other.example.com" },
		"wrong sni":       func(i *nativeInbound) { i.TLS.ServerName = "other.example.com" },
		"wrong edge port": func(i *nativeInbound) { i.CDN.EdgePort = 80 },
		"invalid path":    func(i *nativeInbound) { i.Path = "/a\nHost: injected" },
		"not direct":      func(i *nativeInbound) { i.HostDirect = false },
		"bound slot":      func(i *nativeInbound) { i.BoundSlot = 1 },
		"vision":          func(i *nativeInbound) { i.Clients[0].Flow = "xtls-rprx-vision" },
		"duplicate edge":  func(i *nativeInbound) { i.CDN.Entries = append(i.CDN.Entries, cdnEntry{Address: "104.16.1.1"}) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			i := cloneNativeStore(st).Inbounds[0]
			change(i)
			if err := validateCDNInbound(i); err == nil {
				t.Fatal("invalid CDN inbound accepted")
			}
		})
	}
}

func TestCDNCandidateRecheckAndTransactionIsolation(t *testing.T) {
	original := []cdnEntry{{Address: "104.16.1.1", Verified: true, CheckedAt: "2026-10-30T00:00:00Z"}}
	entries, err := reconcileCDNEntries([]string{"104.16.1.1", "edge.example.com"}, original, false)
	if err != nil || entries[0].Verified || len(entries) != 2 {
		t.Fatalf("stale check carried across editing: %+v, %v", entries, err)
	}
	entries, err = reconcileCDNEntries([]string{"104.16.1.1"}, original, true)
	if err != nil || !entries[0].Verified {
		t.Fatalf("preserve option lost old check: %v", err)
	}
	if _, err := reconcileCDNEntries([]string{"104.16.1.1", "104.16.1.1"}, nil, false); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, err := reconcileCDNEntries([]string{"192.168.1.1"}, nil, false); err == nil {
		t.Fatal("private edge accepted")
	}

	accepted := &nativeStore{NextID: 2, Inbounds: []*nativeInbound{cdnFixture()}}
	candidate := cloneNativeStore(accepted)
	candidate.Inbounds[0].CDN.Entries[0].Verified = false
	candidate.Inbounds[0].CDN.Domain = "other.example.net"
	candidate.Inbounds[0].TLS.ServerName = "other.example.net"
	if !accepted.Inbounds[0].CDN.Entries[0].Verified ||
		accepted.Inbounds[0].CDN.Domain != "cdn.example.com" ||
		accepted.Inbounds[0].TLS.ServerName != "cdn.example.com" {
		t.Fatal("uncommitted edits mutated the accepted CDN configuration")
	}
}

func TestCDNVerifiedExportAndMihomoOptions(t *testing.T) {
	ib := cdnFixture()
	ib.CDN.Entries = append(ib.CDN.Entries, cdnEntry{Address: "edge.example.com"})
	links := cdnLinksForClient(ib, ib.Clients[0])
	if len(links) != 1 {
		t.Fatalf("unchecked candidate exported: %v", links)
	}
	u, err := url.Parse(links[0])
	if err != nil || u.Hostname() != "104.16.1.1" || u.Port() != "443" ||
		u.Query().Get("sni") != "cdn.example.com" || u.Query().Get("path") != "/edge" ||
		u.Query().Get("type") != "ws" {
		t.Fatalf("CDN share link malformed: %v, %v", u, err)
	}
	parsed, err := clashProxy(links[0])
	if err != nil || parsed["network"] != "ws" || parsed["tls"] != true ||
		parsed["skip-cert-verify"] != false {
		t.Fatalf("Mihomo WS export invalid: %v, %v", parsed, err)
	}
	ib.Network = "httpupgrade"
	parsed, err = clashProxy(cdnLinksForClient(ib, ib.Clients[0])[0])
	if err != nil || parsed["network"] != "httpupgrade" {
		t.Fatalf("HTTPUpgrade export rejected: %v, %v", parsed, err)
	}
	opts, ok := parsed["httpupgrade-opts"].(map[string]any)
	if !ok || opts["path"] != "/edge" || opts["host"] != "cdn.example.com" {
		t.Fatalf("HTTPUpgrade host/path lost: %v", parsed)
	}
	ib.Enable = false
	if links := cdnLinksForClient(ib, ib.Clients[0]); len(links) != 0 {
		t.Fatal("disabled inbound exported")
	}
	ib.Enable = true
	ib.Clients[0].Enable = false
	if links := cdnLinksForClient(ib, ib.Clients[0]); len(links) != 0 {
		t.Fatal("disabled client exported")
	}
}

func TestCDNCheckCommitsResultWithCopyOnWrite(t *testing.T) {
	n, runtime, _ := rollbackFixture(t)
	ib := cdnFixture()
	ib.CDN.Entries = []cdnEntry{{Address: "8.8.8.8", Verified: true}}
	n.store.Inbounds[0] = ib
	if err := n.store.save(n.dir); err != nil {
		t.Fatal(err)
	}
	// All candidates are rejected without network dialing. This also tests
	// that CheckCDN commits the probe result after beginChange clones pointers.
	_, ipnet, _ := net.ParseCIDR("127.0.0.0/8")
	cloudflarePrefixes.Lock()
	savedNetworks, savedTime := cloudflarePrefixes.nets, cloudflarePrefixes.at
	cloudflarePrefixes.nets, cloudflarePrefixes.at = []*net.IPNet{ipnet}, time.Now()
	cloudflarePrefixes.Unlock()
	t.Cleanup(func() {
		cloudflarePrefixes.Lock()
		cloudflarePrefixes.nets, cloudflarePrefixes.at = savedNetworks, savedTime
		cloudflarePrefixes.Unlock()
	})
	result, err := n.CheckCDN(1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].Verified || result[0].CheckedAt == "" || result[0].Error == "" {
		t.Fatalf("invalid probe result was accepted: %+v", result)
	}
	if n.store.Inbounds[0].CDN.Entries[0].Verified || runtime.starts != 1 {
		t.Fatal("check result did not commit")
	}
	fromDisk, err := loadNativeStore(n.dir)
	if err != nil || fromDisk.Inbounds[0].CDN.Entries[0].Verified {
		t.Fatalf("check result was not persisted: %v", err)
	}
}
