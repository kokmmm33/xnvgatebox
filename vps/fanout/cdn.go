package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CDN entries are quarantined until an operator runs a successful Cloudflare
// network + TLS + Upgrade check. Probe success is not a VLESS end-to-end test.
type cdnEntry struct {
	Address   string `json:"address"`
	Verified  bool   `json:"verified"`
	CheckedAt string `json:"checked_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

type cdnConfig struct {
	Domain   string     `json:"domain"`
	EdgePort int        `json:"edge_port"`
	Entries  []cdnEntry `json:"entries"`
}

type cdnRequest struct {
	Action    string   `json:"action"`
	ID        int      `json:"id"`
	Domain    string   `json:"domain"`
	Port      int      `json:"port"`
	EdgePort  int      `json:"edge_port"`
	Transport string   `json:"transport"`
	Path      string   `json:"path"`
	CertFile  string   `json:"cert_file"`
	KeyFile   string   `json:"key_file"`
	Remark    string   `json:"remark"`
	Enable    *bool    `json:"enable"`
	Addresses []string `json:"addresses"`
}

var domainLabel = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

func validCDNDomain(name string) bool {
	if len(name) < 4 || len(name) > 253 || net.ParseIP(name) != nil || strings.HasSuffix(name, ".") {
		return false
	}
	parts := strings.Split(name, ".")
	if len(parts) < 2 || len(parts[len(parts)-1]) < 2 {
		return false
	}
	for _, part := range parts {
		if !domainLabel.MatchString(part) {
			return false
		}
	}
	return true
}

func validCDNEdge(addr string) bool {
	if ip := net.ParseIP(addr); ip != nil {
		return ip.IsGlobalUnicast() && !ip.IsPrivate()
	}
	return validCDNDomain(addr)
}

func validCDNEdgePort(port int) bool {
	switch port {
	case 443, 2053, 2083, 2087, 2096, 8443:
		return true
	}
	return false
}

func validCDNPath(path string) bool {
	if len(path) == 0 || len(path) > 2048 || !strings.HasPrefix(path, "/") ||
		strings.ContainsAny(path, "\r\n\t #?\\") {
		return false
	}
	parsed, err := url.ParseRequestURI(path)
	return err == nil && parsed.Host == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func validateCDNInbound(ib *nativeInbound) error {
	c := ib.CDN
	if c == nil {
		return nil
	}
	if ib.Protocol != "vless" || (ib.Network != "ws" && ib.Network != "httpupgrade") || ib.Security != "tls" ||
		ib.TLS == nil || ib.TLS.SelfSigned || ib.TLS.CertFile == "" || ib.TLS.KeyFile == "" ||
		!ib.HostDirect || ib.BoundSlot != 0 || ib.BoundTo != "" || ib.ThirdParty != nil || ib.SocksSlot != 0 || ib.ManagedSlot ||
		!validCDNDomain(c.Domain) || !strings.EqualFold(ib.Host, c.Domain) || !strings.EqualFold(ib.TLS.ServerName, c.Domain) ||
		!validCDNEdgePort(c.EdgePort) || !validCDNPath(ib.Path) {
		return fmt.Errorf("CDN 入站要求 VLESS + WS/HTTPUpgrade + TLS、有效域名及明确本机直出")
	}
	if len(c.Entries) > 64 {
		return fmt.Errorf("每个 CDN 入站最多 64 条候选")
	}
	seen := map[string]bool{}
	for _, e := range c.Entries {
		name := strings.ToLower(e.Address)
		if !validCDNEdge(e.Address) || seen[name] {
			return fmt.Errorf("CDN 候选地址无效或重复: %q", e.Address)
		}
		seen[name] = true
	}
	for _, cl := range ib.Clients {
		if cl.Flow != "" {
			return fmt.Errorf("CDN VLESS 不支持 Vision flow")
		}
	}
	return nil
}

func validateCDNCert(domain, certFile, keyFile string) error {
	if certFile == "" || keyFile == "" || !strings.HasPrefix(certFile, "/") || !strings.HasPrefix(keyFile, "/") {
		return fmt.Errorf("请提供绝对路径的源站 TLS 证书及私钥，不能使用自动生成的自签证书")
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return fmt.Errorf("源站证书或私钥无效: %w", err)
	}
	blob, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(blob)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("证书 PEM 格式无效")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if err := cert.VerifyHostname(domain); err != nil {
		return fmt.Errorf("源站证书不包含域名 %s: %w", domain, err)
	}
	if now := time.Now(); now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("源站证书尚未生效或已经过期")
	}
	if cert.Subject.String() == cert.Issuer.String() && cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil {
		return fmt.Errorf("请使用 CA 签发的源站证书（Cloudflare Origin CA 或公开可信 CA）")
	}
	return nil
}

// A changed connection configuration invalidates its previous probe results.
func reconcileCDNEntries(addresses []string, old []cdnEntry, preserve bool) ([]cdnEntry, error) {
	if len(addresses) > 64 {
		return nil, fmt.Errorf("每个 CDN 入站最多 64 条候选")
	}
	byName := map[string]cdnEntry{}
	if preserve {
		for _, e := range old {
			byName[strings.ToLower(e.Address)] = e
		}
	}
	seen := map[string]bool{}
	entries := make([]cdnEntry, 0, len(addresses))
	for _, raw := range addresses {
		a := strings.TrimSpace(raw)
		key := strings.ToLower(a)
		if !validCDNEdge(a) || seen[key] {
			return nil, fmt.Errorf("候选地址无效或重复: %q", a)
		}
		seen[key] = true
		if prior, ok := byName[key]; ok {
			entries = append(entries, prior)
		} else {
			entries = append(entries, cdnEntry{Address: a})
		}
	}
	return entries, nil
}

func cdnLinksForClient(ib *nativeInbound, cl nativeClient) []string {
	if ib.CDN == nil || !ib.Enable || !cl.Enable {
		return nil
	}
	var links []string
	for _, e := range ib.CDN.Entries {
		if !e.Verified {
			continue
		}
		q := url.Values{"encryption": {"none"}, "security": {"tls"}, "type": {ib.Network},
			"sni": {ib.CDN.Domain}, "host": {ib.CDN.Domain}, "path": {ib.Path}, "fp": {"chrome"}}
		label := ib.Remark + " · " + e.Address
		links = append(links, fmt.Sprintf("vless://%s@%s?%s#%s", cl.ID,
			net.JoinHostPort(e.Address, strconv.Itoa(ib.CDN.EdgePort)), q.Encode(), url.PathEscape(label)))
	}
	return links
}

type cdnRecord struct {
	ID        int        `json:"id"`
	Port      int        `json:"port"`
	Remark    string     `json:"remark"`
	Enable    bool       `json:"enable"`
	Transport string     `json:"transport"`
	Path      string     `json:"path"`
	Domain    string     `json:"domain"`
	EdgePort  int        `json:"edge_port"`
	CertFile  string     `json:"cert_file"`
	KeyFile   string     `json:"key_file"`
	Entries   []cdnEntry `json:"entries"`
	Links     []string   `json:"links"`
}

func (n *Native) CDNRecords() []cdnRecord {
	n.mu.Lock()
	defer n.mu.Unlock()
	result := []cdnRecord{}
	for _, ib := range n.store.sorted() {
		if ib.CDN == nil {
			continue
		}
		c := ib.CDN
		rec := cdnRecord{ID: ib.ID, Port: ib.Port, Remark: ib.Remark, Enable: ib.Enable,
			Transport: ib.Network, Path: ib.Path, Domain: c.Domain, EdgePort: c.EdgePort,
			CertFile: ib.TLS.CertFile, KeyFile: ib.TLS.KeyFile, Entries: append([]cdnEntry{}, c.Entries...)}
		for _, cl := range ib.Clients {
			rec.Links = append(rec.Links, cdnLinksForClient(ib, cl)...)
		}
		result = append(result, rec)
	}
	return result
}

func (n *Native) CDNLinks() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var links []string
	for _, ib := range n.store.Inbounds {
		if ib.CDN != nil {
			for _, cl := range ib.Clients {
				links = append(links, cdnLinksForClient(ib, cl)...)
			}
		}
	}
	return links
}

func (n *Native) SaveCDN(req cdnRequest, tunnels []*Tunnel) (int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	finish := n.beginChange()
	defer finish()

	req.Domain = strings.ToLower(strings.TrimSpace(req.Domain))
	if !validCDNDomain(req.Domain) || !validCDNEdgePort(req.EdgePort) ||
		(req.Transport != "ws" && req.Transport != "httpupgrade") ||
		!validCDNPath(req.Path) {
		return 0, fmt.Errorf("域名、CDN 边缘端口、传输类型或路径无效")
	}
	if err := validateCDNCert(req.Domain, req.CertFile, req.KeyFile); err != nil {
		return 0, err
	}
	if len(req.Remark) > 120 {
		return 0, fmt.Errorf("备注过长")
	}
	var ib *nativeInbound
	if req.Action == "create" {
		if req.Port == 0 {
			port, err := freeRandomPort(n.store.usedPorts())
			if err != nil {
				return 0, err
			}
			req.Port = port
		}
		ib = &nativeInbound{ID: n.store.NextID, Protocol: "vless", Security: "tls",
			Manual: true, HostDirect: true, Enable: true, Clients: []nativeClient{{
				Email: "cdn-" + randomHex(3), ID: newUUID(), Enable: true}}}
		n.store.NextID++
		n.store.Inbounds = append(n.store.Inbounds, ib)
	} else if req.Action == "update" {
		ib = n.store.byID(req.ID)
		if ib == nil || ib.CDN == nil {
			return 0, fmt.Errorf("CDN 入站不存在")
		}
	} else {
		return 0, fmt.Errorf("操作类型无效")
	}
	if req.Port < 1 || req.Port > 65535 {
		return 0, fmt.Errorf("源站监听端口无效")
	}
	for _, other := range n.store.Inbounds {
		if other.ID != ib.ID && other.Port == req.Port {
			return 0, fmt.Errorf("监听端口已占用")
		}
	}
	if req.Port != ib.Port && externalUsedPorts()[req.Port] {
		return 0, fmt.Errorf("监听端口已被其他服务占用")
	}
	old := ib.CDN
	var previous []cdnEntry
	if old != nil {
		previous = old.Entries
	}
	// Every edit invalidates the previous probe, including replacement of a
	// certificate or private key stored at an unchanged file path.
	entries, err := reconcileCDNEntries(req.Addresses, previous, false)
	if err != nil {
		return 0, err
	}
	ib.Port, ib.Network, ib.Path, ib.Host = req.Port, req.Transport, req.Path, req.Domain
	ib.TLS = &tlsConfig{ServerName: req.Domain, CertFile: req.CertFile, KeyFile: req.KeyFile}
	ib.CDN = &cdnConfig{Domain: req.Domain, EdgePort: req.EdgePort, Entries: entries}
	if req.Enable != nil {
		ib.Enable = *req.Enable
	}
	if name := strings.TrimSpace(req.Remark); name != "" {
		ib.Remark = name
	} else if ib.Remark == "" {
		ib.Remark = "Cloudflare CDN " + req.Domain
	}
	if err := validateCDNInbound(ib); err != nil {
		return 0, err
	}
	if err := n.apply(tunnels); err != nil {
		return 0, err
	}
	return ib.ID, nil
}

func (n *Native) DeleteCDN(id int, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	finish := n.beginChange()
	defer finish()
	ib := n.store.byID(id)
	if ib == nil || ib.CDN == nil {
		return fmt.Errorf("CDN 入站不存在")
	}
	kept := make([]*nativeInbound, 0, len(n.store.Inbounds)-1)
	for _, inbound := range n.store.Inbounds {
		if inbound.ID != id {
			kept = append(kept, inbound)
		}
	}
	n.store.Inbounds = kept
	return n.apply(tunnels)
}

// The published Cloudflare prefixes are checked before any probe TCP dial.
// This prevents an attacker-controlled DNS answer from turning the verifier
// into an internal-network port scanner.
var cloudflarePrefixes struct {
	sync.Mutex
	at   time.Time
	nets []*net.IPNet
}

func currentCloudflarePrefixes() ([]*net.IPNet, error) {
	cloudflarePrefixes.Lock()
	defer cloudflarePrefixes.Unlock()
	if time.Since(cloudflarePrefixes.at) < 30*time.Minute && len(cloudflarePrefixes.nets) > 0 {
		return cloudflarePrefixes.nets, nil
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var ranges []*net.IPNet
	for _, endpoint := range []string{"https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"} {
		resp, err := client.Get(endpoint)
		if err != nil {
			return nil, fmt.Errorf("无法读取 Cloudflare 官方 IP 段: %w", err)
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("Cloudflare 官方 IP 段返回错误: %s", resp.Status)
		}
		count := 0
		for _, line := range strings.Fields(string(data)) {
			_, network, err := net.ParseCIDR(line)
			if err != nil {
				return nil, fmt.Errorf("Cloudflare IP 段格式无效")
			}
			ranges = append(ranges, network)
			count++
		}
		if count == 0 {
			return nil, fmt.Errorf("Cloudflare IP 段为空")
		}
	}
	cloudflarePrefixes.nets, cloudflarePrefixes.at = ranges, time.Now()
	return ranges, nil
}

func probeCDNEntry(c cdnConfig, transport, path, address string, ranges []*net.IPNet) error {
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	defer cancel()
	var ips []net.IP
	if ip := net.ParseIP(address); ip != nil {
		ips = []net.IP{ip}
	} else {
		rows, err := net.DefaultResolver.LookupIPAddr(ctx, address)
		if err != nil {
			return fmt.Errorf("DNS 解析失败: %w", err)
		}
		for _, row := range rows {
			ips = append(ips, row.IP)
		}
	}
	for _, ip := range ips {
		trusted := false
		for _, cidr := range ranges {
			if cidr.Contains(ip) {
				trusted = true
				break
			}
		}
		if !trusted {
			continue
		}
		conn, err := (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(c.EdgePort)))
		if err != nil {
			continue
		}
		tlsConn := tls.Client(conn, &tls.Config{ServerName: c.Domain, MinVersion: tls.VersionTLS12})
		_ = tlsConn.SetDeadline(time.Now().Add(4 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			continue
		}
		// Xray WS and HTTPUpgrade both accept a WebSocket-style Upgrade.
		request := "GET " + path + " HTTP/1.1\r\nHost: " + c.Domain + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
		_, err = io.WriteString(tlsConn, request)
		if err == nil {
			resp, readErr := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodGet})
			if readErr == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusSwitchingProtocols {
					conn.Close()
					return nil
				}
			}
		}
		conn.Close()
	}
	return fmt.Errorf("未通过 Cloudflare IP、可信 TLS 及 %s Upgrade(101) 检查", transport)
}

func (n *Native) CheckCDN(id int, tunnels []*Tunnel) ([]cdnEntry, error) {
	n.mu.Lock()
	ib := n.store.byID(id)
	if ib == nil || ib.CDN == nil {
		n.mu.Unlock()
		return nil, fmt.Errorf("CDN 入站不存在")
	}
	original := *ib.CDN
	sourceInbound := ib
	original.Entries = append([]cdnEntry(nil), ib.CDN.Entries...)
	transport, path := ib.Network, ib.Path
	n.mu.Unlock()
	ranges, checkErr := currentCloudflarePrefixes()
	limiter := make(chan struct{}, 8)
	var checks sync.WaitGroup
	for i := range original.Entries {
		checks.Add(1)
		limiter <- struct{}{}
		go func(i int) {
			defer checks.Done()
			defer func() { <-limiter }()
			e := &original.Entries[i]
			err := checkErr
			if err == nil {
				err = probeCDNEntry(original, transport, path, e.Address, ranges)
			}
			e.Verified = err == nil
			e.CheckedAt = time.Now().UTC().Format(time.RFC3339)
			e.Error = ""
			if err != nil {
				e.Error = err.Error()
			}
		}(i)
	}
	checks.Wait()
	n.mu.Lock()
	defer n.mu.Unlock()
	ib = n.store.byID(id)
	if ib != sourceInbound || ib == nil || ib.CDN == nil || ib.CDN.Domain != original.Domain || ib.CDN.EdgePort != original.EdgePort ||
		ib.Network != transport || ib.Path != path || len(ib.CDN.Entries) != len(original.Entries) {
		return nil, fmt.Errorf("检测期间 CDN 配置已变更，请重新检测")
	}
	for i, e := range original.Entries {
		if ib.CDN.Entries[i].Address != e.Address {
			return nil, fmt.Errorf("检测期间候选地址已变更，请重新检测")
		}
	}
	// Check the committed inbound before beginChange creates deep-copied
	// pointers; otherwise every check appears to be a concurrent edit.
	finish := n.beginChange()
	defer finish()
	ib = n.store.byID(id)
	ib.CDN.Entries = original.Entries
	if err := n.apply(tunnels); err != nil {
		return nil, err
	}
	return original.Entries, nil
}

func apiCDN(m *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		panel, err := openPanel()
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		n, ok := panel.(*Native)
		if !ok {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "CDN 管理需要启用内置 Xray 模式"})
			return
		}
		if r.Method == http.MethodGet {
			if target := r.URL.Query().Get("target"); target != "" {
				links := n.CDNLinks()
				var data []byte
				var exportErr error
				switch target {
				case "links":
					data = []byte(strings.Join(links, "\n"))
				case "base64":
					data = []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n"))))
				case "mihomo":
					data, exportErr = renderClash(links)
				default:
					writeJSON(w, 400, map[string]string{"error": "导出格式无效"})
					return
				}
				if exportErr != nil {
					writeJSON(w, 400, map[string]string{"error": exportErr.Error()})
					return
				}
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store")
				_, _ = w.Write(data)
				return
			}
			writeJSON(w, http.StatusOK, n.CDNRecords())
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET/POST"})
			return
		}
		defer r.Body.Close()
		dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
		dec.DisallowUnknownFields()
		var req cdnRequest
		if err := dec.Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "CDN 请求 JSON 无效"})
			return
		}
		var result any
		switch req.Action {
		case "create", "update":
			var id int
			id, err = n.SaveCDN(req, m.Tunnels())
			result = map[string]int{"id": id}
		case "delete":
			err = n.DeleteCDN(req.ID, m.Tunnels())
			result = map[string]bool{"ok": true}
		case "check":
			result, err = n.CheckCDN(req.ID, m.Tunnels())
		default:
			writeJSON(w, 400, map[string]string{"error": "CDN 操作无效"})
			return
		}
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		invalidateInbounds()
		writeJSON(w, http.StatusOK, result)
	}
}
