package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func decodeShareBase64(s string) ([]byte, error) {
	for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := e.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("invalid_share_base64")
}

func normalizeVmessShare(link string) (string, error) {
	if !strings.HasPrefix(link, "vmess://") || strings.Contains(strings.SplitN(strings.TrimPrefix(link, "vmess://"), "#", 2)[0], "@") {
		return link, nil
	}
	b, err := decodeShareBase64(strings.SplitN(strings.TrimPrefix(link, "vmess://"), "#", 2)[0])
	if err != nil {
		return "", err
	}
	var v map[string]any
	if json.Unmarshal(b, &v) != nil {
		return "", fmt.Errorf("invalid_vmess_share")
	}
	value := func(k string) string {
		if v[k] == nil {
			return ""
		}
		return fmt.Sprint(v[k])
	}
	q := url.Values{"type": {value("net")}, "security": {"none"}, "sni": {value("sni")}, "host": {value("host")}, "path": {value("path")}, "alterId": {value("aid")}, "encryption": {value("scy")}, "fp": {value("fp")}}
	if value("tls") == "tls" {
		q.Set("security", "tls")
	}
	if value("net") == "grpc" {
		q.Set("serviceName", value("path"))
	}
	u := url.URL{Scheme: "vmess", Host: net.JoinHostPort(value("add"), value("port")), User: url.User(value("id")), RawQuery: q.Encode(), Fragment: value("ps")}
	return u.String(), nil
}

func clashProxy(link string) (map[string]any, error) {
	link, err := normalizeVmessShare(link)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(link)
	if err != nil || u.User == nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid_share_link")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid_share_port")
	}
	q := u.Query()
	p := map[string]any{"name": u.Fragment, "server": u.Hostname(), "port": port, "udp": false}
	transport := q.Get("type")
	if transport == "" {
		transport = "tcp"
	}
	if transport != "tcp" && transport != "ws" && transport != "grpc" && transport != "httpupgrade" {
		return nil, fmt.Errorf("unsupported_clash_transport")
	}
	switch u.Scheme {
	case "vless":
		p["type"], p["uuid"] = "vless", u.User.Username()
		if f := q.Get("flow"); f != "" {
			if f != "xtls-rprx-vision" {
				return nil, fmt.Errorf("unsupported_clash_flow")
			}
			p["flow"] = f
		}
	case "vmess":
		p["type"], p["uuid"], p["cipher"], p["alterId"] = "vmess", u.User.Username(), "auto", 0
		if a := q.Get("alterId"); a != "" {
			n, e := strconv.Atoi(a)
			if e != nil || n < 0 {
				return nil, fmt.Errorf("invalid_vmess_alter_id")
			}
			p["alterId"] = n
		}
		if cipher := q.Get("encryption"); cipher != "" {
			p["cipher"] = cipher
		}
	case "trojan":
		p["type"], p["password"] = "trojan", u.User.Username()
	default:
		return nil, fmt.Errorf("unsupported_clash_protocol")
	}
	if u.User.Username() == "" {
		return nil, fmt.Errorf("missing_share_credential")
	}
	security := q.Get("security")
	if security == "" {
		security = "none"
		if u.Scheme == "trojan" {
			security = "tls"
		}
	}
	if security != "none" && security != "tls" && security != "reality" {
		return nil, fmt.Errorf("unsupported_clash_security")
	}
	if u.Scheme == "trojan" && security != "tls" {
		return nil, fmt.Errorf("unsupported_clash_security")
	}
	if security != "none" {
		p["tls"], p["skip-cert-verify"] = true, false
		key := "servername"
		if u.Scheme == "trojan" {
			key = "sni"
		}
		if sni := q.Get("sni"); sni != "" {
			p[key] = sni
		}
		if fp := q.Get("fp"); fp != "" {
			p["client-fingerprint"] = fp
		} else if security == "reality" {
			p["client-fingerprint"] = "chrome"
		}
		if alpn := q.Get("alpn"); alpn != "" {
			p["alpn"] = strings.Split(alpn, ",")
		}
		if pin := q.Get("pinSHA256"); pin != "" {
			b, e := hex.DecodeString(strings.ReplaceAll(pin, ":", ""))
			if e != nil || len(b) != 32 {
				return nil, fmt.Errorf("invalid_certificate_pin")
			}
			p["fingerprint"] = hex.EncodeToString(b)
		}
	}
	if security == "reality" {
		if u.Scheme != "vless" {
			return nil, fmt.Errorf("unsupported_clash_reality")
		}
		key, e := base64.RawURLEncoding.DecodeString(q.Get("pbk"))
		if e != nil || len(key) != 32 {
			return nil, fmt.Errorf("invalid_reality_key")
		}
		sid := q.Get("sid")
		if _, e := hex.DecodeString(sid); e != nil || len(sid) > 16 {
			return nil, fmt.Errorf("invalid_reality_short_id")
		}
		p["reality-opts"] = map[string]any{"public-key": q.Get("pbk"), "short-id": sid}
	}
	if transport != "tcp" {
		p["network"] = transport
	}
	if transport == "ws" {
		path := q.Get("path")
		if path == "" {
			path = "/"
		}
		ws := map[string]any{"path": path}
		if host := q.Get("host"); host != "" {
			ws["headers"] = map[string]string{"Host": host}
		}
		p["ws-opts"] = ws
	}
	if transport == "httpupgrade" {
		path := q.Get("path")
		if path == "" {
			path = "/"
		}
		opts := map[string]any{"path": path}
		if host := q.Get("host"); host != "" {
			opts["host"] = host
		}
		p["httpupgrade-opts"] = opts
	}
	if transport == "grpc" {
		p["grpc-opts"] = map[string]string{"grpc-service-name": q.Get("serviceName")}
	}
	return p, nil
}

// JSON is a YAML 1.2 document and avoids injecting user names or credentials
// into YAML syntax. Mihomo consumes this complete profile directly.
func renderClash(links []string) ([]byte, error) {
	proxies := []map[string]any{}
	names := []string{}
	used := map[string]bool{"xnvgatebox": true, "DIRECT": true, "REJECT": true, "GLOBAL": true}
	for i, link := range links {
		p, err := clashProxy(link)
		if err != nil {
			return nil, fmt.Errorf("第 %d 个入口无法导出 Clash 配置（%s）", i+1, err)
		}
		name, _ := p["name"].(string)
		name = strings.TrimSpace(name)
		if name == "" {
			name = fmt.Sprintf("节点 %02d", i+1)
		}
		base := name
		for n := 2; used[name]; n++ {
			name = fmt.Sprintf("%s · %d", base, n)
		}
		used[name] = true
		p["name"] = name
		names = append(names, name)
		proxies = append(proxies, p)
	}
	return json.MarshalIndent(map[string]any{"mode": "rule", "log-level": "warning", "ipv6": false, "proxies": proxies, "proxy-groups": []any{map[string]any{"name": "xnvgatebox", "type": "select", "proxies": names}}, "rules": []string{"MATCH,xnvgatebox"}}, "", "  ")
}
