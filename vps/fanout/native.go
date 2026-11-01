package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
)

// Native 是 fanout 自己跑 Xray 的后端，用在本机没装 3x-ui 的场合。
//
// 入站数据存在 native.json，Xray 的运行配置每次改动后整份重新生成。
// 全量重写比增量改省心：配置是纯函数产物，不会出现改了一半的中间态。
type Native struct {
	mu              sync.Mutex
	dir             string
	store           *nativeStore
	proc            *xrayProc
	committed       *nativeStore
	runtime         nativeRuntime
	transactionHook func(string) error
	unavailable     bool
}

func openNative(workDir string) (*Native, error) {
	if workDir == "" {
		return nil, fmt.Errorf("自建模式缺少工作目录")
	}
	bin, err := findXray(workDir)
	if err != nil {
		return nil, err
	}
	proc := &xrayProc{bin: bin, dir: workDir}
	proc.reapOrphan()
	if err := recoverConfigTransaction(workDir, nativeJournal, nativeConfigFiles); err != nil {
		return nil, err
	}
	store, err := loadNativeStore(workDir)
	if err != nil {
		return nil, err
	}
	n := &Native{
		dir:       workDir,
		store:     store,
		proc:      proc,
		committed: store,
	}
	return n, nil
}

func (n *Native) Kind() string { return "native" }

func (n *Native) Describe() string {
	return "xnvgatebox"
}

// OnTunnelsChanged 在隧道集合变化后重建配置。自建模式下出站直接由隧道列表
// 推导，所以隧道一变就要重新生成，否则新出口没有对应的 socks 出站。
func (n *Native) OnTunnelsChanged(tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.apply(tunnels)
}

// Close 停掉自己拉起的 Xray。
func (n *Native) Close() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.proc.stop()
}

func (n *Native) Inbounds(live map[string]bool) ([]Inbound, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.unavailable {
		return nil, fmt.Errorf("配置运行恢复未完成，内置 Xray 保持阻断")
	}

	list := n.store.sorted()
	out := make([]Inbound, 0, len(list))
	for _, ib := range list {
		if ib.SocksSlot > 0 || ib.ThirdParty != nil {
			continue
		}
		boundUp := live[ib.BoundTo]
		if ib.BoundSlot > 0 {
			boundUp = live[slotOutboundTag(ib.BoundSlot)]
		}
		out = append(out, Inbound{
			ID: ib.ID, Port: ib.Port, Protocol: ib.Protocol,
			Remark: ib.Remark, Enable: ib.Enable, Tag: ib.tag(),
			HostDirect: ib.HostDirect, ManagedSlot: ib.ManagedSlot, Manual: ib.Manual, BoundTo: ib.BoundTo, BoundUp: boundUp, BoundSlot: ib.BoundSlot, NameMode: inboundNameMode(ib.NameMode, ib.Remark),
		})
	}
	return out, nil
}

func (n *Native) InboundDetail(id int, publicHost string) (*InboundDetail, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.unavailable {
		return nil, fmt.Errorf("配置恢复未完成，订阅服务已阻断")
	}

	ib := n.store.byID(id)
	if ib == nil {
		return nil, fmt.Errorf("入站 %d 不存在", id)
	}
	detail := &InboundDetail{
		Inbound: Inbound{
			ID: ib.ID, Port: ib.Port, Protocol: ib.Protocol,
			Remark: ib.Remark, Enable: ib.Enable, Tag: ib.tag(),
			HostDirect: ib.HostDirect, ManagedSlot: ib.ManagedSlot, Manual: ib.Manual, BoundTo: ib.BoundTo, BoundSlot: ib.BoundSlot, NameMode: inboundNameMode(ib.NameMode, ib.Remark),
		},
		Listen:  "0.0.0.0",
		Network: ib.netOrTCP(),
		TLS:     ib.securityOrNone(),
	}
	for _, c := range ib.Clients {
		id := c.ID
		if ib.Protocol == "trojan" {
			id = c.Password
		}
		detail.Clients = append(detail.Clients, ClientInfo{Email: c.Email, ID: id, Enable: c.Enable})
		if ib.CDN != nil {
			detail.Links = append(detail.Links, cdnLinksForClient(ib, c)...)
		} else {
			detail.Links = append(detail.Links, shareLink(ib, c, publicHost))
		}
	}
	return detail, nil
}

func (n *Native) InboundLinks(ids []int, publicHost string) ([]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.unavailable {
		return nil, fmt.Errorf("配置恢复未完成，订阅服务已阻断")
	}

	var out []string
	for _, id := range ids {
		ib := n.store.byID(id)
		if ib == nil || ib.SocksSlot > 0 {
			continue
		}
		for _, c := range ib.Clients {
			if !c.Enable {
				continue
			}
			if ib.CDN != nil {
				out = append(out, cdnLinksForClient(ib, c)...)
			} else {
				out = append(out, shareLink(ib, c, publicHost))
			}
		}
	}
	return out, nil
}

func (n *Native) Bind(inboundTag string, hostname string, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	finish := n.beginChange()
	defer finish()

	var target *Tunnel
	if hostname != "" {
		for _, t := range tunnels {
			if t.Node.HostName == hostname {
				target = t
				break
			}
		}
		if target == nil {
			return fmt.Errorf("节点 %s 没有运行中的隧道", hostname)
		}
		if target.Status != "up" {
			return fmt.Errorf("节点 %s 的隧道还没连通（当前 %s）", hostname, target.Status)
		}
	}

	var found *nativeInbound
	for _, ib := range n.store.Inbounds {
		if ib.tag() == inboundTag {
			found = ib
			break
		}
	}
	if found == nil {
		return fmt.Errorf("入站 %s 不存在", inboundTag)
	}

	if found.HostDirect || found.SocksSlot > 0 || found.ThirdParty != nil || found.ManagedSlot {
		return fmt.Errorf("此入口由本机直出或 SOCKS 访问设置管理")
	}
	if target == nil {
		found.BoundTo = ""
		found.BoundSlot = 0
	} else {
		found.BoundTo = sanitizeTag(target.Node.HostName)
		found.BoundSlot = target.Slot
	}
	return n.apply(tunnels)
}

func (n *Native) Rebind(oldHost string, target *Tunnel, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	finish := n.beginChange()
	defer finish()

	oldTag := sanitizeTag(oldHost)
	newTag := sanitizeTag(target.Node.HostName)
	newLabel := exitLabel(target)
	for _, ib := range n.store.Inbounds {
		if ib.BoundSlot > 0 {
			if ib.BoundSlot != target.Slot {
				continue
			}
		} else if oldTag == "" || ib.BoundTo != oldTag {
			continue
		}
		ib.BoundTo = newTag
		ib.BoundSlot = target.Slot
		// 备注里带着旧出口的地区和 IP 尾段，换了节点要跟着改
		if ib.NameMode != "custom" {
			ib.Remark = renameExitLabel(ib.Remark, newLabel)
		}
	}
	return n.apply(tunnels)
}

func (n *Native) ResyncOutbound(t *Tunnel, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.apply(tunnels)
}

// CloneToTunnels 以某个入站为模板，为每条指定隧道复制一个入站并绑好出口。
//
// 客户端凭据整套沿用模板：同一个 UUID 能走所有出口，用户只改端口。
func (n *Native) CloneToTunnels(templateID int, hosts []string, tunnels []*Tunnel) ([]int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	finish := n.beginChange()
	defer finish()

	tpl := n.store.byID(templateID)
	if tpl == nil {
		return nil, fmt.Errorf("模板入站 %d 不存在", templateID)
	}
	if tpl.ThirdParty != nil || tpl.CDN != nil {
		return nil, fmt.Errorf("第三方代理请在代理资源中管理")
	}

	byHost := map[string]*Tunnel{}
	for _, t := range tunnels {
		byHost[t.Node.HostName] = t
	}

	used := n.store.usedPorts()
	// 别名撞了客户端会丢节点，先把已有备注收进来避让
	takenRemarks := map[string]bool{}
	for _, ib := range n.store.Inbounds {
		takenRemarks[strings.TrimSpace(ib.Remark)] = true
	}
	created := []int{}
	for _, host := range hosts {
		t := byHost[host]
		if t == nil || t.Status != "up" {
			continue
		}
		port, err := freeRandomPort(used)
		if err != nil {
			return nil, err
		}
		used[port] = true

		remark := uniqueRemark(exitLabel(t), takenRemarks)
		takenRemarks[remark] = true

		clone := &nativeInbound{
			ID:       n.store.NextID,
			Port:     port,
			Protocol: tpl.Protocol,
			Network:  tpl.Network,
			Path:     tpl.Path,
			Host:     tpl.Host,
			// 安全层必须跟着复制：漏掉的话从 REALITY/TLS 模板复制出来的
			// 入站会变成明文，而分享链接照样标着模板的协议，很难发现
			Security:  tpl.Security,
			TLS:       tpl.TLS,
			Reality:   tpl.Reality,
			Remark:    remark,
			Enable:    true,
			Manual:    true,
			Clients:   append([]nativeClient(nil), tpl.Clients...),
			BoundTo:   sanitizeTag(t.Node.HostName),
			BoundSlot: t.Slot, NameMode: "auto",
		}
		n.store.NextID++
		n.store.Inbounds = append(n.store.Inbounds, clone)
		created = append(created, port)
	}

	if len(created) == 0 {
		return nil, fmt.Errorf("没有可用的隧道")
	}
	if err := n.apply(tunnels); err != nil {
		return nil, err
	}
	return created, nil
}

func (n *Native) DeleteInbounds(ids []int, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	finish := n.beginChange()
	defer finish()

	drop := map[int]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	for _, ib := range n.store.Inbounds {
		if drop[ib.ID] && ib.ManagedSlot {
			for _, t := range tunnels {
				if t.Slot == ib.BoundSlot {
					return fmt.Errorf("自动入口由出口数量维护，请停用入口或在出口管理删除对应出口")
				}
			}
		}
	}
	kept := make([]*nativeInbound, 0, len(n.store.Inbounds))
	for _, ib := range n.store.Inbounds {
		if !drop[ib.ID] {
			kept = append(kept, ib)
		}
	}
	n.store.Inbounds = kept
	return n.apply(tunnels)
}

// UpdateInbound 改端口、备注与启停。
//
// 端口变了 inboundTag 也跟着变（tag 里含端口），所以路由规则要一起重写；
// apply 是整份重建，天然覆盖了这点。
func (n *Native) UpdateInbound(id int, patch InboundPatch, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	finish := n.beginChange()
	defer finish()

	ib := n.store.byID(id)
	if ib == nil {
		return fmt.Errorf("入站 %d 不存在", id)
	}

	if patch.Port != nil && *patch.Port != ib.Port {
		if ib.CDN != nil {
			return fmt.Errorf("CDN 节点端口请在 CDN 管理页面修改并重新检测候选")
		}
		port := *patch.Port
		if port < 1 || port > 65535 {
			return fmt.Errorf("端口 %d 不在合法范围", port)
		}
		for _, other := range n.store.Inbounds {
			if other.ID != id && other.Port == port {
				return fmt.Errorf("端口 %d 已被入站 %q 占用", port, other.Remark)
			}
		}
		ib.Port = port
	}
	if patch.NameMode != nil {
		if *patch.NameMode != "auto" && *patch.NameMode != "custom" {
			return fmt.Errorf("命名模式无效")
		}
		ib.NameMode = *patch.NameMode
	}
	if patch.Remark != nil {
		if r := strings.TrimSpace(*patch.Remark); r != "" {
			ib.Remark = r
			if patch.NameMode == nil {
				ib.NameMode = "custom"
			}
		}
	}
	if patch.Enable != nil {
		ib.Enable = *patch.Enable
	}
	return n.apply(tunnels)
}

// AddClient 给入站加一个客户端。同一入站上可以有多套凭据，便于分发给不同人。
func (n *Native) AddClient(id int, email string, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	finish := n.beginChange()
	defer finish()

	ib := n.store.byID(id)
	if ib == nil {
		return fmt.Errorf("入站 %d 不存在", id)
	}

	email = strings.TrimSpace(email)
	if email == "" {
		email = fmt.Sprintf("%s-%d-%s", ib.Protocol, ib.Port, randomHex(3))
	}
	for _, c := range ib.Clients {
		if c.Email == email {
			return fmt.Errorf("客户端 %q 已存在", email)
		}
	}

	ib.Clients = append(ib.Clients, nativeClient{
		Email:    email,
		ID:       newUUID(),
		Password: randomHex(8),
		Enable:   true,
		Flow:     visionFlow(ib),
	})
	return n.apply(tunnels)
}

// DeleteClient 摘掉一个客户端。留下最后一个是有意的：
// 没有任何客户端的入站在 Xray 里虽然合法，但谁也连不上，只会让人以为坏了。
func (n *Native) DeleteClient(id int, email string, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	finish := n.beginChange()
	defer finish()

	ib := n.store.byID(id)
	if ib == nil {
		return fmt.Errorf("入站 %d 不存在", id)
	}
	if len(ib.Clients) <= 1 {
		return fmt.Errorf("这是最后一个客户端，删掉就没人能连了")
	}

	kept := make([]nativeClient, 0, len(ib.Clients))
	for _, c := range ib.Clients {
		if c.Email != email {
			kept = append(kept, c)
		}
	}
	if len(kept) == len(ib.Clients) {
		return fmt.Errorf("客户端 %q 不存在", email)
	}
	ib.Clients = kept
	return n.apply(tunnels)
}

// ResetClient 换一套新凭据，旧链接立即失效。
func (n *Native) ResetClient(id int, email string, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	finish := n.beginChange()
	defer finish()

	ib := n.store.byID(id)
	if ib == nil {
		return fmt.Errorf("入站 %d 不存在", id)
	}
	for i := range ib.Clients {
		if ib.Clients[i].Email == email {
			ib.Clients[i].ID = newUUID()
			ib.Clients[i].Password = randomHex(8)
			return n.apply(tunnels)
		}
	}
	return fmt.Errorf("客户端 %q 不存在", email)
}

// visionFlow 沿用入站已有客户端的 flow，让新加的客户端与其余保持一致。
func visionFlow(ib *nativeInbound) string {
	for _, c := range ib.Clients {
		if c.Flow != "" {
			return c.Flow
		}
	}
	return ""
}

// NewInboundSpec 是自建模式下新建入站的参数。
//
// 留空的字段都有合理默认：端口随机、备注按协议加端口自动生成、
// 路径随机、REALITY 的密钥与 shortId 自动生成。
type NewInboundSpec struct {
	// Internal batch provisioning may reuse one successful check of the exact
	// same destination. This field cannot be set by HTTP/JSON input.
	realityChecked bool
	BoundSlot      int // explicit stable target for a new manual entry
	Protocol       string
	Network        string
	Port           int
	Remark         string
	Path           string
	Host           string
	Security       string
	// Vision 请求给 VLESS 客户端启用 xtls-rprx-vision
	Vision bool

	// TLS：留空 CertFile 就生成自签证书
	ServerName string
	CertFile   string
	KeyFile    string

	// REALITY
	Dest        string
	ServerNames string // 逗号分隔，留空则从 Dest 推出来
	ShortID     string
	Fingerprint string
}

// nativeProtocols 是自建模式支持的协议，与前端下拉保持一致。
var nativeProtocols = map[string]bool{"vless": true, "vmess": true, "trojan": true}

// CreateInbound 新建一个入站，端口留空时随机分配。
func (n *Native) CreateInbound(spec NewInboundSpec, tunnels []*Tunnel) (*CreatedInbound, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	finish := n.beginChange()
	defer finish()

	var target *Tunnel
	if spec.BoundSlot < 0 {
		return nil, fmt.Errorf("出口编号无效")
	}
	if spec.BoundSlot > 0 {
		for _, t := range tunnels {
			if t.Slot == spec.BoundSlot {
				target = t
				break
			}
		}
		if target == nil {
			return nil, fmt.Errorf("选择的出口不存在")
		}
	}
	ib, err := n.prepareInbound(spec, n.store.usedPorts())
	if err != nil {
		return nil, err
	}

	ib.Manual = true
	if target != nil {
		v := target.snapshot()
		ib.BoundSlot = v.Slot
		ib.BoundTo = sanitizeTag(v.Node.HostName)
	}
	n.store.NextID++
	n.store.Inbounds = append(n.store.Inbounds, ib)

	if err := n.apply(tunnels); err != nil {
		return nil, err
	}

	return &CreatedInbound{
		ID:       ib.ID,
		Port:     ib.Port,
		Protocol: ib.Protocol,
		Remark:   ib.Remark,
		Network:  ib.netOrTCP(),
		Security: ib.securityOrNone(),
	}, nil
}

// shareLink 生成客户端可直接导入的分享链接。
func shareLink(ib *nativeInbound, c nativeClient, host string) string {
	net := ib.netOrTCP()
	sec := ib.securityOrNone()

	q := url.Values{}
	q.Set("type", net)
	q.Set("security", sec)

	switch net {
	case "ws", "httpupgrade", "xhttp":
		q.Set("path", ib.Path)
		if ib.Host != "" {
			q.Set("host", ib.Host)
		}
	case "grpc":
		q.Set("serviceName", strings.TrimPrefix(ib.Path, "/"))
	}

	switch sec {
	case "tls":
		if ib.TLS != nil {
			if ib.TLS.ServerName != "" {
				q.Set("sni", ib.TLS.ServerName)
			}
			// 自签证书验不过 CA。Xray 26.x 移除了 allowInsecure，
			// 改用证书指纹让客户端固定信任这一张。
			if ib.TLS.SelfSigned && ib.TLS.CertSha256 != "" {
				q.Set("pinSHA256", ib.TLS.CertSha256)
			}
		}
	case "reality":
		if ib.Reality != nil {
			if len(ib.Reality.ServerNames) > 0 {
				q.Set("sni", ib.Reality.ServerNames[0])
			}
			// pbk 是分享链接的通用写法，各家客户端都认；
			// 注意 Xray 26.x 自己的配置文件里这个字段叫 password 而不是 publicKey
			q.Set("pbk", ib.Reality.PublicKey)
			if len(ib.Reality.ShortIDs) > 0 {
				q.Set("sid", ib.Reality.ShortIDs[0])
			}
			if ib.Reality.Fingerprint != "" {
				q.Set("fp", ib.Reality.Fingerprint)
			}
		}
	}

	if c.Flow != "" && ib.Protocol == "vless" {
		q.Set("flow", c.Flow)
	}

	frag := url.PathEscape(ib.Remark)

	switch ib.Protocol {
	case "trojan":
		return fmt.Sprintf("trojan://%s@%s:%d?%s#%s", url.User(c.Password).String(), host, ib.Port, q.Encode(), frag)
	case "vmess":
		// vmess 的 base64 形式各家客户端解析不一，用通用的 URI 形式
		q.Set("encryption", "auto")
		return fmt.Sprintf("vmess://%s@%s:%d?%s#%s", c.ID, host, ib.Port, q.Encode(), frag)
	default:
		q.Set("encryption", "none")
		return fmt.Sprintf("vless://%s@%s:%d?%s#%s", c.ID, host, ib.Port, q.Encode(), frag)
	}
}

// buildTLS 组装 TLS 配置。没给证书路径就生成一张自签的，落在 dir/certs 下。
func buildTLS(dir string, spec NewInboundSpec) (*tlsConfig, error) {
	name := strings.TrimSpace(spec.ServerName)
	if name == "" {
		name = "localhost"
	}
	conf := &tlsConfig{ServerName: name}

	cert, key := strings.TrimSpace(spec.CertFile), strings.TrimSpace(spec.KeyFile)
	// 只填一个多半是漏填，静默退回自签会让用户以为用上了自己的证书
	if (cert == "") != (key == "") {
		return nil, fmt.Errorf("证书和私钥要成对填写，或者都留空用自签证书")
	}
	if cert != "" && key != "" {
		if _, err := os.Stat(cert); err != nil {
			return nil, fmt.Errorf("证书文件不可读: %w", err)
		}
		if _, err := os.Stat(key); err != nil {
			return nil, fmt.Errorf("私钥文件不可读: %w", err)
		}
		conf.CertFile, conf.KeyFile = cert, key
		return conf, nil
	}

	// 自签证书验不过 CA，靠链接里的证书指纹让客户端固定信任
	c, k, err := selfSignedCert(dir, name)
	if err != nil {
		return nil, err
	}
	conf.CertFile, conf.KeyFile, conf.SelfSigned = c, k, true
	// 指纹是自签证书唯一能让客户端验过的凭据，算不出来就没法生成可用链接
	fp, err := certFingerprint(c)
	if err != nil {
		os.Remove(c)
		os.Remove(k)
		return nil, err
	}
	conf.CertSha256 = fp
	return conf, nil
}

// buildReality 组装 REALITY 配置，密钥和 shortId 都自动生成。
// xrayBin 用来跑 `xray x25519` 生成密钥对。
func buildReality(xrayBin string, spec NewInboundSpec) (*realityConfig, error) {
	dest := strings.TrimSpace(spec.Dest)
	if dest == "" {
		// REALITY 要跟 dest 完成一次真实 TLS1.3 握手，dest 不稳会让所有连接
		// 静默回落。microsoft.com 在部分机房握手经常走不完，这里选更可靠的。
		dest = "www.tesla.com:443"
	}
	if !strings.Contains(dest, ":") {
		dest += ":443"
	}

	var names []string
	for _, s := range strings.Split(spec.ServerNames, ",") {
		if s = strings.TrimSpace(s); s != "" {
			names = append(names, s)
		}
	}
	if len(names) == 0 {
		// 默认用 dest 的主机名：REALITY 要求 SNI 与被借用的站点一致
		names = []string{strings.SplitN(dest, ":", 2)[0]}
	}

	priv, pub, err := realityKeys(xrayBin)
	if err != nil {
		return nil, err
	}
	if !spec.realityChecked {
		if err := checkRealityDest(dest, names[0]); err != nil {
			return nil, fmt.Errorf("REALITY 目标站点不可用，换一个 dest: %w", err)
		}
	}

	short := strings.TrimSpace(spec.ShortID)
	if short == "" {
		short = randomShortID()
	}
	fp := strings.TrimSpace(spec.Fingerprint)
	if fp == "" {
		fp = "chrome"
	}

	return &realityConfig{
		Dest:        dest,
		ServerNames: names,
		PrivateKey:  priv,
		PublicKey:   pub,
		ShortIDs:    []string{short},
		Fingerprint: fp,
	}, nil
}

func (n *Native) prepareInbound(spec NewInboundSpec, used map[int]bool) (*nativeInbound, error) {
	ns, err := normalizeInboundSpec(spec, used)
	if err != nil {
		return nil, err
	}
	proto, network, security, port := ns.Protocol, ns.Network, ns.Security, ns.Port

	ib := &nativeInbound{
		NameMode: "custom",
		ID:       n.store.NextID,
		Port:     port,
		Protocol: proto,
		Network:  network,
		Path:     ns.Path,
		Host:     ns.Host,
		Security: security,
		Remark:   ns.Remark,
		Enable:   true,
	}

	switch security {
	case "tls":
		conf, err := buildTLS(n.dir, spec)
		if err != nil {
			return nil, err
		}
		ib.TLS = conf
	case "reality":
		conf, err := buildReality(n.proc.bin, spec)
		if err != nil {
			return nil, err
		}
		ib.Reality = conf
	}

	ib.Clients = []nativeClient{{
		Email:    fmt.Sprintf("%s-%d", proto, port),
		ID:       newUUID(),
		Password: randomHex(8),
		Flow:     ns.Flow,
		Enable:   true,
	}}

	return ib, nil
}
