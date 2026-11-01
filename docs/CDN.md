# Cloudflare CDN 节点管理（实验性）

本功能在 xnvgatebox 的 **内置 Xray 模式** 添加独立的 CDN 入站管理。保留原有 VPN Gate、Xray 出口、订阅和管理界面；不负责自动创建 Cloudflare DNS、Origin Rules 或申请证书。

## 前置条件

1. 自己控制的域名已接入 Cloudflare，且已创建指向源站服务器公网 IP 的 DNS 记录，并启用 **Proxied（橙云）**。
2. Cloudflare SSL/TLS 使用 **Full (strict)**。在源站预先准备域名匹配的有效证书和私钥（可使用 Cloudflare Origin CA，或公开可信 CA 签发的证书），把证书文件放在运行 Xray 的服务器上，并保证 Xray 可以读取。
3. 在服务器防火墙及云安全组里放行选定的 **源站监听 TCP 端口**，并限制不必要的入站来源。强烈建议只允许 Cloudflare 官方公布的回源 IP 段访问该端口；变更前先确认现有直连服务、SSH 不受影响。
4. 选择 Cloudflare 支持的 HTTPS 边缘端口：**443、2053、2083、2087、2096、8443**。源站端口可以不同，但必须配置 Cloudflare **Origin Rules**（支持该功能的套餐/规则）将目的端口改写为实际源站监听端口；或者直接使用与边缘相同的端口。DNS/回源路由配置必须事先正常工作。
5. 自行确认 Cloudflare 对流量类型、流量大小及使用方式的相关政策与限制。

## 创建与使用

1. 打开 Web 高级管理界面的 **Cloudflare CDN 节点** 区域，点击 **新建 CDN 节点**。
2. 输入 CDN 域名、边缘端口、源站端口（留空随机）、VLESS 传输（**WS** 或 **HTTPUpgrade**）、请求路径（例如 `/cdn`）、源站证书/私钥绝对路径和备注。Cloudflare 的域名应与 TLS SNI 一致。
3. 添加最多 64 个候选地址，每行一个：官方 Cloudflare IP，或解析至官方 Cloudflare IP 的优选域名。保存后候选状态均为 **未验证**。
4. 点击 **检查候选**，程序会检查解析后的 IP 是否属于 Cloudflare 官方段，并尝试 TLS 校验和 HTTP Upgrade 的 101 响应；**只有检查通过且入口、客户端均启用的候选** 才会提供可复制的链接。
5. 可导出 **明文 VLESS 链接、Base64 链接或 Mihomo JSON/YAML 1.2 兼容配置**。传统订阅入口也会包含已验证 CDN 节点。编辑证书、域名、传输或候选列表后，会清空原有成功状态，必须重新检查。
6. 使用管理界面的启用/停用按钮或编辑弹窗控制入口。删除节点会使关联的客户端链接失效。

## 检查范围与限制

- **探测成功表示 Cloudflare IP 归属、证书链/TLS 握手和 HTTP Upgrade 101 响应通过；不代表 VLESS 身份验证、代理出站或端到端流量一定可用。** 需要用真实客户端完成一次实际连通性测试。
- 探测不会替你自动创建 DNS 或更新 Cloudflare 设置；不会在源站打开防火墙端口或配置反向代理。
- 探测仅接受 Cloudflare 公布的 IP 网段。部分第三方优选域名如解析到非官方网段，将被拒绝验证；IPv4/IPv6 地址可能因 DNS 和网络条件在不同时间表现不同。
- 源站端口、路径、证书或 Cloudflare Origin Rules 不一致时，通常无法通过验证。证书路径需真实存在且可由服务读取；域名和证书变更后重新检查。
- 候选状态保存到 `native.json`，只有成功验证的地址会加入订阅。状态是上次检测的快照，**不会自动保证后续持续可用**，建议周期性手动复测。
- 节点仍使用 VLESS + TLS，由 Xray 处理 HTTP Upgrade 和连接。Cloudflare 网络侧的策略或代理行为可能导致部分入口无法正常转发，尤其是 HTTPUpgrade；需要以真实客户端测试为准。

## 变更和回滚

部署前备份 `native.json`、`xray.json` 和 TLS 证书文件，保留服务二进制旧版本及 Cloudflare 规则配置。修改节点会通过现有 Native 配置事务生成、验证并尝试应用完整配置；应用失败会使用已有事务恢复机制。首次试用建议先在测试服务器验证 CDN 域名、证书、回源端口与订阅。若升级后出现问题，恢复旧二进制与同一时间点的配置快照，必要时恢复 Cloudflare Origin Rules。

**当前实现没有自动 Cloudflare API DNS/Origin Rules/证书生命周期管理，也没有经过生产环境端到端验收。**
