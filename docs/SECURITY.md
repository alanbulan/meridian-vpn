# Security boundary

## Implemented
- GUI remains unprivileged. NetworkManager and distro-managed OpenConnect or L2TP/IPsec services own privileged networking; no custom elevated shell/script interface is exposed.
- Fixed command structures use `exec.CommandContext`, not a shell. User profiles cannot set executable/script paths or arbitrary options.
- AnyConnect HTTPS gateways reject embedded credentials, query strings, fragments, control characters, invalid ports and overlong values. TLS verification stays enabled.
- Password travels to unprivileged OpenConnect via stdin. Its authenticated cookie/certificate/gateway tuple travels to nmcli via `/proc/self/fd/0`, not argv or a secret file. Authentication output is parsed as a strict data format, never evaluated as shell code.
- NetworkManager profiles are uniquely UUID-scoped, in-memory (`save no`) and non-autoconnecting. Cleanup addresses that generated UUID only.
- Command output is bounded. Raw stderr/errors are not shown or persisted. Go strings and runtime copies cannot guarantee cryptographic zeroization of all process memory; sensitive byte buffers are cleared where practical.
- `Connected` requires NetworkManager activation and the expected interface being up with an address. It is not inferred from subprocess launch.
- Graceful disconnect/quit waits for cleanup. Cleanup uncertainty remains explicit; reconnect is blocked rather than claiming the system is safe.

## Advanced fields and imports
- Custom CA is a bounded regular PEM trust-root file, not a client private key. Linux no-follow/nonblocking opens reject symlink/FIFO races. No privileged backend receives the user-selected CA path; the authenticated gateway fingerprint crosses the boundary.
- Proxy URLs reject embedded credentials and unsupported schemes. Any proxy requires fresh explicit consent for possible system integrated authentication; the runtime-only flag is excluded from JSON and strict import rejects injected consent. Authentication uses `--proxy-auth=none`; the NM tunnel may use its normal integrated-auth behavior only after the explicit per-attempt authorization.
- When no explicit proxy is configured, authentication passes `--no-proxy`. GUI-created subprocess environments drop inherited `*_proxy` variables (including embedded credentials) and enforce the C locale. This does not modify or inspect the separate administrator-managed NetworkManager service environment; deployment must ensure that trusted service has the intended proxy policy.
- Auth group, MTU and transport options use validated typed fields, never shell interpolation. Certificate checks cannot be disabled.
- Meridian JSON import is versioned, size-bounded, duplicate-safe and atomic. A separate bounded, read-only INI structural preview reports counts only; it never imports vendor settings, exposes values, interprets hooks or executes paths. Export omits in-memory credentials/consent and cannot overwrite the active configuration.
- Metrics are read only from the verified app-generated interface and cached every two seconds; failures return unavailable rather than invented traffic.

## Limits / deployment checklist
- A real OpenConnect client passed a controlled local TLS authentication fixture, but no actual enterprise gateway was available for interoperability verification. This is not universal enterprise SSLVPN or verified LeagSoft UniVPN support.
- Linux AnyConnect and L2TP/IPsec have concrete NetworkManager adapters. L2TP requires IPsec, typed PPP/IPsec options and a bare hostname/IP gateway. Both still require live deployment validation; other protocols are not implied by profile storage.
- MFA/SSO and posture-check negotiation may fail; interactive prompts are not bypassed or automatically accepted.
- No automatic root elevation, certificate bypass, arbitrary imported hooks, kill switch or DNS/route leak audit.
- System NetworkManager policy, plugin version, TUN permissions and OS authorization must be validated by the deployer. OS package installations and network changes are separate user-authorized actions.
- Forced process termination may leave a system-managed connection alive. Inspect and disconnect the app-named NetworkManager connection after an abnormal exit. A future supervised service needs a crash/lease policy.
- POSIX mode 0600 is not a Windows ACL guarantee. Windows/macOS backends, code signing/notarization and installers are not delivered as production-ready.
- The native UI never presents mocked process fixtures as real connectivity.

## 客户端证书与交互认证

- 配置只保存证书格式及身份引用。PEM验证有效期、用途与密钥匹配；PKCS#12要求owner-only容器和带MAC的有限ASN.1结构，密码/加密完整性/身份由OpenConnect验证，不把保存成功当作认证成功。PKCS#11只接受非秘密对象选择URI，拒绝PIN、模块路径、查询及未知属性，不安装或枚举令牌。Linux文件引用拒绝符号链接/FIFO并持有校验后的描述符；CA亦拒绝其他用户可写文件。详见CERTIFICATE-AUTHENTICATION.md。加密私钥口令只在本次认证内存中，通过匿名管道/私有IPC提供，绝不放入argv、环境变量或明文临时文件。
- 可选 `meridian-auth-helper` 是非特权、认证专用的libopenconnect进程，不创建隧道。GUI不解析stderr/终端提示来猜测MFA；结构化表单限制大小、字段数、轮次、会话和时间，取消会终止进程。服务器文案仅作普通文本显示，不解释HTML、链接或命令。
- 所有表单响应均属于当前SessionID/Round；过期回答拒绝。取消、后退、切换与退出清除界面引用，不复用口令、OTP或代理授权。Go字符串与原生输入框由运行时回收，不承诺内存取证级绝对抹除。
- 多网关是用户每次明确选择目标，不是自动信任其他主机。快速切换必须先确认旧连接清理，清理未知时停止，随后要求新认证和授权。
- 可选组件依赖与认证夹具结果不等于所有厂商MFA/SSO/终端合规互通，亦不等于真实VPN端到端已验证。

## 命令行与诊断

`meridianctl` 的配置与诊断命令仍保持离线/只读；Linux前台 `connect` 必须提供明确配置索引、`--authorize-network` 与 `--credentials-stdin`。凭据只经非终端stdin输入有界JSON，不接受argv/环境变量，拒绝重复键、未知键和额外JSON对象。只清理本进程拥有的Engine会话，取消或输出失败不跳过清理；不提供跨进程disconnect、自动重连或终端MFA。SIGKILL/崩溃/断电不保证清理，实际网关与系统网络恢复仍需独立验收。列表默认脱敏，显示私有配置需明确参数。导入先预览或创建新文件，避免与正在运行的GUI争写；导出拒绝覆盖已有文件。诊断仅含固定白名单状态，不含路径、网关、用户名、接口IP、环境变量、原始日志、密码、Cookie或私钥。

## L2TP/IPsec新增边界

密码与PSK只驻留本次Credentials，通过nmcli私有stdin密码通道传入，不进入argv、配置或应用临时文件。临时UUID配置禁用自动连接，秘密标记为不保存；这不承诺系统特权插件不使用root-only运行时文件。连接成功要求该UUID激活及其PPP接口/地址匹配；失败仅清理本次UUID，清理未知时阻止重连。默认加密提案取决于系统插件，管理员应提供符合策略的IKE/ESP提案。PAP/CHAP属于旧方法且始终要求IPsec。受控测试未创建真实PPP/TUN、修改宿主路由/DNS或接触企业网关。

## 实验性UniVPN broker

持续双TLS传输不使用AnyConnect的认证Cookie交接路径。实验性broker包含Unix SO_PEERCRED校验、固定可信执行程序/钩子及生命周期接口；具体NetworkController及ip/resolvectl适配已实现并以受控runner测试，严格限制独占已标记TUN、地址、split routes、DNS和端点逃逸路由，要求清理后的状态证明。可信hook会话来源、完整后代进程隔离和独占网络命名空间租约尚未实现，故默认GUI连接不可用。Unix socket集成测试受到当前沙箱EPERM限制，必须列为未执行/跳过而非通过。尚未安装或运行特权服务、创建内核TUN、改动路由DNS，也未验证崩溃后的真实网络恢复。
