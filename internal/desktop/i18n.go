package desktop

import (
	"github.com/egoist/mygo/ui"
	"strings"
)

func (a *App) tr(s string) string {
	if a.Config.Settings.Language == "en" || a.Config.Settings.Language == "system" && a.SystemLanguage == "en" {
		return s
	}
	if z, ok := zh[s]; ok {
		return z
	}
	return s
}
func (a *App) label(c *ui.Context, s string) {
	ui.Text(c, a.tr(s)).FontSize(12).TextColor(c.Theme().TextMuted).FillWidth()
}

func (a *App) SetSystemLanguages(tags []string) {
	a.SystemLanguage = "zh"
	for _, tag := range tags {
		if strings.HasPrefix(strings.ToLower(tag), "zh") {
			a.SystemLanguage = "zh"
			return
		}
		if strings.HasPrefix(strings.ToLower(tag), "en") {
			a.SystemLanguage = "en"
			return
		}
	}
}

var zh = map[string]string{
	"Review the connection and authorize network changes before connecting": "连接前请检查连接配置并授权网络更改",
	"The previous session gateway is unavailable; choose a connection and sign in again": "上次会话的网关已不可用，请选择连接并重新登录",
	"Experimental UniVPN: direct TLS password authentication only":                                    "实验性 UniVPN：仅支持直连 TLS 密码认证",
	"A reviewed native engine and trusted continuous-session broker must be explicitly configured":    "必须另行明确配置经审核的原生引擎及可信的持续会话代理",
	"Authentication domain (blank = gateway host)":                                                    "认证域（留空使用网关主机名）",
	"Proxy, client certificates and interactive MFA are not supported by this experimental transport": "此实验传输暂不支持代理、客户端证书或交互式 MFA",
	"Linux · AnyConnect / L2TP-IPsec · NetworkManager":                                                "Linux · AnyConnect / L2TP-IPsec · NetworkManager",
	"Experimental UniVPN requires a separately configured trusted broker":                             "实验性 UniVPN 需要单独配置可信会话代理",
	"Tunnel verified by the trusted broker and its interface":                                         "可信会话代理及网络接口已确认隧道",

	"MRU (blank = automatic)":                                                             "MRU（留空为自动）",
	"MRU must be a whole number":                                                          "MRU 必须是整数",
	"Linux AnyConnect and L2TP/IPsec adapters via NetworkManager":                         "Linux AnyConnect 与 L2TP/IPsec 的 NetworkManager 适配器",
	"LeagSoft SSL VPN, national crypto and QUIC have no verified production support":      "联软专有 SSL VPN、国密与 QUIC 尚无经验证的生产支持",
	"Password, PEM/PKCS#12/PKCS#11 reference handling, custom CA and optional MFA helper": "密码、PEM/PKCS#12/PKCS#11 引用处理、自定义 CA 与可选 MFA 组件",
	"PKCS#12 unlock and hardware token use still require real-client validation; SSO/posture and password change remain unsupported": "PKCS#12 解锁与硬件令牌仍需真实客户端验证；SSO/终端合规和修改密码未支持",

	"L2TP/IPsec requires a host or IP, not an HTTPS URL": "L2TP/IPsec 网关填写主机名或 IP，而非 HTTPS 网址",
	"PPP authentication":                                     "PPP 认证方式",
	"PPP domain (optional)":                                  "PPP 域（可选）",
	"IPsec remote identity (optional)":                       "IPsec 对端身份（可选）",
	"IKE proposals (blank = system default)":                 "IKE 提案（留空使用系统默认）",
	"ESP proposals (blank = system default)":                 "ESP 提案（留空使用系统默认）",
	"Force IPsec encapsulation":                              "强制 IPsec 封装",
	"IPsec PSK is requested per session and is never stored": "每次会话单独输入 IPsec 预共享密钥，不保存",
	"IPsec pre-shared key (this session only)":               "IPsec 预共享密钥（仅本次会话）",

	"Certificate format":                 "证书格式",
	"PKCS#11 certificate URI":            "PKCS#11 证书 URI",
	"PKCS#11 private key URI (optional)": "PKCS#11 私钥 URI（可选）",
	"Token provider must already be configured; PIN is requested per session": "须先配置系统令牌提供方；每次会话单独输入 PIN",
	"Client certificate bundle (PKCS#12)":                                     "客户端证书包（PKCS#12）",
	"Certificate passphrase / token PIN (if required)":                        "证书口令 / 令牌 PIN（如需要）",

	"Inspect INI (read only)": "只读检查 INI",
	"INI file cannot be safely read or parsed; nothing was changed":                                                           "无法安全读取或解析 INI；未修改任何配置",
	"Read-only INI: %d sections, %d entries. All names and values hidden. Vendor compatibility unverified; nothing imported.": "INI 只读检查：%d 个分节，%d 个配置项。名称和值均隐藏，厂商兼容性未验证，未导入任何配置。",
	"Up to 16 explicit gateways, safe switching and fresh-authentication loss reminder":                                       "最多16个手选网关、安全切换、断线后新认证提醒",
	"Interface metrics, redacted diagnostics, profiles, CLI and opt-in Linux login startup":                                   "接口统计、脱敏诊断、配置管理、CLI、Linux可选登录启动",
	"Proprietary import, full system reports and automatic updates remain unsupported":                                        "专有配置导入、完整系统报告及自动升级未支持",

	"Linux opt-in login startup; proprietary import, full system reports and updates remain unsupported": "Linux可选登录启动；专有配置导入、完整系统报告及自动升级未支持",
	"Login startup is available on Linux only":                                                           "登录启动管理目前仅支持Linux",
	"Launch at login": "登录系统时启动",
	"Enable":          "启用",
	"Disable":         "停用",
	"Starts the application only; never automatically connects": "只启动应用，不自动连接VPN",
	"Confirm changing this user login entry?":                   "确认修改此用户登录启动项？",
	"Confirm change":                                                        "确认修改",
	"Startup settings are unavailable":                                      "当前无法管理登录启动项",
	"Existing startup entry cannot be safely managed":                       "已有启动文件不属于本应用或权限不安全，未修改",
	"Startup entry change could not be confirmed; check the current status": "启动项操作未能确认完成，请检查当前状态",

	"Required VPN backend capability is unavailable": "所需VPN后端当前不可用",
	"VPN backend could not start": "VPN后端无法启动",
	"VPN tunnel readiness was not verified": "未能确认VPN隧道已就绪",
	"VPN tunnel connection was lost": "VPN隧道连接已中断",
	"VPN authentication failed": "VPN认证失败",
	"VPN peer trust could not be verified": "无法验证VPN对端的信任",
	"VPN configuration was rejected": "VPN配置被拒绝",
	"VPN transport failed": "VPN传输失败",
	"VPN connection failed": "VPN连接失败",
	"VPN cleanup could not be confirmed; inspect the system VPN service before reconnecting or quitting": "无法确认VPN已清理。请先检查系统VPN服务，再重新连接或退出。",

	"Offer fresh authentication after connection loss":   "断线后提醒重新认证",
	"Connection lost; cleanup completed. Sign in again?": "连接中断，清理已确认。是否重新认证？",
	"Sign in again": "重新认证",
	"Dismiss":       "暂不处理",

	"Password, PEM client certificate, custom CA, optional interactive MFA helper":             "密码、PEM客户端证书、自定义CA、可选交互式MFA组件",
	"PKCS#12, hardware keys, SSO/posture and gateway password change are not implemented":      "未支持PKCS#12、硬件密钥、SSO/终端合规、网关改密",
	"Up to 16 explicit gateways; switch only after confirmed cleanup and fresh authentication": "最多16个手动选择网关；旧连接清理确认后重新认证切换",
	"Automatic gateway failover/reconnect/login and saved passwords are not implemented":       "未支持自动网关切换、自动重连/登录、记住密码",
	"Verified interface metrics, redacted diagnostics, profile import/export and headless CLI": "真实接口统计、脱敏诊断、配置导入导出、命令行管理",

	"client certificate and private key must both be configured":                            "客户端证书与私钥必须同时配置",
	"client certificate and private key must use absolute paths without control characters": "证书和私钥须使用有效绝对路径",
	"at most 15 additional gateways are supported":                                          "最多添加15个其他网关",
	"gateway addresses must be distinct":                                                    "网关地址不能重复",
	"client certificate/key must be a readable regular PEM file under 4 MiB; private keys must be owner-only and certificates must not be writable by other users": "证书/私钥须为可读PEM文件且小于4MiB；私钥仅本人可读写，证书不可由其他用户修改",
	"client certificate file must contain only PEM certificates":                                                   "客户端证书文件只能包含PEM证书",
	"client certificate must be a currently valid end-entity certificate":                                          "客户端证书须在有效期内且为终端证书",
	"certificate is not valid for client authentication":                                                           "证书不支持客户端认证",
	"client certificate does not match its private key":                                                            "客户端证书与私钥不匹配",
	"private key must be RSA, EC or PKCS#8 PEM; PKCS#12 and hardware tokens are not supported":                     "私钥须为RSA、EC或PKCS#8 PEM；暂不支持PKCS#12或硬件令牌",
	"invalid or unsupported client private key":                                                                    "客户端私钥无效或格式不受支持",
	"interactive authentication failed; check credentials, certificate trust and supported gateway authentication": "交互式认证失败，请检查凭据、证书信任与网关认证方式",
	"Interactive authentication requires the optional meridian-auth-helper and libopenconnect 9.12 or newer.":      "交互式认证需要meridian-auth-helper组件及libopenconnect 9.12以上",

	"Interactive authentication helper is not installed": "交互式认证组件未安装；安装后重新检测",
	"Interactive authentication (MFA helper)":            "交互式认证（MFA组件）",
	"Gateway authentication":                             "网关认证",
	"Continue authentication":                            "继续认证",
	"Export diagnostics":                                 "导出诊断",

	"Additional gateways (up to 15, separated by spaces)": "其他网关（最多15个，用空格分隔）",
	"Client certificate (PEM)":                            "客户端证书（PEM）",
	"Client private key (PEM)":                            "客户端私钥（PEM）",
	"Choose client certificate":                           "选择客户端证书",
	"Choose private key":                                  "选择私钥",
	"Only file references are saved; key passphrase is requested per session": "仅保存文件路径；私钥口令每次连接输入",
	"Session authentication":                                      "连接认证",
	"Private key passphrase (if encrypted)":                       "私钥口令（若已加密）",
	"Gateway for this session":                                    "本次连接网关",
	"Switch connection":                                           "切换连接",
	"Disconnect current VPN, then sign in again?":                 "断开当前连接，再认证新连接？",
	"Confirm switch":                                              "确认切换",
	"Connection switch stopped because cleanup was not confirmed": "旧连接清理未确认，已停止切换",

	"profile ID is empty or duplicated": "配置标识为空或重复，无法导入。", "unsupported settings version": "不支持此配置文件版本。", "settings file contains trailing data": "配置文件包含多余内容，无法导入。", "settings file exceeds size limit": "配置文件过大，无法导入。", "selected profile does not exist": "配置文件中选中的连接不存在。", "export cannot replace the active configuration file": "导出文件不能覆盖当前运行配置。",

	"MTU must be 0 (automatic) or 576–9000": "MTU 只能为自动（0）或 576–9000。", "unsupported proxy scheme": "代理仅支持 HTTP / SOCKS5，不支持 HTTPS。", "proxy must be an HTTP or SOCKS5 URL without embedded credentials or extra fields": "请输入不含账号密码或其他参数的 HTTP / SOCKS5 代理地址。", "invalid proxy port": "代理端口无效。", "CA certificate must be a regular PEM file under 4 MiB": "请选择小于 4 MiB 的普通 PEM 证书文件。", "CA certificate file cannot be opened": "无法打开 CA 证书文件。", "CA file must contain only PEM certificates": "CA 文件只能包含 PEM 证书，不能包含私钥。", "CA file contains an invalid or non-CA certificate": "文件中包含无效证书或非 CA 证书。", "CA file contains no certificates": "文件中没有可用 CA 证书。", "profile limit is 128": "最多支持 128 个连接配置。", "invalid authentication group": "认证组格式无效。", "description is invalid or exceeds 4096 bytes": "描述格式无效或超过 4096 字节。",

	"Follow system":                   "跟随系统",
	"Capabilities & reference fields": "能力与参考字段", "Reference: LeagSoft UniVPN 20260903; exact deployed version unconfirmed": "参考联软 UniVPN 20260903 手册，用户实际版本待核。", "Connection types": "连接类型", "Linux AnyConnect via OpenConnect / NetworkManager": "已接线：Linux AnyConnect（OpenConnect / NetworkManager）", "LeagSoft SSL VPN, national crypto, QUIC, L2TP and L2TP over IPsec are not implemented": "未实现：联软专有 SSL VPN、国密、QUIC、L2TP、L2TP over IPsec。", "Username/password, authentication group, custom CA trust": "已接线：账号密码、认证组、自定义 CA 信任。", "Client-certificate PKI, MFA/OTP and gateway password change are not implemented; USB-Key is a Windows reference feature": "未实现：PKI 客户端证书、MFA/动态码、网关修改密码。USB-Key 为 Windows 参考功能。", "Connection policy": "连接策略", "Explicit connect/disconnect; verified state and cleanup": "已接线：手动连接/断开、状态验证、退出清理。", "Gateway priority/backup, automatic reconnect/login and saved passwords are not implemented": "未实现：网关优选/链路备份、自动重连/登录、记住密码。", "Transport": "传输设置", "HTTP/SOCKS proxy with fresh consent, MTU, TCP-only mode": "已接线：需单次授权的 HTTP/SOCKS 代理、MTU、仅 TCP 模式。", "System proxy, embedded proxy credentials and proprietary TLS options are not supported": "不支持：系统代理、地址内代理凭据、专有 TLS 选项。", "Diagnostics & files": "诊断与文件", "Verified interface IP/traffic/session duration, structured logs, Meridian JSON import/export": "已接线：真实接口 IP/流量/时长、结构化日志、Meridian JSON 导入导出。", "UniVPN proprietary configuration import, full system reports, startup integration and updates are not implemented": "未实现：UniVPN 专有配置导入、系统报告、开机启动、自动升级。", "A configured protocol is not proof of enterprise gateway interoperability": "协议可配置不等于已验证企业网关互通。",

	"Allow proxy to use system authentication for this connection": "允许此次代理连接使用系统集成认证",
	"Proxy URL (HTTP / SOCKS5)":                                    "代理地址（HTTP / SOCKS5）", "No embedded credentials; HTTP may use system authentication": "地址不含账号密码；HTTP 可能使用系统认证",
	"No new profiles to import": "没有需要新增的配置", "Imported %d connections": "已导入 %d 个连接", "Import Meridian profiles": "导入 Meridian 配置", "Import profiles": "导入配置", "Export profiles": "导出配置", "Export activity": "导出日志", "Choose CA certificate": "选择 CA 证书", "Description": "描述", "Authentication & transport": "认证与传输", "Authentication group": "认证组", "Custom CA certificate": "自定义 CA 证书", "Proxy URL (no credentials)": "代理地址（不含账号密码）", "Use TCP only (disable UDP/DTLS)": "仅使用 TCP（禁用 UDP/DTLS）", "MTU (blank = automatic)": "MTU（留空自动）", "Automatic": "自动", "Configure proxy for the selected connection": "配置当前连接的代理", "MTU must be a whole number": "MTU 必须为整数",

	"VPN connection": "VPN 连接", "Back to connections": "返回连接列表", "This device": "本机", "VPN name": "VPN 名称", "Uploaded": "上行数据总量", "Downloaded": "下行数据总量", "Connection duration": "连接时长", "Virtual IP": "虚拟 IP 地址", "Authentication": "认证状态", "Authenticated": "已认证", "Choose connection": "选择 VPN 连接", "Proxy settings": "代理设置", "Proxy support is not available in this version": "此版本暂不支持代理设置", "New connection": "新建连接", "Search connections": "搜索连接", "No matching connections": "没有匹配的连接",

	"Light appearance": "浅色外观", "Dark appearance": "深色外观", "My connections": "我的连接", "No connections yet": "还没有连接", "Add connection": "添加连接", "Select a connection": "选择一个连接", "Setup needed": "环境待配置", "View details": "查看详情", "Ready to connect": "可以连接", "Protocol": "协议", "Session": "会话时长", "%d connections": "%d 个连接", "Name": "名称", "Gateway": "网关", "Username": "用户名", "Optional": "选填", "This session": "本次运行", "Appearance": "外观", "Diagnostics": "运行环境",

	"Live VPN requires Linux with NetworkManager and its OpenConnect plugin.":                                         "实际连接需要 Linux、NetworkManager 及其 OpenConnect 插件；当前平台暂不支持。",
	"NetworkManager CLI is not installed; live connection unavailable.":                                               "尚未安装 NetworkManager 命令行工具，暂不能建立实际连接。",
	"OpenConnect is not installed; live connection unavailable.":                                                      "尚未安装 OpenConnect，暂不能建立实际连接。",
	"NetworkManager OpenConnect plugin is not installed.":                                                             "尚未安装 NetworkManager 的 OpenConnect 插件。",
	"NetworkManager service is unavailable.":                                                                          "NetworkManager 系统服务不可用。",
	"Linux AnyConnect via NetworkManager. Gateway compatibility must be validated; OS authorization may be required.": "可通过 NetworkManager 建立 Linux AnyConnect 连接，仍需验证网关兼容性；系统可能要求授权。",
	"Waiting for verified tunnel readiness":                                                                           "正在等待系统服务确认隧道就绪。",
	"Waiting for verified tunnel cleanup":                                                                             "正在等待系统服务确认隧道清理完成。",
	"Tunnel verified by NetworkManager and its interface":                                                             "NetworkManager 已确认活动连接，隧道接口已启用并获得地址。",
	"Backend could not start. Check prerequisites, authentication and gateway configuration.":                         "连接引擎未能启动，请检查环境、认证方式与网关配置。",
	"VPN cleanup could not be confirmed; inspect NetworkManager before reconnecting or quitting":                      "无法确认 VPN 已清理。请先检查 NetworkManager，再重新连接或退出。",
	"OpenConnect authentication + NetworkManager service":                                                             "OpenConnect 认证 ＋ NetworkManager 系统服务",

	"%d saved profiles · local to this device": "%d 个已保存配置 · 仅存储于本机",
	"Overview": "连接", "Profiles": "连接配置", "Activity": "运行日志", "Settings": "设置",
	"PRIVATE ACCESS, SIMPLIFIED": "让安全访问，更简单", "NATIVE GO / v0.1": "原生 GO / v0.1", "No browser. No webview.": "无需浏览器 · 无网页容器",
	"YOUR WORKSPACE, WITHIN REACH": "工作所需，安全直达", "●  OFFLINE": "●  未连接", "CONNECTION STATUS": "当前连接状态",
	"A quieter way to connect.": "少一点打扰，多一点连接。", "Disconnected": "未连接", "Connecting": "正在连接", "Connected": "已连接", "Disconnecting": "正在断开", "Failed": "连接失败", "CleanupFailed": "清理未完成，请检查网络",
	"Add your organization's gateway to get started.": "添加组织提供的网关，开始配置安全访问。", "+  Add profile": "＋ 添加配置", "Manage profiles": "管理配置", "Connect": "连接", "Disconnect": "断开连接",
	"01 / SECURITY": "01 / 安全设计", "Nothing stored in secret": "凭据，不落盘", "Passwords and session cookies are never written to disk.": "密码与会话 Cookie 仅在内存中使用，不写入磁盘。",
	"02 / ENGINE": "02 / 连接引擎", "OpenConnect adapters": "OpenConnect 协议适配", "Protocol support depends on your gateway and installed engine.": "具体兼容性取决于企业网关、认证方式与已安装引擎。",
	"Setup required before connecting": "连接前，还需要完成环境配置", "No VPN tunnel is active. Your routes and DNS have not been changed.": "当前没有 VPN 隧道，未更改系统路由或 DNS。", "UniVPN compatibility is not established; ask IT for the gateway and protocol.": "尚未验证 UniVPN 兼容性，请向 IT 确认网关与协议。",
	"+ New profile": "＋ 新建配置", "Your gateway belongs here.": "把你的工作网络，放在这里。", "No sample servers or pre-filled credentials. Add the details supplied by IT.": "没有预置服务器或账号，请填写 IT 提供的真实连接信息。", "Create your first profile": "创建第一个连接配置", "SELECTED": "当前使用", "Select": "使用此配置", "Edit": "编辑", "Delete": "删除", "Delete this profile permanently?": "确定永久删除此配置？", "Cancel": "取消", "Confirm delete": "确认删除",
	"Connection profile": "连接配置", "PROFILE NAME": "配置名称", "HTTPS GATEWAY": "HTTPS 网关地址", "PROTOCOL · CONFIRM WITH YOUR IT TEAM": "连接协议 · 请与 IT 确认", "USERNAME · OPTIONAL, NOT A PASSWORD": "用户名 · 可选，请勿填写密码", "Certificates remain verified. No insecure TLS override is available.": "始终验证服务器证书，不提供跳过 TLS 验证选项。", "Save profile": "保存配置", "Work network": "工作网络", "Your account name": "你的账号",
	"A clear record. No secrets.": "运行记录，清晰且克制。", "Only structured lifecycle events are shown. Raw engine output is discarded.": "仅保留结构化状态事件，丢弃原始引擎输出，避免泄露敏感信息。", "Clear activity": "清空日志", "Application ready. No tunnel has been started.": "应用已就绪，尚未启动隧道。", "No VPN tunnel is active": "当前没有活动 VPN 隧道", "Activity history cleared.": "运行日志已清空。",
	"Designed to stay out of your way.": "按你的习惯，安静运行。", "Keep in tray when the window closes": "关闭窗口后保留在系统托盘", "Tray integration unavailable in this desktop session.": "当前桌面会话不支持系统托盘。", "THEME": "外观", "Midnight · native dark interface": "午夜 · 原生深色界面", "ENGINE": "连接引擎", "Recheck prerequisites": "重新检查运行环境", "NetworkManager owns network configuration; missing dependencies disable connection.": "网络配置由系统服务负责，缺少依赖时不会尝试提权连接。", "PRIVACY": "隐私", "No telemetry. No credential persistence. Local profiles only.": "无遥测，不保存凭据，连接配置仅存储在本机。", "ABOUT": "关于", "Meridian 0.1 / MyGo 0.7.4 / pure Go native UI": "Meridian 0.1 / MyGo 0.7.4 / 纯 Go 原生界面", "Gateway interoperability and platform packaging require deployment validation.": "网关互通性与各平台安装包仍需实际部署验证。",
	"OpenConnect is not installed. Install it through your operating system package manager.":               "尚未安装 OpenConnect，请通过操作系统包管理器安装。",
	"OpenConnect found; a verified privileged tunnel broker is not installed. Live connection is disabled.": "已找到 OpenConnect，但尚未安装可信隧道服务，暂不能连接。",
	"Saved locally. Credentials are never stored.":                                                          "已保存至本机，不包含密码或会话凭据。",
	"profile name must be 1–80 characters":                                                                  "请输入 1–80 字节的配置名称。", "gateway must be an HTTPS URL without credentials, query or fragment": "网关必须是 HTTPS 地址，且不包含账号密码、查询参数或片段。",
	"LANGUAGE": "语言", "Authorize network changes": "允许此次连接更改系统路由和 DNS", "Session password": "本次会话密码", "Password is used once and never saved.": "密码仅供本次连接使用，不会保存。", "Only AnyConnect is available through the Linux adapter in this version.": "此版本的 Linux 实际连接仅支持 AnyConnect 协议。",
	"Connect to this gateway": "连接此网关", "Authentication is not compatible with every MFA/SSO flow.": "部分 MFA、SSO 和终端合规检查流程暂不支持。",
}
