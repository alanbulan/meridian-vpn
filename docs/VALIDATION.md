# 验证记录 — 2026-11-03

官方Go1.27.3，MyGo v0.7.4。GUI/CLI发布构建CGO_ENABLED=0；可选MFA组件是单独C程序，动态依赖libopenconnect9.12+，不能称为全Go协议实现。

## 原归档验证记录（恢复前快照）

以下计数、真实认证及人工QA是恢复文件保留的历史记录，不是本轮新代码的重新执行结果。新增L2TP、PKCS#12/PKCS#11和INI能力不能继承这些结论。本轮检查另列于本文末尾；未提供外部认证依赖时可选测试跳过，不算通过。

## 归档已执行与结果

|阶段|结果|范围|
|---|---|---|
|默认测试|147项顶层PASS，18项可选外部验证默认SKIP（17项认证+1项desktop-file解析）|core、原生UI、autostart、CLI、diagnostics；SKIP不算通过，完整名称见TEST-RESULTS.json|
|全项目并发检测|go test -race -count=1 ./... PASS|最终源码；测试插桩使用cgo，发布GUI不使用cgo|
|静态检查|go vet ./... PASS|最终全部Go包；MFA C组件另有GCC -fanalyzer及shell语法检查|
|真实OpenConnect认证|9项顶层测试实际PASS|生产认证参数/文件描述符/解析器；密码、明文及加密PEM/PKCS#8客户端证书、拒绝密码/证书/密钥/口令、取消|
|真实libopenconnect MFA|8项顶层集成测试实际PASS|密码→OTP/选择→错误码重试→成功、配置组刷新、DNS/SNI/RESOLVE、TLS拒绝、取消、轮次/表单限制、SSO拒绝、明文/加密客户端证书|
|组合真实认证并发检查|同时启用两套官方认证依赖，go test -race -count=1 ./internal/core PASS|17项外部认证测试实际运行，并非默认跳过；本次3.235秒|
|Linux原生人工QA|PASS|实际MyGo窗口/CPU渲染器，见下方；没有HTML替代|
|自动启动安全测试|隔离目录多次race PASS|唯一文件归属、无覆盖、0600、Exec转义、目录/可执行文件祖先、symlink/FIFO、非阻塞锁；另用实际desktop-file-validate验证转义，未修改宿主启动项|
|跨平台编译|macOS ARM64/Windows AMD64界面与CLI可编译|不代表VPN后端或原生运行通过；Linux为本轮重点|

复现入口：`integration/authfixture/run-auth-only.sh`、`integration/mfa-helper/run-auth-only.sh`及对应README、固定官方Debian包/哈希与脱敏RESULTS。运行时测试证书/私钥只在临时夹具中生成，不随发布包交付。测试只执行认证，零HTTP CONNECT、零TUN、零实际NetworkManager配置变更、零路由/DNS修改。单纯认证成功不代表VPN连接成功。

## 原生桌面人工QA

- 官方Lucide主界面/图标浅深色显示，设置保存重启；主界面符合UniVPN双栏字段排列。
- 搜索/选择/空结果、CRUD、HTTP拒绝、取消不覆盖、确认删除；Unicode字符注入保存（未测完整IME候选窗）。
- 长高级编辑器滚动时左侧连接按钮仍完整可见；证书/私钥、交互认证、其他网关、认证组/代理/TCP/MTU字段可见。
- 多网关增加、保存、重启重载；发现单行输入框换行重载导致第二行裁切，已改为空格并增加回归测试，实际重启复验通过。
- 坏配置导入拒绝而原配置不变，重复导入不产生重复；实际配置/日志导出0600且不含秘密/运行时授权。
- 实际诊断导出0600，只有脱敏白名单状态，不含网关/账号/密码；没有把缺依赖或未测试隧道标成成功。
- 独立、明确标为“不联网”的原生MFA界面夹具：密码掩码、下拉选项、继续后清除、取消/后退测试通过，从未显示Connected。其图形交互验证与上方真实协议认证测试分开。
- 登录启动项打开确认显示精确XDG目标和可执行文件，取消后实际宿主文件不存在；未确认启用。断线提醒偏好可保存。

## 生命周期与安全回归

包含双重启动、取消/超时、部分启动清理、已终止Session不能短暂Connected、意外断线保留Failed、清理失败进入CleanupFailed并阻止连接/安全退出声明；秘密不在argv/env/配置/日志、代理单次授权不可导入、无环境代理回退、文件有界/no-follow/所有者检查、严格框架长度/会话/轮次、表单取消/迟到回答、导入去重与原子权限、官方图标哈希与原生渲染。

快速切换仅在旧会话清理已确认后打开全新认证；不带旧密码/私钥口令/代理授权。可选断线提醒等待5秒且仅一次，主动断开或未知清理不提示；它不是自动重连，不缓存或重放秘密。

## 未验证与未实现

没有真实企业网关、TUN、内网访问或路由/DNS恢复闭环。NM阶段命令/状态/清理由受控runner验证。没有联软专有协议互通、完整SSO/终端合规、IPv6泄漏或kill switch结论。托盘宿主在云桌面不可用，未运行验收托盘交互。自动启动只测安全代码与原生确认/取消，没有真实登录启动验收。macOS/Windows没有VPN后端或签名/安装/运行验收。

完整当前字段覆盖见REFERENCE-COVERAGE.md，未完成能力及具体原因见REMAINING-WORK.md。不存在“Linux完整VPN实网全部打通”或“三平台VPN/GUI完整验收通过”的结论；后续原生构建与单测结果见下方明确的提交记录。

`docs/screenshots/`均为真实原生Linux窗口，使用example.com示例配置。旧手绘图标/过期能力截图已移除。

原归档记载：当时全项目race重跑启用17项真实认证与desktop-file-validate并通过。此历史结论不代表本轮恢复后已重新执行这些外部验证。

## 本轮恢复后的实际检查（2026-11-03）

- 官方Go 1.27.3 linux/amd64已按go.dev发布SHA256验证，模块完整性检查通过。
- 证书工作分支执行 `integration/authfixture/run-auth-only.sh`：10项真实OpenConnect认证测试通过，使用本地合成身份与受控TLS服务，包含PEM、加密PEM/PKCS#8、PKCS#12、错误密码、TLS拒绝、取消与错误/缺少容器口令。仅认证，零CONNECT、零TUN及路由/DNS变更；不覆盖PKCS#11硬件或企业网关。完整本轮日志见 `integration/authfixture/RECOVERY-RESULTS.txt`。
- 原生UniVPN：9项本地TLS模拟测试通过（含控制通道静默、数据通道静默、分片超时）；codec ASAN/UBSAN通过，因ptrace不支持LeakSanitizer而关闭detect_leaks，不声称泄漏检测通过。buftest/seqtest/lzstest通过。日志见 `integration/univpn-native/RESULTS.txt`。不覆盖真实网关、内核TUN、特权broker或路由/DNS恢复。
- 06:12 UTC最终禁用实验功能检查点聚合：默认测试202项顶层PASS、20项SKIP；全项目race、vet、模块完整性、Linux GUI/CLI及Windows AMD64/macOS ARM64 GUI和CLI交叉编译通过。日志见RECOVERY-TEST-RESULTS.jsonl和RECOVERY-RACE-RESULTS.txt。20项跳过包含10项外部OpenConnect认证（已有上方单独实测）、8项MFA、desktop-file-validator、Unix socket IPC。broker关闭等待与精确网关白名单修复已包含在本次测试中。可选libopenconnect MFA和桌面人工QA在本轮尚未重新执行。
- UniVPN网络控制器：确定性runner测试涵盖严格政策、TUN身份、端点逃逸路由、DNS/route readback及回滚。未执行任何ip/resolvectl真实命令；可信hook源、后代进程隔离及独占网络命名空间租约仍缺失，不能启动实网连接。
- 原生patch 0006直接exec hook并传播失败；真实脚本函数测试经过TUN打开防护，确认失败pre-init零TUN打开尝试。最终六补丁源码通过9项TLS模拟测试（108.291秒）；该结果不证明hook、cgroup或系统网络集成。


## 三平台原生 CI 检查点（2026-11-03 14:07 UTC）

源提交 `fa52b2a383d5e7c2a4a1b6799c41cff01a8de22a` 的 [Actions #2](https://github.com/alanbulan/meridian-vpn/actions/runs/41650135848) 四个 job 全部通过：

- Linux amd64：595 个测试/子测试通过、0 失败、21 跳过。
- macOS arm64：264 个测试/子测试通过、0 失败、25 跳过。
- Windows amd64：256 个测试/子测试通过、0 失败、25 跳过。
- 三平台模块校验、vet、原生 GUI/CLI 编译以及 CLI help/version 启动均通过；Linux 独立 race、bootstrap 静态构建/注入测试、离线 provisioning 均通过。

这些计数包括子测试，不能与较早的顶层测试计数直接比较。Linux 私有FD认证测试只在Linux运行；其他平台保留拒绝不支持传输的测试。POSIX文件权限不被当作Windows ACL保证。缺少外部授权或组件的测试继续明确跳过，不将其计为通过。

以上记录只针对该提交，不自动证明后续提交。没有新增真实企业网关、TUN、路由/DNS修改、GUI人工交互、签名或安装验收。原生构建成功不等于平台VPN后端已实现。
