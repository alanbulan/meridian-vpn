# Linux 独立验证矩阵，2026-11-03

范围：原生 MyGo 客户端源码；审查者未实际编辑主机路由/DNS，未激活 VPN、安装特权服务、填入测试凭据或对外部网关进行认证。macOS/Windows 工作已按用户要求暂停。

| 层面 | 证据 | 结果 / 剩余条件 |
|---|---|---|
| 配置档案/存储校验 | 独立隔离测试：>1MiB 配置后跟隐藏 JSON；多行配置档案名称 | 开发方修复后通过 |
| 认证解析器 | 重复 RESOLVE 键且第一个值为空；现有注入测试 | 开发方修复后通过；仅严格支持部分输出格式，不代表支持所有认证 |
| 状态/并发 | 完整复制的核心测试套件、Go 竞态检测器、重复 100 次 | 通过 |
| 隧道监控失败 | 启动模拟 NM 会话，等待 Connected，然后将模拟状态改为 notReady；运行实际 2s 监控器 | 通过：进入 Failed，而不是普通 Disconnected |
| 终态就绪 | 100 个会话，Ready 成功且终态 Done 已排队 | 通过：不产生 Connected/就绪事件 |
| 带类型 nil 的适配器会话 | 初始独立压力测试发现 Stop 中存在空指针解引用；开发方最新的 nilInterface 防护 | 已修复；重复压力测试通过 |
| 激活/删除契约 | 现有模拟测试检查临时配置档案、UUID 所有权、stdin 元组和清理错误 | 测试套件中通过；仅为模拟 |
| 操作系统子进程保真度 | 未真实激活 OpenConnect/NM | 模拟测试无法证明 |
| 真实隧道 | 未进行获批的真实网关测试 | 未验证 |
| 网络正确性 | 路由、内部 DNS、IPv4/IPv6 泄漏、MTU、DTLS、休眠/网络切换 | 未验证 |
| 真实故障恢复 | 网关认证错误/MFA、操作系统授权被拒绝、NM 守护进程重启、进程崩溃、物理链路丢失 | 源码/模拟部分覆盖；需要真实测试 |
| 分发 | 在主机架构上构建不等于签名打包发布 | 发布验证待完成 |

命令：
- `GOCACHE=/tmp/mygo-go-cache GOPATH=/tmp/mygo-gopath /workspace/shared/toolchains/go/bin/go test -race -count=100 ./core`，在独立复制的 `/tmp/mygo-vpn-adversarial` 中运行：通过（`ok audit/core 1.736s`）。
- 使用同一工具链运行 `go test -race -run TestAudit -v ./core`：全部 5 项独立测试通过（`ok audit/core 3.025s`）。
- 独立源码/测试产物：`/tmp/mygo-vpn-adversarial/core/adversarial_test.go`。

## 真实 Linux 验收的前置条件
明确获得授权、可弃用的 Linux 测试机或隔离网络实验环境，具备可用的 TUN、NetworkManager/OpenConnect 插件、系统 D-Bus 和 Polkit；已明确的 AnyConnect 兼容网关、测试账户/认证要求，以及范围明确的网络修改授权。凭据应由用户私密输入，绝不粘贴到源码或 argv。记录前后路由和 DNS、隧道 IP、接受的服务器身份、预期内部端点的可达性，以及清理情况。必须不触碰用户现有的 VPN。不具备可用 NM/TUN 的容器，不足以证明完整链路可运行。

## 相关官方契约
- https://www.infradead.org/openconnect/nonroot.html ：独立的非特权认证，以及 NM cookie/gateway/gwcert/resolve 元组。
- https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nmcli.html ：激活、临时 `add save no`、按 UUID 删除。
- https://raw.githubusercontent.com/GNOME/NetworkManager-openconnect/main/src/nm-openconnect-service.c ：插件支持具名 TUN。

## 高级功能审查，01:23 UTC
- 已审查真实选项流：非特权认证中的 auth-group 和额外 CA；两个阶段中的代理；NetworkManager 插件配置中的 MTU 和 disable-UDP。
- 发现/修复：OpenConnectArgs 的 CA 校验错误被忽略；FIFO 路径可能阻塞 CA 打开。当前 CA 预检使用有界的仅证书 PEM 解析、IsCA 校验，以及带身份复查的 Linux 非阻塞/不跟随符号链接文件打开。
- 代理隐私：拒绝内嵌凭据和不受支持的 HTTPS 代理方案。认证子进程使用 --proxy-auth=none。由于 NM 插件无法在第二阶段限制集成认证，每个会话都需要新的明确授权；授权不能通过 JSON 序列化/导入，且 UI 会将其重置。这不是匿名代理支持。
- 指标是所生成且归自身所有的接口上的真实计数器/IP，在 UI 路径之外缓存。缺失计数器标记为不可用，而不是伪造为 0；断开连接会清除会话指标/时间。
- 认证解析器接受实际 OpenConnect 的 RESOLVE= 空值输出，但不接受任意未加引号的赋值或 shell 求值。
- 新一轮隔离运行的 `go test -race -count=1 -v ./core` 通过（3.090s），`go vet ./core` 通过，包含独立对抗性测试用例。显式的真实 OpenConnect 环回测试仍需主动选择运行（未计入本轮已执行测试）。
- 此快照未发现其他严重源码问题。
