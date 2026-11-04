# Meridian 命令行

`meridianctl` 是独立的无界面配置与就绪检查工具，不依赖 GTK 或图形会话。Linux 另提供明确授权的前台连接模式，复用桌面版 Engine 与 NetworkManager；Ctrl+C 或 SIGTERM 清理该进程拥有的会话。其他命令保持离线/只读，不自动安装软件或调用 sudo。

## 构建

```sh
go build -buildvcs=false -trimpath -o build/meridianctl ./cmd/meridianctl
go test ./cmd/meridianctl ./internal/diagnostics
go test -race ./cmd/meridianctl ./internal/diagnostics
go vet ./cmd/meridianctl ./internal/diagnostics
```

可通过 `-ldflags '-X main.version=0.2.0'` 注入发布版本；未注入时报告 `dev`。不使用 MyGo 或其运行库，但与桌面程序复用同一个 `core.Store` 和配置校验器。

## 查看与校验

全局 `--config FILE` 必须放在命令之前。省略时与桌面版使用相同的 `os.UserConfigDir()/meridian/profiles.json`。

```sh
./build/meridianctl --config ./profiles.json profiles list --json
./build/meridianctl --config ./profiles.json validate --json
./build/meridianctl --config ./profiles.json validate --check-files --json
```

默认列表只显示从 1 开始的索引、选中状态、协议、`interactive_auth` 开关和配置项是否存在；不显示名称、ID、网关、账号、描述、认证组、代理地址或证书路径。`profiles list --show-private` 明确开启这些本地私有字段。不要把详细列表当作脱敏诊断分享。

`validate` 检查版本化 Meridian JSON 和字段约束；缺失配置不是“校验成功”。`--check-files` 还本地校验 CA、客户端证书/私钥文件，不发送文件内容。加密私钥只能静态检查封装；实际解锁、配对以及服务端接受情况仍需真实认证。校验通过不等于企业网关兼容或 VPN 已连接。

## 只读诊断

```sh
./build/meridianctl diagnostics --json > meridian-diagnostics.json
```

报告只包括应用版本、OS/CPU 架构、所需依赖是否可用、NetworkManager 服务状态以及明确的阻断项。它不读取连接配置，不包含机器名、用户名、网关、私有 IP、路由/DNS 表、证书/密钥内容、环境变量、命令路径或原始子进程输出。

Linux 检查固定的 `nmcli`/`openconnect` 可执行文件可用性和标准插件描述文件。服务探测仅运行 `nmcli -t -f RUNNING general`，最多等待 3 秒、最多捕获 4096 字节；插件文件每个最多 64 KiB。

另有 `interactive_auth_helper` 可选检查，复用核心的 helper 查找和能力校验：先找同目录打包的 helper，再找 PATH 中满足安全检查的 helper；只运行 `--protocol-version`，核心限制为 3 秒和 64 KiB 输出，报告仅保留通过/未通过。它不会返回可执行路径、原始输出或错误内容。缺失 helper 不影响普通后端的 `prerequisites_available`，但启用交互式认证的配置必须满足该项。

所有探测均不联系网关、不认证、不启动隧道。依赖存在并不证明版本兼容、Polkit 授权、路由策略或 DNS/泄漏测试成功。

JSON 有稳定的 `schema_version: 1`、`read_only: true`、`backend.prerequisites_available` 和 `backend.blockers`。非 Linux 明确报告后端不支持。

### 交互式认证配置

Meridian 配置字段 `interactive_auth` 是布尔值，省略或 `false` 使用原有非交互认证路径；`true` 要求可选 `meridian-auth-helper`，用于结构化 MFA/OTP、认证选项等交互流程。Linux amd64/arm64 前台 CLI 可在同时指定 `--interactive-auth` 时使用控制终端完成这些表单。它不等同于支持所有企业 SSO、Host Checker 或终端合规要求。`validate` 仅校验本地配置，是否装有可用 helper 请看 `diagnostics` 的可选检查。

## 导入预览与导出

```sh
# 只预览合并并去重，不写任何文件。
./build/meridianctl --config ./profiles.json profiles import --file ./received.json --json

# 保存到全新的配置文件；已有配置与导入源都不变。
./build/meridianctl --config ./profiles.json profiles import --file ./received.json --output ./reviewed-profiles.json

# 导出全部配置，或只导出列表中索引为 2 的配置。
./build/meridianctl --config ./profiles.json profiles export --output ./backup-profiles.json
./build/meridianctl --config ./profiles.json profiles export --profile 2 --output ./one-profile.json
```

仅接受 Meridian JSON，不接受 UniVPN 私有格式。导入保留当前设置和已有选中项，重复内容忽略，新配置生成新 ID，总数不超过 128。导出不携带界面设置或本次运行授权。配置包含账号、网关及证书/密钥路径，但不含密码、Cookie、证书/私钥文件内容。

所有输出必须是不存在的新文件，且上级目录必须已存在。通过同目录临时文件和独占硬链接发布，POSIX 权限为 0600；拒绝覆盖已有文件、符号链接或硬链接。文件系统不支持硬链接时安全失败。这样不会在 GUI 打开期间覆盖它可能尚未保存的配置。确认合并结果后，可关闭原桌面窗口，再用 `./build/meridian --config ./reviewed-profiles.json` 打开新配置。

退出码：`0` 成功/就绪，`1` 配置无效、依赖不可用或执行失败，`2` 参数用法错误。诊断存在阻断项时仍输出完整 JSON，但退出码为 1，便于脚本处理。没有自动上传或遥测。

## INI 只读结构检查（恢复版新增）

`meridianctl profiles preview-ini --file received.ini --json` 可检查有界 UTF-8 INI 的分节与配置项数量。原生设置页也提供“只读检查 INI”。不显示任何分节名、字段名或值，不读取活动配置，不推断协议，不导入或写入文件。重复键、重复分节、非法编码、控制字符与超限输入会被拒绝。识别到的密码类字段数量仅作提示，不代表识别了所有秘密。

这不是 UniVPN 私有 INI 格式兼容导入。没有经过验证的厂商字段契约时，不把未知字段转换成网关、安全策略或认证配置。


## Linux 前台连接与断开

```sh
# 私密凭据应由可信秘密管理器经 stdin 提供；不要把密码写进 shell 参数或历史。
secret-manager-command | ./build/meridianctl --config ./profiles.json connect \
  --profile 1 --authorize-network --credentials-stdin
```

这里 `secret-manager-command` 是占位说明，需替换为自己的可信秘密来源，不是随应用提供的命令。输入是单个 JSON 对象，并在发送后关闭写端（EOF）；可用字段仅为 `password`、`ipsec_psk`、`key_password`，值必须是字符串。PKCS#12/PEM 私钥口令使用 `key_password`；L2TP 同时要求 password 与 ipsec_psk，其他协议禁止 PSK。无需秘密的证书模式可输入空对象。拒绝终端直接输入，避免密码回显；不接受密码 argv、环境变量、额外对象、重复键、未知键、null、超过 16 KiB 的输入或超过 4096 字节的字段。

每次运行必须同时指定 1-based `--profile`、`--authorize-network` 和 `--credentials-stdin`，不保存授权。授权覆盖该配置的网关认证及本次路由/DNS 变更，不自动切换备用网关、不重放凭据或重连。凭据不写配置/日志，拥有的字节缓冲区在使用后清零；Go JSON 解码的短暂字符串及运行时副本无法承诺物理内存完全擦除。

连接保持前台运行，仅输出 Connecting/Connected/Disconnecting 等状态，不打印账号、网关、IP 或原始后端错误。Connected 只表示核心后端的隧道/接口验证通过，不代表企业内网资源或 DNS 策略已验收。

**断开：** 对这个前台命令按 Ctrl+C，或向这个进程发送 SIGTERM。Unix 终端挂断（SIGHUP）、Ctrl+\（SIGQUIT）、Ctrl+Z/后台终端访问相关信号与输出管道断开也进入自身会话清理流程，不会把拥有 VPN 的进程挂起。程序等待自身会话的清理确认才退出，不终止 GUI、其他进程或其他 VPN。没有跨进程 `disconnect` 命令，也没有 PID 文件、后台守护或重连功能。不要使用 SIGKILL/强制关闭代替正常断开；强制杀死、系统崩溃及断电不能保证清理。

正常取消并确认清理返回 0；认证失败、意外连接丢失、输出失败或无法确认清理返回 1；缺少授权参数等用法错误返回 2。清理无法确认时，明确提示检查系统 VPN 服务后再连接。外部浏览器 SSO 和非 Linux VPN 后端不在此命令支持范围。

本实现的测试使用假后端、私有文件/管道、PTY 及可选 localhost TLS 合成认证夹具，不连接真实企业网关，不修改测试宿主的路由、DNS 或接口。实际企业隧道仍需要单独授权的验收环境。

### 前台 MFA

```sh
secret-manager-command | ./build/meridianctl --config ./profiles.json connect \
  --profile 1 --authorize-network --credentials-stdin --interactive-auth
```

配置必须已启用 `interactive_auth`，协议为 AnyConnect，且可信 `meridian-auth-helper` 可用。这个参数只允许本次交互，不修改配置或扩大网关授权。初始密码/私钥口令仍经非终端 JSON stdin 提供；没有初始秘密时可由可信输入源提供 `{}`。后续文本、密码/OTP、选择均从该进程的前台 `/dev/tty` 读取，全部关闭回显，不从 stdin 再读，不接受 argv/env 中的回答。无控制终端、后台运行、终端配置失败或并发提示时安全拒绝。

网关字段与选项标签仅在控制终端显示，去掉控制字符和隐藏格式符、引号包裹并截到 96 字符；忽略自由格式标题/说明。请选择本地编号，不输入服务器字段 ID。最多 8 轮、每轮 16 字段、每字段 32 选项，单回答最多 4096 字节；超长、非法选择或不支持表单直接失败，不截断后提交。NetworkManager 总认证时限为 90 秒；每个终端提示也有 90 秒上限，并受较短的父时限约束。

Enter 提交当前字段，Backspace 删除，Ctrl+U 清空，Ctrl+D 取消认证，Ctrl+C 取消并退出。提示结束或错误时恢复原终端设置、丢弃未消费输入并清除已拥有的回答；中途失去前台进程组也安全停止输入，终端操作线程临时屏蔽后台读写信号以避免系统调用自动重启阻塞，并在结束时恢复原信号掩码，不修改全局信号处理；恢复失败不提交回答，退出时提示重置终端。stdout/stderr 仍只有固定状态与固定错误，绝不复制网关提示或回答。无回显不能防止外部终端录制/键盘监控，也不承诺 Go/runtime 内存物理擦除。强制 SIGKILL、进程崩溃或断电不能保证终端或网络恢复。

仅支持结构化 text/password/select 表单。网页 SSO、脚本、Host Checker、推送轮询及没有字段的确认流程仍拒绝；没有把认证夹具成功当作真实隧道或企业 MFA 兼容验收。
