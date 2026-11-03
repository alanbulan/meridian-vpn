# Meridian 命令行

`meridianctl` 是独立的无界面配置与就绪检查工具，不依赖 GTK 或图形会话。它没有连接/断开、密码输入、自动安装、sudo 或修改路由/DNS 的命令。

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

Meridian 配置字段 `interactive_auth` 是布尔值，省略或 `false` 使用原有非交互认证路径；`true` 要求可选 `meridian-auth-helper`，用于桌面程序中的结构化 MFA/OTP、认证选项等交互流程。它不等同于支持所有企业 SSO、Host Checker 或终端合规要求。CLI 会保留并展示此开关，但不采集密码/OTP、不启动该流程。`validate` 仅校验本地配置，是否装有可用 helper 请看 `diagnostics` 的可选检查。修改和连接请在原生桌面界面完成。

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
