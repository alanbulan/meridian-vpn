# Linux 桌面登录启动（显式选择）

`internal/autostart` 实现 Linux XDG **用户级桌面登录启动**。它只在用户下一次登录支持 XDG autostart 的桌面环境时打开 Meridian，不是开机服务，不自动连接 VPN，也不保存当前命令行参数、配置文件路径、密码、Cookie 或运行时授权。

## API 和确认要求

- `New(Options{})`：解析当前用户配置目录和当前程序的真实绝对路径。只读，不创建目录。
- `Status()`：读取本应用注册状态。`Supported` 反映平台支持；`Enabled` 仅表示已验证的本应用启动项存在，不保证桌面策略允许实际启动。`Path` 是完整目标路径，`Executable` 是当前程序真实路径，`RegisteredExecutable` 是已登记的程序路径。冲突和不安全路径明确返回错误，不伪装为关闭。
- `Preview()`：返回准备写入的完整 `.desktop` 内容，不修改任何文件。
- `Enable()` / `Disable()`：唯一有修改行为的入口。调用者必须先显示实际路径、程序路径和“只启动界面，不自动连接”的说明，并取得本次明确确认。初始化、读取设置或取消确认不得调用它们。
- `Options{ConfigDir, Executable}`：用于显式指定目录、程序以及隔离测试。未指定目录时遵循 `os.UserConfigDir()`，即 Linux 的 `$XDG_CONFIG_HOME` 或 `~/.config`。

唯一固定启动项为：

```
$XDG_CONFIG_HOME/autostart/meridian-vpn.desktop
```

未设置 `$XDG_CONFIG_HOME` 时为 `~/.config/autostart/meridian-vpn.desktop`。本实现不写系统级启动目录、不注册服务、不触发启动项、不开隧道、不修改网络设置。

当前程序从符号链接启动时，登记的是解析后的真实文件路径。移动或删除该文件会使原启动项失效。已有注册指向另一安装位置时，`Enable()` 返回 `ErrDifferentExecutable`；需先明确关闭旧注册，再确认开启新位置。`Disable()` 不要求旧程序仍存在。

因不保留启动参数，使用 `--config` 的独立测试配置不会被带入桌面登录启动；届时使用程序正常默认配置。应用退出行为、登录会话行为和 VPN 连接流程保持独立。

## 文件和路径保护

- 每个目录组件均通过 `openat`、`O_DIRECTORY`、`O_NOFOLLOW` 固定描述符，拒绝目录符号链接和不安全替换，不依赖先 `Lstat` 后按完整路径写入。
- 配置目录和 autostart 目录必须属于当前用户且不可被组或其他用户写入。祖先必须属于当前用户或 root；仅允许 root 拥有的 sticky 共享目录作为祖先，例如测试路径中的 `/tmp`。共享目录不能作为配置目录或 autostart 目录。
- 程序文件及其祖先也检查所有权和写权限。程序必须是当前用户或 root 拥有的普通可执行文件，不能被组或其他用户写入。启用前重新检查；不调用程序。
- 新目录权限为 `0700`。新文件在安全目录内使用随机临时文件、`O_EXCL` 和 `0600` 写入及同步，然后通过 `linkat` 原子发布。目标已存在就失败，绝不覆盖。发布后移除临时链接并同步目录。
- 仅接受固定所有权标记和**完全一致的规范内容**。外来文件、修改后的文件、符号链接、硬链接、目录、FIFO、异常权限或超大文件均保留并报告冲突。用户手动新增 `Hidden=true`、修改 `Exec` 或添加参数的文件也不会被覆盖/删除。
- 停用只删除已验证的本应用启动项，不删除目录、不处理其他应用。删除前重新核对文件身份和内容。
- 目录上的非阻塞 `flock` 协调本应用多个进程。其他持有者正在操作时立即返回 `ErrBusy`，不让启动界面无限等待。
- `Exec` 使用 Desktop Entry 的两层转义和完整参数引号，不经过 shell；百分号转为 `%%`，控制字符、无效 UTF-8 和程序路径中的 `=` 被拒绝。绝不增加任何参数。

安全边界是已检查的目录所有权。不能防御以相同 UID 任意修改目录的恶意程序或 root；Linux 没有按 inode 条件删除路径的通用 `unlink` 操作。描述符固定、进程协作锁和删除前复查缩小竞态，但不宣称可对抗同一用户的任意并发恶意修改。文件系统不支持所需原语时返回错误，不降级为不安全写法。

若崩溃恰好发生在临时文件发布前后，可能留下本应用随机临时文件；本实现不会扫描和自动删除不确定的文件。目录同步或临时链接清理失败会报告“已创建/已移除但同步或清理失败”，调用者应重新读取状态，不应假装操作完全成功。

## 平台和验证范围

Windows 和 macOS 的 `Status().Supported` 为 `false`，不提供假开关；修改入口返回 `ErrUnsupported`。不操作 Windows 注册表、计划任务或 macOS LaunchAgents。

所有测试文件、程序占位文件和注入的 HOME/XDG 路径都在 `t.TempDir()` 下。测试不运行启动程序，不触碰实际 `~/.config/autostart`。覆盖只读初始化/状态/预览、完整生命周期、权限、重复操作、跨安装位置、特殊字符转义、篡改内容、符号/硬链接、FIFO、目录替换、锁冲突及并发原子发布。

包级验证：

```sh
go test -race ./internal/autostart
go vet ./internal/autostart
# 可选：已安装的 freedesktop 验证器，只解析临时文件，不启动程序
MERIDIAN_DESKTOP_FILE_VALIDATE=/usr/bin/desktop-file-validate go test -run TestDesktopFileValidatorWhenRequested ./internal/autostart
```

本轮包级 race（含重复 10 次）、vet、Windows amd64 和 macOS arm64 测试二进制交叉编译均通过；额外使用本机已有 `/usr/bin/desktop-file-validate` 验证包含空格、百分号、双引号、反斜线、美元号、反引号等路径的生成文件，通过。默认测试未设置验证器路径时明确跳过这个外部工具检查。交叉编译测试二进制未在目标系统运行。

桌面实际登录启动仍需在目标 Linux 桌面环境中由用户明确授权后验收。单元测试通过和交叉编译通过均不等于此项验收完成。

依据：[XDG Autostart Specification](https://specifications.freedesktop.org/autostart/latest/) 和 [Desktop Entry Exec 规则](https://specifications.freedesktop.org/desktop-entry/latest/exec-variables.html)。
