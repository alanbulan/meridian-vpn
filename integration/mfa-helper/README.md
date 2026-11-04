# 可选的结构化认证辅助程序

Meridian 的 MyGo GUI 和 Go 桥接层保持纯 Go 实现（`CGO_ENABLED=0`）。需要交互式 AnyConnect 认证的 Linux 用户，可以选择构建小型的**独立 C 可执行程序** `meridian-auth-helper`。它使用官方 libopenconnect 的 `process_auth_form` 回调，而不是从 CLI 的 stderr 猜测提示内容。禁用交互式认证时，现有的仅密码/证书 CLI 路径仍然可用。

辅助程序只调用 `openconnect_obtain_cookie`。它**绝不会创建隧道、调用 NetworkManager、打开 TUN、安装路由/DNS、安装 CA 或更改宿主机的安全设置**。认证完成后，由现有的 Go NetworkManager 后端处理另行获得授权的隧道操作。认证成功不代表隧道已就绪。

## 支持范围与不支持的功能

- 支持类型化的文本/密码字段（包括服务器请求的一次性验证码）、选择列表、重试表单、精确匹配已配置认证组，以及 PEM 客户端证书/私钥认证。
- 只有首个表单仅包含已识别的用户名/密码字段时，才会复用初始用户名/密码。附加字段或后续验证请求需要通过原生 GUI 提示用户输入。已保存的认证组必须与服务器提供的 ID 或标签精确匹配；绝不会自行虚构认证组。
- 支持正常的系统信任及可选的、经过校验的私有 CA 文件。TLS 错误**始终导致拒绝**。不存在证书例外按钮或允许例外的回调路径。
- **拒绝**外部浏览器/WebView SSO 和 SSO 表单字段。隔离的辅助程序遇到 SSO 字段会立即退出，因为 libopenconnect v9.12 即使在表单回调返回错误后，也可能继续进入 SSO 处理；浏览器回调同样会终止辅助程序，而不会启动任何内容。CSD/Host Checker 始终禁用：辅助程序绝不会调用 `openconnect_setup_csd`、配置包装程序或启用用于执行脚本的用户。尚未实现软件令牌种子、PKCS#11/USB 密钥、推送通知轮询器或终端合规流程。
- 已针对临时的 localhost TLS AnyConnect 测试夹具进行测试，未针对企业网关测试。测试覆盖真实的官方 libopenconnect 回调、密码 → OTP + 方式选择 → 错误验证码重试 → 成功，以及拒绝、取消、有界表单和客户端证书。这不代表支持所有 MFA、兼容 UniVPN 或已完成真实 VPN 端到端测试。

## 使用系统开发依赖构建

要求：Linux、C11 编译器、pkg-config，以及官方 libopenconnect **9.12 或更高版本 / API 5.9 或更高版本**的头文件和运行时库。请通过操作系统的软件包管理器单独安装和维护这些依赖；本项目绝不会自动安装软件包。Debian 常见开发包名称为 `libopenconnect-dev`。

从仓库根目录运行：

```sh
./integration/mfa-helper/build.sh ./build/meridian-auth-helper
CGO_ENABLED=0 go build -o ./build/meridian ./cmd/meridian
```

辅助程序采用动态链接和加固标志构建，不设置工作区 RPATH。请将其放在 **GUI 可执行文件旁边**，或放入 `PATH` 中常规且受信任的可执行文件目录。GUI 优先查找同目录文件，其次查找 PATH，并通过固定的 `--protocol-version` 握手探测。查找过程会拒绝符号链接可执行文件、非普通文件、缺少执行权限的文件、所有者不是 root 或当前用户的文件，以及同组用户/其他用户可写的文件或上级目录。不要将其安装到 `/tmp` 或共享可写目录，也不要以 root 身份运行。这些检查保障的是路径安全，不是数字签名；当前用户账户和系统管理员仍被视为可信。

辅助程序必须能够通过正常机制找到系统 libopenconnect 运行时。如果辅助程序或运行时缺失、不兼容、所在位置不安全或无法启动，GUI 会明确禁用交互式认证。提供的辅助程序二进制文件不包含运行时库，也不是经过签名的安装程序。Linux 二进制文件不是 macOS/Windows 后端。

## 可复现的 Debian 私有暂存环境

对于兼容的 Linux amd64 测试主机，以下需显式启用的脚本会下载锁定版本的 Debian 官方软件包，验证记录的 SHA-256 哈希，并仅在选定工作区内解压。它不会运行软件包维护脚本、安装软件包、启动服务或修改系统文件。常规系统依赖的 ABI 必须事先兼容。

```sh
./integration/mfa-helper/stage-debian-helper.sh /absolute/private/workspace/mfa-stage

MERIDIAN_MFA_HELPER_TEST_BINARY=/absolute/private/workspace/mfa-stage/meridian-auth-helper \
LD_LIBRARY_PATH=/absolute/private/workspace/mfa-stage/root/usr/lib/x86_64-linux-gnu \
  ./integration/mfa-helper/run-auth-only.sh
```

运行时软件包及其哈希来自 [`../authfixture/debian-packages.sha256-urls`](../authfixture/debian-packages.sha256-urls)。额外的开发头文件包为 Debian `libopenconnect-dev_9.12-3+deb13u2_amd64.deb`，SHA-256 为 `c38741a011ce2840bf792c3727bfa14d0b661dc02f58f500af5f907641caafd8`。软件包 URL 来自官方 `https://deb.debian.org/debian/pool/main/` 归档。这些哈希锁定下载的文件；脚本并不声称额外验证了 Debian 发布签名。

不要将 `LD_LIBRARY_PATH` 指向不可信目录。它只用于此处的私有暂存示例，正常安装运行时不需要这样设置。下载的依赖不包含在本仓库和源码交付物中。

测试需显式启用：未设置环境变量时，常规 `go test ./...` 会跳过 `TestRealMFA*`。跳过测试不等于集成测试通过。`RESULTS.txt` 记录了一次经过脱敏的运行，环境为 Go 1.27.3、Debian libopenconnect 9.12-3+deb13u2 和 GnuTLS 3.8.9。测试秘密信息使用固定的合成值。测试 CA 私钥始终留在内存中；只有公开 CA 证书和临时测试客户端身份夹具文件会写入私有测试目录。

## 私有 IPC 协议 v1

协议消息仅通过子进程继承的 stdin 和 stdout 管道传输。不使用套接字监听器、临时凭据文件、shell 求值、含秘密信息的命令参数、含秘密信息的环境变量或凭据日志。stderr 和进度输出会被丢弃。辅助程序进程禁用核心转储，并在认证后退出。对于自身拥有的内存缓冲区会执行清空；Go 字符串、界面控件字符串和 libopenconnect 分配的内存无法保证抵御内存取证。

每帧以一个 4 字节的大端载荷长度开头，范围为 **36–65,536 字节**。载荷结构如下：

1. 协议版本 `u8 = 1`。
2. 消息类型 `u8`：`1` 初始化，`2` 验证请求，`3` 回答，`4` 认证成功结果。其他值一律拒绝。
3. 会话 ID：每次尝试由 Go 使用 16 个随机字节生成的 32 个 ASCII 小写十六进制字符。
4. 轮次：大端 `u16`。初始化时为零。验证请求从一开始严格递增。回答必须回传当前会话和轮次。结果回传最后一轮的轮次；仅证书认证时为零。
5. 各消息类型对应的数据，不接受尾随字节。

字符串/字节值以大端 `u16` 表示字节长度，后面紧跟恰好该长度的数据。传输格式不以 NUL 结尾。到达 Go 边界的字符串必须是有效 UTF-8。内嵌 NUL 或不支持的控制字符会导致失败；元数据可以包含作为普通文本处理的换行符和制表符。ID、选项、回答和认证字段不接受换行符或控制分隔符。

- **初始化：**网关、保留的 CA 文件描述符路径或空值、明确获准的代理或空值、保留的客户端证书文件描述符路径或空值、保留的密钥文件描述符路径或空值、仅本次尝试使用的密钥口令或空值、配置的认证组或空值。仅通过 `ExtraFiles` 传递已检查并保留的文件描述符；`/proc/self/fd/N` 通过私有通道发送。不使用服务器提供的文件路径。
- **验证请求：**标题、消息、字段数量 `u16`；随后依次为每个字段的 ID、标签、类型 `u8`（`1=text`、`2=password/token`、`3=select`）、选项数量 `u16`，以及每个选项的 ID 和标签。隐藏的后端状态保留在 libopenconnect 内部。不支持的字段类型会导致失败。重复的字段或选项 ID 会导致失败。
- **回答：**字段数量 `u16`，随后按照验证请求中的字段顺序给出每个字段的 ID 和值。必须恰好包含当前字段集合；选择值必须匹配提供的某个选项 ID。桥接层在使用后清空回答字节切片。
- **认证成功结果：**Cookie、HTTPS 连接 URL、已验证的对端证书指纹，以及可选的 `DNSNAME:IP` 解析提示。DNS 负载均衡同时保留已认证地址和原始主机名/SNI。Go 会先验证返回的 URL 和数字地址解析映射，再将三元组交给 NetworkManager。

两端均执行以下限制：**每次认证尝试最多 180 秒，最多八个可见表单，每个表单最多十六个可见字段，每个选择字段最多三十二个选项**。辅助程序还将全部表单选项（包括隐藏选项）限制为 64 个。ID 最多 128 字节，标题/标签最多 2,048 字节，横幅/消息/重试文本合计最多 4,096 字节，回答最多 4,096 字节，返回的 Cookie/URL/指纹最多 16,384 字节。超大、格式错误、过期、重复、不完整或不匹配的帧一律拒绝。GUI 回调必须响应取消。取消会终止辅助程序并关闭其管道，同时防范输出管道被继承的情况，因此不会留下可以回答旧会话的认证进程。

## 源码与许可

新增辅助程序源码采用 MIT 许可证（SPDX 见 `main.c`）；它动态使用另行安装、采用 **LGPL-2.1 许可证的 libopenconnect 库**。OpenConnect 命令行应用及相关组件可能有不同的许可义务。仅包含本辅助程序并不能满足打包/分发外部库的要求；必须保留发行方的声明/源码，并遵守适用的许可要求。本项目不复制或捆绑该库的实现。

以下一手参考资料已与官方 v9.12 源码核对：

- [公开回调与生命周期 API，openconnect.h](https://gitlab.com/openconnect/openconnect/-/blob/v9.12/openconnect.h)。
- [认证表单处理与库生命周期，library.c](https://gitlab.com/openconnect/openconnect/-/blob/v9.12/library.c)。
- [AnyConnect 表单与默认禁用的 CSD，auth.c](https://gitlab.com/openconnect/openconnect/-/blob/v9.12/auth.c)。
- [官方 CLI 的仅认证结果与 RESOLVE 处理，main.c](https://gitlab.com/openconnect/openconnect/-/blob/v9.12/main.c)。
- [OpenConnect 非 root 认证架构](https://www.infradead.org/openconnect/nonroot.html)。
