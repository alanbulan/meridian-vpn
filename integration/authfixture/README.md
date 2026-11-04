# 真实 OpenConnect 仅认证集成测试

这些需要显式启用的测试会启动**真实的 OpenConnect 客户端**，而不是模拟运行器，并连接本机回环 HTTPS AnyConnect XML 认证夹具。测试代码位于 `internal/core/authfixture_integration_test.go`，因此真实客户端参数来自生产代码 `OpenConnectArgs`（包括自定义 CA 校验和直连模式的 `--no-proxy`）；子进程环境使用生产代码的代理净化逻辑，成功输出直接交给生产代码 `parseAuthentication`。

## 范围

以下项目已使用 Debian OpenConnect **9.12-3+deb13u2**、GnuTLS **3.8.9**、Linux amd64 验证：

1. 信任夹具的 TLS 证书 → 用户名/密码挑战与应答 → 生产代码解析认证 Cookie、网关和证书指纹。
2. 真实挑战与应答后拒绝无效的合成密码，不返回 Cookie。
3. 在 HTTP 凭据到达服务器前拒绝不受信任的夹具证书，错误明确指向证书验证。
4. 取消等待中的认证会终止真实子进程，不返回 Cookie。
5. 无用户名/密码的真实 mTLS 纯证书认证，分别使用未加密的 EC PEM 私钥和兼容 OpenSSL 的加密 EC PEM 私钥。
6. 本地网关不信任的客户端证书会在 TLS 阶段被拒绝，早于 HTTP 认证。
7. 加密私钥口令缺失或错误时安全拒绝，不发出 HTTP 凭据请求。
8. 取消等待中的客户端证书认证会终止真实子进程。
9. 加密 PKCS#8（PBES2、AES-256-CBC、PBKDF2-HMAC-SHA256）通过私有文件描述符传递口令完成认证；口令缺失、错误或证书不匹配时安全拒绝。

客户端证书测试使用生产代码 `authenticateOpenConnect` 和 `execRunner`，包括不跟随符号链接的文件校验、保留的文件描述符、严格的结果解析器和取消逻辑。另有真实子进程测试，检查密码和私钥口令从不出现在 argv 或环境变量中，仅通过 stdin 和继承的文件描述符 3 到达。证书和私钥使用继承的文件描述符 4 和 5；只有已认证的 Cookie 三元组进入 NetworkManager 阶段，该阶段仍使用模拟实现。

每次客户端调用均使用 **`--authenticate`**。夹具统计并拒绝 HTTP `CONNECT`；记录中的成功运行产生了**零次隧道 CONNECT 请求**。测试绝不运行 `nmcli`、访问 `/dev/net/tun`、创建网络接口、设置路由/DNS、连接企业网关或建立 VPN。这些结果**不构成 Linux VPN 端到端验证，也不证明 UniVPN 兼容性**。

凭据是固定的合成测试值；密码通过 stdin 传递。真实生成的 Cookie（可能带有 HPKE 私钥前缀）仅保存在内存中，不打印、不写入文件。测试 CA 和合成客户端身份文件写入私有的 0600 临时文件，由测试框架删除。不使用真实凭据。TLS 服务器私钥保留在 Go 测试服务器内存中；测试 CA 不安装到操作系统信任库。私钥口令作为生成的配置经匿名管道传递，不进入进程参数、环境变量或配置文件。夹具的 `--cafile` 仅指向临时测试 CA，`--no-proxy` 确保请求停留在回环网络。TLS 验证不会关闭。

## 使用已安装的可信客户端运行

在仓库根目录执行：

```sh
MERIDIAN_OPENCONNECT_TEST_BINARY=/usr/sbin/openconnect \
  ./integration/authfixture/run-auth-only.sh
```

未设置环境变量时，普通 `go test ./...` 会**跳过**这九个需显式启用的测试函数。跳过不等于通过。每项测试都会验证客户端 `--version` 前置条件；真实客户端无法启动时，拒绝类测试也不能错误地通过。

## 仅在工作区暂存 Debian 组件

无需 root，也不安装软件包。在兼容的 Linux amd64 系统上，脚本会从 `https://deb.debian.org/debian/pool/main/` 下载固定版本的软件包，逐个校验已记录的 SHA-256，并解压到指定的私有暂存目录：

```sh
./integration/authfixture/stage-debian-client.sh /absolute/workspace/openconnect-fixture

MERIDIAN_OPENCONNECT_TEST_BINARY=/absolute/workspace/openconnect-fixture/root/usr/sbin/openconnect \
LD_LIBRARY_PATH=/absolute/workspace/openconnect-fixture/root/usr/lib/x86_64-linux-gnu \
  ./integration/authfixture/run-auth-only.sh
```

脚本**不会**安装软件包、运行软件包维护脚本、启动服务、更改安全策略或修改系统文件。其他普通系统库（glibc、GnuTLS、libxml2 等）必须已有兼容的 ABI。软件包哈希固定了通过 HTTPS 获取的制品；本夹具不声称另外验证过 Debian 发行版签名。不要替换成不可信的可执行文件。

云端执行工作区中的实际命令使用 Go 1.27.3 和以下明确路径：

```sh
GO=/workspace/shared/toolchains/go/bin/go \
GOCACHE=/workspace/shared/go-build GOPATH=/workspace/shared/go-path \
LD_LIBRARY_PATH=/workspace/shared/openconnect-fixture/root/usr/lib/x86_64-linux-gnu \
MERIDIAN_OPENCONNECT_TEST_BINARY=/workspace/shared/openconnect-fixture/root/usr/sbin/openconnect \
  ./integration/authfixture/run-auth-only.sh
```

还在 `/workspace/shared/openconnect-fixture-repro` 完成过一次全新暂存复现：12 个归档的 SHA-256 检查全部通过，暂存客户端可以运行，原先四项认证测试再次通过。这是历史基线，当前扩展结果见 `RESULTS.txt`。Shell 语法检查和核心代码 vet 检查通过。

`RESULTS.txt` 保存最终的脱敏测试输出。下载的可执行文件和运行库不包含在源码归档中。

## 一手参考资料

- [OpenConnect：以非特权用户单独执行认证](https://www.infradead.org/openconnect/nonroot.html)。
- [OpenConnect：AnyConnect 协议概述](https://www.infradead.org/openconnect/anyconnect.html)。
- 已检出的官方上游源码提交 `70d1e79d1e55849dfc71dcc199b1edb535b547e4`：[`auth.c`](https://gitlab.com/openconnect/openconnect/-/blob/70d1e79d1e55849dfc71dcc199b1edb535b547e4/auth.c)、[`main.c`](https://gitlab.com/openconnect/openconnect/-/blob/70d1e79d1e55849dfc71dcc199b1edb535b547e4/main.c) 和 [`tests/fake-cisco-server.py`](https://gitlab.com/openconnect/openconnect/-/blob/70d1e79d1e55849dfc71dcc199b1edb535b547e4/tests/fake-cisco-server.py)。夹具使用自行编写的最小认证处理程序，不是完整网关，也不是复制的服务器实现。
- Debian 官方软件包 URL 和固定的归档哈希：`debian-packages.sha256-urls`。

## 客户端身份格式与校验

配置仅保存证书和私钥绝对路径的引用。PEM 证书链的首张证书应是当前有效的客户端叶证书，并使用独立的 RSA/EC/PKCS#8 PEM 私钥。私钥必须具有仅所有者可访问的 POSIX 权限（例如 `0600`）；证书不能允许组或其他用户写入。本地会拒绝符号链接、FIFO、目录、超大文件、格式错误的 PEM、过期或非客户端证书，以及不匹配的未加密私钥。加密私钥由原生 TLS 实现解密并匹配。本节原有验证范围尚未实现 PKCS#12 容器和硬件/USB 令牌。

传统加密 PEM 测试在 DEK-Info 头中使用兼容 OpenSSL 的大写十六进制 IV。OpenConnect 9.12 会拒绝 Go 已弃用的旧式 PEM 加密函数生成的小写十六进制 IV；夹具只规范化自己生成的合成头。加密 PKCS#8 没有这一旧格式限制。不能根据已测试格式推断所有密码算法或提供程序均受支持。

OpenConnect 配置值不使用 shell 引号转义。生成的 key-password 行保留字面量引号、`#` 和 `=`。口令为空时省略该行。启动任何进程前，会拒绝 CR/LF/NUL、开头为空格或制表符、以及超过 4096 字节的口令。
