# 客户端证书格式

Meridian 配置支持三种明确的身份格式。这些格式用作 OpenConnect 的客户端认证输入，
并不表示已兼容任何商业网关。本功能不会加入绕过服务器证书验证的方式。

| `certificate_format` | `client_certificate` | `client_key` |
| --- | --- | --- |
| 未设置 / `pem` | PEM 证书的绝对路径 | PEM 私钥的绝对路径 |
| `pkcs12` | DER 格式 PKCS#12/PFX 容器的绝对路径 | 必须为空 |
| `pkcs11` | PKCS#11 证书对象 URI | 可选的 PKCS#11 私钥 URI |

GUI 提供格式及身份引用的设置入口。持久化保存的只有引用。
容器密码和令牌 PIN 仅以本次认证所用的 `Credentials.KeyPassword` 字节数据存在，
绝不作为配置属性、进程参数、环境变量或文件保存。
对托管缓冲区的清空只能尽力而为：无法保证 Go、运行时和 UI 产生的字符串副本都从内存中擦除。

## 文件与秘密信息

PEM 私钥和 PKCS#12 容器必须是仅文件所有者可访问的普通文件，大小不超过 4 MiB。
Linux 打开文件时拒绝符号链接，并在整个认证期间保持已校验的文件描述符处于打开状态。
PEM 公共证书不得允许同组用户或其他用户写入。
命令后端通过继承的文件描述符和私有配置管道接收身份文件；
交互式辅助程序通过其大小受限的私有协议接收引用和秘密信息。
这两条路径都不会将身份材料传给 nmcli。

PKCS#12 的本地校验只检查 ASN.1 PFX 的版本和内容封装，不验证其密码学有效性。
必须包含结构有效、用于基于密码的完整性校验的 MAC；不带 MAC 的容器会被拒绝。
仅接受第 3 版、内容类型为 data 的 PFX，不接受 signed-data 类型的 PFX。
MAC 验证、解密、证书链加载、证书检查和私钥匹配由 OpenConnect 的 TLS 后端执行。
因此，配置保存成功不能证明容器密码或身份有效。

## 令牌

PKCS#11 需要用户已有且配置正确的提供程序，以及支持令牌的 OpenConnect TLS 构建版本。
Meridian 不会安装提供程序、加载用户选择的模块、枚举令牌、修改 PIN 或改动系统密钥环。
URI 必须选择一个 `id` 或 `object`。可选的类型选择器中，证书必须对应 `cert`，私钥必须对应 `private`。
接受 RFC 7512 的 `type` 和较早 OpenConnect 文档中的 `object-type`，但不能同时使用两者。
不适合直接用于 URI 的字节必须采用百分号编码。

只允许已知且不含秘密信息的身份属性。在保存或启动前，会拒绝 URI 查询和片段、
`pin-value`、`pin-source`、模块选择器、重复或未知属性，以及文本选择器中的控制字符。
支持二进制对象 ID。例如：

```
pkcs11:token=Synthetic%20Token;id=%01;type=cert
```

如果提供程序不使用 `key-password`，应通过交互式认证处理提供程序发出的 PIN 验证请求。
是否支持传入的 PIN 取决于 TLS 后端。辅助程序现有的、有界密码表单回调可以显示这类请求，
但本次恢复工作尚未验证真实硬件与提供程序的互操作性。测试中未访问任何生产环境令牌。

## 验证范围

`go test ./internal/core` 包含模拟的文件描述符传递、防注入及 URI 持久化检查。
如果 OpenSSL 可用，会在本地生成全新的合成加密 PFX，用于验证封装。
这不会访问远程网关或硬件令牌。仅验证封装的测试夹具刻意不包含真实身份，仅用于传递测试。

`TestRealOpenConnectPKCS12` 沿用现有测试夹具框架，通过 `MERIDIAN_OPENCONNECT_TEST_BINARY` 显式启用。
它使用全新的合成凭据和本机回环 TLS，配合 `--authenticate`，校验返回的认证三元组，
并拒绝错误或缺失的密码。它绝不会请求创建隧道、调用 nmcli 或设置主机路由和 DNS。
如果明确指定的真实可执行文件不可用，该测试会被跳过，而不是被标记为通过。

### 恢复验证结果（2026-11-03）

完整的仅认证脚本已使用保留的 OpenConnect 9.21 可执行文件，通过全部十个具名真实 OpenConnect 测试。
该可执行文件应用了 UniVPN 补丁，并使用 OpenSSL 后端。
使用的包装脚本是 `recovery/native-univpn-linux-amd64/openconnect`；
它加载相邻位置的隔离库，不安装系统软件。

PKCS#12 使用新生成的合成凭据，以及通过私有文件描述符传递的容器和口令，完成了真实的本机回环 mTLS。
缺失或错误的容器密码均被拒绝。PEM、加密 PEM、加密 PKCS#8、服务器/客户端信任拒绝及取消测试也全部通过。
测试夹具断言隧道 CONNECT 请求数为零。未测试生产网关或硬件 PKCS#11。

调用命令为 `sh integration/authfixture/run-auth-only.sh`，
其中 `MERIDIAN_OPENCONNECT_TEST_BINARY` 设置为包装脚本的绝对路径。
捕获的输出保存在恢复工作区的 `recovery/meridian-auth-only-validation.log`。
这些结果只证明已测试的 OpenSSL 分支构建版本的表现，不涵盖所有 TLS 后端与提供程序组合。

## 一手参考资料

- https://www.infradead.org/openconnect/connecting.html
- https://www.infradead.org/openconnect/pkcs11.html
- https://www.infradead.org/openconnect/manual.html

现有辅助程序使用 `openconnect_set_client_cert` 和 `openconnect_set_key_password`；
选择格式不需要引入新的辅助程序通信协议。
按照 OpenConnect 的规定，容器中的私钥与证书使用同一个文件，因此省略单独的私钥引用。
