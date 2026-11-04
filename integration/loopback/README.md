# 显式启用的回环集成测试运行器

这些 Linux 夹具使用合成本机 TLS 服务器，运行真实认证与实验性原生代码。它们**不是**企业网关、真实 TUN、路由/DNS 恢复、特权部署或沙箱验收测试。请在私有工作区内以普通用户运行。运行器拒绝 root，不安装依赖，不运行 NetworkManager，也不启用应用的实验性后端。合成夹具凭据不是真实账号。不要提供企业凭据或企业网关。

## 认证（官方 OpenConnect 与可选 MFA 辅助程序）

前置条件：项目要求的 Go 工具链、C 编译器、pkg-config、官方 OpenConnect/libopenconnect 开发包 **9.12+**、Python 3 和 OpenSSL。例如，单独准备的 Debian trixie CI 环境提供 `build-essential pkg-config libopenconnect-dev openconnect openssl ca-certificates
python3 git`。依赖安装是 CI 管理员单独执行的步骤，不由本运行器完成。记录验证证据时应记录软件包版本。不能将 Ubuntu 24.04 较旧的 libopenconnect 误认为与辅助程序兼容。

依赖已准备好后，在仓库根目录执行：

```sh
sh integration/mfa-helper/build.sh "$PWD/build/meridian-auth-helper"
MERIDIAN_OPENCONNECT_TEST_BINARY=/usr/sbin/openconnect \
MERIDIAN_MFA_HELPER_TEST_BINARY="$PWD/build/meridian-auth-helper" \
  python3 integration/loopback/run.py auth --reports reports/loopback-auth
```

如果系统 OpenConnect 路径不同，请使用其真实绝对路径。辅助程序及其所有祖先目录必须私有且可信；不要放到所有用户可写的 `/tmp` 下。此命令不接受生产凭据。`auth.jsonl` 是原始 `go test -json` 证据；stderr 单独记录。运行器要求全部 18 项具名顶层真实认证测试及整个包均通过。任何跳过（包括子测试）、失败、格式错误的输出或预期测试缺失，都会使套件失败，不会用普通单元测试通过冒充集成测试成功。

## 实验性原生回归测试

额外依赖：`autoconf automake libtool libtool-bin gettext
libssl-dev libxml2-dev zlib1g-dev` 和 make。在已准备好的 Linux 主机上执行：

```sh
python3 integration/loopback/run.py native \
  --native-build "$PWD/build/loopback-native" --reports reports/loopback-native
```

原生构建目标目录不得已存在。准备流程会验证随仓库附带的上游归档，并应用记录中的完整补丁链。此入口必须使用随附归档，缺失时绝不下载。打补丁后必须存在所需测试源码，避免旧构建脚本的条件检查静默遗漏 UniVPN 夹具。随后运行既有原生构建/回归脚本，使用脚本 TUN 套接字、本地 TLS、继承的数据包套接字和包装系统调用的 TUN/netlink 测试，不使用内核 TUN。日志及明确标注 `live_vpn_acceptance: false` 的汇总写入报告目录。这些只是回归检查，不是由操作系统强制隔离恶意代码的沙箱。不要运行生产工作进程引导程序或安装特权服务。

## 运行器回归与证据限制

```sh
python3 -m unittest discover -s integration/loopback -v
```

测试覆盖遇错即拒绝的证据解析，以及嵌套 Git 工作区中的真实补丁应用，包括继承的 Git 目录覆盖设置。准备流程必须隔离 Git 仓库发现行为，否则 `git apply` 可能找到父仓库，在静默跳过所有解压树路径后仍返回成功。

本次改动时，六项运行器/准备流程测试通过。当时编辑主机缺少所需 Go/C 开发依赖，因此**没有**执行真实认证或编译、运行原生夹具。某个精确提交的套件是否通过，应以新的 CI 结果为准，不能依据本地解析器结果或旧归档夹具日志判定。即使失败，也要保留 `reports/loopback-*`。
