# Linux L2TP/IPsec 后端

后端实现在 `internal/core/l2tp.go` 中，使用已安装、由发行版支持的 NetworkManager-l2tp 服务。
这是一个已实现并通过模拟测试的适配器，不代表已成功连接企业网关。

## 配置

- 协议为 `l2tp`；网关只能是主机名或 IP 地址，不能是 HTTPS URL，也不能使用 host:port 格式。
- 必须提供用户名、仅用于本次会话的密码和 IPsec PSK。IPsec 不能禁用。
- 类型化的 `l2tp` 选项包括：`ppp_auth`（`pap`、`chap`、`mschapv2`；省略时默认使用 MSCHAPv2）、`domain`、`remote_id`、`ike`、`esp`、`force_encapsulation` 和 `mru`。支持共用的 MTU 字段。
- 只允许选择一种 PPP 认证方式。PAP/CHAP 属于旧式方法，只有在管理员确认网关要求后才应选择；加密由强制启用的 IPsec 提供。
- IKE/ESP 只接受单个算法提案。列表、空白字符、分隔符注入和任意插件选项均会被拒绝。提案为空时，使用已安装插件的默认值，其中可能包含旧算法。如果策略有要求，管理员应提供经批准的提案。
- OpenConnect 专用的代理、TLS 证书、认证组、交互式 MFA 和禁用 UDP 设置会被拒绝，不会被静默忽略。

## 秘密信息与生命周期边界

密码和 PSK 存在于 `Credentials` 中，而非 `Profile` 中，也不会被序列化到 JSON。
引擎会复制并清空自身的秘密信息缓冲区。激活时，通过 stdin 和 `/proc/self/fd/0`
将秘密信息传给 nmcli 的密码文件读取器，绝不放入命令参数或应用生成的文件。
秘密信息标志使用 `2`（不保存）。这并不保证发行版的特权插件在自身的 IPsec 集成过程中，
绝不会写入仅 root 可访问的运行时秘密信息文件。

适配器创建仅保存在内存中的 `save no` 配置，并禁用自动连接；只激活本次新生成的 UUID，
且在失败或断开时只删除该 UUID。它会验证 VPN 已激活，并确认 PPP 接口地址与该 UUID 的 IP 配置匹配。
随机请求的 PPP 单元编号可减少冲突；发生竞态时，pppd 可能选择其他编号，因此不匹配时会拒绝继续并触发清理。
清理结果不确定时，状态保持为 `CleanupFailed`，并阻止重新连接。

OpenConnect 和 L2TP 的依赖会分别检测。需要 Linux、正在运行的 NetworkManager、nmcli、
L2TP 插件，以及管理员安装的 PPP/IPsec 依赖。实际激活可能需要操作系统授权。
开发期间未安装依赖，也未修改宿主机网络。

## 验证

新增的受控测试覆盖以下方面：不含秘密信息的 argv、临时配置及秘密信息标志、类型化选项映射、
从 JSON 中排除秘密信息、拒绝无效主机/参数/秘密信息、插件缺失、取消、
添加/激活/就绪检查/地址检查失败、回滚及清理失败。
实现期间，恢复的源代码通过了 `go test ./...`、`go vet ./...` 和 `go test -race ./internal/core`。

仍需在获得明确授权的 Linux 集成环境和网关上验证：发行版及插件版本兼容性、真实 IKE/PPP 协商、
策略允许的提案选择、经路由传输的流量和 DNS、真实 polkit 授权过程中的取消，以及网络恢复结果。
测试中未改动真实 TUN、路由、DNS、PPP 或 IPsec 服务。

## 已查阅的一手参考资料

- 持续维护的项目及依赖文档：https://github.com/nm-l2tp/NetworkManager-l2tp
- 属性名称和认证类型：https://github.com/nm-l2tp/NetworkManager-l2tp/blob/main/shared/nm-service-defines.h
- 插件属性校验、秘密信息字典、PPP 和 IPsec 映射：https://github.com/nm-l2tp/NetworkManager-l2tp/blob/main/src/nm-l2tp-service.c
- nmcli 临时配置、按 UUID 激活/删除，以及密码文件：https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nmcli.html
- PPP 单元编号冲突行为：https://github.com/ppp-project/ppp/blob/master/pppd/sys-linux.c

此适配器未复制上游实现代码。
