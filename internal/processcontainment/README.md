# Cgroup v2 生命周期基础组件（仅限 Linux）

本包包含需显式启用的 UniVPN 工作进程引导适配器，但**尚未接入默认的 UniVPN 部署**。
参见 `integration/worker-bootstrap/README.md`。
它不是隔离机制提供方、网络所有权租约或完整的沙箱。
单元测试中的所有内核操作和进程启动均通过注入模拟。
在这一阶段，未更改任何 cgroup 或安全设置，也未启动任何特权进程。

## 已实现的边界

`Adopt` 复制由受信任管理器提供的空 cgroup 目录 FD。
它要求原始 FD 已设置 CLOEXEC（调用方必须保持该设置），并检查以下条件：
cgroup2 文件系统；目录归 root 所有，且同组用户和其他用户无写权限；
类型为 `domain`；控制文件位于同一 cgroup2 文件系统上，是归 root 所有的普通文件；
`cgroup.kill` 可用；状态严格为 `populated 0`/`frozen 0`。
固定名称的控制文件相对于持有的目录打开，并使用 NOFOLLOW 和 CLOEXEC。
本包既不会创建目录，也不会通过名称重新获取 cgroup。

`Start` 在 `exec.Cmd.Start` 期间持续持有目录，选择 Go 的 `UseCgroupFD`/`CgroupFD` 路径，
绝不退回到迁移已经运行的 PID 的方式。它保留其他已配置的启动属性。
如果内核无法使用 clone3/CLONE_INTO_CGROUP，启动就会失败。
目标命令必须已经是经过审查的引导程序；直接启动具有特权的原生 VPN 工作进程是不安全的。
通过比较设备和 inode 标识，会拒绝 ExtraFiles 和基于文件的标准流中所持有 cgroup 描述符的别名。
引导程序仍须限制所有其他具有高权限能力的描述符和路径。
该命令由此生命周期独占，不得通过其他引用再次启动。
不支持调用方在 Start 执行期间并发修改命令。

`KillAndWait` 向已固定持有的终止控制文件写入恰好一个 `1`，
并通过已固定持有的事件 FD 检查层级的 populated 状态，直到为空、发生错误或最多等待两秒。
这段等待时间也包括等待并发的 Start 完成。
尚未完成的 Start 会返回不确定结果，并保留句柄；绝不会将其视为空 cgroup。
它会拒绝格式错误、重复或缺失的状态以及短写入。
启动失败也必须取得同样的清理证明。失败时会保留句柄以供重试；
在终止成功之前，`Close` 拒绝丢弃已尝试启动所对应的句柄。
Close 会返回忙碌错误，而不会等待尚未完成的 Start 或清理操作。
Close 失败会持续保留为错误状态，不会针对可能已被复用的 FD 重试关闭。
cgroup 目录的删除由提供该目录的服务负责，不属于本包职责。

此处使用的 Go 1.27.3 工具链将 UseCgroupFD 交由 clone3 处理，并设置 CLONE_INTO_CGROUP。
原子放入 cgroup 的行为见 [clone(2)](https://man7.org/linux/man-pages/man2/clone.2.html)。
层级 populated 状态和子树终止的含义见 [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)。

## 必须满足的外部前提，不属于本 API 能证明的性质

- 受信任的服务管理器必须提供全新、专用且不是根 cgroup 的 domain cgroup，
  排除无关成员，并在整个会话期间保护其父层级、权限、成员关系和后代 cgroup。
  仅凭目录的 uid、模式和空状态读取结果，**不能**证明这些性质。
- 在执行原生程序之前，经过审查的引导程序必须禁止进程迁出该 cgroup。
  不得暴露可写的 cgroup 文件系统/FD、宿主机 proc 视图、命名空间句柄、
  继承的高权限凭据或代理服务控制用 Unix 套接字。
- 完整沙箱必须包括：专用的非 root 身份，不带附加组和 capabilities；
  适当的文件系统/挂载与网络命名空间；受限的继承 FD；no-new-privileges；以及经过审查的系统调用策略。
  单独一个 cgroup 或空网络命名空间都不能提供上述全部保障。
- 恶意宿主机 root、服务管理器或改变这些前提的管理员不在威胁模型范围内。
  任何进程成员快照都无法证明未来不会发生外部迁移或权限更改。

no-new-privileges 在 exec 后仍然有效，并阻止通过 exec 获得更高权限；
它不会移除已有权限，也不会阻止接收具有特权能力的描述符。
[内核 no-new-privileges 文档](https://docs.kernel.org/userspace-api/no_new_privs.html)

Seccomp 只是一层防护，不是完整沙箱。
其引导程序和兼顾 ABI 的策略必须在获得授权、可弃置的虚拟机中接受审计和测试。
当前工具链中的 Go SysProcAttr 不提供通用且安全的子进程 exec 前回调来安装这类策略。
在代理服务的多线程运行时中调用 prctl/setns 不能作为可接受的替代方案。
`integration/worker-bootstrap` 中现已有独立的静态 C 引导程序和具体的、需显式启用的 Go 适配器；
它们的注入测试不能替代必须通过的授权虚拟机/内核验证关卡。
[内核 seccomp 文档](https://docs.kernel.org/userspace-api/seccomp_filter.html)

## 为何独占宿主网络租约仍不可用

已打开的单队列、非持久 TUN 可以将设备生命周期绑定到代理服务持有的 FD。
但它无法阻止宿主机上另一个拥有 CAP_NET_ADMIN 的主体更改设备、路由表或命名空间。
随机名称/别名、ifindex、netns FD、flock 或 cgroup 都不能撤销其他主体的权限。
解析器配置是另一个可被写入的独立对象。
仅用运行时布尔值声称已实现独占，不能构成真实证明。
[内核 TUN 文档](https://docs.kernel.org/networking/tuntap.html)

目前有意不提供会返回成功的 UniVPNNetworkLease 或 UniVPNHostLeaseProvider 实现。
现有代理服务的激活仍被禁用。确切缺失的前提是以下两者之一：
由管理员强制实施、经过审查的独占网络/解析器控制域；
或者明确重新设计约定，信任宿主机网络管理器并处理冲突，而不作全面独占的承诺。
将 VPN 和使用 VPN 的应用同时放入私有命名空间是另一种可能的产品方案，
但它不能提供对整个宿主机透明的路由和 DNS。

## 集成前的验收要求

必须在获得授权、可弃置的虚拟机中验证：启动顺序；有效 UID、capabilities、seccomp 和命名空间标识；
迁移/命名空间/套接字逃逸失败；派生的后代进程在主进程退出后继续存活但仍会被终止；
不存在未列明的继承 FD；clone3 被拒绝时不回退；取消操作，以及引导和终止失败。
真实网关、TUN 及宿主机 DNS/路由测试仍是独立的验收关卡。
此处的模拟测试仅证明控制流程，不能证明这些性质。
