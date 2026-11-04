# 原生工作进程引导检查点（仅限 Linux x86-64）

这是具体的受信任引导实现，**已提供主动启用的集成，但尚未通过虚拟机验证**，
不是可用于生产的 UniVPN 隔离提供方。`make all` 构建静态可执行程序；
`make test` 仅运行注入的阶段失败和用户空间 seccomp 解释器。
两个目标都不会执行生产引导流程，也不会改变主机安全设置、命名空间、挂载、
凭据、网络配置、TUN、DNS 或 cgroup。
不要将其安装为 setuid 程序、手动运行它，或在此检查点启用 UniVPN。

## 信任与输入契约

经过审查的特权代理服务/服务管理器必须：

- 为此工作进程服务独占保留 UID **65532** 和 GID **65532**。
  不要复用已有的 nobody/容器/应用身份。出现冲突时拒绝部署。
  使用该身份的不受信任主机进程不在此边界的保护范围内：普通 exec 会将
  dumpability 重置为 1。引导程序的 dumpable=0 只保护其 exec 前阶段；
  它不能证明原生工作进程不可转储。
- 配置全新的专用 domain cgroup、资源限制（包括内存、CPU 和 pids），
  以及受保护的父级层次结构。落实 `internal/processcontainment/README.md`
  的所有要求。会话存活期间，任何外部主体都不得移动成员或修改该 cgroup。
- 固定并验证静态引导可执行程序及其不可变、归 root 所有的路径名。
  不接受解释器、动态引导加载器、调用方选择的可执行程序、调用方环境或 setuid 安装。
  此代码不是通用特权启动器，也不得将其作为通用特权启动器暴露。
- 将 `/var/lib/meridian/worker-root` 配置为不可变、最小化且归 root 所有的文件集合：
  仅包含经过审查的原生 `/bin/meridian-univpn`、其必需的加载器/库、
  经过审查的 OpenSSL 配置/提供方文件，以及获准的 CA 材料。
  不得包含主机秘密、shell、辅助可执行程序、proc、sysfs、cgroupfs、
  命名空间句柄、套接字、设备、可写路径或主机绑定挂载视图。
  审查符号链接和原生程序/库的哈希。顶层目录归 root 所有，并不能证明符合此文件清单。
  会话期间，必须保护祖先目录、内容和主机挂载拓扑不被更改。
  引导程序验证的是不含符号链接的固定祖先路径和固定的根 inode，
  而不是每个 rootfs 文件或管理员。
- 使用代理服务已验证的原生参数（包括所有必需的会话/传输/数据包参数）、
  全新的最小环境，以及且仅以下显式描述符，构造新的引导命令：

  | FD | 角色 |
  | --- | --- |
  | 0 | 只读密码管道，argv/环境变量中不含秘密 |
  | 1, 2 | 只写 `/dev/null`，绝不是代理服务通道 |
  | 3 | 只写会话管道 |
  | 4, 5 | 来自 fdtransport、彼此独立且已连接的 IPv4 TCP 控制/数据套接字 |
  | 6 | 未命名、非阻塞、已连接的 AF_UNIX SOCK_SEQPACKET 数据包端点 |
  | 7 | 与固定不可变根路径匹配的固定根目录 |
  | 8 | 只读、通过 SHA 固定的静态引导映像，在原生程序执行前关闭 |

  使用 `fdtransport.Prepare` 验证**获准的**对端，而不只是验证两个对端相同。
  引导程序会独立验证套接字类型、TCP 协议、对端相等、inode 标识彼此独立，
  以及 FD 方向。`packetrelay` 保留另一端点和主机 TUN。
  代理服务的数据包对端绝不能发送 SCM_RIGHTS/SCM_CREDENTIALS，
  也不能充当任意描述符代理。原生程序不持有 TUN、代理服务控制、cgroup
  或命名空间描述符。未列出的所有代理服务 FD 必须已经设置 CLOEXEC；
  close_range 也会在早期移除所有 >=8 的子进程 FD。
  FD8 仅用于通过 /proc/self/fd/8 对精确指定的映像执行引导 exec。
- 绝不向未经验证的引导映像发送秘密。其受信任代码不会读取 FD0：
  只有所有隔离操作成功后，原生程序才会读取。
  exec 已启动本身不代表沙箱就绪；只有经过此已验证引导流程后，
  原生认证会话协议才能推进会话。

## 精确的启动与失败顺序

1. `processcontainment.Adopt` 验证并固定管理器的空 cgroup。
   将引导命令传给 `Group.Start`，它会在执行任何引导/原生指令前
   使用 CLONE_INTO_CGROUP。不要以移动已运行 PID 的方式回退。
2. 静态单线程引导程序拒绝初始真实/有效 UID/GID 非 root 的情况，
   丢弃环境，限制核心转储，重置信号处理方式和掩码，并将自身 exec 前阶段设为不可转储。
3. 验证描述符角色/身份、固定根路径和根 FD。必须使用 close_range 关闭 >=8 的 FD。
   不使用 proc 扫描或猜测的上限。
4. 通过 `unshare` 创建全新的挂载/网络/IPC/UTS 命名空间，
   然后递归将挂载传播设为私有。不会在新网络命名空间内添加或启用任何接口。
   已连接的主机 TCP 描述符仍然可用。
5. 将固定的最小根目录非递归地绑定挂载到自身（不继承子挂载）。
   遍历其**绝对**路径以进入新的挂载，并重新检查根 inode。
   递归使用 mount_setattr 设置 readonly/nosuid/nodev，执行 pivot_root(".",".")，
   分离堆叠的旧根目录，再执行 chdir("/")。不受支持的调用会触发安全拒绝。
6. 关闭所有 >=7 的 FD，包括根句柄。将打开的 FD 数量限制为 64。
7. 清空 ambient capabilities；移除并回读每个受支持的 bounding-set capability；
   锁定 NOROOT、NO_SETUID_FIXUP 和 KEEP_CAPS 安全位。
   清空附加组，并将所有真实/有效/保存的 GID 和 UID 设为 65532。
   使用 capset 清零 permitted/effective/inheritable 集合，并通过 capget 验证；
   回读所有 ID/组。UID 更改后，再次将引导程序标记为不可转储。
8. 设置并回读 no_new_privs。安装 x86-64 LP64 seccomp 允许列表，
   未知 ABI/系统调用默认触发 KILL_PROCESS。不提供运行时策略文件或宽松回退。
   拒绝 x32 和 i386。Fork/clone、命名空间创建/进入、挂载、套接字创建/connect、
   ioctl、ptrace、process_vm、pidfd_getfd、发送信号、io_uring、bpf 和 keyring 均不可用。
   recvmsg 仅允许用于 FD6。sendto 限制为 FDs4..6，且不能指定目的地。
   fcntl 仅支持 GETFD/GETFL 和受约束的 SETFD/SETFL，不支持信号所有权或 O_ASYNC。
   TCP_NODELAY 是唯一获准的 setsockopt，仅限 FD4/5，且长度只能为 int 长度。
   prlimit64 只能查询自身，不能修改限制。
   pipe/pipe2 支持原生内部命令管道，pipe2 标志限于 CLOEXEC/NONBLOCK。
   只读 rootfs 加上 FD 关闭提供文件系统隔离；
   seccomp 无法检查路径字符串或 msg_control 内容。
9. 仅执行 `/bin/meridian-univpn`，并设置 LANG=C、LC_ALL=C 和 HOME=/。
   此模式没有钩子或子辅助程序。过滤器在 exec 后保留，并禁止创建进程。
   任何阶段错误都会立即返回退出码 100..107；任何 exec 返回都会以 108 退出。
   缺少参数时以 99 退出。不打印秘密或原始系统调用错误。
   失败后绝不会继续执行原生程序。
10. 即使发生启动失败、引导失败、取消或原生主进程退出，代理服务也必须回收
    主进程并调用 `Group.KillAndWait`。
    只有分层空状态证明成立，才允许关闭句柄和释放网络资源。
    不确定时保留所有权/句柄，不视为成功。此引导程序不提供主机租约。

## 需要主动启用的 Go 集成

`NewUniVPNWorkerIsolation` 位于 `internal/core/univpn_worker_bootstrap_linux.go`，
接受由具体管理器接管的 `*processcontainment.Group`、设置了 CLOEXEC 的固定根目录、
引导程序路径/哈希，以及原生程序哈希。
它检查**实际固定根目录内的原生映像哈希**，而不只是单独的主机可执行程序；
验证静态 x86-64 ELF；并复制/验证根目录身份。
构造失败不会接管调用方的 Group 或 Root。成功后转移 Group 所有权，
并保留自身的 Root 副本和引导程序 FD。
如果从未将其交给 Launch，调用方必须调用 RollbackLaunch(ctx,nil)。

将此实例用作 `UniVPNExecLauncher.Isolation`，并同时提供原生会话、fdtransport
和数据包提供方。启动器要求其原生 SHA 与根映像 SHA 相同。
私有且需主动启用的命令包装步骤将 Path 改为 `/proc/self/fd/8`，
提供精确验证过的引导程序 FD8 和根 FD7，并将 stdout/stderr 打开为 `/dev/null`。
此步骤发生在现有不可变命令快照之前。
`Prepare` 仍不能更改受保护的启动字段。
私有的原子启动方法调用 Group.Start，而不是直接调用 cmd.Start，
且不允许回退到不受约束的启动。针对另一条命令或第二次启动的调用会被拒绝。
拆除流程先使用 KillAndWait，再调用 Close；终止结果不确定时，
根/引导程序句柄会继续保留。早期验证/获取失败也会清理所拥有的组。
FD 关闭失败时不会盲目重试。

获准的原生 CA 路径及其获准内容必须存在于最小根目录**内部**。
此适配器不制作映像，不验证完整的库/提供方文件清单，不保留 UID，
不创建 cgroup，也不满足主机网络租约要求。
这些仍是受信任配置/发布流程的责任，不能用布尔值声明替代。
没有默认应用构造函数选择此适配器，普通 UniVPN 可用性仍保持禁用。
运行其测试并不授权运行它。

## 已验证与尚未验证的内容

已通过：严格静态编译且无 ELF 解释器；每个注入的阶段失败都会阻止后续阶段/exec；
exec 返回失败；在用户空间评估 ABI 拒绝、禁止的系统调用、fd 编号/高位字检查、
sendto 目的地限制、fcntl 命令/标志限制，以及范围严格受限的兼容性系统调用。
注入的 Go 适配器测试覆盖精确命令/FD 绑定、原子启动、重复/外来命令拒绝、
早期失败/取消清理，以及清理结果不确定时保留句柄。
默认 Go 测试套件通过，其中现有真实网络和 Unix 凭据测试被跳过；
专项 Go 竞态测试通过。模拟测试不会执行或证明内核凭据、能力、挂载、
seccomp 或命名空间行为。

生产激活前必需：经授权、可弃用的虚拟机必须通过 Group.Start 测试真实启动，
检查原生 exec 前后的 ID/能力/seccomp/命名空间/FD，
验证 rootfs 文件清单和加载器/提供方访问，证明引导失败绝不会消耗凭据，
拒绝所有逃逸和 FD 接收尝试，并验证启动失败/取消/cgroup 拆除。
保守的系统调用允许列表尚未针对真实沙箱原生会话进行调优；
遗漏的调用会刻意终止进程，而不会扩大允许范围。
虚拟机测试期间被拒绝的原生调用需要具体审查，不能自动加入允许列表。
必须进行启动/派生/子孙进程和 exec 转储属性测试。
真实网关兼容性、主机 TUN/路由/DNS 所有权和独占主机网络租约，
仍是独立且未解决的发布条件。

## 参考的第一手资料

- [内核 no_new_privs](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [内核 seccomp 过滤器](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [Linux 能力](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Linux unshare](https://man7.org/linux/man-pages/man2/unshare.2.html)
- [Linux pivot_root、堆叠根目录顺序](https://man7.org/linux/man-pages/man2/pivot_root.2.html)
- [Linux mount_setattr](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)
- [Linux close_range](https://man7.org/linux/man-pages/man2/close_range.2.html)
- [内核 cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
