# UniVPN 离线部署准备

本检查点增加的是可执行的**离线制品验证器和工作区暂存工具**，不是系统安装器、服务、根文件系统分发包或激活入口。它不会创建用户/cgroup、安装文件、执行二进制、调用包管理器、更改新工作区目录以外的权限、使用套接字或修改 TUN/路由/DNS。由于还没有经过审查、可运行的服务入口，因此不提供 systemd 单元或安装后钩子。UniVPN 默认仍禁用。

## 经审查的输入契约

提供专用的组件包目录及单独审查过的 JSON 清单：

```json
{"version":1,"files":[{"path":"rootfs/bin/meridian-univpn","sha256":"<64 lowercase hex characters>","mode":365,"size":12345}]}
```

此示例刻意不完整，无法通过验证。每项清单必须包含精确路径、摘要、十进制权限模式（292 = 0444，365 = 0555）和正数大小。必需文件：

- `rootfs/bin/meridian-univpn` 和 `bootstrap/meridian-worker-bootstrap`（0555）。
- `licenses/OPENCONNECT-LGPL-2.1.txt`、`licenses/UNIVPN-CONNECT-MIT.txt` 和 `licenses/THIRD_PARTY_NOTICES.md`。保留 `integration/univpn-native/licenses/` 中完整的原始声明，并履行适用的源码提供/重新链接义务。
- 按需提供根文件系统 `lib/`、`lib64/`、`usr/lib/` 下明确审查过的加载器、库及提供程序，以及 `etc/ssl/` 下的 CA/OpenSSL 配置。不接受其他清单路径。加载器符号链接必须在精确运行路径上物化为经过审查的普通文件，每个文件单独计算哈希。

清单属于管理员/发布审查的信任输入。SHA 摘要不是签名，也不能证明代码安全。不要从不可信制品自动生成清单后就称其已验证。工具仅检查字节一致性，不验证库依赖闭包、ELF 正确性、配置安全、许可证合规或来源。现有 Go 工作进程构造器会在启动时另行检查引导程序 ELF 结构及引导程序/原生程序两者的哈希；它不解析原生程序的 ELF 结构。提供程序/库加载及保守的 seccomp 策略仍需在虚拟机中验证。根文件系统包中绝不能包含私钥、账号导出、网关凭据、宿主配置或个人证书材料。

清单输入限制为 2 MiB、4096 个文件、每文件 64 MiB、总计 256 MiB。未知字段、重复 JSON 键/路径、含糊路径、可写文件或特殊权限文件、符号链接、硬链接、设备/FIFO/套接字、扩展文件属性（包括能力）、额外文件/目录及缺失条目均被拒绝。验证器通过相对文件描述符的 NOFOLLOW 遍历检测文件元数据变化，并对之后实际复制的内存字节计算哈希。它不运行 `ldd` 或任何制品。为支持工作区使用，源码目录可由所有者写入，但不能被组或其他用户写入，也不能具有特殊权限。这**不是**已部署不可变根文件系统验证、祖先路径审计、挂载拓扑证明，也不能防止恶意所有者/root 同时修改工作区。

```sh
python3 provision.py --manifest reviewed-manifest.json --bundle ./reviewed-bundle
python3 provision.py --manifest reviewed-manifest.json --bundle ./reviewed-bundle --stage-parent ./workspace-output
python3 -m unittest -v
```

第一条命令只读。第二条在已有可信工作区目录内新建权限 0700 的 `meridian-offline-*` 子目录，绝不替换现有部署。输出包含已验证字节、排序后的清单和 `installation-plan.json`，其中激活及服务启用/启动标志始终为 false。清单本身不属于制品清单条目；重新验证暂存字节时，应另取仅含清单路径的副本，不能直接使用包含计划/清单的整个输出。命令行拒绝源码与输出互相嵌套。

暂存需要可信且没有外部并发修改的父目录。失败时，只有路径的 inode/设备身份仍匹配，才按日志逆序回滚；被替换的对象会保留，清理失败会报告不确定性。工具不会递归删除任意目录。成功输出归调用者所有，之后不会自动清理或安装。崩溃/断电可能留下不完整的私有目录，应隔离检查，不要将其用作已安装镜像。不承诺具有崩溃持久性的激活事务。

## 身份与 cgroup 部署计划

可选的 `--passwd-export` 和 `--group-export` 接收管理员提供的一对 NSS 快照。出现 UID/GID 65532、工作进程账号名称或使用该主 GID 的账号时，均视为冲突，即使账号看起来属于本应用。绝不自动接管或复用账号。导出数据不写入输出。空、过期、不完整的导出或仅有 `/etc/passwd`，都不能证明实时 NSS 唯一性、远程映射、不存在相关进程或身份已被保留。可信安装器必须保留固定身份、拒绝冲突、验证所有 NSS 来源及活跃进程，并在运行期间维持身份独占使用。不要将账号导出放入发布制品。

生成计划指定全新的专用 cgroup v2 `domain`，以及 cpu/memory/pids 控制器；初始建议限制为内存 256 MiB、进程数 16 和一个 CPU 的配额。这些只是审查起点，不是实测得到的原生程序容量。未来管理器必须建立受保护、root 拥有的祖先目录和控制器委派，仅创建自己的唯一空组，启动前配置并回读限制。应将固定的文件描述符与 `processcontainment.Adopt` 及原子 `CLONE_INTO_CGROUP` 启动集成；不能以移动已经运行的 PID 作为后备方案。任何启动尝试后，都必须通过 KillAndWait 证明整个层级为空，再仅删除本次创建的同一 cgroup。结果不确定时保留所有权并隔离。绝不能删除已有组、回收已复用的 UID、修改管理器拥有的父控制器集合，或以递归删除层级作为回滚方式。

cgroup 证据快照、目录锁、专用 UID 或工作进程私有网络命名空间，都不能建立对宿主路由/解析器的独占控制。这仍是单独的发布阻断项。本工具**未实现**根文件系统所有权、不可变挂载布局、UID 保留和 cgroup 创建；它完成的是制品完整性与配置准备，而不是假装已经安装这些组件。

## 后续 Linux 打包策略

本检查点没有构建或安装软件包。未来 Debian 包必须同时禁止自动启用**和**启动（debhelper 的 `--no-enable
--no-start`），并单独审查升级/卸载行为。不要覆盖管理员改动，也不要自动重启处于隔离状态的后端。单靠预设不能可靠保证默认禁用，因为管理员/发行版的优先级可能覆盖它；systemd 建议集中维护发行版预设策略。本实现不将伪造的 `ExecStart=/bin/true` 或激活标记用作安全边界。

已查阅的一手参考资料：
- [Debian dh_installsystemd](https://manpages.debian.org/testing/debhelper/dh_installsystemd.1.en.html)
- [systemd 预设策略与优先级](https://www.freedesktop.org/software/systemd/man/latest/systemd.preset.html)
- [systemd 执行沙箱](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
- [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)

测试仅使用临时夹具文件和注入故障，绝不运行真实原生工作进程/引导程序、配置用户或 cgroup，也不使用真实凭据。
