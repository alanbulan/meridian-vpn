# Existing macOS L2TP service control (not enabled in the application)

This package implements actual CoreFoundation/SystemConfiguration function
bindings, not a simulated backend. It is an **unintegrated development primitive**,
not a completed VPN backend. It is not called by the GUI or `meridianctl`.

## Scope

- Opens an explicit service identifier, not a display name. Requires an enabled
  service whose interface chain is PPP over L2TP. IDs are limited to 127 ASCII
  alphanumeric/hyphen bytes, leaving a NUL byte in the 128-byte native text buffer. Never creates, edits or removes
  a system VPN profile, installs a helper, requests elevation or writes secrets.
- `StartExistingL2TP` requires explicit authorization for that existing service.
  This includes use of credentials already configured in macOS; the package makes
  no claim that those system credentials are ephemeral or absent from Keychain.
- Refuses a service already connecting/connected/disconnecting. Calls
  `SCNetworkConnectionStart` with NULL overrides and `linger=false` and retains
  the returned native reference. The OS can deny the request.
- Start is asynchronous. `WaitConnected` tolerates initial Disconnected until
  Connecting/Connected is observed; regression to Disconnected after progress is
  a failure. Callers must supply a deadline/cancelable context to bound a start
  that never advances. Progress is retained across waits and Status observations.
- `WaitConnected` observes only the OS's high-level status. **It does not satisfy
  `core.Session.Ready`**: interface/address, route/DNS and intranet verification
  are still absent. A successful start request alone is never Connected.
- Caller must call `Stop` after successful Start, including after a canceled or
  failed wait. Stop uses `forceDisconnect=false`; it cannot forcibly disconnect
  another application's interest. It releases the reference only after observing
  Disconnected. On timeout/error the caller retains the Session and must report
  cleanup uncertainty and may retry Stop. Do not abandon the session silently.
- OS arbitration is not exclusive ownership. A second application may race the
  initial disconnected check or edit a system service. This primitive does not
  create an immutable configuration lease and is not suitable as a security
  boundary against concurrent privileged configuration changes.

The main Engine currently requires per-attempt L2TP password/PSK. Reusing an
existing system service needs a distinct, explicit UI/configuration mode; quietly
mapping a Meridian profile to a similarly named service would be incorrect.
No automatic dispatch has therefore been added.

## Verification

- Platform-independent fake tests cover authorization, identifier validation,
  refusal to adopt active services, failed/canceled start, connected-state polling,
  stop failure, cleanup uncertainty, retry and reference release. Deterministic
  asynchronous status fixtures cover delayed propagation, missed Connecting,
  never-advancing starts, regression after progress, and progress across retries.
- Cross-platform fake bindings test CF ownership, strict service types and the exact
  NULL/no-linger/non-force parameters. These do not exercise a real macOS ABI.
- Intended commands: `go test ./internal/macosvpn`, `go test -race
  ./internal/macosvpn`; the native-wrapper fake tests now run on every platform.
  Cross-compile both supported macOS architectures with `go test -c` (compilation
  is not ABI execution).
- The verified Go 1.27.3 toolchain now runs offline package tests in the editing
  environment. See the dated verification record below. Native framework loading,
  real system configuration, signing/entitlements, route/DNS restoration, crash
  behavior and real gateway connectivity are **not validated**.
- Before integration, run read-only native API checks on the minimum supported
  macOS and an authorized isolated L2TP fixture. Do not run mutation tests in CI
  on ordinary hosts or claim connected state proves complete network readiness.

## Official API references

- [SCNetworkConnection header and ABI](https://github.com/apple-oss-distributions/configd/blob/main/SystemConfiguration.fproj/SCNetworkConnection.h)
- [SCNetworkConfiguration interface APIs](https://github.com/apple-oss-distributions/configd/blob/main/SystemConfiguration.fproj/SCNetworkConfiguration.h)
- [SCNetworkConnectionStart](https://developer.apple.com/documentation/systemconfiguration/scnetworkconnectionstart(_:_:_:))
- [SCNetworkConnectionStop](https://developer.apple.com/documentation/systemconfiguration/scnetworkconnectionstop(_:_:))

The ABI uses `int32_t` connection states, one-byte CoreFoundation Boolean,
pointer-width CFIndex, and opaque CF pointers. Frameworks are loaded only on an
explicit call, from absolute Apple system framework paths. No Go callbacks are
registered. This needs execution on macOS to validate beyond source inspection.

## Read-only service-to-interface evidence slice

`Session.InspectInterface` now performs a concrete native read path:

1. Confirm this retained connection is Connected and not stopping.
2. Read `SCNetworkConnectionCopyServiceID` and require the exact requested ID.
3. Read assigned IPv4 addresses from `SCNetworkConnectionCopyExtendedStatus`.
4. Read only `State:/Network/Service/<ID>/IPv4` from SCDynamicStore; extract its
   InterfaceName and Addresses using CF type checks and bounded arrays/strings.
5. Require equal nonempty IPv4 address sets, a `ppp<number>` interface, and a real
   `net.InterfaceByName` with a positive index, Up + PointToPoint flags and all
   those assigned addresses. Private IPv4 addresses are valid; loopback,
   unspecified, multicast, broadcast, link-local and IPv4-mapped IPv6 are rejected.
6. Recheck Connected after inspection. Return interface evidence, not Ready.

This is read-only; it never queries credentials or returns raw native dictionaries.
It currently covers IPv4 only. The reads are **not atomic**: a reconnect between
status samples, stale configuration or interface name/index reuse can escape the
checks. It neither proves exclusive ownership nor validates routes, DNS, traffic
flow, IPv6 policy, tunnel identity over time or cleanup. Do not connect this method
straight to `core.Session.Ready`.

Fake tests cover mismatched service/address/interface data, missing/down/non-PPP
interfaces, invalid CF types, oversized arrays, CF ownership/release, disconnected
state during inspection, rejection after Stop, and serialized Inspect/Stop calls.
These fake tests run on Linux without Apple frameworks. Real Apple API execution
remains untested; passing injected bindings does not validate the native ABI.

Official references:
- [Extended status schema](https://developer.apple.com/documentation/systemconfiguration/scnetworkconnectioncopyextendedstatus(_:))
- [Dynamic store API](https://developer.apple.com/documentation/systemconfiguration/scdynamicstore-gb2)
- [Apple schema constants and value types](https://github.com/apple-oss-distributions/configd/blob/main/SystemConfiguration.fproj/SCSchemaDefinitions.h)

## Remaining bridge design gates (not implemented)

- Introduce an explicit "existing macOS system service" profile mode, with a
  selected service ID and a review of its gateway/configuration. Do not reuse the
  per-attempt L2TP password/PSK mode, infer identity from display names, silently
  ignore profile options, or fetch saved secrets into Meridian.
- Bind a session generation to service ID, PPP connection time and interface
  identity, and revalidate the user-approved non-secret configuration around
  activation. Document which concurrent changes can and cannot be excluded.
- Read actual kernel routing state and compare only the expected tunnel policy.
  Declared route settings in SystemConfiguration are not installed-route proof.
- Read service DNS configuration and validate relevant effective resolver
  selection. A populated DNS dictionary is not proof that domain queries select
  it; a successful generic DNS query can be satisfied outside the VPN. Do not
  claim DNS-leak prevention from these observations.
- Before activation capture a bounded baseline for service-owned network state.
  After non-force Stop, require disappearance of this session's service/interface
  state and attributable route/DNS changes. Do not overwrite a global baseline:
  Wi-Fi changes, another VPN and other apps may legitimately alter the network.
  Ambiguous ownership, stale state or another application's retained interest
  must result in cleanup uncertainty, not force-disconnect or global rollback.
- Only after those contracts are established, implement a core Adapter with
  bounded startup/stop, single Ready/Done publication, cancellation, continuous
  generation-aware observation and CleanupFailed mapping. Its UI must disclose
  existing system credential usage and the limited verification guarantee.
- Validate on authorized isolated macOS hosts: real API ABI, supported OS versions,
  delayed state propagation, concurrent system changes, adapter reuse, route/DNS
  recovery and real gateway traffic. Compilation/fixtures cannot replace this.

### Additional verification gates

Native SystemConfiguration and `net.Interface` reads are synchronous. They have
no cancellation/context deadline and execute under the Session mutex, so a slow
read can delay Stop. A caller context does not bound these native calls. Designing
and verifying a bounded, cancellation-safe inspection/stop path is a production
integration gate; the current primitive makes no bounded-native-call claim.

Additional fake tests inject failures at Copy/Create allocation/read stages and
compare every acquired CF reference against every release, including failures
while reading dictionaries/arrays. Boundary fixtures cover 127/128-byte native
strings and service IDs, empty/negative/16/17-element arrays, bad IPv4 values,
duplicates, and 15/16-byte PPP interface names. These fixtures are now executed in the offline checks below; none exercises a
real system service.

## Read-only selected-service diagnostic

`InspectExistingService(ctx, serviceID)` reads one enabled PPP-over-L2TP service,
without starting, stopping or adopting it. It takes two fresh configuration samples and
extracts only the configured gateway (`CommRemoteAddress`), explicit PPP
`AuthProtocol` values and IPsec `AuthenticationMethod`. Missing/implicit defaults
are rejected as incomplete rather than guessed. These fields are a **partial
allowlisted summary**, not an activation policy or complete configuration hash:
scripts, routing, DNS, authentication details and other unreported settings remain
unverified. The function never extracts passwords, shared-secret values, account
names, certificate contents or Keychain items; native configuration dictionaries
can nevertheless contain secret fields in native memory. Do not describe this as
proof that no credential-bearing memory was touched.

For an already Connected service, it correlates the existing interface evidence
with a positive integer PPP `ConnectTime` before and after the inspection. It
rejects transitions and observed configuration, status or connection-time drift.
It releases only its read reference, without taking a connection interest or
stopping someone else's service. Disconnected services return no generation.
A `ConnectTime` sample is not a unique session token: same-tick reconnects, stale
state and changes that revert between reads can escape detection. Native interface
name/index reuse and changes outside the allowlist are not excluded. The result
must not authorize activation, imply ownership or publish `Ready`.

The call has a fixed number of reads and bounded output. `ctx` is checked between
backend operations, but cannot interrupt synchronous native calls; it is **not a
wall-clock timeout guarantee**. No detached worker is left holding native objects.
All CF text used by this package is now length-checked ASCII, rejecting embedded
NUL truncation rather than accepting a misleading prefix. Fake native tests cover
allowlisted reads, CF ownership/failure paths, type/length/NUL errors and strict
integer generation conversion. Platform-independent tests cover drift, incomplete
evidence, cleanup and cancellation. These are diagnostic fixtures, not live ABI,
entitlement, protocol, routing/DNS or real-network validation. GUI/CLI activation
remains disabled and the production integration gates above still apply.

## Offline verification, 2026-11-04

The parsing, ownership and validation wrappers are now platform-independent; only
framework loading and symbol binding remain Darwin-specific. Fake CF references
and injected functions run unchanged on Linux, rather than being trapped behind
a Darwin build constraint. No fixture loads an Apple framework or reads/changes
an actual VPN profile, credential, interface, route or DNS configuration.

Verified locally with official SHA256-checked Go 1.27.3 on Linux amd64:

- `go test -count=1 -json ./internal/macosvpn`: 128 passing tests/subtests, including
  native-wrapper allocation failures, strict CF types, ownership and diagnostic
  generation checks.
- `go test -race -count=1 ./internal/macosvpn`: passed.
- `go vet ./internal/macosvpn`: passed.
- `go test -count=1 ./...` and `go vet ./...`: passed across the repository
  (default unit suites only; environment-gated integration tests are not enabled).
- `GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go test -c ./internal/macosvpn`: passed.
- `GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go test -c ./internal/macosvpn`: passed.
- `GOOS=windows GOARCH=386 CGO_ENABLED=0 go test -c ./internal/macosvpn`: passed,
  checking that the portable wrapper types do not impose Darwin pointer width.

Cross-compiled binaries were not executed. These checks do not establish native
Darwin ABI correctness, usable signing/entitlements, network readiness or real
VPN connectivity. Activation stays unintegrated and disabled.

## 原生只读 ABI 与服务预检

新增的 `integration/macos-preflight` 提供独立进程中的原生 ABI 验证，并可在用户明确选择服务后执行只读服务预检。它不会启动或停止 VPN，不把系统状态或预检通过映射为 `Ready`。原生测试默认跳过；专用运行器要求全部指定测试确实通过，拒绝用跳过、交叉编译或部分日志替代原生执行证据。详见该目录的中文说明。

该进程边界仅用于只读检查。应用尚未接入生产连接工作进程；原有激活、路由/DNS、会话归属、清理、签名和真实网关验收门槛仍然有效。

## 明确选择现有服务的受控适配器（实验阶段）

`NewExistingServiceAdapter` 提供实际 Apple API 的受控入口，不是 `core.Adapter`，也没有接入普通 GUI 连接按钮。创建适配器本身不会加载框架或操作系统网络；`Select` 只读检查调用方明确给出的服务 ID，要求服务当前断开、显式 MSCHAP2 和 SharedSecret 配置。返回的选择凭据属于该实例且仅可使用一次，结构体值拷贝不能绕过消费状态。允许字段不是完整配置锁，未覆盖字段仍可能改变。

`Connect` 必须同时得到本次系统网络更改、使用系统已保存凭据、共享系统服务、有限验证范围四项明确授权；不会把普通密码/PSK 配置自动转换成该模式。开始前再次核对所选配置和断开状态，然后通过 `SCNetworkConnectionStart(NULL, linger=false)` 保留本应用的服务兴趣。等待与系统调用串行，取消不会将尚未返回的原生调用丢给后台线程。

系统报告连接后，适配器借用保留的同一个原生引用，检查配置、PPP ConnectTime、服务 ID、PPP 接口、接口索引与 IPv4 地址，并保留首个观测代际。借用检查不释放活动连接引用。返回的 `SystemConnected` 仅说明已观察到系统状态；`RouteDNSIPv6Verified` 始终为 false。该 API **不会发布 Ready**，也不是可信流量通路。后续调用 `Check` 发现配置、状态或代际漂移会尝试撤销本应用兴趣。没有后台持续观测，调用方不能把一次结果当作持续有效。

`Stop` 使用非强制断开，不删除系统服务或凭据。成功退出原生会话后另行确认服务已断开，返回 `InterestReleased` 和 `ServiceDisconnected`；`NetworkRestored` 始终为 false，不承诺全局路由或 DNS 恢复。检查失败、共享连接仍存活、未知启动结果或原生清理失败时保留隔离状态，拒绝重连。已释放兴趣后只重试只读确认，不重复撤销。调用方必须保留仍活动或清理不确定的适配器，进程崩溃恢复尚未实现。

上下文为阶段之间的等待设置期限；同步 Apple API 本身不可被该机制强制中断。Connect 的等待上限为90秒、Check 为10秒、清理等待为30秒，**不是硬性墙钟超时保证**。本轮只运行注入单测，没有通过该适配器执行真实连接/断开；生产整合仍取决于路由、有效 DNS、IPv6、退出恢复、并发系统修改与隔离真实网关验收。

如果等待、观测或停止的原生边界发生 panic，适配器将该会话标记为不可重入并保留隔离；不会把恢复 Go panic 误认为原生调用已安全完成，也不会立即再次进入可能仍持锁的 Session。该情况必须报告清理不确定，不能自动重连。普通返回的清理错误仍可按既有规则重试；panic 与普通错误有不同恢复边界。

## 独立策略证据与 core 生命周期桥接（尚未启用）

新增 `ExistingCoreAdapter` 实现 `core.Adapter`/`core.Session` 契约；普通密码/PSK 模式不变，新模式标识为尚未加入 Engine 的 `macos-system-l2tp`。测试验证先记录基线、受控连接、验证路由/DNS/IPv6与连接代际、再发布 Ready，随后持续检查，失败则撤销本应用兴趣并验证清理。生产策略验证器明确返回不可用，因而生产入口在调用系统连接前失败关闭。只有内部注入测试可满足完整证明，不能以测试通过宣布 VPN 已可用。

`ReadKernelRoutes` 通过固定只读 sysctl 获取有界内核路由表，严格解析 IPv4/IPv6、作用域和接口；`ReadDNSConfiguration` 运行固定 `/usr/sbin/scutil --dns`，限制时间、输出字节与解析字段，不发送 DNS 查询，不记录原始输出。解析器配置不等于实际查询使用的解析器，更不能证明应用专用 DNS、加密 DNS 或 IPv6 无旁路。

`ReadNetworkPolicySnapshot` 两次读取并比较稳定的规范化摘要；不是原子快照，也不排除两次之间发生再恢复的修改。`CompareNetworkRestoration` 只证明所表示路由与解析器字段相等，`CompleteCleanupVerified` 始终为 false；未表示的路由指标、每应用策略、防火墙、接口残留及变更归属尚无完整证明。绝不通过覆盖整个旧配置来“恢复”他人的并发变更。

原生读回专用测试必须显式设置 `MERIDIAN_MACOS_POLICY_READBACK=1`，仅在候选 CI 中读取当前 runner 路由和解析器，不启动/停止服务。默认单测使用注入数据。同步 Apple 调用仍不能硬中断；core Stop 超时返回清理失败并保留执行者，清理重试也有等待上限，绝不并发重入尚未返回的清理调用。

## 指定目的地址的内核选路验证

`LookupDestinationRoute` 不从路由表自行猜测最佳路径，而是通过固定 `/sbin/route -n get -inet/-inet6 数值地址` 取得内核 RTM_GET 的最佳匹配，核对完整输出及实际接口索引。拒绝主机名、作用域地址、多播、未指定地址和任意命令选项；不接受 `-ifscope`，避免强制期望接口掩盖正常选路旁路。子进程输出上限16 KiB、等待期限3秒、管道收尾1秒；警告输出、缺字段、未知格式、地址不匹配均失败关闭。同步接口索引读取仍不具备硬性墙钟中断保证。

`VerifyDestinationRoutes` 最多核验16个明确目的地址，将 IPv4/IPv6 内核结果与已有 PPP 代际中的接口名和索引绑定，拒绝 down/reject/blackhole/condemned/local/broadcast/multicast 结果。持有原生会话的调用方仍必须在前后重新核实代际。结果只证明这些目的地址的无接口提示内核查询匹配，`CompletePolicyVerified` 始终为 false；不能推广到整个 CIDR、指定源地址/接口的流、每应用 NECP 策略或真实包传输。

Apple 的 [route 源码](https://github.com/apple-oss-distributions/network_cmds/blob/main/route.tproj/route.c) 将 get 映射为 RTM_GET，[XNU rtsock.c](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/rtsock.c) 的该分支执行 rt_lookup 并报告结果，非路由增删。`-n` 禁止符号名称解析。CI 仅查询 IPv4/IPv6 回环地址，不发送 IP 包、DNS 请求，不启动或停止 VPN。

### 生产保证仍缺少的边界

Apple 的 [VPN 路由说明](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic) 明确普通默认路由可受更具体路由及应用接口选择影响。Network Extension 的策略强制机制属于另一种受控配置，不能凭现有 L2TP 服务读取结果宣称相同保证。

[Network 连接解析报告](https://developer.apple.com/documentation/network/nwconnection/establishmentreport/resolution) 只覆盖对应连接，可能使用缓存，其目标端点不等于 DNS 服务器身份；[加密 DNS](https://developer.apple.com/videos/play/wwdc2020/10047/) 可按应用/连接配置。系统解析器快照不足以证明全部查询去向。指定 DNS 服务器被绕过与加密 DNS 的传输绕过隧道是不同问题，不能混为同一保证。

[SCNetworkConnection 官方头文件](https://github.com/apple-oss-distributions/configd/blob/main/SystemConfiguration.fproj/SCNetworkConnection.h) 明确 Start/Stop 是共享兴趣仲裁，`linger=false` 不是独占租约，Stop(false) 成功不保证其他应用已释放兴趣。当前阶段不承诺全局独占或完整整机恢复。需进一步约定有限的产品保证、独立策略强制方案及获授权的真实网络验收，不能仅凭读回给生产 Ready 放行。

## 显式有限现有服务模式

新增 `NewLimitedExistingCoreAdapter` 是独立入口，不启用前述完整策略验证构造器。`macos-system-l2tp` 与普通密码/PSK `l2tp` 分开；四项同意、选中服务、期望网关和1–16个数值目标必须明确，拒绝空目标。系统服务已连接、选择被使用、配置漂移或范围不匹配均拒绝。本模式不接收密码、PSK、证书或代理参数，不修改系统服务配置。

Ready 只表示系统报告所选服务已连接、可信 PPP 接口/地址证据存在，且全部指定目的地址的内核路由匹配该接口。每轮目标查询前后重新核对同一保留连接引用的代际，连接期间持续检查。Engine 的 `VerificationScope=system-service-target-routes` 与界面文案始终明确有限保证；严格构造器及其他协议的既有契约不变，有限后端/会话不能替代普通协议。

清理只撤销自身兴趣，确认所选服务断开，并确认已观察的 PPP 接口名/索引及指向该索引的路由不残留。接口身份复用、共享连接仍存在、读取失败或未返回原生调用均保留清理失败，不覆盖整机基线，不强制断开其他使用者。未观察到有效接口代际的失败尝试，只确认自身兴趣与所选服务状态，不声称完成整个系统恢复。同步原生调用无法被硬中断，Stop 的等待期限不等于杀死原生执行者。

GUI 在 macOS 设置页提供专用入口：先只读检查，再逐次同意并连接。目标/网关/服务变化、离开页面、取消或提交一次尝试后清除授权；此入口不自动保存配置或凭据。专用 `meridian-macos-service` 前台工具也要求明确参数及四项许可，帮助/默认调用完全不启动连接。真实网关互通、企业部署与签名公证仍未验收；测试只使用注入连接，原生 CI 只执行只读检查。
