# Windows RAS adapter: implemented boundary and remaining work

## Status

`internal/windowsvpn` is a portable, injected RAS lifecycle controller, **not a
working Windows VPN backend**. It is not wired into the desktop/engine. There is
no native dialing/cleanup driver, no default system driver, and no network-capable command
runner. Calling `New(nil).Start(...)` reports unavailable. Existing Windows
capability reporting must continue to say that a VPN backend is unavailable.

The package implements the parts that can be exercised without changing a real
machine: bounded input policy, separate per-attempt consent for network changes
and PSK storage, caller-owned secret preservation and temporary-copy erasure,
serialized single-session ownership with independently accessible cancellation,
rollback after partial failures, fresh
connection identity/interface/address validation, independent cleanup contexts,
and cleanup retry with reconnect blocked until confirmation. Injected driver
errors are redacted rather than passed into UI/logs. It does not claim interface
validation proves route/DNS correctness or leak prevention.

Lifecycle tests use an in-memory driver; discovery/property tests inject fake
API functions, and SDK checks compile declarations only. None are real RAS
operation tests. The
controller is intentionally separate from `core.Adapter`: integrating it before
implementing the native contract and additional consent would misrepresent the
current capability. Any future bridge must reject unsupported profile options,
not silently discard Linux-specific IKE/ESP/MRU, certificates or proxy fields.

## Protocol and credential boundary

Only L2TP/IPsec with MSCHAPv2 is represented by this contract. It provides no
UniVPN, AnyConnect, proprietary SSL, national-cryptography, or vendor compliance
support. Password/PSK are byte slices, never profile fields or command arguments.
The supported inputs are UTF-8, bounded to the corresponding restricted UTF-16
credential lengths. Configure borrows only the PSK; Dial borrows only the password. Both calls
must finish or cancel every native consumer and erase their conversion buffers
before returning. The controller erases each supplied slice immediately after
that stage (and all copies before failure cleanup). Drivers must not retain a
password copy between stages, cache it in Windows, or retain it for reconnect.
Driver buffers must also be erased after use. Erasing Go
slices is best-effort hygiene, not a guarantee against process-memory inspection.

Windows RAS `RasSetCredentials` stores credentials associated with a phonebook
entry. Its PSK route therefore cannot be advertised as memory-only. The native
implementation must require a separate, explicit storage grant before setting
a PSK; ordinary route/DNS permission alone is insufficient. It must attempt PSK
removal at cleanup and disclose that a crash or power loss can leave a key
stored. Do not bypass Windows privilege checks or elevate silently.

Stop requests cancellation without waiting for the operation-serialization lock.
It then waits for the canceled driver operation to return before cleanup, so
cleanup never races native credential consumers. A driver that ignores context
cancellation violates the contract; the controller cannot safely kill arbitrary
in-process native code. Concurrent stop requests prevent a new operation from
starting until all queued cleanup requests have finished.

## Required native-driver contract

1. Reserve an unpredictable per-attempt identity without mutating Windows.
   Configure must exclusively create an owned phonebook entry, refusing an
   existing entry. Never edit, adopt or remove the user's other VPN profiles.
2. Use a version-correct Windows SDK binding to RAS APIs. Do not use `rasdial`
   with a plaintext password, command interpolation, environment secrets, or
   PowerShell script source containing credentials. Select only supported
   L2TP/IPsec and MSCHAPv2 flags; do not fall back to weaker authentication.
3. Store only the authorized per-entry PSK. Supply password through the native
   dial API without saving it. Use explicit identity rather than an ambient
   login credential fallback. Obey deadlines and handle partial dial results.
4. Verify the returned RAS handle, owned entry, connected state, interface and
   projected address. Native status-query success alone is not connection
   success. Check both function status and the connection error field.
5. Hang up only the owned handle. Wait for termination confirmation before
   clearing secrets and removing the owned entry. `RasHangUp` returning success
   alone does not prove termination. Retain uncertain cleanup for retry and
   block reconnect. No unconditional deletion of unrelated entries.
6. Before desktop wiring, add a bounded status monitor, core session channel
   integration, Windows storage-consent UI, crash recovery with ownership proof,
   native architecture builds, and authorized real Windows acceptance tests.

Real dialing remains blocked on audited dial/connection/credential ABI
bindings, native lifetime implementation, and Windows runtime acceptance. The
read-only property/layout slice below addresses discovery, not those operations. A Windows-only cgo binding could use official SDK structure definitions,
but would require a deliberate exception to the project's CGO-disabled release
policy. A pure-Go binding instead needs audited ABI sizes/layouts on every
supported architecture. Neither option should be represented as complete based
on portable mock tests.

## Authoritative references

- [RasSetCredentials and stored credentials / PSK permissions](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rassetcredentialsa)
- [RasHangUp and termination confirmation](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rashangupa)
- [RasGetConnectStatus and connection error status](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasgetconnectstatusw)

## Reproducible checks

With the project's supported Go toolchain, run:

```sh
go test -count=1 ./internal/windowsvpn
go test -race -count=1 ./internal/windowsvpn
go vet ./internal/windowsvpn
```

These commands do not create phonebook entries, persist actual credentials,
load RAS, alter routes/DNS, or contact a gateway. Their results must be recorded
separately from target-platform runtime and real-tunnel acceptance.


## Native read-only discovery slice

`EnumerateSystemEntries` now has a real Windows `RasEnumEntriesW` binding.
It loads Rasapi32 from the directory returned by the KnownDLL kernel32, only
when explicitly invoked, caches the DLL/procedure resolution (including failure)
once per process, and enumerates current-user and all-user phonebook
entries. A DLL-resolution failure remains fail-closed until process restart.
It returns entry name, phonebook path and raw scope flags; it never
reads saved credentials. A path is retained internally to distinguish duplicate
names across phonebooks, not for logs or telemetry. Entry names and paths can
contain personal or organization information; do not automatically persist,
export or display them outside the explicit local selection workflow. These entries may be dial-up
or otherwise unsupported; discovery is not a compatibility check or connection
permission. No user-interface or CLI path invokes it yet.

The boundary validates the pointer-free RASENTRYNAMEW ABI, limits buffer size
and retries, and rejects malformed counts, unterminated strings, and invalid
UTF-16. Tests use an injected enumeration function, including ABI layout tests
on the target runner. No test loads the real DLL or reads a user's phonebook.
Native calls are not claimed tested until Windows acceptance is performed.
Loading RAS can cause Windows to start its Remote Access Connection Manager
service; read-only here means no dialing, phonebook edits, or credential calls,
not a guarantee of zero OS service activity.

Sources:
- [RasEnumEntriesW](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasenumentriesw)
- [RASENTRYNAME layout](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa377267(v=vs.85))
- [RAS service and connection operations](https://learn.microsoft.com/en-us/windows/win32/rras/ras-connection-operations)

## Borrowing an existing user-configured connection: remaining blockers

Using an already configured L2TP profile could avoid a new PSK storage request,
but it must not reuse the owned-entry cleanup contract above. A separate borrowed
profile mode must never clear credentials, edit the profile, or delete it. The
user must choose the exact phonebook/entry and explicitly authorize using its
configured identity and changing the network.

There are unresolved correctness requirements before implementing dialing:

- `RasDial` can reference an already connected entry rather than create a new
  connection. Every successful reference needs its matching release. Observing
  a connection beforehand does not prevent another process racing to create it.
  Waiting for the entire shared handle to disappear can incorrectly report
  cleanup failure, while repeatedly hanging up could disconnect another owner.
  This needs an ownership/reference state machine and target-system tests, not
  a broad `rasdial /disconnect` fallback.
- The read-only slice below implements strict protocol, gateway, authentication
  and custom dialer/script checks through `RASENTRYW`, with SDK layout checks.
  Native API acceptance is still pending. A future dialer must revalidate
  identity around operations and close the configuration/connection race;
  neither entry enumeration nor a metadata snapshot is safe-to-dial proof.
- Do not assume omitting `RasSetCredentials` proves that a successful dial cannot
  update a credential cache. The saved-credential behavior and current OS policy
  need verification. Do not read or clear existing secrets to test this. If a
  no-persistence guarantee is unavailable, disclose and obtain a specific grant
  or decline the operation. Do not silently use ambient Windows logon secrets.
- Async native cancellation must preserve callback and credential buffer
  lifetimes until every native consumer has finished. A detached Go goroutine
  wrapping a synchronous RasDial call is not safe cancellation.

Sources:
- [RasDial reference semantics, asynchronous operation, and error cleanup](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasdialw)
- [Stored-credential semantics](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rassetcredentialsw)
- [RAS dial extensions and custom scripting](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa377029(v=vs.85))

Required acceptance environment: supported Go toolchain plus Windows amd64
runner for compilation/ABI tests; then an explicitly authorized isolated Windows
machine with a disposable user-configured L2TP/IPsec entry and test gateway.
Test no saved password, saved password, connection already active, concurrent
external dialing, cancellation at each phase, service errors, and route/DNS
recovery without altering unrelated profiles or credentials. Do not request
real secrets in chat. No real dialing or system changes were performed here.



## Read-only existing-profile validation slice

`InspectSystemEntry` now reads the exact selected phonebook and entry with
`RasGetEntryPropertiesW`. It requires an explicit local fixed-drive `.pbk` path
and a separately supplied intended gateway. It rejects observed reparse points
in every path component; a concurrent filesystem replacement remains a race.
Before native calls, every path component rejects U+0000–U+001F characters and
Win32 device aliases, including extension-bearing and superscript-digit names
such as `NUL.pbk` and `COM¹`. Spaces before a device-name extension and the
console aliases `CONIN$`/`CONOUT$` are conservatively rejected as well. These
lexical restrictions follow Microsoft's [file naming rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
and do not establish atomic file identity or eliminate path-replacement races.
It never chooses a default entry,
reads credentials, edits/deletes a profile, or calls `RasDial`. A name/path match
is not ownership: `EntryEvidence` cannot be used by the owned-entry controller.

The narrow allowlist requires VPN type, L2TP-only (no fallback), PPP/IP,
MSCHAPv2-only, PSK mode, and required encryption. It rejects alternate targets,
multilink, scripts, custom dialers/authentication, prerequisite connections,
ambient-logon options, credential-cache/automatic-reconnect flags and unknown
options. Gateway comparison accepts equivalent IP spellings and case-insensitive
DNS names, without DNS lookup, preserving the absolute trailing-dot distinction
and rejecting ambiguous legacy numeric IPv4 forms. Unsupported or ambiguous profiles fail closed;
these checks do not promise compatibility with every Windows-created profile.

The opaque snapshot retains the entry's read-only GUID and complete fixed
properties. `RevalidateSystemEntry` rereads the exact selection and rejects
observed replacement or configuration drift, including route/DNS properties.
This is **not an atomic lock or a safe-to-dial certificate**. It cannot close a
change-after-read race, prove an existing PSK is usable, validate global IPsec
policy, or prove that a later dial will not update credential caches. The
borrowed-handle lifetime, independent connection verification and native
cancellation requirements above remain open. No production dialing is enabled.

The pointer-free Windows 10 `RASENTRYW` layout is checked by Go fake-reader tests
and compile-only assertions against the installed Microsoft Windows SDK on x64
and x86 CI. Windows 386 fake tests also execute under the x64 runner's WOW64
support, while Windows arm64 Go packages are compile-only; arm64 SDK/native-
runtime acceptance remains unverified. The tests exercise
buffer growth/error bounds, malformed UTF-16, protocol/target rejection and
identity/configuration drift. They never load RAS or read a real phonebook.
SDK compilation checks layout and constants, not actual native API behavior.

Sources:
- [RasGetEntryPropertiesW and explicit phonebook/entry buffers](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasgetentrypropertiesw)
- [RASENTRY fields, protocol fallback and read-only GUID](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa377274(v=vs.85))
- [Microsoft SDK RAS declarations](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/Ras.h)


## Read-only existing-connection evidence slice

`ObserveSystemConnections` now binds `RasEnumConnectionsW` and
`RasGetConnectStatusW`, but does not expose their handles or acquire any RAS
reference. It accepts only an opaque, previously validated entry snapshot,
revalidates that profile before and after observation, and compares two bounded
connection enumerations. Matching requires the exact phonebook/name and entry
GUID, with stable handle, device, scope flags, logon LUID and connection
correlation GUID. Status checks verify both the API return code and `dwError`,
connected state, device identity and the reported dialed target. Ambiguous
identity, malformed data, partial errors, appearance/disappearance and observed
handle reuse fail closed. Unrelated connection status is not queried.

**Every snapshot blocks dialing.** `ConnectionSnapshot.DialBlocker()` returns
an existing-connection blocker if any matching connection was observed and an
exclusivity-unproven blocker otherwise, including for a zero-value snapshot.
It does not return a reference count, ownership token, cleanup lease, readiness
claim or permission. Windows enumeration cannot list a connection as active
until RAS has connected successfully, so an external in-flight dial may be
invisible. A connection can also appear after the last read. Repeating reads
cannot establish atomic exclusion. `RASCF_OwnerKnown`/`RASCF_OwnerMatch` are not
proof that this process created or owns a connection. An enumerated handle must
never be passed to `RasHangUp` merely because it was observed.

The wrapper loads only enumeration/status procedures and performs no dialing,
hangup, credential read/write, profile creation/edit/deletion or network changes.
No application entry point invokes it. Loading RAS can still start its service.
No actual RAS procedure is executed by the tests; the Windows runner uses fake
functions and compile-only SDK assertions. Synchronous native query duration
and real system behavior remain unverified; allocation/retry bounds are not a
native API cancellation guarantee.

`RASCONNW` uses four-byte SDK packing even on x64, where its pointer sits at
byte offset four. The implementation decodes it from aligned word storage
rather than using a naturally aligned Go `uintptr` struct. Fake tests cover
both pointer layouts and malformed buffers. Microsoft SDK assertions check
x86/x64 connection/status sizes, field offsets and enum constants; Go Windows
386 fake tests execute under WOW64; arm64 is compile-only. Both remain
separate from real RAS runtime acceptance.

Sources:
- [RasEnumConnectionsW, including the in-flight visibility limit](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasenumconnectionsw)
- [RasGetConnectStatusW and distinct API/connection errors](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasgetconnectstatusw)
- [RASCONN entry and correlation identities](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa376725(v=vs.85))
- [RASCONNSTATUS fields](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa376728(v=vs.85))
- [RasDial reference semantics](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasdialw)

## Private-phonebook dialing design: unresolved isolation and credential gates

A per-attempt random entry and private phonebook are candidates for avoiding
accidental collision with existing user profiles, **not proof of exclusive RAS
ownership**. Do not enable a native driver from the following proposal alone.

- Create a fresh namespace with `CREATE_NEW`, an explicit protected DACL,
  noninheritable handles and verified filesystem identity. `CREATE_NEW` protects
  the initial file creation only. `RasSetEntryProperties` updates a same-named
  entry if one exists; a preceding name check is not atomic create-only.
- A user-SID DACL or logon SID does not isolate this process from other processes
  with the same token. A service-specific security principal and service-owned
  directory may provide a stronger boundary, but secure service installation,
  token/IPC validation and RAS compatibility have not been implemented or
  verified. Do not silently elevate, install a service, or widen an ACL.
- A no-sharing file handle prevents subsequent opens even by the same process.
  RAS takes a path rather than the application's existing file handle, so an
  exclusive `CreateFile` handle cannot simply be assumed compatible with it.
  Relaxing sharing or closing the handle would reopen the race. RAS's actual
  read/write/replacement needs must be validated before claiming a lock.
- The official `RasSetEntryProperties` documentation still warns that an
  explicit phonebook argument may not be supported after Windows XP, and gives
  additional all-users path restrictions. This is a compatibility uncertainty
  to resolve on each supported Windows version, not evidence of universal
  failure or permission to fall back to the user's default phonebook.
- A private PBK is not a documented credential-storage sandbox. Microsoft
  describes saved connection information from successful `RasDial` calls.
  Clearing `RASEO2_CacheCredentials` and setting `RASEO2_DontUseRasCredentials`
  are defensive settings, not a universal no-save guarantee; the latter is
  specifically about credentials used to access other network resources.
- The documented L2TP PSK route is `RasSetCredentials(RASCM_PreSharedKey)`.
  `RASDIALPARAMS` has no separate session-only IPsec PSK input, and no documented
  blanket no-save flag was found in `RASDIALEXTENSIONS`. Existing owned-entry
  PSK storage consent therefore remains necessary; a password no-persistence
  promise also needs evidence or a revised, explicit storage contract.
- Deleting an entry or PBK does not establish that every credential store was
  cleared. Masked credential clearing and separate PSK clearing are distinct
  operations with possible privilege/errors/crash leftovers. Logical clearing
  is not a secure physical-erasure guarantee. Never probe or clear the user's
  existing saved credentials as an experiment.

Before any production dial: prove namespace isolation and actual native
identity; validate the intended target, protocol and authentication; establish
credential/storage semantics; implement bounded asynchronous cancellation and
native buffer/callback lifetimes; then verify route/DNS restoration and crash
recovery on an explicitly authorized disposable Windows setup. Current CI does
none of these real network/credential operations.

### One-reference release ledger (injected only)

`dialReference` now models a single future native call's direct return. It is
unexported, has no native implementation and is not wired to the controller.
It stores no password, PSK or phonebook path. An enumerated or callback handle
must never be recorded as a newly acquired reference. Native result provenance
is an unresolved integration requirement, not something this ledger proves.

Wrapper copies share one ledger, and a zero-value ledger rejects operations.
Retain exactly one constructor result per direct native invocation; making two
independent ledgers for the same result would violate the integration contract.
The first result is immutable. A nonzero handle creates one release obligation,
even if the dial return code is an error. A duplicate/misrouted result cannot
replace that handle and taints cleanup consideration. The ledger consumes its
one release attempt before invoking the injected function, so concurrent Stop,
retries, a failure result or an uncertain/panicking boundary cannot hang up the
same reference twice. A nil boundary, before any call, does not consume it.

Successful hangup is not termination. Subsequent read-only probes remain
pending until the status API returns `ERROR_INVALID_HANDLE`; a successful query
or a disconnected state is insufficient. Errors, a still-shared/reused handle,
or uncertain hangup keep cleanup blocked. The ledger never repeats hangup to
force another owner's reference to disappear. A failed hangup is quarantined,
not automatically retried. Native query cancellation is not implemented.

Confirmed reference termination is only an ordering prerequisite: a future
implementation must separately establish native consumer quiescence and fresh
object ownership/identity before clearing credentials or deleting its objects.
No deletion/credential capability is exposed here, and a null-handle failure
does not infer callback quiescence. Private-phonebook exclusivity, password
persistence, PSK storage, and actual native dialing remain blocked.

Sources:
- [CreateFile creation and sharing semantics](https://learn.microsoft.com/en-us/windows/win32/fileio/creating-and-opening-files)
- [RasSetEntryProperties create-or-update and compatibility notes](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rassetentrypropertiesw)
- [Access tokens and shared user security context](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [Service-specific SIDs](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info)
- [Saved dial information](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasgetentrydialparamsw)
- [Credential/PSK storage and clearing](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rassetcredentialsw)
- [RasDial direct-result and reference obligations](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasdialw)
- [RasHangUp asynchronous termination](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rashangupw)
- [RasDeleteEntry scope](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasdeleteentryw)

### Dial parameter marshalling (offline, injected only)

`withDialParameters` prepares four-byte-aligned `RASDIALPARAMSW` storage and an
explicit phonebook path for a synchronous injected consumer. The Windows 10
layout includes the Windows 8+ `szEncPassword` pointer; its x86/x64 size and every
field offset are asserted against the installed Microsoft SDK in CI. Native
arm64 ABI acceptance remains unverified; its Go test binary is compile-only.

The boundary rejects missing entry/path/user/password, malformed UTF-8, embedded
NUL/CR/LF, field-length overflow, and `*` as a saved-phonebook domain selector.
An empty domain deliberately means the remote server's domain. All override,
callback, subentry, interface and encrypted-password fields remain zero. No PSK
or saved-credential API is involved. This does not prove that a future native
dial cannot persist credentials or that an opaque saved-password token cannot
be interpreted specially by RAS; native credential semantics remain a gate.

The password is encoded directly from bytes into mutable UTF-16 storage without
an immutable string or intermediate rune slice. All owned buffers are cleared
after the injected consumer returns, errors or panics; the caller's password is
unchanged. The consumer must not retain buffers or start asynchronous work.
**Do not pass this scoped buffer to asynchronous RasDial:** its immediate return
does not establish consumer quiescence. This package neither loads nor calls a
dial API, and marshalling grants no network permission, profile ownership or
readiness. Future native lifecycle integration must establish independent
callback/buffer lifetime, cancellation and profile-revalidation contracts.

References: [current SDK declarations](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/Ras.h),
[parameter semantics](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa377238(v=vs.85)),
and [asynchronous RasDial lifetime](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasdialw).

### Callback routing and trampoline (no dialing)

An unexported callback router now provides bounded scalar notification mailboxes:
at most 32 registrations and 16 queued events per registration. Its nonzero
integer callback IDs are never reused, including after retirement; machine-word
ID exhaustion blocks registration permanently. Overflow faults the attempt and
discards queued observations instead of silently dropping a terminal event.
Callbacks do not execute application handlers, wait for consumers, interpret
readiness, or acquire ownership of the reported handle. Events may arrive before
a direct dial return, out of order or repeatedly.

Windows has one lazily allocated process-lifetime `RASDIALFUNC2` trampoline using
Go's Windows callback bridge. The SDK compile-only check verifies its declared
seven-argument WINAPI signature; Windows amd64 and WOW64 386 tests invoke only
our own trampoline through `SyscallN`, never a RAS function or DLL. The test
checks scalar argument transport, singleton reuse and rejection of late events.
The arm64 binary remains compile-only. No native dialer uses the trampoline.

Retirement serializes with the Go dispatch body, removes its ID, clears queued
events and wakes its consumer. Future callbacks safely reject the retired ID.
This is **not native callback-stack or credential-buffer quiescence**: the
process-lifetime trampoline is not freed, and native input consumers are outside
this registry. Returning zero suppresses notifications, not the connection.
Canceling an observer wait does not retire an attempt or create cleanup rights.
The existing direct-result reference ledger remains separate. A production
driver still needs verified native input lifetime, cancellation, isolation and
credential-persistence behavior before any real dial is enabled.

References: [RASDIALFUNC2 behavior](https://learn.microsoft.com/en-us/windows/win32/api/ras/nc-ras-rasdialfunc2)
and [Go Windows callback implementation](https://go.dev/src/syscall/syscall_windows.go).
