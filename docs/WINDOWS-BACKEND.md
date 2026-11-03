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
in every path component; a concurrent filesystem replacement remains a race. It never chooses a default entry,
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
