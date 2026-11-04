# Explicit Windows RAS read-only acceptance probe

This standalone utility makes the existing native metadata bindings manually
testable on Windows. It is not a VPN client, dialer, background monitor or a
production-backend readiness test. It is not included in the application UI or
the normal release binaries. No command installs a service or modifies a profile.

With the repository's supported Go toolchain, build on Windows:

```powershell
go build -buildvcs=false -trimpath -o build/meridian-ras-inspect.exe ./cmd/meridian-ras-inspect
.\build\meridian-ras-inspect.exe --help
```

Help and invocation without arguments do not load RAS or inspect the host.
On a development host with Make, `make ras-inspect` builds a native probe, and
`make windows-probe` cross-builds separate amd64, 386 and arm64 executables.
These optional targets do not change the normal application build or Linux
release. Cross-compilation is not evidence that a Windows executable ran.

The following is a **manual, opt-in** acceptance step for a disposable or
otherwise authorized Windows environment with an existing L2TP/PSK/MSCHAPv2
profile. Do not create a profile, save credentials or dial simply to run this
probe. Obtain the expected gateway independently from the intended configuration.

```powershell
.\build\meridian-ras-inspect.exe `
  --phonebook 'C:\AuthorizedFixture\rasphone.pbk' `
  --entry 'Authorized fixture' `
  --gateway 'vpn.example.test' `
  --acknowledge-service-start
```

Loading RAS can start its Windows service. The acknowledgement is required even
though the probe only reads metadata. It performs the explicit profile-property
check, bounded connection enumeration/status checks, and profile revalidation.
It does not read credentials, authenticate, dial, hang up, edit/delete entries,
change routes/DNS, or infer reference ownership. Synchronous native query
cancellation/duration remains unverified; no hard timeout is promised.

JSON includes only booleans, a matching-connection count after a successful
observation, and fixed error codes. It does not emit the selected name, path,
gateway, native handle, account, or native error text. However, command-line
arguments may remain visible in shell history/process listings; do not paste
private selections into public logs. The supplied examples are placeholders.

Exit 0 means these observations completed, **not that the tunnel works**.
Every report states `dialing_allowed: false`, `live_tunnel_verified: false`, and
`native_quiescence_verified: false`. Empty connection results do not prove
exclusivity. Reads do not close profile/path replacement races. Failed metadata
checks may mean unsupported settings or unavailable evidence, not necessarily
an invalid Windows VPN configuration. Exit 1 denotes unverified/unavailable or
output failure, including nonempty selections rejected by metadata validation;
exit 2 denotes parsing/missing-input errors or missing acknowledgement.

## Verification boundaries

`go test ./cmd/meridian-ras-inspect` uses injected boundaries only on all platforms.
It tests acknowledgement/default behavior, exact selection, partial failure,
redaction and output errors. It does not call actual RAS. Manual target-system
execution, actual native property reads and enterprise gateway acceptance must
be recorded separately; adding this utility does not mark them complete.
