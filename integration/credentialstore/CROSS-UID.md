# Production UID guards: dedicated disposable-container tests

This suite tests the production `NewSystem` entry against deliberately mismatched
Unix process identities. It is separate from the real-GNOME same-UID suite. A real
private D-Bus daemon and a minimal in-memory counting Secret Service are used;
no GNOME daemon or stored credentials are needed for these negative cases.

## Boundary and invocation

Use a **new dedicated GitHub container**, with no host HOME, runtime, sockets,
credentials, devices or other concurrent workloads. Create two distinct non-root
fixture users with distinct non-root primary groups. Install official Go and
D-Bus packages, as for the other integration suites. Do not create either user's
`/run/user/<uid>` directory. The checkout, all source directories/files and the
script must be trusted, root-owned and not writable by either fixture user. Do
not reuse a checkout previously handed to an unprivileged fixture job.

```sh
GITHUB_ACTIONS=true MERIDIAN_CROSS_UID_TESTS=1 \
  bash integration/credentialstore/run-crossuid-tests.sh meridian-a meridian-b
```

The root runner compiles a test binary into a fresh root-owned `/run` build tree.
Its binary and ancestors are not writable by fixture users. It runs only the
anchored supervisor test. The supervisor runs each service, client and D-Bus
process as A or B with all supplementary groups removed. Helpers recheck real
and effective UID/GID and empty supplementary groups, reject unknown roles, use
an anchored helper-test selector and receive a minimal environment. They never
inherit a user's bus, credentials, HOME or runtime selectors.

Root only supervises these processes and manages newly created fixture paths.
Every case requires an exclusive fresh `/run/user/A` directory. Existing entries
cause failure without modification. The runtime initially belongs to the bus UID
so it can bind its private socket. To connect the cross-UID service, root briefly
sets the runtime to A:group-B mode 0710 and its socket to A:group-B mode 0660.
After service readiness, runtime permissions return to A:group-A mode 0700 **before
any tested client operation**. No 0777 directory or anonymous authentication is
used. The bus accepts EXTERNAL only, explicitly admits just A and B, and has no
activation directories, includes, TCP listeners, or service helpers.

## Evidence and controls

1. Same UID: bus A, service A and client A. A legitimate authorized `Load` reaches
   the empty fixture and returns not-found. Exactly one SearchItems call proves
   the call counter is live and the production entry can reach the service.
2. Wrong socket peer: bus B, service A, client A. Despite the socket file owner
   being A, independently observed SO_PEERCRED must identify B.
3. Wrong service owner: bus A, service B, client A. Independently observed
   GetConnectionUnixUser for the current unique service owner must identify B.

For every client, an ordinary private D-Bus connection must authenticate and
resolve the expected service owner after the directory is secured. The actual
socket peer UID and unique owner UID must match the case before guard assertions.
Thus a missing/broken fixture is a test failure, not successful rejection.

Each negative case requests `Load`, `Save` and `Delete` using the correct explicit
consent enums and a valid synthetic reference. Every operation must return
unavailable; Load must return no data. After all calls finish, a parent-to-service
pipe request must report **zero SearchItems calls**. The probe does not call
Secret Service methods. The synthetic save value is in memory only and cleared;
it is never an argument, environment value, log or configuration entry.

## Cleanup and limits

Children stay attached to exact process handles. Cleanup sends TERM, uses a
bounded grace period, then kills and waits for only those children. Service/client
processes are stopped before the bus. Only the recorded socket inode is unlinked,
and only the same runtime directory inode is removed while empty. There is no
recursive deletion under `/run/user`. Private root-created build/config trees
may be recursively removed; fixture users cannot alter those trees. Hard crashes
or the overall 120-second timeout require disposal of the whole container.

Environment flags and a Docker marker are misuse guards, not proof that the CI
job has no host mounts. Review the job definition before enabling this runner.
This suite has not run in the editing environment. Exact-commit CI must succeed
before claiming coverage. It does not validate malicious same-UID services,
wrong-owner runtime directories, other keyring implementations, desktop/UI
behavior, or Windows/macOS stores.

The fixture configuration follows the official [D-Bus daemon documentation](https://dbus.freedesktop.org/doc/dbus-daemon.1.html)
for custom bus configurations, EXTERNAL authentication, Unix listeners and user
policies. It never modifies the container's standard bus configuration.
