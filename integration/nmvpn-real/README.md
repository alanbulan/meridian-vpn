# Deferred disposable-VM NetworkManager acceptance

**Not run. Not an installed service, a VPN driver, or end-to-end acceptance.**
This directory prepares a guarded evidence-capture/checking procedure for a
future authorized, disposable full VM running NetworkManager **1.52.1**. The
current repository has no deployable product entry with real host-policy
providers. Stop at that missing prerequisite; do not replace providers with mocks
and describe the result as product acceptance.

`accept.py` never starts a service, creates a TUN, changes a route, installs a
package, deletes a connection, repairs networking, or retries activation. Its
capture modes perform real read-only NM/system-bus/kernel queries in the VM and
write private evidence. `audit` only reads saved files. None of the capture modes
was invoked in development. Default CI must not invoke them.

## Mandatory gates before a live run

1. Obtain authorization for the named disposable VM and actual networking/service
   operations. Prior approval for offline CI does not prove VM access or authorize
   bypassing a denied netlink/system-bus operation. Do not run on a workstation,
   production server, nested container or the assistant's current executor.
2. Use a fresh, snapshotted full VM with no physical, bridged, NAT, shared-folder or
   forwarded connections to the user's host/network. Install official dependencies
   before detaching its NIC. Use the VM console, not SSH. The preprovisioned parent
   must be an NM-managed dummy named `meridian-base0`; only it and `lo` may exist
   before the run. Neither IPv4 nor IPv6 may have a default route. The independent container rejection, VM detector
   and interface checks are safeguards, not cryptographic isolation proof.
3. Provision and review NM 1.52.1, iproute2, systemd busctl and Python. Review exact
   daemon/config/dispatcher/service-registration files and artifact hashes. Disable
   unrelated activation, dispatchers and DNS managers in this disposable image.
   This harness does not configure these settings or claim manifest completeness.
4. Build a **reviewed real entry** using `core.NewUniVPNNMService` and
   `nmvpn.Service.Run`. It must supply the concrete pinned launcher/containment,
   retained host authority through `UniVPNNMServiceHosts`, independent
   `ServicePolicy` with revocation, fresh pinned system-bus identity, boot identity,
   and distinct durable activation/publication journals. These concrete production
   providers and executable are **still missing**. The callable service alone is
   insufficient. See [SERVICE.md](../../internal/nmvpn/SERVICE.md).
5. Use only fixture credentials and a separately reviewed local synthetic native
   endpoint. No real enterprise account, gateway or external DNS is involved. The
   fixed test profile UUID is `7bbd9315-f867-454e-abf1-ff801794604b`, TUN name
   `meridian-test0`, address `198.18.0.2/30`, offered split route
   `198.19.0.0/24`, and endpoint `192.0.2.1` on the dummy parent's test subnet.
   These values must come from trusted provisioning. No default route, DNS,
   IPv6, arbitrary script or unsupported offer is permitted.

There is intentionally no dummy production authority, permissive driver contract,
automatic installer, `sudo` wrapper, generic command hook or enablement flag here.

## Capture procedure after every gate is satisfied

Run from the VM console as root. Review the scripts before execution. Capture the
current VM boot ID and pass it explicitly at every phase. Set both opt-ins:

```
export MERIDIAN_REAL_NM_VM=1
BOOT_ID=$(cat /proc/sys/kernel/random/boot_id)
ACK=I_ACCEPT_NETWORK_CHANGES_IN_THIS_DISPOSABLE_VM
python3 integration/nmvpn-real/accept.py --phase before \
  --accept "$ACK" --boot-id "$BOOT_ID" --evidence /root/meridian-nm-acceptance
```

The evidence directory must be new, private, and under root-owned non-writable
ancestors. `/tmp` is deliberately rejected. No driver is launched by capture.

Start the reviewed entry using its documented, explicitly authorized interface.
Preserve the exact binary/source/config digests and process/journal ownership in
separate evidence. Wait for actual NM activation and host readback, never just
`ServiceResult.Published` or plugin STARTED. Then capture:

```
python3 integration/nmvpn-real/accept.py --phase active \
  --accept "$ACK" --boot-id "$BOOT_ID" --evidence /root/meridian-nm-acceptance
```

Cancel the original service context through its reviewed control path. Wait for
`Run` to return and retain its complete error/result plus both original journals.
Do not start another instance, clear quarantine or delete resources by guessed
names. Capture once the owner reports teardown complete:

```
python3 integration/nmvpn-real/accept.py --phase after \
  --accept "$ACK" --boot-id "$BOOT_ID" --evidence /root/meridian-nm-acceptance
```

`after` requires all three samples and performs the same offline audit as:

```
python3 integration/nmvpn-real/accept.py --phase audit \
  --evidence /root/meridian-nm-acceptance
```

Any missing field, query failure, timeout, observed owner/bus change, unsupported
shape, failed invariant or incomplete phase is a failure, not a skip. Failed
samples remain available. A failed capture can leave the service running because
this tool owns no handles: stop it through its original owner, retain uncertainty,
and discard the entire VM. Do not retry destructive operations or “repair” a
sample until it passes. Use a fresh VM/boot/evidence directory for another attempt.

## Assertions and deliberate limits

- Baseline allows exactly loopback and the active synthetic dummy parent, no
  default route or existing VPN.
- Active requires the fixed NM VPN UUID/device and real TUN type/address, unchanged
  parent links/addresses and NM activations, retained baseline routes, the offered
  main-table unicast route, only narrowly allowed TUN subnet/local/broadcast routes,
  and unchanged RPDB, IPv6 routes, bus identity/owner and `/etc/resolv.conf` bytes.
- After requires exact baseline equality after removing only packet counters and
  address lifetime counters. Added routes reject unknown keys. TUN link/address
  records allow extra metadata; baseline restoration compares all retained fields
  after the stated normalization. This is not a closed schema for every observation.
- A matching three-sample audit is **not** complete host-policy proof. Reads are
  sequential; transient changes, NM caches, hostile root, hidden mount/network
  namespaces, dispatcher quiescence and executable provenance are not established.
  `/etc/resolv.conf` equality does not inspect systemd-resolved per-link state or
  prove DNS leak absence. Process/relay containment and journal correctness require
  the service's independent evidence. Exported data is not an authenticated lease.
- Resolver reads stop after 64 KiB plus one byte. Command capture uses a
  15-second timeout and rejects stdout above 1 MiB, but subprocess stdout/stderr
  are buffered before that check. This is **not** a hard command-memory bound;
  use only the controlled disposable VM, not hostile/unbounded command output.
- No packets traverse the offered route in this procedure; native transport,
  data-plane delivery and real enterprise gateway compatibility remain separate.
- Pre-publication failure, owner loss, worker loss, policy revocation, restart and
  reboot recovery require separate fixtures and expectations. This three-phase
  checker must not count those absent cases as passed. In particular the current
  service intentionally retains activation quarantine after shutdown.

## Offline verification only

```
python3 -m unittest discover -s integration/nmvpn-real -v
```

Tests use in-memory JSON fixtures and temporary ordinary files. They never invoke
`ip`, `nmcli`, `busctl`, service execution, root setup or networking operations.
The test suite checks guard rejection, unexpected state shapes through comparison,
route/DNS/RPDB drift, bus/boot identity, and restoration.
It cannot validate real NM output compatibility or the unavailable product path.

References: [NM daemon](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/NetworkManager.html),
[NM configuration](https://www.networkmanager.dev/docs/api/latest/NetworkManager.conf.html),
[VPN protocol](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.VPN.Plugin.html).
