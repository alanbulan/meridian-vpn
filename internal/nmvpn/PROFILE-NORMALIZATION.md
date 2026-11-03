# Narrow NetworkManager profile equivalence

`equivalentProfiles` first applies `ValidateProfile` independently to both complete
secret-free network dictionaries. Unknown sections/properties, unsupported values,
wrong signatures and wrong Go types fail before any key is removed. The two
canonical dictionaries are then compared with exact remaining keys, signatures
and values. Input maps are never modified. This is not a general NetworkManager
normalizer, a policy approval, or proof of applied host configuration.

The same helper compares the manager's frozen profile with both the authenticated
Connect snapshot and current GetSettings output. The separate envelope validator
continues to require the exact manager nonce, username and password-flags=2. A
password in GetSettings remains forbidden. UUID, owner and object-path checks do
not change.

## Allowed differences

Only properties already admitted by the strict grammar participate. Listed
defaults may be absent or explicitly present with the exact value and wire type.

| Section | Property | Allowed default / handling |
| --- | --- | --- |
| connection | timestamp | Any validated uint64 (`t`) is ignored as NM-maintained bookkeeping. |
| connection | read-only | Any validated boolean (`b`) is ignored; NM documents this deprecated property as having no effect. |
| connection | interface-name, zone, controller, master, port-type, slave-type | Empty string (`s`) only. An actual bound interface is never removed. |
| connection | multi-connect, autoconnect-priority | int32 zero (`i`) only. |
| connection | permissions, secondaries | Empty string array (`as`) only. |
| vpn | persistent | Boolean false (`b`) only. |
| vpn | timeout | uint32 zero (`u`) only. |
| vpn | data, secrets | Empty string dictionary (`a{ss}`) only. Nonempty envelopes are validated and stripped separately. |
| ipv4 / ipv6 | ignore-auto-routes | Boolean false (`b`) only. |
| ipv4 / ipv6 | gateway | Empty string (`s`) only. |
| ipv4 / ipv6 | route-table | uint32 zero (`u`), not main-table 254. Zero can still inherit global policy. |
| ipv4 / ipv6 | route-metric | int64 minus one (`x`), not zero or a resolved metric. |
| ipv4 / ipv6 | dns-priority | int32 zero (`i`) only. |
| ipv6 | never-default, ignore-auto-dns | Boolean false (`b`) only. True remains distinct even with IPv6 disabled. |
| ipv4 / ipv6 | dns-data, dns-search | Empty string array (`as`) only. |
| ipv4 / ipv6 | route-data, address-data, routing-rules | Empty dictionary array (`aa{sv}`) only. |
| ipv4 | dns; addresses; routes | Empty `au`; empty `aau`; empty `aau`, respectively. |
| ipv6 | dns; addresses; routes | Empty `aay`; empty `a(ayuay)`; empty `a(ayuayu)`, respectively. Struct representation must validate before removal. |
| proxy | entire setting | Absent, empty dictionary, or only method=int32(0) are equivalent. |

DNS options are an intentional exception: absent `dns-options` means use defaults,
whereas a present empty `as` means no options. Their presence is preserved. Nil
and non-nil empty Go slices are equivalent only when the property is present,
because both encode the same empty wire array.

`connection.id` and `connection.autoconnect` remain exact, including presence.
The manager explicitly writes autoconnect=false; an omitted property, whose NM
default is true, cannot substitute for it. Required UUID, type, service-type,
IPv4 method/never-default/ignore-auto-dns and IPv6 disabled-method fields remain
mandatory. Unsupported NM defaults such as addr-gen-mode are not admitted just
because a version of NM documents them.

Canonicalization copies only dictionary maps. It does not generically erase
container values, so a future grammar expansion cannot accidentally make a new
nonempty property equivalent to an empty one. Its equivalence needs a separately
reviewed allowlist entry.

## Actual library-output evidence

`integration/nmvpn/export-profile-fixture.py` runs in the disposable unprivileged
wire-test container with the distribution's official libnm/GI packages. It uses
`NM.SimpleConnection.new_from_dbus`, which normalizes a connection in memory, then
`to_dbus(ALL)`. It never constructs NM.Client or contacts a bus. The fixture has
no password, gateway, address or real-world identity.

The generated `reports/nmvpn-wire/libnm-profile.json` retains each property's
actual GVariant signature, input dictionary, normalized dictionary and library
version. Go tests consume that output through the private real D-Bus daemon with
synthetic NM, separately for Connect, GetSettings, and both. Additional explicitly
synthetic cases add the allowlisted defaults/bookkeeping or tamper with policy/envelope
fields. These cases must pass without skipping in the dedicated workflow.

Only the network profile is roundtripped through libnm. The private-bus fixture
overlays its original authenticated username, nonce and secret envelope unchanged;
it does not claim that those envelope fields were normalized by libnm.

This is actual client-library serialization evidence, not a captured real NM
daemon's GetSettings/Connect traffic. Client libnm omits some manager-only legacy
address/route representations; those have separate exact-signature unit coverage.
Real NM, applied/global/dispatcher policy and gateway acceptance remain open.

## Primary basis

- [Connection settings](https://networkmanager.dev/docs/api/latest/settings-connection.html), including timestamp, deprecated read-only, interface binding and defaults.
- [IPv4 settings](https://networkmanager.dev/docs/api/latest/settings-ipv4.html) and [IPv6 settings](https://networkmanager.dev/docs/api/latest/settings-ipv6.html), especially the missing/empty DNS-options distinction and inherited route-table behavior.
- [VPN settings](https://networkmanager.dev/docs/api/latest/settings-vpn.html) and [proxy settings](https://networkmanager.dev/docs/api/latest/settings-proxy.html).
- [NM 1.52 normalization implementation](https://github.com/NetworkManager/NetworkManager/blob/1.52.0/src/libnm-core-impl/nm-connection.c): `_normalize_ip_config` adds a missing proxy setting.
- [NM 1.52 proxy implementation](https://github.com/NetworkManager/NetworkManager/blob/1.52.0/src/libnm-core-impl/nm-setting-proxy.c) and [generic serialization](https://github.com/NetworkManager/NetworkManager/blob/1.52.0/src/libnm-core-impl/nm-setting.c): default method=int32(0) is omitted, producing an empty proxy dictionary. This behavior was also inspected in 1.42.4.
- [NM 1.52 IP configuration implementation](https://github.com/NetworkManager/NetworkManager/blob/1.52.0/src/libnm-core-impl/nm-setting-ip-config.c): `direct_strv_preserve_empty` deliberately preserves empty DNS options.
- [SimpleConnection API](https://networkmanager.dev/docs/libnm/latest/NMSimpleConnection.html) and [serialization API](https://networkmanager.dev/docs/libnm/latest/NMConnection.html).
