# UniVPN v2 offer controller (experimental, fail closed)

The v2 native packet mode reports authenticated metadata over its private pipe,
not a TUN interface. `UniVPNNativeOfferSource` accepts only the matching launched
process, exact 32-character session nonce, bounded strict v2 records, one offer,
and a terminal `relay-closed` record. Duplicate/unknown fields, v1 records,
partial lines and missing terminal records are rejected. The terminal record is
not host-network cleanup evidence.

`NewUniVPNOfferController` requires a trusted offer source, an exclusive host
lease provider, actual kernel/resolver operations, administrator network
allowlists and a separate immutable packet policy. No provider is created by
this constructor, and no production exclusive host lease is supplied. A missing
provider prevents construction; the shipped GUI does not enable this path.

Before acquisition, addresses, routes, DNS and endpoint must pass the exact
network allowlists. Assigned IPv4, remote routes and resolvers must also exactly
match administrator packet policy. Session ownership never comes from gateway
metadata. A trusted provider must acquire a fresh broker-owned TUN under verified
whole-process-tree containment, enforce exclusive ownership against concurrent
network writers, and provide the actual kernel identity and broker-only packet
endpoint. Partial acquisition must be recoverable or explicitly uncertain.

The existing network controller installs only approved state and checks kernel,
route and resolver readbacks. The relay starts with independent session lifetime,
not the temporary readiness timeout. Readiness requires both pumps to have
entered packet reads, no observed relay failure, and a final process-bound live
offer check. Entering a read is not a successful packet exchange or a VPN probe.
A relay failure stops the native process. Terminal or corrupt native records
also stop that process. The broker still checks native exit before reporting ready.

Cleanup cancels and joins the relay, proves native containment/channel closure,
uses ownership-checked network rollback/readback, then releases the exclusive
lease. Lease release must independently refuse replacement/uncertain resources
and close its packet endpoint even when setup never started the relay. Uncertain
source acquisition, relay closure, rollback, proof or release quarantines the
controller/backend. Host cleanup is never inferred from `relay-closed`.

## Still required for deployment

- A reviewed concrete whole-tree containment and launch rollback provider.
- A reviewed concrete exclusive host lease provider implementing identity,
  broker-only TUN ownership, partial acquisition rollback, concurrency exclusion
  and absence proofs. Interface names, aliases and matching indexes alone do not
  establish this guarantee.
- Trusted provisioning of the two preconnected gateway TCP sockets and unnamed
  seqpacket endpoints, pinned executable identity and administrator policies.
- An authorized host integration environment and actual gateway interoperability,
  packet transfer, disconnect and rollback verification.

The new parser/source/controller tests use memory packet endpoints and injected
kernel operations only. They create no host TUN, routes, DNS changes, network
connections or Unix listeners. Focused race checks cover concurrent single-owner
packet claims, terminal/corrupt channels, rejected policies before acquisition,
startup cancellation, partial setup, final liveness and sticky uncertainty.
