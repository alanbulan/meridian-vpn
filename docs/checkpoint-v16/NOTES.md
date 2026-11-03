# Meridian source checkpoint v16

This checkpoint preserves every source file from the v15 checkpoint byte-for-byte
and adds the inactive `internal/processcontainment` Linux lifecycle primitive,
injected tests, its documented threat model, and this validation record.

Baseline archive: meridian-native9-fd6-offer-final-20261103T0714Z.zip
Baseline SHA256: 7aa9e2d652aaa9a5828ff5f69b50568299b80fde289606792af2cdfa00f5e4e4
Baseline comparison: no changed or missing archived source files.

Validation scope: Go 1.27.3 on Linux amd64; commands and exit statuses are in
VALIDATION.txt. Tests use mocked cgroup/process operations and ordinary pipe FDs.
Independent security review passed for the documented inactive primitive scope.
This does not approve production confinement, host network exclusivity, or VPN
activation. Existing default remains disabled; no privileged settings, cgroups,
network namespaces, TUN devices, routes, DNS or Unix listeners were created here.
Prior native integration evidence is retained from v15, not rerun or relabeled.

The archive excludes build binaries, toolchains, caches and local credentials.
The unchanged pinned upstream OpenConnect source tarball includes public upstream
test certificates/private-key fixtures. They are reproducibility test data, not
user or service credentials. The tarball remains byte-for-byte pinned rather than
silently removing upstream fixture content and breaking its checksum.

See internal/processcontainment/README.md for prerequisites and official sources.
A reviewed bootstrap enforcing identity/capabilities/namespaces/filesystem/FD and
syscall policy, plus an enforceable ownership model for host network and resolver
writers, is still required before deployment.
