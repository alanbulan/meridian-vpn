# Local UniVPN packet channel provider

`UniVPNLocalPacketProvider` implements the existing `UniVPNPacketProvider`
contract with a fresh unnamed Linux AF_UNIX SOCK_SEQPACKET socketpair. Both
endpoints are created atomically with SOCK_NONBLOCK and SOCK_CLOEXEC. There is no
bind, listen, IP connection, TUN, route or DNS operation. No endpoint is retained
by the provider, and successive acquisitions never share a channel, even for
the same session ID.

The native endpoint is returned as an owned `os.File`; the broker relay endpoint
is validated and returned as an owned `packetrelay.DatagramPackets`. The existing
launcher duplicates and validates the native endpoint and closes its original.
The returned relay must be consumed or closed by the caller. Failure/cancellation
closes both endpoints; a close error is `CleanupError`, never assumed clean or
retried by descriptor number. Wrapper failure retains raw-file ownership,
including typed-nil interface returns. The session ID is syntax-checked but does
not establish authorization, a host-network lease or security isolation.

This fills a concrete local transport dependency. It is not wired into the GUI,
does not enable UniVPN, does not implement `UniVPNHostLeaseProvider`, and cannot
connect a gateway by itself. Host network ownership, trusted deployment,
bootstrap/kernel acceptance and real gateway interoperability remain separate.

Tests use real unnamed socketpairs and private failure injection. They check
flags, the existing launcher's duplicate/validation path, packet boundaries,
bidirectional transfer, peer EOF, repeated relay Close, fresh-channel separation,
cancellation, wrapper errors/typed-nil returns and cleanup uncertainty. A socket
creation error is a failing test, not a skip. No private credentials are used.

Run on Linux:

```sh
go test -count=1 ./internal/core -run '^TestLocalPacketProvider'
go test -race -count=1 ./internal/core -run '^TestLocalPacketProvider'
```

The editing environment has no usable Go compiler or gofmt. These Go tests were
written and independently reviewed, but not run locally. Confirm the exact
commit's Linux CI results before reporting them as passed. Existing fake tests
and this real local channel test do not prove a production worker sandbox.
