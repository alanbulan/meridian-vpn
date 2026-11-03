//go:build linux

package packetrelay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

// These tests create only anonymous, local AF_UNIX pairs. No IP connection,
// pathname socket, device, TUN, namespace or network configuration is touched.
func pairEnds(t *testing.T) (*DatagramPackets, *DatagramPackets) {
	t.Helper()
	native, relay, err := OpenPacketPair(context.Background())
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { _ = relay.Close() })
	peer, err := NewDatagramPackets(native)
	if err != nil { _ = native.Close(); t.Fatal(err) }
	t.Cleanup(func() { _ = peer.Close() })
	return peer, relay
}

func packetPairFlags(t *testing.T, f *os.File) (uintptr, syscall.Stat_t) {
	t.Helper()
	raw, err := f.SyscallConn()
	if err != nil { t.Fatal(err) }
	var fd uintptr
	var st syscall.Stat_t
	err = raw.Control(func(n uintptr) {
		fd = n
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, n, syscall.F_GETFD, 0)
		if errno != 0 || flags&syscall.FD_CLOEXEC == 0 { t.Error("missing CLOEXEC") }
		flags, _, errno = syscall.Syscall(syscall.SYS_FCNTL, n, syscall.F_GETFL, 0)
		if errno != 0 || flags&syscall.O_NONBLOCK == 0 { t.Error("missing NONBLOCK") }
		if err := syscall.Fstat(int(n), &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFSOCK { t.Error("not a retained socket") }
		for _, option := range []struct{ option, want int }{{syscall.SO_TYPE, syscall.SOCK_SEQPACKET}, {syscall.SO_PROTOCOL, 0}} {
			v, e := syscall.GetsockoptInt(int(n), syscall.SOL_SOCKET, option.option)
			if e != nil || v != option.want { t.Error("unexpected socket type/protocol") }
		}
		local, e := syscall.Getsockname(int(n))
		if e != nil || unnamedUnix(local) != nil { t.Error("not anonymous local AF_UNIX") }
		remote, e := syscall.Getpeername(int(n))
		if e != nil || unnamedUnix(remote) != nil { t.Error("not anonymous connected peer") }
	})
	if err != nil { t.Fatal(err) }
	return fd, st
}

func TestPacketPairActualIdentityAndBoundaries(t *testing.T) {
	native, relay := pairEnds(t)
	n, ns := packetPairFlags(t, native.file)
	r, rs := packetPairFlags(t, relay.file)
	if n == r || (ns.Dev == rs.Dev && ns.Ino == rs.Ino) { t.Fatal("pair aliases one endpoint") }
	for _, direction := range [][2]*DatagramPackets{{native, relay}, {relay, native}} {
		if err := direction[1].file.SetReadDeadline(time.Now().Add(2*time.Second)); err != nil { t.Fatal(err) }
		for _, packet := range [][]byte{[]byte("first record"), []byte("second distinct record")} {
			if n, err := direction[0].WritePacket(packet); err != nil || n != len(packet) { t.Fatal("write", n, err) }
		}
		for _, want := range [][]byte{[]byte("first record"), []byte("second distinct record")} {
			b := make([]byte, 128)
			n, err := direction[1].ReadPacket(b)
			if err != nil || !bytes.Equal(b[:n], want) { t.Fatal("pair/record boundary mismatch", err) }
		}
	}
	if err := native.Close(); err != nil { t.Fatal(err) }
	if n, err := relay.ReadPacket(make([]byte, 32)); n != 0 || !errors.Is(err, io.EOF) { t.Fatal("opposite endpoint did not observe EOF", n, err) }
}

func TestPacketPairActualTruncation(t *testing.T) {
	native, relay := pairEnds(t)
	if err := relay.file.SetReadDeadline(time.Now().Add(2*time.Second)); err != nil { t.Fatal(err) }
	if _, err := native.WritePacket(bytes.Repeat([]byte{'x'}, 64)); err != nil { t.Fatal(err) }
	if n, err := relay.ReadPacket(make([]byte, 8)); n != 0 || !errors.Is(err, ErrRejected) { t.Fatal("truncated packet accepted") }
}

func TestPacketPairActualCloseUnblocksIO(t *testing.T) {
	for _, write := range []bool{false, true} {
		native, _ := pairEnds(t)
		entered := make(chan struct{})
		var once sync.Once
		if write {
			// Saturate this private queue without waiting or changing socket options.
			full := false
			if err := native.raw.Control(func(fd uintptr) {
				for i := 0; i < 8192; i++ {
					_, err := sendMessage(int(fd), []byte{'x'})
					if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK { full = true; break }
					if err != nil { t.Error(err); break }
				}
			}); err != nil || !full { t.Fatal("private queue was not saturated", err) }
			native.send = func(fd int, b []byte) (int, error) {
				n, err := sendMessage(fd, b)
				if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK { once.Do(func() { close(entered) }) }
				return n, err
			}
		} else {
			native.recv = func(fd int, b []byte) (int, int, error) {
				n, flags, err := receiveMessage(fd, b)
				if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK { once.Do(func() { close(entered) }) }
				return n, flags, err
			}
		}
		done := make(chan error, 1)
		go func() {
			var err error
			if write { _, err = native.WritePacket([]byte{'x'}) } else { _, err = native.ReadPacket(make([]byte, 32)) }
			done <- err
		}()
		select { case <-entered: case <-time.After(2*time.Second): t.Fatal("I/O did not wait") }
		if err := native.Close(); err != nil { t.Fatal(err) }
		select { case err := <-done: if err == nil { t.Fatal("closed I/O succeeded") }; case <-time.After(2*time.Second): t.Fatal("close did not unblock I/O") }
	}
}

func TestPacketPairRejectsUnsupportedSocketModes(t *testing.T) {
	for _, mode := range []int{syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, syscall.SOCK_DGRAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, syscall.SOCK_SEQPACKET|syscall.SOCK_NONBLOCK, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC} {
		fds, err := syscall.Socketpair(syscall.AF_UNIX, mode, 0)
		if err != nil { t.Fatal(err) }
		first, second := os.NewFile(uintptr(fds[0]), "private-negative-pair"), os.NewFile(uintptr(fds[1]), "private-negative-peer")
		func() {
			defer first.Close(); defer second.Close()
			if p, err := NewDatagramPackets(first); err == nil { _ = p.Close(); t.Fatal("unsupported mode accepted") }
			if _, err := first.Stat(); err != nil { t.Fatal("validator consumed caller file") }
		}()
	}
}

func realPairOps() packetPairOps {
	return packetPairOps{
		pair: syscall.Socketpair,
		validateNative: func(f *os.File) error { _, err := validateDatagramFile(f); return err },
		wrapRelay: NewDatagramPackets,
		closeFile: (*os.File).Close,
		closeRelay: (*DatagramPackets).Close,
	}
}

func TestPacketPairInjectedAcquisitionFailures(t *testing.T) {
	for _, phase := range []string{"syscall", "negative", "partial", "alias", "cancel-pair", "native", "cancel-native", "relay", "relay-with-owner", "cancel-relay", "close-native", "close-peer", "close-both"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ops := realPairOps()
			pairCalls := 0
			closed := map[*os.File]int{}
			var first *os.File
			ops.pair = func(domain, mode, protocol int) ([2]int, error) {
				pairCalls++
				if domain != syscall.AF_UNIX || mode != syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK || protocol != 0 { t.Fatal("wrong atomic socketpair request") }
				if phase == "syscall" { return [2]int{0, 0}, syscall.EMFILE }
				if phase == "negative" { return [2]int{-1, -1}, nil }
				fds, err := syscall.Socketpair(domain, mode, protocol)
				if err != nil { t.Fatal(err) }
				if phase == "partial" || phase == "alias" {
					if err := syscall.Close(fds[1]); err != nil { t.Fatal(err) }
					if phase == "partial" { fds[1] = -1 } else { fds[1] = fds[0] }
				}
				if phase == "cancel-pair" { cancel() }
				return fds, nil
			}
			ops.validateNative = func(f *os.File) error {
				first = f
				if phase == "native" { return io.ErrUnexpectedEOF }
				_, err := validateDatagramFile(f)
				if phase == "cancel-native" { cancel() }
				return err
			}
			ops.wrapRelay = func(f *os.File) (*DatagramPackets, error) {
				if phase == "relay" { return nil, io.ErrUnexpectedEOF }
				p, err := NewDatagramPackets(f)
				if phase == "cancel-relay" { cancel() }
				if phase == "relay-with-owner" || phase == "close-native" || phase == "close-peer" || phase == "close-both" { err = io.ErrUnexpectedEOF }
				return p, err
			}
			ops.closeFile = func(f *os.File) error {
				closed[f]++
				err := f.Close()
				if f == first && (phase == "close-native" || phase == "close-both") { err = errors.Join(err, syscall.EIO) }
				return err
			}
			ops.closeRelay = func(p *DatagramPackets) error {
				closed[p.file]++
				err := p.Close()
				if phase == "close-peer" || phase == "close-both" { err = errors.Join(err, syscall.ENOSPC) }
				return err
			}
			native, relay, err := openPacketPair(ctx, ops)
			if native != nil || relay != nil || err == nil || pairCalls != 1 { t.Fatal("partial ownership returned or operation replayed") }
			want := 2
			if phase == "syscall" || phase == "negative" { want = 0 }
			if phase == "partial" || phase == "alias" { want = 1 }
			if len(closed) != want { t.Fatalf("closed %d handles, want %d", len(closed), want) }
			for f, n := range closed { if n != 1 { t.Fatal("handle closed twice") }; if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) { t.Fatal("owned handle remains open") } }
			uncertain := phase == "close-native" || phase == "close-peer" || phase == "close-both"
			if errors.Is(err, ErrCleanup) != uncertain { t.Fatal("cleanup uncertainty lost or invented", err) }
		})
	}
}

func TestPacketPairRejectsBeforeSyscall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	for _, c := range []context.Context{nil, ctx} {
		ops := realPairOps()
		ops.pair = func(int, int, int) ([2]int, error) { t.Fatal("syscall after invalid context"); return [2]int{}, nil }
		if a, b, err := openPacketPair(c, ops); a != nil || b != nil || err == nil { t.Fatal("invalid context accepted") }
	}
	if a, b, err := openPacketPair(context.Background(), packetPairOps{}); a != nil || b != nil || err == nil { t.Fatal("missing operations accepted") }
}

func TestPacketPairCancellationAfterTransferDoesNotClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	native, relay, err := OpenPacketPair(ctx)
	if err != nil { t.Fatal(err) }
	defer native.Close(); defer relay.Close()
	cancel()
	if _, err := native.Write([]byte("owned")); err != nil { t.Fatal("late cancellation closed caller ownership", err) }
	if err := relay.file.SetReadDeadline(time.Now().Add(time.Second)); err != nil { t.Fatal(err) }
	b := make([]byte, 16)
	if n, err := relay.ReadPacket(b); err != nil || string(b[:n]) != "owned" { t.Fatal("transferred pair unusable", err) }
}
