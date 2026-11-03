//go:build linux

package core

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"mygo-vpn/internal/packetrelay"
)

const packetPairSession = "0123456789abcdef0123456789abcdef"

func checkPacketLaunchFlags(t *testing.T, f *os.File) {
	t.Helper()
	raw, err := f.SyscallConn()
	if err != nil { t.Fatal(err) }
	err = raw.Control(func(fd uintptr) {
		flags, _, e := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0)
		if e != 0 || flags&syscall.FD_CLOEXEC == 0 { t.Error("launch descriptor lost CLOEXEC") }
		flags, _, e = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
		if e != 0 || flags&syscall.O_NONBLOCK == 0 { t.Error("launch descriptor lost NONBLOCK") }
	})
	if err != nil { t.Fatal(err) }
}

func TestUniVPNPacketPairLauncherIntegration(t *testing.T) {
	provider := NewUniVPNPacketPairProvider()
	native, endpoint, err := acquireUniVPNPacket(context.Background(), provider, packetPairSession, duplicateUniVPNPacket)
	if err != nil { t.Fatal(err) }
	defer native.owner.Close(); defer endpoint.Close()
	if peer, ok := endpoint.(*packetrelay.DatagramPackets); !ok || peer == nil { t.Fatal("concrete relay type lost") }
	checkPacketLaunchFlags(t, native.file)
	cmd, unused := packetWiringCmd(t)
	defer unused.Close()
	if err = wireUniVPNPacket(cmd, native.file); err != nil { t.Fatal(err) }
	checkPacketLaunchFlags(t, native.file)
	// No command is started. Actual private packet exchange verifies that the
	// launch duplicate still reaches the exact retained peer after original close.
	if err := native.file.SetReadDeadline(time.Now().Add(2*time.Second)); err != nil { t.Fatal(err) }
	if _, err = endpoint.WritePacket([]byte("peer-to-duplicate")); err != nil { t.Fatal(err) }
	b := make([]byte, 64)
	if n, err := native.owner.ReadPacket(b); err != nil || string(b[:n]) != "peer-to-duplicate" { t.Fatal("duplicate is not paired", err) }
	if _, err = native.owner.WritePacket([]byte("duplicate-to-peer")); err != nil { t.Fatal(err) }
	done := make(chan error, 1)
	go func() { b := make([]byte, 64); n, e := endpoint.ReadPacket(b); if e == nil && string(b[:n]) != "duplicate-to-peer" { e = io.ErrUnexpectedEOF }; done <- e }()
	select { case err := <-done: if err != nil { t.Fatal(err) }; case <-time.After(2*time.Second): t.Fatal("paired relay did not receive") }
	if a, b, err := provider.AcquirePacket(context.Background(), packetPairSession); a != nil || b != nil || err == nil { t.Fatal("one-shot provider reused") }
}

func TestUniVPNPacketPairProviderInvalidAndCopied(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background()); cancel()
	for _, input := range []struct { ctx context.Context; session string }{{nil, packetPairSession}, {canceled, packetPairSession}, {context.Background(), ""}, {context.Background(), "0123456789ABCDEF0123456789ABCDEF"}, {context.Background(), packetPairSession+"0"}, {context.Background(), packetPairSession[:31]}} {
		p := NewUniVPNPacketPairProvider()
		open := func(context.Context) (*os.File, *packetrelay.DatagramPackets, error) { t.Fatal("invalid input acquired pair"); return nil, nil, nil }
		if a, b, err := p.acquire(input.ctx, input.session, open); a != nil || b != nil || err == nil { t.Fatal("invalid input accepted") }
		if a, b, err := p.acquire(context.Background(), packetPairSession, open); a != nil || b != nil || err == nil { t.Fatal("failed attempt not consumed") }
	}
	p := NewUniVPNPacketPairProvider()
	copyP := reflect.New(reflect.TypeOf(p).Elem()).Interface().(*UniVPNPacketPairProvider)
	reflect.ValueOf(copyP).Elem().Set(reflect.ValueOf(p).Elem())
	for _, invalid := range []*UniVPNPacketPairProvider{nil, {}, copyP} {
		if a, b, err := invalid.AcquirePacket(context.Background(), packetPairSession); a != nil || b != nil || err == nil { t.Fatal("nil/zero/copied provider accepted") }
	}
}

func TestUniVPNPacketPairProviderCancellationAndCleanup(t *testing.T) {
	for _, phase := range []string{"opener", "uncertain", "cancel-after-open", "missing-peer", "close-failure"} {
		t.Run(phase, func(t *testing.T) {
			p := NewUniVPNPacketPairProvider()
			ctx, cancel := context.WithCancel(context.Background()); defer cancel()
			var native *os.File
			var peer *packetrelay.DatagramPackets
			calls := 0
			open := func(c context.Context) (*os.File, *packetrelay.DatagramPackets, error) {
				calls++
				if phase == "opener" { return nil, nil, io.ErrUnexpectedEOF }
				if phase == "uncertain" { return nil, nil, errors.Join(packetrelay.ErrCleanup, syscall.EIO) }
				var err error
				native, peer, err = packetrelay.OpenPacketPair(c)
				if err != nil { t.Fatal(err) }
				if phase == "missing-peer" { _ = peer.Close(); return native, nil, nil }
				if phase == "close-failure" { _ = native.Close() }
				cancel()
				return native, peer, nil
			}
			a, b, err := p.acquire(ctx, packetPairSession, open)
			if a != nil || b != nil || err == nil { t.Fatal("partial failure transferred endpoints") }
			var ce *CleanupError
			uncertain := phase == "uncertain" || phase == "close-failure"
			if errors.As(err, &ce) != uncertain { t.Fatal("cleanup uncertainty mapping incorrect", err) }
			if native != nil { if _, err := native.Stat(); !errors.Is(err, os.ErrClosed) { t.Fatal("native leaked") } }
			if peer != nil { if _, err := peer.ReadPacket(make([]byte, 1)); !errors.Is(err, os.ErrClosed) { t.Fatal("relay was not closed", err) } }
			if a, b, err := p.acquire(context.Background(), packetPairSession, open); a != nil || b != nil || err == nil || calls != 1 || errors.As(err, &ce) != uncertain { t.Fatal("repeated call replayed or erased failed cleanup") }
		})
	}
}

func TestUniVPNPacketPairProviderConcurrentOneShot(t *testing.T) {
	p := NewUniVPNPacketPairProvider()
	var calls atomic.Int32
	open := func(c context.Context) (*os.File, *packetrelay.DatagramPackets, error) { calls.Add(1); return packetrelay.OpenPacketPair(c) }
	var successes atomic.Int32
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			a, b, err := p.acquire(context.Background(), packetPairSession, open)
			if err == nil { successes.Add(1); _ = a.Close(); _ = b.Close() } else if a != nil || b != nil { t.Error("losing caller received ownership") }
		}()
	}
	group.Wait()
	if calls.Load() != 1 || successes.Load() != 1 { t.Fatal("concurrent provider did not have exactly one owner") }
}
