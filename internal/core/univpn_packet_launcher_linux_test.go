//go:build linux

package core

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"sync/atomic"
	"syscall"
	"testing"

	"mygo-vpn/internal/packetrelay"
)

type packetProviderFunc func(context.Context, string) (*os.File, packetrelay.PacketIO, error)

func (f packetProviderFunc) AcquirePacket(c context.Context, s string) (*os.File, packetrelay.PacketIO, error) {
	return f(c, s)
}

type launcherPacketFake struct {
	file     *os.File
	closes   atomic.Int32
	closeErr error
}

func (p *launcherPacketFake) ReadPacket([]byte) (int, error)    { return 0, io.EOF }
func (p *launcherPacketFake) WritePacket(b []byte) (int, error) { return len(b), nil }
func (p *launcherPacketFake) Close() error {
	p.closes.Add(1)
	if p.file != nil {
		return errors.Join(p.closeErr, p.file.Close())
	}
	return p.closeErr
}

func TestPacketLauncherAcquireOwnership(t *testing.T) {
	for _, mode := range []string{"success", "provider", "duplicate", "cancel-before", "cancel-provider", "cancel-duplicate", "missing-relay", "original-close"} {
		t.Run(mode, func(t *testing.T) {
			original, other := transportPipe(t)
			dup, unused := transportPipe(t)
			defer other.Close()
			defer unused.Close()
			owner := &launcherPacketFake{file: dup}
			relay := &launcherPacketFake{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel-before" {
				cancel()
			}
			provider := packetProviderFunc(func(context.Context, string) (*os.File, packetrelay.PacketIO, error) {
				if mode == "cancel-before" {
					t.Fatal("provider called after cancellation")
				}
				switch mode {
				case "provider":
					return original, relay, errors.New("acquire")
				case "cancel-provider":
					cancel()
				case "missing-relay":
					return original, nil, nil
				case "original-close":
					original.Close()
				}
				return original, relay, nil
			})
			native, got, err := acquireUniVPNPacket(ctx, provider, "session", func(f *os.File) (uniVPNPacketNative, error) {
				if f != original {
					t.Fatal("wrong original")
				}
				if mode == "cancel-duplicate" {
					cancel()
				}
				result := uniVPNPacketNative{dup, owner}
				if mode == "duplicate" {
					return result, errors.New("duplicate")
				}
				return result, nil
			})
			if mode == "success" {
				if err != nil || native.file != dup || got != relay {
					t.Fatal(err)
				}
				assertTransportClosed(t, original)
				if _, e := dup.Stat(); e != nil {
					t.Fatal("duplicate closed before Start")
				}
				if closeUniVPNPacketLaunch(native, got, nil, nil, errors.New("start")) == nil {
					t.Fatal("lost launch error")
				}
				assertTransportClosed(t, dup)
				if relay.closes.Load() != 1 {
					t.Fatal("relay leaked")
				}
			} else {
				if err == nil || got != nil || native.file != nil {
					t.Fatal("accepted failure")
				}
				if mode != "cancel-before" {
					assertTransportClosed(t, original)
				}
				if mode == "duplicate" || mode == "cancel-duplicate" || mode == "original-close" {
					assertTransportClosed(t, dup)
				}
				if mode != "cancel-before" && mode != "missing-relay" && relay.closes.Load() != 1 {
					t.Fatal("relay not closed")
				}
			}
		})
	}
}
func TestPacketLauncherRejectsActualPipe(t *testing.T) {
	r, w := transportPipe(t)
	defer w.Close()
	if native, e := duplicateUniVPNPacket(r); e == nil {
		native.owner.Close()
		t.Fatal("pipe accepted")
	}
	if _, e := r.Stat(); e != nil {
		t.Fatal("validator closed caller original")
	}
}
func packetWiringCmd(t *testing.T) (*exec.Cmd, *os.File) {
	t.Helper()
	a, b := transportPipe(t)
	c, d := transportPipe(t)
	cmd := exec.CommandContext(context.Background(), "/never-executed", "--meridian-session-fd=3", "--meridian-control-fd=4", "--meridian-data-fd=5", "--", "https://gateway.invalid")
	cmd.ExtraFiles = []*os.File{a, b, c}
	return cmd, d
}
func TestPacketLauncherFixedFD6(t *testing.T) {
	cmd, f := packetWiringCmd(t)
	previous := append([]*os.File(nil), cmd.ExtraFiles...)
	if e := wireUniVPNPacket(cmd, f); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(cmd.ExtraFiles, append(previous, f)) || cmd.Args[len(cmd.Args)-3] != "--meridian-packet-fd=6" {
		t.Fatal("wrong packet FD wiring")
	}
	if e := wireUniVPNPacket(cmd, f); e == nil {
		t.Fatal("double wiring accepted")
	}
}
func TestPacketLauncherRejectsCollisionAndMissingContract(t *testing.T) {
	for _, mode := range []string{"collision", "missing-session", "missing-control", "missing-data", "missing-files", "existing-flag"} {
		t.Run(mode, func(t *testing.T) {
			cmd, f := packetWiringCmd(t)
			switch mode {
			case "collision":
				f = cmd.ExtraFiles[0]
			case "missing-session":
				cmd.Args[1] = "--meridian-session-fd=4"
			case "missing-control":
				cmd.Args[2] = "--meridian-control-fd=5"
			case "missing-data":
				cmd.Args[3] = "--meridian-data-fd=6"
			case "missing-files":
				cmd.ExtraFiles = cmd.ExtraFiles[:2]
			case "existing-flag":
				cmd.Args = append(cmd.Args[:4], "--meridian-packet-fd=7", "--", "https://gateway.invalid")
			}
			if e := wireUniVPNPacket(cmd, f); e == nil {
				t.Fatal("accepted invalid packet contract")
			}
		})
	}
}
func TestPacketLauncherPostPrepareTamper(t *testing.T) {
	cmd, f := packetWiringCmd(t)
	if e := wireUniVPNPacket(cmd, f); e != nil {
		t.Fatal(e)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	isolation := &transportIsolation{mutate: func(c *exec.Cmd) { c.ExtraFiles[3] = nil }}
	if e := startUniVPNContained(context.Background(), cmd, isolation, func() error { t.Fatal("tampered fd6 started"); return nil }); e == nil {
		t.Fatal("tamper accepted")
	}
}
func TestPacketLauncherCloseFailurePreservesLifecycle(t *testing.T) {
	native := uniVPNPacketNative{owner: &launcherPacketFake{closeErr: errors.New("close")}}
	relay := &launcherPacketFake{}
	p := &uniVPNExecProcess{}
	stopped := false
	if e := closeUniVPNPacketLaunch(native, relay, p, func() error { stopped = true; return nil }, nil); e != nil || !stopped || p.launchCleanupErr == nil || relay.closes.Load() != 0 {
		t.Fatal("lost successful process lifecycle", e)
	}
	if e := closeUniVPNPacketLaunch(uniVPNPacketNative{}, &launcherPacketFake{closeErr: errors.New("close")}, nil, nil, errors.New("start")); e == nil {
		t.Fatal("lost cleanup error")
	} else {
		var ce *CleanupError
		if !errors.As(e, &ce) {
			t.Fatal("missing cleanup type")
		}
	}
}
func TestPacketLauncherWaitClosesOnlyUnclaimed(t *testing.T) {
	for _, claimed := range []bool{false, true} {
		p := &uniVPNExecProcess{cmd: &exec.Cmd{}, exited: make(chan struct{}), contained: make(chan struct{}), isolation: &transportIsolation{}}
		relay := &launcherPacketFake{}
		if !claimed {
			p.packet = relay
		}
		_ = p.Wait()
		want := int32(1)
		if claimed {
			want = 0
		}
		if relay.closes.Load() != want {
			t.Fatal("wrong packet ownership close")
		}
	}
}
func TestPacketLauncherWaitCloseFailureIsContainmentFailure(t *testing.T) {
	p := &uniVPNExecProcess{cmd: &exec.Cmd{}, exited: make(chan struct{}), contained: make(chan struct{}), isolation: &transportIsolation{}, packet: &launcherPacketFake{closeErr: errors.New("close")}}
	p.offer = newUniVPNOfferChannel()
	p.offer.terminal = true
	close(p.offer.done)
	e := p.Wait()
	var ce *CleanupError
	if !errors.As(e, &ce) || p.containmentErr == nil {
		t.Fatal("unclaimed cleanup uncertainty erased")
	}
	if e := (UniVPNNativeOfferSource{}).ProveClosed(context.Background(), p); e == nil {
		t.Fatal("source accepted uncertain packet cleanup")
	}
}
func TestPacketLauncherRequiresTransport(t *testing.T) {
	l := UniVPNExecLauncher{Isolation: &transportIsolation{}, NativeSessionChannel: true, PacketProvider: packetProviderFunc(func(context.Context, string) (*os.File, packetrelay.PacketIO, error) {
		t.Fatal("acquired without transport")
		return nil, nil, nil
	})}
	if _, e := l.Launch(context.Background(), "/never-executed", brokerArgs(), nil); e == nil {
		t.Fatal("packet mode without TCP accepted")
	}
}
