//go:build linux

package packetrelay

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"
)

// These callbacks are injected; no socket/socketpair/connect/listen is executed.
type fakeRaw struct {
	retries int
	err     error
}

func (f *fakeRaw) Control(fn func(uintptr)) error {
	if f.err != nil {
		return f.err
	}
	fn(0)
	return nil
}
func (f *fakeRaw) Read(fn func(uintptr) bool) error {
	if f.err != nil {
		return f.err
	}
	for i := 0; i < 4; i++ {
		if fn(0) {
			return nil
		}
		f.retries++
	}
	return errors.New("fake poll exhausted")
}
func (f *fakeRaw) Write(fn func(uintptr) bool) error { return f.Read(fn) }
func TestDatagramReadTruncationAndRetry(t *testing.T) {
	for _, flag := range []int{0, syscall.MSG_TRUNC, syscall.MSG_CTRUNC} {
		raw := &fakeRaw{}
		calls := 0
		d := &DatagramPackets{raw: raw, recv: func(_ int, b []byte) (int, int, error) {
			calls++
			if calls == 1 {
				return 0, 0, syscall.EINTR
			}
			if calls == 2 {
				return 0, 0, syscall.EAGAIN
			}
			copy(b, "abc")
			return 3, flag, nil
		}}
		n, e := d.ReadPacket(make([]byte, 4))
		if flag != 0 {
			if !errors.Is(e, ErrRejected) || n != 0 {
				t.Fatal("accepted truncation")
			}
		} else if e != nil || n != 3 {
			t.Fatalf("%d %v", n, e)
		}
		if raw.retries != 1 || calls != 3 {
			t.Fatal("poll retry wrong")
		}
	}
}
func TestDatagramWriteAtomicity(t *testing.T) {
	for _, short := range []bool{false, true} {
		raw := &fakeRaw{}
		calls := 0
		d := &DatagramPackets{raw: raw, send: func(_ int, b []byte) (int, error) {
			calls++
			if calls == 1 {
				return 0, syscall.EAGAIN
			}
			if short {
				return len(b) - 1, nil
			}
			return len(b), nil
		}}
		n, e := d.WritePacket([]byte("abc"))
		if short {
			if !errors.Is(e, io.ErrShortWrite) {
				t.Fatal("short write accepted")
			}
		} else if e != nil || n != 3 {
			t.Fatalf("%d %v", n, e)
		}
		if raw.retries != 1 || calls != 2 {
			t.Fatal("poll retry wrong")
		}
	}
}
func TestDatagramPollError(t *testing.T) {
	d := &DatagramPackets{raw: &fakeRaw{err: os.ErrClosed}}
	if _, e := d.ReadPacket(make([]byte, 2)); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
	if _, e := d.WritePacket([]byte("x")); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
}
func TestDatagramRejectsRegularFile(t *testing.T) {
	f, e := os.CreateTemp(t.TempDir(), "no-socket")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = NewDatagramPackets(f); e == nil {
		t.Fatal("regular file accepted")
	}
	if _, e = f.Stat(); e != nil {
		t.Fatal("ownership lost on error")
	}
	if _, e = NewDatagramPackets(nil); e == nil {
		t.Fatal("nil accepted")
	}
}

// These tests create only local socketpairs; no listener, IP socket, TUN,
// route, DNS, credentials or live VPN configuration is used.
func TestUnnamedUnixOnly(t *testing.T) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	files := [2]*os.File{
		os.NewFile(uintptr(pair[0]), "unnamed-packet"),
		os.NewFile(uintptr(pair[1]), "unnamed-peer"),
	}
	defer files[0].Close()
	defer files[1].Close()
	for i, fd := range pair {
		for _, peer := range []bool{false, true} {
			if err := unnamedUnixFD(fd, peer); err != nil {
				t.Fatalf("unnamed endpoint (peer=%v): %v", peer, err)
			}
		}
		p, err := NewDatagramPackets(files[i])
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
	}
}

func TestDatagramRejectsNamedLocalAndPeer(t *testing.T) {
	for _, tc := range []struct {
		label string
		name  string
	}{
		{"empty-abstract", "@"},
		{"abstract", fmt.Sprintf("@meridian-unnamed-%d", os.Getpid())},
		{"pathname", t.TempDir() + "/named"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			files := [2]*os.File{
				os.NewFile(uintptr(pair[0]), "named-packet"),
				os.NewFile(uintptr(pair[1]), "peer-packet"),
			}
			defer files[0].Close()
			defer files[1].Close()
			// A connected socketpair endpoint can be bound without creating a
			// listener. The other endpoint then has a named peer.
			if err := syscall.Bind(pair[0], &syscall.SockaddrUnix{Name: tc.name}); err != nil {
				t.Fatal(err)
			}
			if unnamedUnixFD(pair[0], false) == nil || unnamedUnixFD(pair[1], true) == nil {
				t.Fatal("named local or peer endpoint accepted")
			}
			for _, f := range files {
				if p, err := NewDatagramPackets(f); err == nil {
					p.Close()
					t.Fatal("named packet channel accepted")
				}
				if _, err := f.Stat(); err != nil {
					t.Fatal("ownership lost on rejection", err)
				}
			}
		})
	}
}

func TestDatagramRejectsUnconnectedSocket(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "unconnected-packet")
	defer f.Close()
	if p, err := NewDatagramPackets(f); err == nil {
		p.Close()
		t.Fatal("unconnected endpoint accepted")
	}
	if _, err := f.Stat(); err != nil {
		t.Fatal("ownership lost on rejection", err)
	}
	for _, peer := range []bool{false, true} {
		if err := unnamedUnixFD(-1, peer); !errors.Is(err, syscall.EBADF) {
			t.Fatalf("invalid descriptor (peer=%v): %v", peer, err)
		}
	}
}
