//go:build linux

package packetrelay

import (
	"errors"
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

func TestUnnamedUnixOnly(t *testing.T) {
	if e := unnamedUnix(&syscall.SockaddrUnix{}); e != nil {
		t.Fatal(e)
	}
	var nilUnix *syscall.SockaddrUnix
	for _, a := range []syscall.Sockaddr{nil, nilUnix, &syscall.SockaddrUnix{Name: "/tmp/denied"}, &syscall.SockaddrUnix{Name: "@abstract"}, &syscall.SockaddrInet4{}} {
		if unnamedUnix(a) == nil {
			t.Fatal("non-private endpoint accepted")
		}
	}
}
