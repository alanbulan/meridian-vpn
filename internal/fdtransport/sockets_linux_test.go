//go:build linux

package fdtransport

import (
	"errors"
	"net/netip"
	"os"
	"syscall"
	"testing"
)

type fakeOps struct {
	states             map[int]socketState
	closed             []int
	dupErr, inspectErr int
}

func (f *fakeOps) duplicate(fd int) (int, error) {
	if fd == f.dupErr {
		return -1, errors.New("dup")
	}
	return fd + 10, nil
}
func (f *fakeOps) inspect(fd int) (socketState, error) {
	if fd == f.inspectErr {
		return socketState{}, errors.New("inspect")
	}
	return f.states[fd], nil
}
func (f *fakeOps) close(fd int) error { f.closed = append(f.closed, fd); return nil }
func fixture() (*fakeOps, Endpoint) {
	e := Endpoint{netip.MustParseAddr("192.0.2.1"), 443}
	return &fakeOps{states: map[int]socketState{13: {syscall.SOCK_STREAM, syscall.IPPROTO_TCP, e, 1, 100}, 14: {syscall.SOCK_STREAM, syscall.IPPROTO_TCP, e, 1, 101}}}, e
}
func TestPrepare(t *testing.T) {
	f, e := fixture()
	got, err := prepare(f, 3, 4, e)
	if err != nil || got != [2]int{13, 14} || len(f.closed) != 0 {
		t.Fatalf("%v %v %v", got, err, f.closed)
	}
}
func TestRejectAndClose(t *testing.T) {
	for _, name := range []string{"duplicate", "inspect", "datagram", "protocol", "peer", "same", "zero"} {
		t.Run(name, func(t *testing.T) {
			f, e := fixture()
			s := f.states[14]
			switch name {
			case "duplicate":
				f.dupErr = 4
			case "inspect":
				f.inspectErr = 14
			case "datagram":
				s.kind = syscall.SOCK_DGRAM
			case "protocol":
				s.protocol = 0
			case "peer":
				s.peer.Port++
			case "same":
				s.inode = 100
			case "zero":
				s.inode = 0
			}
			f.states[14] = s
			if _, err := prepare(f, 3, 4, e); err == nil {
				t.Fatal("accepted")
			}
			want := 2
			if name == "duplicate" {
				want = 1
			}
			if len(f.closed) != want {
				t.Fatalf("closed %v", f.closed)
			}
		})
	}
}
func TestBadPolicyNoDescriptors(t *testing.T) {
	for _, ip := range []string{"::1", "::ffff:192.0.2.1", "0.0.0.0", "224.0.0.1"} {
		f, e := fixture()
		e.Address = netip.MustParseAddr(ip)
		if _, err := prepare(f, 3, 4, e); err == nil || len(f.closed) != 0 {
			t.Fatal(ip)
		}
	}
}
func TestPipeRejectedWithoutClosingInput(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	_, e := fixture()
	if s, err := Prepare(r, w, e); err == nil {
		s.Close()
		t.Fatal("pipe accepted")
	}
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatal("input was closed", err)
	}
}
func TestClosedBundle(t *testing.T) {
	s := &Sockets{}
	if _, err := s.Files(); err == nil {
		t.Fatal("empty accepted")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFirstDescriptorFailure(t *testing.T) {
	for _, inspect := range []bool{false, true} {
		f, e := fixture()
		if inspect {
			f.inspectErr = 13
		} else {
			f.dupErr = 3
		}
		if _, err := prepare(f, 3, 4, e); err == nil {
			t.Fatal("accepted failed first descriptor")
		}
		want := 0
		if inspect {
			want = 1
		}
		if len(f.closed) != want {
			t.Fatalf("closed %v", f.closed)
		}
	}
}
func TestZeroPortAndMissingInputs(t *testing.T) {
	f, e := fixture()
	e.Port = 0
	if _, err := prepare(f, 3, 4, e); err == nil {
		t.Fatal("zero port accepted")
	}
	if _, err := Prepare(nil, nil, e); err == nil {
		t.Fatal("nil inputs accepted")
	}
}
func TestBundleOwnership(t *testing.T) {
	// Exercise ownership methods with ordinary files, without claiming these are
	// validated sockets or allowing this test-only bundle into production launch.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	s := &Sockets{r, w}
	files, err := s.Files()
	if err != nil || len(files) != 2 || files[0] != r || files[1] != w {
		t.Fatal("wrong descriptor order", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal("close not idempotent", err)
	}
	if _, err := s.Files(); err == nil {
		t.Fatal("closed bundle returned files")
	}
	var nilBundle *Sockets
	if err := nilBundle.Close(); err != nil {
		t.Fatal(err)
	}
}
