//go:build linux

// Package fdtransport validates and owns duplicated preconnected transport FDs.
// It does not create connections, launch processes, or establish isolation.
package fdtransport

import (
	"errors"
	"net/netip"
	"os"
	"runtime"
	"syscall"
)

// Endpoint is trusted broker policy, never an unvalidated gateway redirect.
type Endpoint struct {
	Address netip.Addr
	Port    uint16
}
type socketState struct {
	kind, protocol int
	peer           Endpoint
	device, inode  uint64
}
type socketOps interface {
	duplicate(int) (int, error)
	inspect(int) (socketState, error)
	close(int) error
}
type linuxOps struct{}

func (linuxOps) duplicate(fd int) (int, error) {
	n, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_DUPFD_CLOEXEC, 3)
	if e != 0 {
		return -1, e
	}
	return int(n), nil
}
func (linuxOps) close(fd int) error { return syscall.Close(fd) }
func (linuxOps) inspect(fd int) (socketState, error) {
	var s socketState
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return s, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		return s, errors.New("descriptor is not a socket")
	}
	s.device, s.inode = uint64(st.Dev), st.Ino
	var err error
	if s.kind, err = syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE); err != nil {
		return s, err
	}
	if s.protocol, err = syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_PROTOCOL); err != nil {
		return s, err
	}
	peer, err := syscall.Getpeername(fd)
	if err != nil {
		return s, err
	}
	switch a := peer.(type) {
	case *syscall.SockaddrInet4:
		s.peer = Endpoint{netip.AddrFrom4(a.Addr), uint16(a.Port)}
	default:
		return s, errors.New("IPv4 TCP peer required")
	}
	return s, nil
}

// Sockets owns two different connected TCP socket descriptions. Closing these
// duplicates does not close callers' originals. Callers must stop using originals
// before releasing an isolated worker: FD duplication shares socket state.
type Sockets struct{ control, data *os.File }

// Prepare duplicates first, then inspects the owned duplicates to avoid an fd
// number reuse race. The caller must exclusively own inputs during this call.
// Only IPv4 is supported by the current native packet transport.
func Prepare(control, data *os.File, endpoint Endpoint) (*Sockets, error) {
	if control == nil || data == nil {
		return nil, errors.New("two socket descriptors required")
	}
	fds, err := prepare(linuxOps{}, int(control.Fd()), int(data.Fd()), endpoint)
	// Raw syscall fd arguments do not keep os.File finalizers alive.
	runtime.KeepAlive(control)
	runtime.KeepAlive(data)
	if err != nil {
		return nil, err
	}
	return &Sockets{os.NewFile(uintptr(fds[0]), "meridian-control"), os.NewFile(uintptr(fds[1]), "meridian-data")}, nil
}
func prepare(ops socketOps, control, data int, endpoint Endpoint) ([2]int, error) {
	out := [2]int{-1, -1}
	if !endpoint.Address.Is4() || endpoint.Address.IsUnspecified() || endpoint.Address.IsMulticast() || endpoint.Port == 0 {
		return out, errors.New("explicit IPv4 TCP endpoint required")
	}
	var states [2]socketState
	for i, fd := range []int{control, data} {
		dup, err := ops.duplicate(fd)
		if err == nil {
			out[i] = dup
			states[i], err = ops.inspect(dup)
		}
		if err == nil && (states[i].kind != syscall.SOCK_STREAM || states[i].protocol != syscall.IPPROTO_TCP || states[i].peer != endpoint) {
			err = errors.New("connected TCP endpoint mismatch")
		}
		if err != nil {
			for _, v := range out {
				if v >= 0 {
					_ = ops.close(v)
				}
			}
			return [2]int{-1, -1}, errors.New("transport descriptor validation failed")
		}
	}
	if states[0].inode == 0 || states[1].inode == 0 || (states[0].device == states[1].device && states[0].inode == states[1].inode) {
		_ = ops.close(out[0])
		_ = ops.close(out[1])
		return [2]int{-1, -1}, errors.New("control and data require distinct sockets")
	}
	return out, nil
}

// Files returns control then data for exec.Cmd.ExtraFiles. The caller chooses
// the child fd numbers and passes those exact numbers to the patched native
// executable. This is not an authorization to start it: trusted bootstrap,
// TUN ownership, TLS hostname verification and network policy remain required.
// Sockets must stay open until Start returns. Do not call concurrently with Close.
func (s *Sockets) Files() ([]*os.File, error) {
	if s == nil || s.control == nil || s.data == nil {
		return nil, errors.New("transport descriptors closed")
	}
	return []*os.File{s.control, s.data}, nil
}
func (s *Sockets) Close() error {
	if s == nil {
		return nil
	}
	var errs []error
	if s.control != nil {
		errs = append(errs, s.control.Close())
		s.control = nil
	}
	if s.data != nil {
		errs = append(errs, s.data.Close())
		s.data = nil
	}
	return errors.Join(errs...)
}
