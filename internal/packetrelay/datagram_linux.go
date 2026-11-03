//go:build linux

package packetrelay

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
)

// DatagramPackets owns an inherited, connected, nonblocking, unnamed AF_UNIX
// SOCK_SEQPACKET socket. It never creates, binds, listens on, connects, or changes
// flags on a socket. This is the child's packet channel, never its host TUN.
type DatagramPackets struct {
	file     *os.File
	raw      syscall.RawConn
	recv     func(int, []byte) (int, int, error)
	send     func(int, []byte) (int, error)
	once     sync.Once
	closeErr error
}

// NewDatagramPackets verifies transport type and connection before ownership
// transfer. Caller retains ownership on failure. Neither the caller nor another
// descriptor owner may subsequently change the socket configuration or flags.
func NewDatagramPackets(f *os.File) (*DatagramPackets, error) {
	if f == nil {
		return nil, errors.New("nil packet socket")
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var opErr error
	err = raw.Control(func(fd uintptr) {
		var st syscall.Stat_t
		if opErr = syscall.Fstat(int(fd), &st); opErr != nil {
			return
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
			opErr = errors.New("packet channel is not a socket")
			return
		}
		var typ int
		typ, opErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TYPE)
		if opErr != nil {
			return
		}
		if typ != syscall.SOCK_SEQPACKET {
			opErr = errors.New("packet channel must be SOCK_SEQPACKET")
			return
		}
		protocol, e := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PROTOCOL)
		if e != nil {
			opErr = e
			return
		}
		if protocol != 0 {
			opErr = errors.New("packet channel requires protocol zero")
			return
		}
		var a syscall.Sockaddr
		a, opErr = syscall.Getsockname(int(fd))
		if opErr != nil {
			return
		}
		if opErr = unnamedUnix(a); opErr != nil {
			return
		}
		a, opErr = syscall.Getpeername(int(fd))
		if opErr != nil {
			return
		}
		if opErr = unnamedUnix(a); opErr != nil {
			return
		}
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
		if errno != 0 {
			opErr = errno
			return
		}
		if flags&syscall.O_NONBLOCK == 0 {
			opErr = errors.New("packet channel must already be nonblocking")
		}
	})
	if err = errors.Join(err, opErr); err != nil {
		return nil, err
	}
	if err = f.SetReadDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("unpollable packet socket: %w", err)
	}
	if err = f.SetWriteDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("unpollable packet socket: %w", err)
	}
	return &DatagramPackets{file: f, raw: raw, recv: receiveMessage, send: sendMessage}, nil
}

// No ancillary buffer is supplied: SCM_RIGHTS are not accepted. Linux closes
// descriptors discarded by control truncation; MSG_CTRUNC is a fatal error.
func (d *DatagramPackets) ReadPacket(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, ErrRejected
	}
	var n, flags int
	var opErr error
	err := d.raw.Read(func(fd uintptr) bool {
		for {
			n, flags, opErr = d.recv(int(fd), b)
			if opErr != syscall.EINTR {
				break
			}
		}
		return opErr != syscall.EAGAIN && opErr != syscall.EWOULDBLOCK
	})
	if err != nil {
		return 0, err
	}
	if opErr != nil {
		return 0, opErr
	}
	if flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
		return 0, ErrRejected
	}
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}
func (d *DatagramPackets) WritePacket(b []byte) (int, error) {
	if len(b) == 0 || len(b) > 65535 {
		return 0, ErrRejected
	}
	var n int
	var opErr error
	err := d.raw.Write(func(fd uintptr) bool {
		for {
			n, opErr = d.send(int(fd), b)
			if opErr != syscall.EINTR {
				break
			}
		}
		return opErr != syscall.EAGAIN && opErr != syscall.EWOULDBLOCK
	})
	if err != nil {
		return 0, err
	}
	if opErr != nil {
		return n, opErr
	}
	if n != len(b) {
		return n, io.ErrShortWrite
	}
	return n, nil
}
func (d *DatagramPackets) Close() error {
	d.once.Do(func() { d.closeErr = d.file.Close() })
	return d.closeErr
}

func receiveMessage(fd int, b []byte) (int, int, error) {
	n, _, flags, _, err := syscall.Recvmsg(fd, b, nil, syscall.MSG_DONTWAIT|syscall.MSG_CMSG_CLOEXEC)
	return n, flags, err
}
func sendMessage(fd int, b []byte) (int, error) {
	return syscall.SendmsgN(fd, b, nil, nil, syscall.MSG_DONTWAIT|syscall.MSG_NOSIGNAL)
}

func unnamedUnix(a syscall.Sockaddr) error {
	u, ok := a.(*syscall.SockaddrUnix)
	if !ok || u == nil || u.Name != "" {
		return errors.New("packet channel requires unnamed AF_UNIX endpoints")
	}
	return nil
}
