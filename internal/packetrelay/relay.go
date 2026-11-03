package packetrelay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

// PacketIO preserves packet boundaries. Each ReadPacket returns ONE whole
// packet, or an error on truncation; WritePacket writes one complete packet.
// Close MUST promptly unblock concurrent reads AND writes, be concurrency-safe,
// and must not transfer ownership elsewhere. Endpoints must be distinct.
// Stream sockets/pipes are NOT PacketIO without a bounded framing adapter.
type PacketIO interface {
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) (int, error)
	Close() error
}

// FilePackets wraps an already-open packet-oriented device (e.g. IFF_TUN with
// IFF_NO_PI). It never opens/configures devices, routes, DNS, or sockets. The
// caller must guarantee one read/write per packet and close-unblock semantics
// (normally a nonblocking, pollable descriptor). Regular files and streams are
// unsupported. Host FilePackets MUST stay in the trusted broker process.
// Read buffers in Run are max+1, so even a truncating device cannot turn an
// oversized packet into an accepted packet. No duplicated descriptor is made.
type FilePackets struct {
	file     *os.File
	once     sync.Once
	closeErr error
}

// NewFilePackets accepts only pollable Linux TUN devices verified with a
// read-only TUNGETIFF query as exactly IFF_TUN|IFF_NO_PI. The caller retains
// ownership on error. Multi-queue and offload/virtual-header modes are refused. Sockets, regular files and pipes are refused; child
// datagram channels need their own message-aware PacketIO implementation.
func NewFilePackets(f *os.File) (*FilePackets, error) {
	if f == nil {
		return nil, errors.New("nil packet file")
	}
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeCharDevice == 0 {
		return nil, errors.New("packet endpoint is not a character device")
	}
	if err = verifyPacketDevice(f); err != nil {
		return nil, err
	}
	// os.File deadlines require runtime poller support, which also provides
	// Close-unblocks-I/O. Do not accept a blocking/unpollable device descriptor.
	if err = f.SetReadDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("unpollable packet device: %w", err)
	}
	if err = f.SetWriteDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("unpollable packet device: %w", err)
	}
	return &FilePackets{file: f}, nil
}
func (f *FilePackets) ReadPacket(b []byte) (int, error)  { return f.file.Read(b) }
func (f *FilePackets) WritePacket(b []byte) (int, error) { return f.file.Write(b) }
func (f *FilePackets) Close() error {
	f.once.Do(func() { f.closeErr = f.file.Close() })
	return f.closeErr
}

// ErrCleanup identifies uncertain endpoint teardown; callers must quarantine
// the session rather than reusing resources or treating cancellation as clean.
var ErrCleanup = errors.New("packet relay cleanup uncertain")

type Counts struct{ Outbound, Inbound, Rejected uint64 }

// Run takes ownership of both endpoints. Host packets flow outbound to the
// child channel; child packets flow inbound to host. An invalid packet, I/O
// error, short write, cancellation, or oversized packet tears down BOTH sides.
// No packet contents are logged. On return both pump goroutines have stopped.
// Callers must not reuse endpoints or pass the host descriptor to the child.
func nilEndpoint(v PacketIO) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}
func sameEndpoint(a, b PacketIO) bool {
	return !nilEndpoint(a) && !nilEndpoint(b) && reflect.TypeOf(a).Comparable() && reflect.TypeOf(a) == reflect.TypeOf(b) && a == b
}
func Run(ctx context.Context, p *Policy, host, child PacketIO) (counts Counts, result error) {
	var out, in, rejected atomic.Uint64
	var once sync.Once
	var closeErr error
	closeBoth := func() {
		once.Do(func() {
			if !nilEndpoint(host) {
				closeErr = errors.Join(closeErr, host.Close())
			}
			if !nilEndpoint(child) && !sameEndpoint(host, child) {
				closeErr = errors.Join(closeErr, child.Close())
			}
		})
	}
	defer func() {
		closeBoth()
		if closeErr != nil {
			result = errors.Join(result, ErrCleanup, closeErr)
		}
	}()
	if ctx == nil || p == nil || nilEndpoint(host) || nilEndpoint(child) || sameEndpoint(host, child) {
		return Counts{}, errors.New("invalid relay configuration")
	}
	if err := ctx.Err(); err != nil {
		return Counts{}, err
	}
	done := make(chan error, 2)
	pump := func(src, dst PacketIO, d Direction, n *atomic.Uint64) {
		b := make([]byte, p.cfg.MaxPacketSize+1)
		for {
			size, err := src.ReadPacket(b)
			if err != nil {
				done <- fmt.Errorf("packet read: %w", err)
				return
			}
			if size <= 0 || size > p.cfg.MaxPacketSize {
				rejected.Add(1)
				done <- ErrRejected
				return
			}
			if err = p.Validate(b[:size], d); err != nil {
				rejected.Add(1)
				done <- err
				return
			}
			sizeWritten, err := dst.WritePacket(b[:size])
			if err != nil {
				done <- fmt.Errorf("packet write: %w", err)
				return
			}
			if sizeWritten != size {
				done <- io.ErrShortWrite
				return
			}
			n.Add(1)
		}
	}
	go pump(host, child, Outbound, &out)
	go pump(child, host, Inbound, &in)
	var err error
	select {
	case err = <-done:
		closeBoth()
		<-done
	case <-ctx.Done():
		err = ctx.Err()
		closeBoth()
		<-done
		<-done
	}
	return Counts{Outbound: out.Load(), Inbound: in.Load(), Rejected: rejected.Load()}, err
}
