//go:build linux

package packetrelay

import (
	"context"
	"errors"
	"os"
	"regexp"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var errTUNResource = errors.New("TUN resource unavailable or changed")
var tunResourceName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,14}$`)

const tunPacketFlags = uint16(unix.IFF_TUN | unix.IFF_NO_PI)
const tunCreateFlags = tunPacketFlags | uint16(unix.IFF_TUN_EXCL)
const tunOpenFlags = unix.O_RDWR | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOFOLLOW
const tunDirectoryFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW

// TUNObservation describes a local descriptor readback, not a host lease,
// network policy, an NM activation, or independently proven network absence.
// The retained descriptor, never this name or value, is the resource authority.
// It does not identify or prove that the current namespace is the host namespace.
type TUNObservation struct {
	Name  string
	Flags uint16
}

// TUNResource owns one newly created, nonpersistent single-queue Linux TUN.
// It exposes no descriptor, PacketIO, duplication, adoption or reconnect API.
// It is not an NM HostAuthority/HostBinding. BindTUNRelay can attach one local
// relay owner, but acquisition alone does not start packet forwarding.
// Do not copy it. Close is mandatory even when AcquireTUN returns an error and
// a non-nil resource. No method asserts readiness, exclusivity, or host cleanup.
type TUNResource struct {
	self *TUNResource
	mu       sync.Mutex
	device   tunResourceDevice
	initial  TUNObservation
	observed bool
	closed   bool
	closeErr error
	relay    *TUNRelay // permanent one-shot ownership, retained after stop
}

// The alternate device exists only for package tests. Production always opens
// the fixed trusted device-node walk and uses real, retained descriptor ioctls.
type tunResourceDevice interface {
	create(string) error
	observe() (TUNObservation, error)
	pollable() error
	readPacket([]byte) (int, error)
	writePacket([]byte) (int, error)
	close() error
}

// AcquireTUN CHANGES NETWORKING if invoked: TUNSETIFF creates a new interface
// in the namespace captured when /dev/net/tun is opened. It is intentionally
// unconnected to the application. A deployment caller must separately authorize
// that mutation, its namespace, and the complete host policy before calling.
// No test in this repository invokes the production constructor successfully.
//
// Only an explicit trusted ASCII name (1-15 bytes) is accepted. There is no
// generated-name fallback or adoption after collision. EXCL prevents adoption
// at creation; it is not a continuing lease. No link-up, address, MTU, route,
// DNS, persistence, ownership, queue or namespace changes are requested here.
//
// Every acquired handle is retained before the mutating ioctl. Failure closes
// it once and returns the resource as well as the error, including sticky
// ErrCleanup on uncertain close. An ioctl failure can be post-mutation: it is
// never replayed. A successful close is not independently proven host absence.
// Context is checked around bounded operations but cannot interrupt a kernel
// syscall or a mutex wait. This context covers acquisition only; after return,
// the owner must Close even if that context later expires. Privileged concurrent
// changes remain out of scope.
func AcquireTUN(ctx context.Context, name string) (*TUNResource, error) {
	return acquireTUN(ctx, name, openTUNResourceDevice)
}

func acquireTUN(ctx context.Context, name string, open func() (tunResourceDevice, error)) (*TUNResource, error) {
	if ctx == nil || ctx.Err() != nil || !tunResourceName.MatchString(name) || open == nil {
		return nil, errTUNResource
	}
	device, err := open()
	if device == nil {
		if err == nil {
			err = errTUNResource
		}
		return nil, err
	}
	r := &TUNResource{device: device}
	r.self = r
	fail := func(err error) (*TUNResource, error) {
		if errors.Is(err, ErrCleanup) {
			r.closeErr = errors.Join(r.closeErr, err)
		}
		return r, errors.Join(errTUNResource, err, r.Close())
	}
	if err != nil || ctx.Err() != nil {
		return fail(errors.Join(err, ctx.Err()))
	}
	if err = device.create(name); err != nil {
		return fail(err)
	}
	if ctx.Err() != nil {
		return fail(ctx.Err())
	}
	first, err := device.observe()
	if err != nil || first.Name != name || first.Flags != tunPacketFlags {
		return fail(err)
	}
	r.initial, r.observed = first, true
	if ctx.Err() != nil {
		return fail(ctx.Err())
	}
	if err = device.pollable(); err != nil {
		return fail(err)
	}
	if ctx.Err() != nil {
		return fail(ctx.Err())
	}
	second, err := device.observe()
	if err != nil || first != second || ctx.Err() != nil {
		return fail(errors.Join(err, ctx.Err()))
	}
	return r, nil
}

// InitialObservation returns historical metadata even after Close, so local
// failure does not erase provenance. It is never a fresh liveness/readiness check.
func (r *TUNResource) InitialObservation() (TUNObservation, error) {
	if r == nil {
		return TUNObservation{}, errTUNResource
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.observed {
		return TUNObservation{}, errTUNResource
	}
	return r.initial, nil
}

// Observe reads only the original descriptor. Observed name/mode drift or a
// canceled/failed observation permanently closes this resource; it never opens a
// replacement by name. Matching sequential reads are not an atomic host snapshot.
func (r *TUNResource) Observe(ctx context.Context) (TUNObservation, error) {
	if r == nil {
		return TUNObservation{}, errTUNResource
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.device == nil || !r.observed {
		return TUNObservation{}, errors.Join(errTUNResource, r.closeErr)
	}
	if ctx == nil {
		return TUNObservation{}, errors.Join(errTUNResource, r.closeLocked())
	}
	if err := ctx.Err(); err != nil {
		return TUNObservation{}, errors.Join(errTUNResource, err, r.closeLocked())
	}
	value, err := r.device.observe()
	if err != nil || value != r.initial || ctx.Err() != nil {
		return TUNObservation{}, errors.Join(errTUNResource, err, ctx.Err(), r.closeLocked())
	}
	return value, nil
}

// Close performs only original-descriptor cleanup, at most once. A close error
// is sticky: Linux may already have released the numeric FD, so retrying it can
// close an unrelated resource. Neither nil nor an error proves network absence.
// Closing wakes an attached relay, but does not itself join its pumps. Its owner
// must use TUNRelay.Stop or Wait to establish local completion.
func (r *TUNResource) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closeLocked()
}

func (r *TUNResource) closeLocked() error {
	if !r.closed {
		r.closed = true
		if r.device != nil {
			if err := r.device.close(); err != nil {
				r.closeErr = errors.Join(r.closeErr, ErrCleanup, err)
			}
		}
	}
	return r.closeErr
}

type tunFileDevice struct {
	file *os.File
	raw  syscall.RawConn
}

// Roots and ancestors must be root-owned and not group/world writable. The
// node may be world writable (normal /dev/net/tun policy); kernel capabilities
// still govern creation. Root/mount-namespace compromise is not defended here.
func validTUNDirectory(st unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Uid == 0 && st.Mode&0022 == 0
}

func validTUNNode(st unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFCHR && st.Uid == 0 && st.Nlink == 1 && unix.Major(uint64(st.Rdev)) == 10 && unix.Minor(uint64(st.Rdev)) == 200
}

type tunPathOps struct {
	open   func(string, int, uint32) (int, error)
	openat func(int, string, int, uint32) (int, error)
	fstat  func(int, *unix.Stat_t) error
	close  func(int) error
}

func openTUNResourceDevice() (tunResourceDevice, error) {
	fd, err := openTUNPath(tunPathOps{unix.Open, unix.Openat, unix.Fstat, unix.Close})
	if fd < 0 {
		return nil, err
	}
	// os.NewFile sees the preexisting NONBLOCK flag and registers pollable I/O.
	// Ownership is retained before any subsequent failure and before TUNSETIFF.
	d := &tunFileDevice{file: os.NewFile(uintptr(fd), "meridian-owned-tun")}
	if err != nil {
		return d, err
	}
	d.raw, err = d.file.SyscallConn()
	return d, err
}

// A nonnegative return transfers the node FD even on error; directories are
// closed here, once, in reverse order. The caller owns node cleanup. The private
// callbacks let tests exercise every partial-open branch without real devices.
func openTUNPath(ops tunPathOps) (node int, resultErr error) {
	node = -1
	var dirs []int
	defer func() {
		for i := len(dirs) - 1; i >= 0; i-- {
			if err := ops.close(dirs[i]); err != nil {
				resultErr = errors.Join(resultErr, ErrCleanup, err)
			}
		}
	}()
	root, err := ops.open("/", tunDirectoryFlags, 0)
	if err != nil {
		return -1, err
	}
	dirs = append(dirs, root)
	for _, component := range []string{"", "dev", "net"} {
		if component != "" {
			fd, err := ops.openat(dirs[len(dirs)-1], component, tunDirectoryFlags, 0)
			if err != nil {
				return -1, err
			}
			dirs = append(dirs, fd)
		}
		var st unix.Stat_t
		if err := ops.fstat(dirs[len(dirs)-1], &st); err != nil {
			return -1, err
		}
		if !validTUNDirectory(st) {
			return -1, errTUNResource
		}
	}
	node, err = ops.openat(dirs[len(dirs)-1], "tun", tunOpenFlags, 0)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if err = ops.fstat(node, &st); err != nil {
		return node, err
	}
	if !validTUNNode(st) {
		return node, errTUNResource
	}
	return node, nil
}

// Passing the narrow ioctl seam only from private tests proves the request
// shape without opening a TUN or changing the machine's network configuration.
func createTUNOnDescriptor(raw syscall.RawConn, name string, ioctl func(int, uint, *unix.Ifreq) error) error {
	if raw == nil || ioctl == nil || !tunResourceName.MatchString(name) {
		return errTUNResource
	}
	request, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	request.SetUint16(tunCreateFlags)
	var opErr error
	err = raw.Control(func(fd uintptr) { opErr = ioctl(int(fd), unix.TUNSETIFF, request) })
	if err != nil || opErr != nil || request.Name() != name {
		return errors.Join(errTUNResource, err, opErr)
	}
	return nil
}

func (d *tunFileDevice) create(name string) error {
	return createTUNOnDescriptor(d.raw, name, unix.IoctlIfreq)
}

func (d *tunFileDevice) observe() (TUNObservation, error) {
	return observeTUNDescriptor(d.raw, unix.FcntlInt, unix.IoctlIfreq)
}

func observeTUNDescriptor(raw syscall.RawConn, fcntl func(uintptr, int, int) (int, error), ioctl func(int, uint, *unix.Ifreq) error) (TUNObservation, error) {
	if raw == nil || fcntl == nil || ioctl == nil {
		return TUNObservation{}, errTUNResource
	}
	request, err := unix.NewIfreq("")
	if err != nil {
		return TUNObservation{}, err
	}
	var opErr error
	err = raw.Control(func(fd uintptr) {
		// No Fd() call: it can change Go's poller/blocking behavior. Control
		// pins the original descriptor across all observations and close.
		flags, err := fcntl(fd, unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			opErr = errors.Join(errTUNResource, err)
			return
		}
		flags, err = fcntl(fd, unix.F_GETFL, 0)
		if err != nil || flags&unix.O_NONBLOCK == 0 || flags&unix.O_ACCMODE != unix.O_RDWR {
			opErr = errors.Join(errTUNResource, err)
			return
		}
		opErr = ioctl(int(fd), unix.TUNGETIFF, request)
	})
	if err = errors.Join(err, opErr); err != nil {
		return TUNObservation{}, err
	}
	return TUNObservation{Name: request.Name(), Flags: request.Uint16()}, nil
}

func (d *tunFileDevice) pollable() error {
	if err := d.file.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	return d.file.SetWriteDeadline(time.Time{})
}

func (d *tunFileDevice) close() error { return d.file.Close() }

func (d *tunFileDevice) readPacket(b []byte) (int, error) { return d.file.Read(b) }
func (d *tunFileDevice) writePacket(b []byte) (int, error) { return d.file.Write(b) }
