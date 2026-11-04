//go:build linux

package core

import (
	"context"
	"errors"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// UniVPNNMNamespaceObservation contains two matching samples from the original
// child's creation-time pidfd, after its native offer was bound. PID is only a
// diagnostic label; no numeric PID is looked up to acquire this identity.
// Namespace identities are relative to the observer, never proof of initial
// host namespaces, confinement, exclusive administration or execution history.
// Sampling is not atomic and cannot exclude changes between reads, ABA changes,
// or changes immediately after return. This value confers no host authority.
type UniVPNNMNamespaceObservation struct {
	Session   string
	PID       int
	NetworkNS UniVPNObservedInode
	MountNS   UniVPNObservedInode
	UserNS    UniVPNObservedInode
	PIDNS     UniVPNObservedInode // active PID namespace, not pid_for_children
}

var errUniVPNNamespaceObservation = errors.New("original native pidfd namespace observation unavailable")

// All syscall substitution is private to non-executing fixtures. Production
// supplies uniVPNRealPidfdKernel and a descriptor returned by this cmd.Start,
// never pidfd_open, /proc rediscovery, or a caller-supplied PID/descriptor.
type uniVPNPidfdKernel interface {
	flags(int) (int, error)
	dup(int) (int, error)
	ioctl(int, uint) (int, error)
	stat(int) (syscall.Stat_t, error)
	fs(int) (int64, error)
	close(int) error
}

type uniVPNRealPidfdKernel struct{}

func (uniVPNRealPidfdKernel) flags(fd int) (int, error) {
	return unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
}
func (uniVPNRealPidfdKernel) dup(fd int) (int, error) {
	return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
}
func (uniVPNRealPidfdKernel) ioctl(fd int, request uint) (int, error) {
	// Linux v6.16 fs/pidfs.c requires arg == 0 for namespace acquisition.
	// NS_GET_NSTYPE also returns its result directly, without an output pointer.
	n, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(request), 0)
	if err != 0 {
		return -1, err
	}
	return int(n), nil
}
func (uniVPNRealPidfdKernel) stat(fd int) (syscall.Stat_t, error) {
	var st syscall.Stat_t
	err := syscall.Fstat(fd, &st)
	return st, err
}
func (uniVPNRealPidfdKernel) fs(fd int) (int64, error) {
	var st syscall.Statfs_t
	err := syscall.Fstatfs(fd, &st)
	return int64(st.Type), err
}
func (uniVPNRealPidfdKernel) close(fd int) error { return syscall.Close(fd) }

type uniVPNPidfdObservation struct {
	mu          sync.Mutex
	kernel      uniVPNPidfdKernel
	fd, pid     int
	active      int
	unavailable bool
	closed      bool
	cleanupErr  error
}

// Takes exclusive ownership even if validation fails. The original stays owned
// until Wait so a failed optional observation cannot silently drop cleanup
// errors or accidentally close a reused descriptor. Never retry a failed close.
func retainUniVPNCreationPidfd(fd, pid int, k uniVPNPidfdKernel) *uniVPNPidfdObservation {
	o := &uniVPNPidfdObservation{kernel: k, fd: fd, pid: pid}
	if fd < 0 || pid <= 0 || k == nil {
		o.unavailable = true
		return o
	}
	flags, err := k.flags(fd)
	if err != nil || flags&syscall.FD_CLOEXEC == 0 {
		o.unavailable = true
	}
	return o
}

// startUniVPNProcessWithPidfd installs the output slot before the actual Start.
// Go's os.ensurePidfd/getPidfd duplicates a supplied SysProcAttr.PidFD for its
// internal Process handle; this supplied descriptor remains our responsibility.
// There is no retry without pidfd support and no numeric-PID fallback.
func startUniVPNProcessWithPidfd(ctx context.Context, p *uniVPNExecProcess, start func() error, k uniVPNPidfdKernel) (err error) {
	if p == nil || p.cmd == nil || p.cmd.SysProcAttr == nil || p.cmd.SysProcAttr.PidFD != nil || p.namespaces != nil || k == nil {
		return errors.New("invalid native pidfd capture")
	}
	fd := -1 // syscall may leave the slot unchanged on an early Start failure.
	p.cmd.SysProcAttr.PidFD = &fd
	err = startUniVPNContained(ctx, p.cmd, p.isolation, start)
	// The concrete cgroup starter copies SysProcAttr, preserving this pointer.
	if p.cmd.SysProcAttr != nil && p.cmd.SysProcAttr.PidFD == &fd {
		p.cmd.SysProcAttr.PidFD = nil
	}
	pid := 0
	if p.cmd.Process != nil {
		pid = p.cmd.Process.Pid
	}
	p.namespaces = retainUniVPNCreationPidfd(fd, pid, k)
	if err != nil || pid <= 0 {
		if err == nil {
			err = errors.New("native start returned no process")
		}
		// Failed Start normally sets fd back to -1 after Go's own cleanup. A
		// partial provider result still owns its descriptor and child separately.
		err = errors.Join(err, p.namespaces.close())
	}
	return err
}

func (o *uniVPNPidfdObservation) close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closed = true
	if o.active != 0 {
		// Invalidate promptly rather than block Wait behind an ioctl. In-flight
		// duplicates are operation-owned and must not be claimed already closed.
		o.cleanupErr = &CleanupError{}
	}
	if o.fd >= 0 {
		fd := o.fd
		o.fd = -1
		if o.kernel == nil || o.kernel.close(fd) != nil {
			o.cleanupErr = &CleanupError{}
		}
	}
	return o.cleanupErr
}

func (o *uniVPNPidfdObservation) observe(ctx context.Context) (result UniVPNNMNamespaceObservation, err error) {
	if o == nil || ctx == nil || ctx.Err() != nil {
		return result, errUniVPNNamespaceObservation
	}
	o.mu.Lock()
	if o.closed || o.unavailable || o.cleanupErr != nil || o.fd < 0 || o.kernel == nil {
		err := errors.Join(errUniVPNNamespaceObservation, o.cleanupErr)
		o.mu.Unlock()
		return result, err
	}
	k := o.kernel
	fd, dupErr := k.dup(o.fd)
	if dupErr != nil || fd < 0 {
		o.unavailable = true
		if fd >= 0 && k.close(fd) != nil {
			o.cleanupErr = &CleanupError{}
		}
		err := errors.Join(errUniVPNNamespaceObservation, o.cleanupErr)
		o.mu.Unlock()
		return result, err
	}
	o.active++
	pid := o.pid
	o.mu.Unlock()
	defer func() {
		closeErr := k.close(fd)
		o.mu.Lock()
		defer o.mu.Unlock()
		o.active--
		var cleanup *CleanupError
		if closeErr != nil || errors.As(err, &cleanup) {
			o.cleanupErr = &CleanupError{}
		}
		if err != nil || ctx.Err() != nil {
			o.unavailable = true
		}
		if o.closed || o.unavailable || o.cleanupErr != nil {
			result, err = UniVPNNMNamespaceObservation{}, errors.Join(errUniVPNNamespaceObservation, o.cleanupErr)
		}
	}()
	flags, err := k.flags(fd)
	if err != nil || flags&syscall.FD_CLOEXEC == 0 {
		return result, errUniVPNNamespaceObservation
	}
	first, err := readUniVPNPidfdNamespaces(ctx, k, fd, pid)
	if err != nil {
		return result, err
	}
	second, err := readUniVPNPidfdNamespaces(ctx, k, fd, pid)
	if err != nil || first != second || ctx.Err() != nil {
		return result, errors.Join(errUniVPNNamespaceObservation, err)
	}
	return second, nil
}

func readUniVPNPidfdNamespaces(ctx context.Context, k uniVPNPidfdKernel, fd, pid int) (UniVPNNMNamespaceObservation, error) {
	result := UniVPNNMNamespaceObservation{PID: pid}
	for _, ns := range []struct {
		request uint
		kind    int
		value   *UniVPNObservedInode
	}{
		{unix.PIDFD_GET_NET_NAMESPACE, unix.CLONE_NEWNET, &result.NetworkNS},
		{unix.PIDFD_GET_MNT_NAMESPACE, unix.CLONE_NEWNS, &result.MountNS},
		{unix.PIDFD_GET_USER_NAMESPACE, unix.CLONE_NEWUSER, &result.UserNS},
		{unix.PIDFD_GET_PID_NAMESPACE, unix.CLONE_NEWPID, &result.PIDNS},
	} {
		value, err := readUniVPNPidfdNamespace(ctx, k, fd, ns.request, ns.kind)
		if err != nil {
			return UniVPNNMNamespaceObservation{}, err
		}
		*ns.value = value
	}
	return result, nil
}

func readUniVPNPidfdNamespace(ctx context.Context, k uniVPNPidfdKernel, pidfd int, request uint, expected int) (result UniVPNObservedInode, err error) {
	if ctx.Err() != nil {
		return result, errUniVPNNamespaceObservation
	}
	fd, err := k.ioctl(pidfd, request)
	if err != nil || fd < 0 {
		return result, errUniVPNNamespaceObservation
	}
	defer func() {
		if k.close(fd) != nil {
			result, err = UniVPNObservedInode{}, errors.Join(errUniVPNNamespaceObservation, &CleanupError{})
		}
	}()
	flags, err := k.flags(fd)
	if err != nil || flags&syscall.FD_CLOEXEC == 0 {
		return result, errUniVPNNamespaceObservation
	}
	fs, err := k.fs(fd)
	if err != nil || fs != uniVPNNSMagic {
		return result, errUniVPNNamespaceObservation
	}
	st, err := k.stat(fd)
	if err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Ino == 0 {
		return result, errUniVPNNamespaceObservation
	}
	kind, err := k.ioctl(fd, unix.NS_GET_NSTYPE)
	if err != nil || kind != expected || ctx.Err() != nil {
		return result, errUniVPNNamespaceObservation
	}
	return UniVPNObservedInode{Device: uint64(st.Dev), Inode: st.Ino}, nil
}

// ObserveNativeNamespaces is optional, read-only diagnostics for this broker's
// concrete original native child. It neither identifies an initial host nor
// grants a lease, implements HostBinding, publishes policy, or makes it ready.
// All four namespaces must be available and agree across two samples. Missing
// kernel support, access denial, exit, change, or cleanup uncertainty yields no
// partial result and permanently invalidates these optional observations.
// Kernel operations are not guaranteed interruptible. Concurrent Wait does not
// wait for an in-flight ioctl; it reports cleanup uncertainty until all owned
// descriptors have drained, and that uncertainty remains sticky.
func (b *UniVPNNMBroker) ObserveNativeNamespaces(ctx context.Context) (UniVPNNMNamespaceObservation, error) {
	zero := UniVPNNMNamespaceObservation{}
	if b.lock(ctx) != nil {
		return zero, errUniVPNNamespaceObservation
	}
	p, ok := b.process.(*uniVPNExecProcess)
	if !ok || !b.processObservableLocked(p) || p.namespaces == nil || p.launchCleanupErr != nil {
		b.gate <- struct{}{}
		return zero, errUniVPNNamespaceObservation
	}
	observation, session := p.namespaces, b.binding.Identity.Session
	b.gate <- struct{}{}
	result, err := observation.observe(ctx)
	if err != nil {
		return zero, errors.Join(errUniVPNNamespaceObservation, err)
	}
	if b.lock(ctx) != nil {
		return zero, errUniVPNNamespaceObservation
	}
	defer func() { b.gate <- struct{}{} }()
	if b.process != p || p.namespaces != observation || !b.processObservableLocked(p) || p.launchCleanupErr != nil || b.binding.Identity.Session != session || ctx.Err() != nil {
		return zero, errUniVPNNamespaceObservation
	}
	result.Session = session
	return result, nil
}
