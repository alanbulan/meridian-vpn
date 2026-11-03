//go:build linux

// Package processcontainment supplies a cgroup lifecycle primitive, NOT a sandbox
// or a UniVPN isolation provider. See README.md for mandatory trust assumptions.
package processcontainment

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

const cgroup2Magic = 0x63677270

// Group owns pinned CLOEXEC descriptors to an already provisioned empty cgroup.
// The original and all other retained broker descriptors must remain CLOEXEC.
// It creates no cgroups and removes none. A trusted service manager must exclude
// all other membership/permission writers for its entire lifetime. The worker
// must separately be prevented from migrating out; this API cannot prove that.
// Never give this object a shared service cgroup or a cgroup containing the broker.
type Group struct {
	mu                         sync.Mutex
	kernel                     kernel
	dir, events, kill          int
	attempted, stopped, closed bool
	closeErr                   error
}

type kernel interface {
	flags(int) (int, error)
	dup(int) (int, error)
	stat(int) (syscall.Stat_t, error)
	fs(int) (int64, error)
	open(int, string, int) (int, error)
	read(int, []byte) (int, error)
	write(int, []byte) (int, error)
	close(int) error
}

type linuxKernel struct{}

func (linuxKernel) flags(fd int) (int, error) {
	n, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
	if e != 0 {
		return 0, e
	}
	return int(n), nil
}

func (linuxKernel) dup(fd int) (int, error) {
	n, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_DUPFD_CLOEXEC, 3)
	if e != 0 {
		return -1, e
	}
	return int(n), nil
}
func (linuxKernel) stat(fd int) (syscall.Stat_t, error) {
	var s syscall.Stat_t
	e := syscall.Fstat(fd, &s)
	return s, e
}
func (linuxKernel) fs(fd int) (int64, error) {
	var s syscall.Statfs_t
	e := syscall.Fstatfs(fd, &s)
	return int64(s.Type), e
}
func (linuxKernel) open(fd int, name string, flags int) (int, error) {
	return syscall.Openat(fd, name, flags|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
}
func (linuxKernel) read(fd int, b []byte) (int, error)  { return syscall.Pread(fd, b, 0) }
func (linuxKernel) write(fd int, b []byte) (int, error) { return syscall.Write(fd, b) }
func (linuxKernel) close(fd int) error                  { return syscall.Close(fd) }

// Adopt duplicates rather than consumes f. It validates the kernel filesystem,
// directory ownership, domain type, required controls and initial empty state.
// These checks do not prove exclusive administration or migration confinement.
// Merely calling Adopt does not modify any cgroup or launch any process.
func Adopt(f *os.File) (g *Group, err error) {
	if f == nil {
		return nil, errors.New("missing cgroup descriptor")
	}
	raw, e := f.SyscallConn()
	if e != nil {
		return nil, e
	}
	e = raw.Control(func(fd uintptr) { g, err = adopt(linuxKernel{}, int(fd)) })
	if e != nil && g != nil {
		err = errors.Join(err, g.Close())
		g = nil
	}
	return g, errors.Join(e, err)
}
func adopt(k kernel, fd int) (g *Group, err error) {
	flags, e := k.flags(fd)
	if e != nil {
		return nil, e
	}
	if flags&syscall.FD_CLOEXEC == 0 {
		return nil, errors.New("original cgroup descriptor must be CLOEXEC")
	}
	dir, e := k.dup(fd)
	if e != nil {
		return nil, e
	}
	g = &Group{kernel: k, dir: dir, events: -1, kill: -1}
	defer func() {
		if err != nil {
			err = errors.Join(err, g.closeHandles())
			g = nil
		}
	}()
	s, e := k.stat(dir)
	if e != nil {
		return g, e
	}
	if s.Mode&syscall.S_IFMT != syscall.S_IFDIR || s.Uid != 0 || s.Mode&0022 != 0 {
		return g, errors.New("untrusted cgroup directory")
	}
	magic, e := k.fs(dir)
	if e != nil {
		return g, e
	}
	if magic != cgroup2Magic {
		return g, errors.New("not cgroup v2")
	}
	// Fixed single-component names are relative to the held directory, never a
	// pathname supplied by the worker. Root cgroups have no cgroup.kill control.
	typ, e := k.open(dir, "cgroup.type", syscall.O_RDONLY)
	if e != nil {
		return g, e
	}
	if e := validateControl(k, typ, s.Dev); e != nil {
		return g, errors.Join(e, k.close(typ))
	}
	b, e := readControl(k, typ)
	e = errors.Join(e, k.close(typ))
	if e != nil {
		return g, e
	}
	if strings.TrimSpace(string(b)) != "domain" {
		return g, errors.New("non-domain cgroup")
	}
	g.events, e = k.open(dir, "cgroup.events", syscall.O_RDONLY)
	if e != nil {
		return g, e
	}
	g.kill, e = k.open(dir, "cgroup.kill", syscall.O_WRONLY)
	if e != nil {
		return g, e
	}
	for _, fd := range []int{g.events, g.kill} {
		if e := validateControl(k, fd, s.Dev); e != nil {
			return g, e
		}
	}

	empty, e := g.empty()
	if e != nil {
		return g, e
	}
	if !empty {
		return g, errors.New("cgroup already populated")
	}
	return g, nil
}
func validateControl(k kernel, fd int, dev uint64) error {
	s, e := k.stat(fd)
	if e != nil {
		return e
	}
	magic, e := k.fs(fd)
	if e != nil {
		return e
	}
	if magic != cgroup2Magic || s.Dev != dev || s.Uid != 0 || s.Mode&syscall.S_IFMT != syscall.S_IFREG || s.Mode&0022 != 0 {
		return errors.New("untrusted cgroup control")
	}
	return nil
}
func readControl(k kernel, fd int) ([]byte, error) {
	b := make([]byte, 4097)
	n, e := k.read(fd, b)
	if e != nil {
		return nil, e
	}
	if n <= 0 || n >= len(b) {
		return nil, errors.New("invalid cgroup control length")
	}
	return b[:n], nil
}
func (g *Group) empty() (bool, error) {
	b, e := readControl(g.kernel, g.events)
	if e != nil {
		return false, e
	}
	found := false
	frozen := false
	empty := false
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			return false, errors.New("malformed cgroup events")
		}
		if f[0] == "frozen" {
			if frozen || f[1] != "0" {
				return false, errors.New("invalid or frozen cgroup")
			}
			frozen = true
		}
		if f[0] == "populated" {
			if found || (f[1] != "0" && f[1] != "1") {
				return false, errors.New("invalid populated state")
			}
			found = true
			empty = f[1] == "0"
		}
	}
	if !found || !frozen {
		return false, errors.New("missing populated state")
	}
	return empty, nil
}

// CheckLaunchable validates that this is a fresh Adopt-created lifecycle, not a
// nil/zero-value Group. It performs no kernel mutation or launch. Freshness is
// rechecked under Start's lock; this snapshot does not reserve the group.
func (g *Group) CheckLaunchable() error {
	if g == nil {
		return errors.New("missing cgroup lifecycle")
	}
	if !g.mu.TryLock() {
		return errors.New("cgroup lifecycle busy")
	}
	defer g.mu.Unlock()
	return g.checkLaunchable()
}
func (g *Group) checkLaunchable() error {
	if g.kernel == nil || g.dir < 0 || g.events < 0 || g.kill < 0 {
		return errors.New("cgroup lifecycle was not adopted")
	}
	if g.closed || g.attempted || g.stopped {
		return errors.New("cgroup lifecycle not launchable")
	}
	return nil
}

// Start attaches atomically with CLONE_INTO_CGROUP via Go's clone3 path. There
// is no fallback to moving a running PID. It does not install any sandbox or
// drop privileges. The caller must configure a reviewed bootstrap first, own
// cmd exclusively and never reuse/mutate it concurrently. This group is one-shot.
// Even on failure, call KillAndWait before Close: failure is not an exit proof.
func (g *Group) Start(cmd *exec.Cmd) error { return g.start(cmd, func() error { return cmd.Start() }) }
func (g *Group) start(cmd *exec.Cmd, start func() error) error {
	if g == nil {
		return errors.New("missing cgroup lifecycle")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.checkLaunchable(); err != nil {
		return err
	}
	if cmd == nil || cmd.Process != nil {
		return errors.New("invalid command")
	}
	var attr syscall.SysProcAttr
	if cmd.SysProcAttr != nil {
		attr = *cmd.SysProcAttr
	}
	if attr.UseCgroupFD || attr.CgroupFD != 0 {
		return errors.New("command already selects a cgroup")
	}
	files := append([]*os.File(nil), cmd.ExtraFiles...)
	for _, stream := range []any{cmd.Stdin, cmd.Stdout, cmd.Stderr} {
		if f, ok := stream.(*os.File); ok {
			files = append(files, f)
		}
	}
	for _, f := range files {
		if f == nil {
			continue
		}
		st, e := g.kernel.stat(int(f.Fd()))
		if e != nil {
			return e
		}
		for _, held := range []int{g.dir, g.events, g.kill} {
			hs, e := g.kernel.stat(held)
			if e != nil {
				return e
			}
			if st.Dev == hs.Dev && st.Ino == hs.Ino {
				return errors.New("cgroup descriptor exposed to child")
			}
		}
	}

	empty, e := g.empty()
	if e != nil {
		return e
	}
	if !empty {
		return errors.New("cgroup no longer empty")
	}
	attr.UseCgroupFD = true
	attr.CgroupFD = g.dir
	cmd.SysProcAttr = &attr
	g.attempted = true
	return start()
}

// KillAndWait kills the entire cgroup subtree and observes hierarchical
// populated=0 on the pinned events FD. It is bounded even without a caller
// deadline. Timeouts/errors are uncertainty, never success. Calling again after
// an error retries kill/readback; an already successful stop is idempotent.
// No hostile task may migrate out, and no external writer may repopulate the
// group: those are external deployment obligations, not proven by this method.
func (g *Group) KillAndWait(ctx context.Context) error {
	if g == nil {
		return errors.New("missing cgroup lifecycle")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for !g.mu.TryLock() {
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	defer g.mu.Unlock()
	if g.kernel == nil {
		return errors.New("cgroup lifecycle was not adopted")
	}
	if g.closed {
		return errors.New("cgroup closed")
	}
	if g.stopped {
		return nil
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	n, e := g.kernel.write(g.kill, []byte("1"))
	if e != nil {
		return e
	}
	if n != 1 {
		return io.ErrShortWrite
	}
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		empty, e := g.empty()
		if e != nil {
			return e
		}
		if empty {
			g.stopped = true
			return nil
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Close refuses to discard a launched group's handles without successful
// termination proof. It never removes a directory by name or retries close(2)
// on a reused FD. The provisioning service retains directory cleanup ownership.
func (g *Group) Close() error {
	if g == nil {
		return errors.New("missing cgroup lifecycle")
	}
	if !g.mu.TryLock() {
		return errors.New("cgroup lifecycle busy; handles retained")
	}
	defer g.mu.Unlock()
	if g.kernel == nil {
		return errors.New("cgroup lifecycle was not adopted")
	}
	if g.closed {
		return g.closeErr
	}
	if g.attempted && !g.stopped {
		return errors.New("cgroup termination unproven")
	}
	g.closeErr = g.closeHandles()
	g.closed = true
	return g.closeErr
}
func (g *Group) closeHandles() error {
	var errs []error
	for _, p := range []*int{&g.kill, &g.events, &g.dir} {
		if *p >= 0 {
			fd := *p
			*p = -1
			if e := g.kernel.close(fd); e != nil {
				errs = append(errs, fmt.Errorf("close cgroup handle: %w", e))
			}
		}
	}
	return errors.Join(errs...)
}
