//go:build linux && amd64

package core

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"mygo-vpn/internal/processcontainment"
)

const uniVPNWorkerRoot = "/var/lib/meridian/worker-root"

// UniVPNWorkerIsolation is an explicit, single-launch cgroup/bootstrap adapter.
// Construction does NOT prove deployment readiness. The trusted manager must
// satisfy integration/worker-bootstrap/README.md, including a minimal immutable
// rootfs, exclusive UID/GID 65532, protected cgroup hierarchy and authorized VM
// acceptance. No default application path constructs this adapter.
// On constructor success it owns Group and duplicates Root; callers retain Root.
// If Launch is never called, call RollbackLaunch to release the owned group.
type UniVPNWorkerIsolation struct {
	mu                sync.Mutex
	group             uniVPNWorkerGroup
	root, executable  *os.File
	nativeDigest      string
	cmd               *exec.Cmd
	attempted, closed bool
	closeErr          error
}
type uniVPNWorkerGroup interface {
	Start(*exec.Cmd) error
	KillAndWait(context.Context) error
	Close() error
}

// UniVPNWorkerConfig is administrator-only configuration, never desktop IPC.
// Root must match the immutable fixed worker root; both SHA256 values are trusted
// deployment pins, not hashes received alongside untrusted executable bytes.
type UniVPNWorkerConfig struct {
	Group                                        *processcontainment.Group
	Root                                         *os.File
	BootstrapPath, BootstrapSHA256, NativeSHA256 string
}

func openPinnedWorkerFile(path, digest string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(digest) != 64 {
		return nil, errors.New("invalid worker executable pin")
	}
	if err := trustedUniVPNPath(filepath.Dir(path), false); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "meridian-pinned-worker")
	fail := func(err error) (*os.File, error) { return nil, errors.Join(err, f.Close()) }
	st, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || s.Uid != 0 || st.Mode().Perm()&0022 != 0 || st.Mode().Perm()&0111 == 0 {
		return fail(errors.New("untrusted worker executable"))
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return fail(err)
	}
	if hex.EncodeToString(h.Sum(nil)) != digest {
		return fail(errors.New("worker executable pin mismatch"))
	}
	return f, nil
}
func NewUniVPNWorkerIsolation(c UniVPNWorkerConfig) (*UniVPNWorkerIsolation, error) {
	if c.Group == nil || c.Root == nil {
		return nil, errors.New("missing worker cgroup or root")
	}
	if err := c.Group.CheckLaunchable(); err != nil {
		return nil, err
	}
	// Verify the exact fixed in-root native image, separately from the outer
	// launcher's executable pin. Immutable manager ownership remains mandatory.
	native, err := openPinnedWorkerFile(uniVPNWorkerRoot+"/bin/meridian-univpn", c.NativeSHA256)
	if err != nil {
		return nil, err
	}
	if err = native.Close(); err != nil {
		return nil, err
	}
	executable, err := openPinnedWorkerFile(c.BootstrapPath, c.BootstrapSHA256)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*UniVPNWorkerIsolation, error) { return nil, errors.Join(e, executable.Close()) }
	image, err := elf.NewFile(executable)
	if err != nil {
		return fail(err)
	}
	if image.Machine != elf.EM_X86_64 || image.Class != elf.ELFCLASS64 || image.Type != elf.ET_EXEC {
		return fail(errors.New("unsupported worker bootstrap ELF"))
	}
	for _, p := range image.Progs {
		if p.Type == elf.PT_INTERP {
			return fail(errors.New("worker bootstrap must be static"))
		}
	}
	raw, err := c.Root.SyscallConn()
	if err != nil {
		return fail(err)
	}
	fd := -1
	var opErr error
	err = raw.Control(func(original uintptr) {
		flags, _, e := syscall.Syscall(syscall.SYS_FCNTL, original, syscall.F_GETFD, 0)
		if e != 0 {
			opErr = e
			return
		}
		if flags&syscall.FD_CLOEXEC == 0 {
			opErr = errors.New("worker root must be CLOEXEC")
			return
		}
		n, _, e := syscall.Syscall(syscall.SYS_FCNTL, original, syscall.F_DUPFD_CLOEXEC, 3)
		if e != 0 {
			opErr = e
		} else {
			fd = int(n)
		}
	})
	if err = errors.Join(err, opErr); err != nil {
		if fd >= 0 {
			if closeErr := syscall.Close(fd); closeErr != nil {
				err = errors.Join(err, closeErr, &CleanupError{})
			}
		}
		return fail(err)
	}
	root := os.NewFile(uintptr(fd), "meridian-worker-root")
	bad := func(e error) (*UniVPNWorkerIsolation, error) {
		_, e = fail(e)
		return nil, errors.Join(e, root.Close())
	}
	if err = trustedUniVPNPath(uniVPNWorkerRoot, false); err != nil {
		return bad(err)
	}
	actual, err := root.Stat()
	if err != nil {
		return bad(err)
	}
	expected, err := os.Stat(uniVPNWorkerRoot)
	if err != nil {
		return bad(err)
	}
	if !actual.IsDir() || !os.SameFile(actual, expected) {
		return bad(errors.New("worker root identity mismatch"))
	}
	return &UniVPNWorkerIsolation{group: c.Group, root: root, executable: executable, nativeDigest: c.NativeSHA256}, nil
}

func (w *UniVPNWorkerIsolation) wrap(cmd *exec.Cmd, nativeDigest string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.cmd != nil || w.group == nil || w.root == nil || w.executable == nil || nativeDigest != w.nativeDigest {
		return errors.New("worker bootstrap not launchable")
	}
	if cmd == nil || cmd.Process != nil || len(cmd.Args) < 3 || len(cmd.ExtraFiles) != 4 || cmd.Args[len(cmd.Args)-2] != "--" {
		return errors.New("worker requires all fixed native channels")
	}
	required := map[string]int{"--meridian-session-fd=3": 0, "--meridian-control-fd=4": 0, "--meridian-data-fd=5": 0, "--meridian-packet-fd=6": 0}
	for _, a := range cmd.Args[1 : len(cmd.Args)-2] {
		if _, ok := required[a]; ok {
			required[a]++
		}
		if strings.HasPrefix(a, "--script") {
			return errors.New("worker scripts forbidden")
		}
	}
	for _, n := range required {
		if n != 1 {
			return errors.New("missing fixed native channel flag")
		}
	}
	for _, f := range cmd.ExtraFiles {
		if f == nil {
			return errors.New("missing native channel")
		}
	}
	// FD8 pins the exact verified static bootstrap inode through exec. Only its
	// trusted pre-exec code receives it; bootstrap closes >=8 before namespaces.
	cmd.Path = "/proc/self/fd/8"
	cmd.Args = append([]string{"meridian-worker-bootstrap"}, cmd.Args[1:]...)
	cmd.ExtraFiles = append(append([]*os.File(nil), cmd.ExtraFiles...), w.root, w.executable)
	cmd.Stdout = nil
	cmd.Stderr = nil // os/exec opens write-only /dev/null, not copy pipes.
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "HOME=/"}
	w.cmd = cmd
	return nil
}
func (w *UniVPNWorkerIsolation) Prepare(cmd *exec.Cmd) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.cmd == nil || w.cmd != cmd || w.attempted {
		return errors.New("worker command not bound")
	}
	return nil
}

// Private optional hook prevents an external provider from introducing an
// unchecked alternative start path. Production calls the concrete Group.Start.
func (w *UniVPNWorkerIsolation) startContained(cmd *exec.Cmd) error {
	w.mu.Lock()
	if w.closed || w.cmd != cmd || w.attempted {
		w.mu.Unlock()
		return errors.New("worker already started or closed")
	}
	w.attempted = true
	w.mu.Unlock()
	return w.group.Start(cmd)
}
func (w *UniVPNWorkerIsolation) cleanup(ctx context.Context) error {
	if w == nil || w.group == nil {
		return errors.New("worker containment unavailable")
	}
	// Group itself serializes starts and teardown with bounded uncertainty. Never
	// hold w.mu across a potentially blocking start or kernel cleanup.
	w.mu.Lock()
	if w.closed {
		err := w.closeErr
		w.mu.Unlock()
		return err
	}
	w.mu.Unlock()
	if err := w.group.KillAndWait(ctx); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.closeErr
	}
	if err := w.group.Close(); err != nil {
		return err
	}
	// Mark closed before any close: a failed close must not be retried on a reused FD.
	w.closed = true
	w.closeErr = errors.Join(w.root.Close(), w.executable.Close())
	return w.closeErr
}

// Only the launcher's own failure defer uses this method, so a post-wrap early
// failure can clean the owned lifecycle without inventing a foreign command.
func (w *UniVPNWorkerIsolation) rollbackOwned(ctx context.Context) error { return w.cleanup(ctx) }
func (w *UniVPNWorkerIsolation) checkCommand(cmd *exec.Cmd, unbound bool) error {
	if w == nil {
		return errors.New("missing worker isolation")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cmd == nil && cmd == nil && unbound {
		return nil
	}
	if cmd == nil || w.cmd != cmd {
		return errors.New("foreign worker command")
	}
	return nil
}
func (w *UniVPNWorkerIsolation) WaitEmpty(ctx context.Context, cmd *exec.Cmd) error {
	if err := w.checkCommand(cmd, false); err != nil {
		return err
	}
	return w.cleanup(ctx)
}
func (w *UniVPNWorkerIsolation) RollbackLaunch(ctx context.Context, cmd *exec.Cmd) error {
	if err := w.checkCommand(cmd, true); err != nil {
		return err
	}
	return w.cleanup(ctx)
}
