//go:build linux

package processcontainment

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeKernel struct {
	noCloexec bool
	aliases   map[int]int

	mode     uint32
	uid      uint32
	magic    int64
	typ      string
	states   []string
	calls    []string
	closes   []int
	writeN   int
	writeErr error
	failOpen string
	closeErr error
}

func fixture() *fakeKernel {
	return &fakeKernel{mode: syscall.S_IFDIR | 0755, magic: cgroup2Magic, typ: "domain\n", states: []string{"populated 0\nfrozen 0\n"}, writeN: 1}
}
func (f *fakeKernel) flags(int) (int, error) {
	if f.noCloexec {
		return 0, nil
	}
	return syscall.FD_CLOEXEC, nil
}
func (f *fakeKernel) dup(int) (int, error) { f.calls = append(f.calls, "dup"); return 100, nil }
func (f *fakeKernel) stat(fd int) (syscall.Stat_t, error) {
	if alias, ok := f.aliases[fd]; ok {
		fd = alias
	}
	mode := f.mode
	if fd != 100 {
		mode = syscall.S_IFREG | 0600
	}
	return syscall.Stat_t{Mode: mode, Uid: f.uid, Ino: uint64(fd), Dev: 1}, nil
}
func (f *fakeKernel) fs(int) (int64, error) { return f.magic, nil }
func (f *fakeKernel) open(fd int, s string, flags int) (int, error) {
	if fd != 100 {
		panic("not relative to held directory")
	}
	f.calls = append(f.calls, s)
	if s == f.failOpen {
		return -1, syscall.EACCES
	}
	switch s {
	case "cgroup.type":
		return 101, nil
	case "cgroup.events":
		if flags != syscall.O_RDONLY {
			panic("events writable")
		}
		return 102, nil
	case "cgroup.kill":
		if flags != syscall.O_WRONLY {
			panic("kill readable")
		}
		return 103, nil
	}
	panic("unexpected path")
}
func (f *fakeKernel) read(fd int, b []byte) (int, error) {
	if fd == 101 {
		return copy(b, f.typ), nil
	}
	if fd != 102 {
		panic("unexpected read")
	}
	s := f.states[0]
	if len(f.states) > 1 {
		f.states = f.states[1:]
	}
	return copy(b, s), nil
}
func (f *fakeKernel) write(fd int, b []byte) (int, error) {
	if fd != 103 || string(b) != "1" {
		panic("unexpected mutation")
	}
	f.calls = append(f.calls, "kill")
	return f.writeN, f.writeErr
}
func (f *fakeKernel) close(fd int) error { f.closes = append(f.closes, fd); return f.closeErr }
func mustGroup(t *testing.T, f *fakeKernel) *Group {
	t.Helper()
	g, e := adopt(f, 7)
	if e != nil {
		t.Fatal(e)
	}
	return g
}
func TestAdoptRejectsInvalidControls(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*fakeKernel)
	}{
		{"filesystem", func(f *fakeKernel) { f.magic = 123 }},
		{"not directory", func(f *fakeKernel) { f.mode = syscall.S_IFREG | 0600 }},
		{"owner", func(f *fakeKernel) { f.uid = 1000 }},
		{"writable", func(f *fakeKernel) { f.mode |= 0020 }},
		{"threaded", func(f *fakeKernel) { f.typ = "domain threaded\n" }},
		{"kill unavailable", func(f *fakeKernel) { f.failOpen = "cgroup.kill" }},
		{"populated", func(f *fakeKernel) { f.states = []string{"populated 1\nfrozen 0\n"} }},
		{"missing populated", func(f *fakeKernel) { f.states = []string{"frozen 0\n"} }},
		{"duplicate populated", func(f *fakeKernel) { f.states = []string{"populated 0\npopulated 0\nfrozen 0\n"} }},
		{"bad populated", func(f *fakeKernel) { f.states = []string{"populated no\n"} }},
		{"truncated", func(f *fakeKernel) { f.states = []string{strings.Repeat("x", 4097)} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixture()
			tc.change(f)
			g, e := adopt(f, 7)
			if e == nil || g != nil {
				t.Fatal("accepted")
			}
			if len(f.closes) == 0 || f.closes[len(f.closes)-1] != 100 {
				t.Fatal("leaked directory", f.closes)
			}
			for _, c := range f.calls {
				if c == "kill" {
					t.Fatal("adoption mutated state")
				}
			}
		})
	}
}
func TestAtomicStartAndWholeGroupTermination(t *testing.T) {
	f := fixture()
	g := mustGroup(t, f)
	cmd := exec.Command("/not-executed")
	original := &syscall.SysProcAttr{Setpgid: true, Cloneflags: syscall.CLONE_NEWNET}
	cmd.SysProcAttr = original
	if e := g.start(cmd, func() error {
		if !cmd.SysProcAttr.UseCgroupFD || cmd.SysProcAttr.CgroupFD != 100 || !cmd.SysProcAttr.Setpgid || cmd.SysProcAttr.Cloneflags != syscall.CLONE_NEWNET {
			t.Fatal("missing atomic attachment")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if original.UseCgroupFD {
		t.Fatal("mutated original attributes")
	}
	if e := g.Close(); e == nil {
		t.Fatal("closed before proof")
	}
	f.states = []string{"populated 1\nfrozen 0\n", "populated 0\nfrozen 0\n"}
	if e := g.KillAndWait(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := g.KillAndWait(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := g.Close(); e != nil {
		t.Fatal(e)
	}
	g.Close()
	if !reflect.DeepEqual(f.closes, []int{101, 103, 102, 100}) {
		t.Fatal(f.closes)
	}
	kills := 0
	for _, c := range f.calls {
		if c == "kill" {
			kills++
		}
	}
	if kills != 1 {
		t.Fatal(kills)
	}
	if e := g.start(cmd, func() error { t.Fatal("restarted"); return nil }); e == nil {
		t.Fatal("restarted closed group")
	}
}
func TestStartFailureRequiresCleanupNoFallback(t *testing.T) {
	f := fixture()
	g := mustGroup(t, f)
	n := 0
	e := g.start(exec.Command("/not-executed"), func() error { n++; return syscall.ENOSYS })
	if !errors.Is(e, syscall.ENOSYS) || n != 1 {
		t.Fatal(e, n)
	}
	if g.Close() == nil {
		t.Fatal("failed start was treated as proof")
	}
	if e = g.KillAndWait(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = g.Close(); e != nil {
		t.Fatal(e)
	}
}
func TestKillErrorsRetainHandles(t *testing.T) {
	for _, tc := range []string{"short write", "write failure", "read failure", "timeout", "cancel"} {
		t.Run(tc, func(t *testing.T) {
			f := fixture()
			g := mustGroup(t, f)
			g.start(exec.Command("/not-executed"), func() error { return nil })
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			switch tc {
			case "short write":
				f.writeN = 0
			case "write failure":
				f.writeErr = syscall.EACCES
			case "read failure":
				f.states = []string{"populated 9\n"}
			case "timeout":
				f.states = []string{"populated 1\nfrozen 0\n"}
			case "cancel":
				cancel()
			}
			e := g.KillAndWait(ctx)
			if e == nil {
				t.Fatal("uncertainty accepted")
			}
			if tc == "short write" && !errors.Is(e, io.ErrShortWrite) {
				t.Fatal(e)
			}
			if g.Close() == nil {
				t.Fatal("lost cleanup handles")
			}
			if !reflect.DeepEqual(f.closes, []int{101}) {
				t.Fatal(f.closes)
			}
			f.writeN = 1
			f.writeErr = nil
			f.states = []string{"populated 0\nfrozen 0\n"}
			if e = g.KillAndWait(context.Background()); e != nil {
				t.Fatal(e)
			}
			g.Close()
		})
	}
}
func TestStartRejectsExternalPopulationAndCgroupOverride(t *testing.T) {
	for _, tc := range []string{"populated", "override", "nil"} {
		t.Run(tc, func(t *testing.T) {
			f := fixture()
			g := mustGroup(t, f)
			cmd := exec.Command("/not-executed")
			switch tc {
			case "populated":
				f.states = []string{"populated 1\nfrozen 0\n"}
			case "override":
				cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: 5}
			case "nil":
				cmd = nil
			}
			if e := g.start(cmd, func() error { t.Fatal("unexpected start"); return nil }); e == nil {
				t.Fatal("accepted")
			}
			if e := g.Close(); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestCloseFailureIsSticky(t *testing.T) {
	f := fixture()
	g := mustGroup(t, f)
	f.closeErr = syscall.EIO
	if g.Close() == nil || g.Close() == nil {
		t.Fatal("close uncertainty lost")
	}
	if len(f.closes) != 4 {
		t.Fatal("close retried reused FD", f.closes)
	}
}

func TestPendingStartCleanupDeadline(t *testing.T) {
	f := fixture()
	g := mustGroup(t, f)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- g.start(exec.Command("/not-executed"), func() error { close(entered); <-release; return nil })
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if e := g.KillAndWait(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	if e := g.Close(); e == nil {
		t.Fatal("close accepted pending start")
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if e := g.Close(); e == nil {
		t.Fatal("pending start confused with stopped")
	}
	if e := g.KillAndWait(context.Background()); e != nil {
		t.Fatal(e)
	}
	g.Close()
}
func TestFrozenStateRejected(t *testing.T) {
	for _, state := range []string{"populated 0\nfrozen 1\n", "populated 0\n", "populated 0\nfrozen 0\nfrozen 0\n"} {
		f := fixture()
		f.states = []string{state}
		if g, e := adopt(f, 7); e == nil || g != nil {
			t.Fatal("accepted frozen/unknown state", state)
		}
	}
}

func TestRejectInheritedCgroupAliases(t *testing.T) {
	for _, role := range []string{"extra", "stdin", "stdout", "stderr"} {
		t.Run(role, func(t *testing.T) {
			r, w, e := os.Pipe()
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			defer w.Close()
			f := fixture()
			f.aliases = map[int]int{int(r.Fd()): 100}
			g := mustGroup(t, f)
			cmd := exec.Command("/not-executed")
			switch role {
			case "extra":
				cmd.ExtraFiles = []*os.File{r}
			case "stdin":
				cmd.Stdin = r
			case "stdout":
				cmd.Stdout = r
			case "stderr":
				cmd.Stderr = r
			}
			if e := g.start(cmd, func() error { t.Fatal("inherited cgroup alias"); return nil }); e == nil {
				t.Fatal("accepted alias")
			}
			g.Close()
		})
	}
}

func TestAdoptRejectsInheritableOriginal(t *testing.T) {
	f := fixture()
	f.noCloexec = true
	if g, e := adopt(f, 7); e == nil || g != nil {
		t.Fatal("accepted inheritable original")
	}
	if len(f.calls) != 0 {
		t.Fatal("duplicated before rejecting", f.calls)
	}
}

func TestZeroValueGroupFailsClosed(t *testing.T) {
	for _, g := range []*Group{nil, {}} {
		if err := g.CheckLaunchable(); err == nil {
			t.Fatal("unadopted group launchable")
		}
		if err := g.Start(nil); err == nil {
			t.Fatal("unadopted group started")
		}
		if err := g.KillAndWait(context.Background()); err == nil {
			t.Fatal("unadopted group empty proof")
		}
		if err := g.Close(); err == nil {
			t.Fatal("unadopted group close succeeded")
		}
	}
}

func TestCheckLaunchableBusyIsBounded(t *testing.T) {
	g := &Group{}
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.CheckLaunchable(); err == nil {
		t.Fatal("busy group reported launchable")
	}
}
