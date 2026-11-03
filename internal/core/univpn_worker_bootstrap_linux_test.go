//go:build linux && amd64

package core

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"

	"mygo-vpn/internal/processcontainment"
)

type fakeWorkerGroup struct {
	mu                          sync.Mutex
	starts, kills, closes       int
	startErr, killErr, closeErr error
	onStart                     func(*exec.Cmd)
}

func (g *fakeWorkerGroup) Start(c *exec.Cmd) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.starts++
	if g.onStart != nil {
		g.onStart(c)
	}
	return g.startErr
}
func (g *fakeWorkerGroup) KillAndWait(context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.kills++
	return g.killErr
}
func (g *fakeWorkerGroup) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closes++
	return g.closeErr
}
func workerFixture(t *testing.T) (*UniVPNWorkerIsolation, *fakeWorkerGroup, *exec.Cmd) {
	t.Helper()
	g := &fakeWorkerGroup{}
	root, executable := transportPipe(t)
	w := &UniVPNWorkerIsolation{group: g, root: root, executable: executable, nativeDigest: strings.Repeat("a", 64)}
	cmd := exec.Command("/not-executed-native", "--protocol=univpn", "--meridian-session-fd=3", "--meridian-control-fd=4", "--meridian-data-fd=5", "--meridian-packet-fd=6", "--", "https://gateway.invalid")
	for i := 0; i < 4; i++ {
		r, _ := transportPipe(t)
		cmd.ExtraFiles = append(cmd.ExtraFiles, r)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return nil }
	t.Cleanup(func() { _ = w.cleanup(context.Background()) })
	return w, g, cmd
}
func TestWorkerBootstrapFixedCommand(t *testing.T) {
	w, g, cmd := workerFixture(t)
	original := append([]string(nil), cmd.Args[1:]...)
	if err := w.wrap(cmd, w.nativeDigest); err != nil {
		t.Fatal(err)
	}
	if cmd.Path != "/proc/self/fd/8" || cmd.Args[0] != "meridian-worker-bootstrap" || len(cmd.ExtraFiles) != 6 || cmd.ExtraFiles[4] != w.root || cmd.ExtraFiles[5] != w.executable || cmd.Stdout != nil || cmd.Stderr != nil {
		t.Fatal("wrong fixed bootstrap layout")
	}
	if strings.Join(cmd.Args[1:], " ") != strings.Join(original, " ") {
		t.Fatal("native args changed")
	}
	fallback := false
	g.onStart = func(c *exec.Cmd) {
		if c != cmd {
			t.Fatal("wrong cgroup command")
		}
	}
	if err := startUniVPNContained(context.Background(), cmd, w, func() error { fallback = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if fallback || g.starts != 1 {
		t.Fatal("atomic cgroup start bypassed")
	}
	if err := w.startContained(cmd); err == nil {
		t.Fatal("second start accepted")
	}
	if err := w.WaitEmpty(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}
	if g.kills != 1 || g.closes != 1 {
		t.Fatal("teardown not proven")
	}
	assertTransportClosed(t, w.root, w.executable)
}
func TestWorkerBootstrapRejectPartialAndRepeatedWrap(t *testing.T) {
	for _, mode := range []string{"digest", "missing-file", "missing-flag", "duplicate-flag", "script", "already-bound"} {
		t.Run(mode, func(t *testing.T) {
			w, g, c := workerFixture(t)
			digest := w.nativeDigest
			switch mode {
			case "digest":
				digest = "wrong"
			case "missing-file":
				c.ExtraFiles = c.ExtraFiles[:3]
			case "missing-flag":
				c.Args[3] = "--no-control"
			case "duplicate-flag":
				c.Args = append(c.Args[:len(c.Args)-2], "--meridian-packet-fd=6", "--", "https://gateway.invalid")
			case "script":
				c.Args = append(c.Args[:len(c.Args)-2], "--script=/bin/sh", "--", "https://gateway.invalid")
			case "already-bound":
				if err := w.wrap(c, digest); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.wrap(c, digest); err == nil {
				t.Fatal("accepted invalid command")
			}
			if g.starts != 0 {
				t.Fatal("started during preparation")
			}
		})
	}
}
func TestWorkerBootstrapFailureRetainsHandles(t *testing.T) {
	w, g, c := workerFixture(t)
	g.startErr = errors.New("clone3 failed")
	g.killErr = errors.New("uncertain population")
	if err := w.wrap(c, w.nativeDigest); err != nil {
		t.Fatal(err)
	}
	err := startUniVPNContained(context.Background(), c, w, func() error { t.Fatal("uncontained fallback"); return nil })
	var cleanup *CleanupError
	if !errors.As(err, &cleanup) || g.starts != 1 || g.kills != 1 || g.closes != 0 {
		t.Fatalf("failure lost: %v", err)
	}
	for _, f := range []*os.File{w.root, w.executable} {
		if _, err := f.Stat(); err != nil {
			t.Fatal("handle closed without proof")
		}
	}
	g.killErr = nil
	if err := w.RollbackLaunch(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	assertTransportClosed(t, w.root, w.executable)
}
func TestWorkerBootstrapCancellationBeforeStart(t *testing.T) {
	w, g, c := workerFixture(t)
	if err := w.wrap(c, w.nativeDigest); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := startUniVPNContained(ctx, c, w, func() error { t.Fatal("fallback"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
	if g.starts != 0 || g.kills != 1 || g.closes != 1 {
		t.Fatal("canceled launch not cleaned")
	}
}
func TestWorkerBootstrapCloseUncertainty(t *testing.T) {
	w, g, _ := workerFixture(t)
	g.closeErr = errors.New("group close uncertain")
	if err := w.cleanup(context.Background()); err == nil {
		t.Fatal("accepted uncertain close")
	}
	if _, err := w.root.Stat(); err != nil {
		t.Fatal("root discarded")
	}
	g.closeErr = nil
	if err := w.cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := w.cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if g.closes != 2 {
		t.Fatal("completed group close repeated")
	}
}
func TestWorkerBootstrapEarlyLaunchFailureCleans(t *testing.T) {
	w, g, _ := workerFixture(t)
	l := UniVPNExecLauncher{Isolation: w}
	if _, err := l.Launch(context.Background(), "invalid", nil, nil); err == nil {
		t.Fatal("accepted incomplete providers")
	}
	if g.starts != 0 || g.kills != 1 || g.closes != 1 {
		t.Fatal("early failure leaked cgroup")
	}
}
func TestWorkerBootstrapRejectInvalidConstruction(t *testing.T) {
	if _, err := NewUniVPNWorkerIsolation(UniVPNWorkerConfig{}); err == nil {
		t.Fatal("accepted absent prerequisites")
	}
	if _, err := openPinnedWorkerFile("relative", strings.Repeat("0", 64)); err == nil {
		t.Fatal("accepted relative bootstrap")
	}
	var w UniVPNWorkerIsolation
	if err := w.cleanup(context.Background()); err == nil {
		t.Fatal("zero containment accepted")
	}
}

func TestWorkerBootstrapRejectForeignLifecycle(t *testing.T) {
	w, g, c := workerFixture(t)
	if err := w.wrap(c, w.nativeDigest); err != nil {
		t.Fatal(err)
	}
	foreign := exec.Command("/never-executed")
	for _, cmd := range []*exec.Cmd{foreign, nil} {
		if err := w.WaitEmpty(context.Background(), cmd); err == nil {
			t.Fatal("foreign wait accepted")
		}
		if err := w.RollbackLaunch(context.Background(), cmd); err == nil {
			t.Fatal("foreign rollback accepted")
		}
		if err := w.Prepare(cmd); err == nil {
			t.Fatal("foreign preparation accepted")
		}
		if err := w.startContained(cmd); err == nil {
			t.Fatal("foreign start accepted")
		}
	}
	if g.starts != 0 || g.kills != 0 || g.closes != 0 {
		t.Fatal("foreign operation touched group")
	}
	if err := w.rollbackOwned(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerBootstrapRejectUnadoptedGroup(t *testing.T) {
	root, _ := transportPipe(t)
	if _, err := NewUniVPNWorkerIsolation(UniVPNWorkerConfig{Group: &processcontainment.Group{}, Root: root}); err == nil || !strings.Contains(err.Error(), "not adopted") {
		t.Fatalf("unadopted group not rejected before filesystem lookup: %v", err)
	}
	if _, err := root.Stat(); err != nil {
		t.Fatal("constructor consumed caller root")
	}
}
