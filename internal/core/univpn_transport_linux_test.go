//go:build linux

package core

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"syscall"
	"testing"
	"time"

	"mygo-vpn/internal/fdtransport"
)

type transportProviderFunc func(context.Context, string, fdtransport.Endpoint) (*os.File, *os.File, error)

func (f transportProviderFunc) Acquire(c context.Context, g string, e fdtransport.Endpoint) (*os.File, *os.File, error) {
	return f(c, g, e)
}

type transportTestBundle struct {
	files  []*os.File
	closed bool
}

func (b *transportTestBundle) Files() ([]*os.File, error) { return b.files, nil }
func (b *transportTestBundle) Close() error {
	b.closed = true
	var e error
	for _, f := range b.files {
		e = errors.Join(e, f.Close())
	}
	return e
}
func transportPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	return r, w
}
func assertTransportClosed(t *testing.T, files ...*os.File) {
	t.Helper()
	for _, f := range files {
		if _, e := f.Stat(); e == nil {
			t.Fatal("file remains open")
		}
	}
}
func TestTransportAcquireOwnership(t *testing.T) {
	for _, mode := range []string{"success", "provider-error", "duplicate-error", "cancel", "alias", "missing"} {
		t.Run(mode, func(t *testing.T) {
			c, d := transportPipe(t)
			x, y := transportPipe(t)
			bundle := &transportTestBundle{files: []*os.File{x, y}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			duplicated := false
			provider := transportProviderFunc(func(context.Context, string, fdtransport.Endpoint) (*os.File, *os.File, error) {
				switch mode {
				case "provider-error":
					return c, d, errors.New("acquire")
				case "alias":
					d.Close()
					return c, c, nil
				case "missing":
					d.Close()
					return c, nil, nil
				case "cancel":
					cancel()
				}
				return c, d, nil
			})
			got, e := acquireUniVPNTransport(ctx, provider, "https://gateway.invalid", fdtransport.Endpoint{}, func(a, b *os.File, _ fdtransport.Endpoint) (uniVPNTransportBundle, error) {
				duplicated = true
				if a != c || b != d {
					t.Fatal("wrong originals")
				}
				if _, e := c.Stat(); e != nil {
					t.Fatal("closed before duplication")
				}
				if mode == "duplicate-error" {
					return bundle, errors.New("duplicate")
				}
				return bundle, nil
			})
			assertTransportClosed(t, c, d)
			if mode == "success" {
				if e != nil || got != bundle || !duplicated || bundle.closed {
					t.Fatalf("%v %v", got, e)
				}
				got.Close()
				assertTransportClosed(t, x, y)
			} else {
				if e == nil || got != nil {
					t.Fatal("accepted failure")
				}
				if mode == "duplicate-error" && !bundle.closed {
					t.Fatal("duplicate leaked")
				}
			}
		})
	}
}
func TestTransportProductionRejectsPipes(t *testing.T) {
	c, d := transportPipe(t)
	p := transportProviderFunc(func(context.Context, string, fdtransport.Endpoint) (*os.File, *os.File, error) { return c, d, nil })
	_, e := acquireUniVPNTransport(context.Background(), p, "https://gateway.invalid", fdtransport.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 443}, func(c, d *os.File, e fdtransport.Endpoint) (uniVPNTransportBundle, error) {
		return fdtransport.Prepare(c, d, e)
	})
	if e == nil {
		t.Fatal("pipe accepted")
	}
	assertTransportClosed(t, c, d)
}
func TestTransportExactGatewayPolicy(t *testing.T) {
	l := UniVPNExecLauncher{TransportGateways: map[string]fdtransport.Endpoint{"https://gateway.invalid": {Address: netip.MustParseAddr("192.0.2.1"), Port: 443}}}
	if _, e := l.transportEndpoint("https://gateway.invalid"); e != nil {
		t.Fatal(e)
	}
	for _, g := range []string{"https://other.invalid", "https://gateway.invalid/", "http://gateway.invalid", "https://gateway.invalid:444"} {
		if _, e := l.transportEndpoint(g); e == nil {
			t.Fatal("accepted", g)
		}
	}
	l.TransportGateways["https://gateway.invalid"] = fdtransport.Endpoint{Address: netip.MustParseAddr("192.0.2.1"), Port: 444}
	if _, e := l.transportEndpoint("https://gateway.invalid"); e == nil {
		t.Fatal("wrong gateway port accepted")
	}
}

type transportIsolation struct {
	mutate                  func(*exec.Cmd)
	prepareErr, rollbackErr error
	rollbacks               int
}

func (i *transportIsolation) Prepare(c *exec.Cmd) error {
	if i.mutate != nil {
		i.mutate(c)
	}
	return i.prepareErr
}
func (i *transportIsolation) WaitEmpty(context.Context, *exec.Cmd) error { return nil }
func (i *transportIsolation) RollbackLaunch(context.Context, *exec.Cmd) error {
	i.rollbacks++
	return i.rollbackErr
}
func protectedTransportCmd(t *testing.T) *exec.Cmd {
	c, d := transportPipe(t)
	cmd := exec.CommandContext(context.Background(), "/never-executed", "--meridian-session-fd=3", "--meridian-control-fd=4", "--meridian-data-fd=5")
	cmd.Stdin = c
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.ExtraFiles = []*os.File{d, c, d}
	cmd.Env = []string{"LANG=C"}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}
func TestTransportContainedStart(t *testing.T) {
	for _, mode := range []string{"success", "prepare", "start", "cancel", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			cmd := protectedTransportCmd(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			i := &transportIsolation{}
			switch mode {
			case "prepare":
				i.prepareErr = errors.New("prepare")
			case "rollback":
				i.prepareErr = errors.New("prepare")
				i.rollbackErr = errors.New("rollback")
			case "cancel":
				i.mutate = func(*exec.Cmd) { cancel() }
			}
			started := false
			e := startUniVPNContained(ctx, cmd, i, func() error {
				started = true
				if mode == "start" {
					return errors.New("start")
				}
				return nil
			})
			if mode == "success" {
				if e != nil || !started || i.rollbacks != 0 {
					t.Fatal("success failed", e)
				}
			} else {
				if e == nil || i.rollbacks != 1 {
					t.Fatal("rollback missing", e)
				}
				if (mode == "prepare" || mode == "cancel") && started {
					t.Fatal("started after failure")
				}
			}
			if mode == "rollback" {
				var ce *CleanupError
				if !errors.As(e, &ce) {
					t.Fatal("cleanup uncertainty erased")
				}
			}
		})
	}
}
func TestTransportRejectsIsolationMutation(t *testing.T) {
	mutations := map[string]func(*exec.Cmd){"path": func(c *exec.Cmd) { c.Path = "/other" }, "args": func(c *exec.Cmd) { c.Args[1] = "--evil" }, "env": func(c *exec.Cmd) { c.Env[0] = "EVIL=1" }, "dir": func(c *exec.Cmd) { c.Dir = "/tmp" }, "files": func(c *exec.Cmd) { c.ExtraFiles[0] = nil }, "stdin": func(c *exec.Cmd) { c.Stdin = nil }, "stdout": func(c *exec.Cmd) { c.Stdout = os.Stdout }, "stderr": func(c *exec.Cmd) { c.Stderr = os.Stderr }, "pgid": func(c *exec.Cmd) { c.SysProcAttr.Pgid = 123 }, "wait": func(c *exec.Cmd) { c.WaitDelay++ }}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			i := &transportIsolation{mutate: mutate}
			e := startUniVPNContained(context.Background(), protectedTransportCmd(t), i, func() error { t.Fatal("mutated command started"); return nil })
			if e == nil || i.rollbacks != 1 {
				t.Fatal("mutation accepted", e)
			}
		})
	}
}

type cleanupFailLauncher struct{}

func (cleanupFailLauncher) Launch(context.Context, string, []string, []byte) (UniVPNNativeProcess, error) {
	return nil, errors.Join(errors.New("failed prepare"), &CleanupError{})
}
func TestTransportLaunchFailureQuarantinesBackend(t *testing.T) {
	b, _, _ := brokerFixture()
	b.Launcher = cleanupFailLauncher{}
	_, e := b.Start(context.Background(), b.Executable, brokerArgs(), []byte("password"))
	var ce *CleanupError
	if !errors.As(e, &ce) || b.Available() || !b.active || !b.quarantined {
		t.Fatal("cleanup failure lost", e)
	}
}
func TestTransportLauncherRejectsUntrustedFlags(t *testing.T) {
	l := UniVPNExecLauncher{Isolation: &transportIsolation{}, NativeSessionChannel: true}
	for _, flag := range []string{"--meridian-control-fd=4", "--meridian-data-fd=5", "--meridian-packet-fd=6", "--script=/evil", "--config=/evil"} {
		args := brokerArgs()
		args = append(args[:len(args)-2], flag, "--", "https://gateway.invalid")
		if _, e := l.Launch(context.Background(), "/never-executed", args, nil); e == nil {
			t.Fatal("accepted", flag)
		}
	}
}

func TestTransportFixedChildWiring(t *testing.T) {
	session, unused := transportPipe(t)
	defer unused.Close()
	c, d := transportPipe(t)
	bundle := &transportTestBundle{files: []*os.File{c, d}}
	cmd := exec.CommandContext(context.Background(), "/never-executed", "--meridian-session-fd=3", "--", "https://gateway.invalid")
	cmd.ExtraFiles = []*os.File{session}
	if err := wireUniVPNTransport(cmd, bundle); err != nil {
		t.Fatal(err)
	}
	want := []string{"/never-executed", "--meridian-session-fd=3", "--meridian-control-fd=4", "--meridian-data-fd=5", "--", "https://gateway.invalid"}
	if !reflect.DeepEqual(cmd.Args, want) || !reflect.DeepEqual(cmd.ExtraFiles, []*os.File{session, c, d}) {
		t.Fatal("wrong fixed child descriptor wiring", cmd.Args)
	}
	cmd.Stdin = unused
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	started := false
	if err := startUniVPNContained(context.Background(), cmd, &transportIsolation{}, func() error {
		started = true
		for _, f := range cmd.ExtraFiles {
			if _, e := f.Stat(); e != nil {
				t.Fatal("closed before Start returned")
			}
		}
		return nil
	}); err != nil || !started {
		t.Fatal(err)
	}
	if err := bundle.Close(); err != nil {
		t.Fatal(err)
	}
	assertTransportClosed(t, c, d)
	if _, e := session.Stat(); e != nil {
		t.Fatal("transport closed session channel")
	}
}

type failingCloseTransport struct{}

func (failingCloseTransport) Files() ([]*os.File, error) { return nil, nil }
func (failingCloseTransport) Close() error               { return errors.New("close uncertainty") }

type returnTransportProcess struct{ p UniVPNNativeProcess }

func (l returnTransportProcess) Launch(context.Context, string, []string, []byte) (UniVPNNativeProcess, error) {
	return l.p, nil
}
func TestTransportCloseFailureAfterStartQuarantines(t *testing.T) {
	// No process is executed: Cmd.Wait's not-started result is joined with the
	// finalizer's cleanup flag by the actual uniVPNExecProcess.Wait method.
	p := &uniVPNExecProcess{cmd: &exec.Cmd{}, exited: make(chan struct{}), contained: make(chan struct{}), isolation: &transportIsolation{}}
	stopped := false
	if e := closeUniVPNLaunchTransport(failingCloseTransport{}, p, func() error { stopped = true; return nil }, nil); e != nil || !stopped || p.launchCleanupErr == nil {
		t.Fatal("successful lifecycle lost", e)
	}
	b, _, _ := brokerFixture()
	b.Launcher = returnTransportProcess{p}
	session, e := b.Start(context.Background(), b.Executable, brokerArgs(), []byte("password"))
	if e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-session.Done():
	case <-time.After(time.Second):
		t.Fatal("teardown did not finish")
	}
	var cleanup *CleanupError
	if !errors.As(e, &cleanup) || b.Available() {
		t.Fatal("post-start close uncertainty not quarantined", e)
	}
}
func TestTransportCloseFailureBeforeStart(t *testing.T) {
	e := closeUniVPNLaunchTransport(failingCloseTransport{}, nil, nil, errors.New("start failed"))
	var cleanup *CleanupError
	if !errors.As(e, &cleanup) {
		t.Fatal("close failure erased")
	}
}
func TestTransportCanceledBeforeAcquire(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := transportProviderFunc(func(context.Context, string, fdtransport.Endpoint) (*os.File, *os.File, error) {
		t.Fatal("acquire after cancel")
		return nil, nil, nil
	})
	if _, e := acquireUniVPNTransport(ctx, p, "", fdtransport.Endpoint{}, nil); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
func TestTransportCanceledAfterDuplicate(t *testing.T) {
	c, d := transportPipe(t)
	x, y := transportPipe(t)
	bundle := &transportTestBundle{files: []*os.File{x, y}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := transportProviderFunc(func(context.Context, string, fdtransport.Endpoint) (*os.File, *os.File, error) { return c, d, nil })
	_, e := acquireUniVPNTransport(ctx, p, "", fdtransport.Endpoint{}, func(*os.File, *os.File, fdtransport.Endpoint) (uniVPNTransportBundle, error) {
		cancel()
		return bundle, nil
	})
	if !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	assertTransportClosed(t, c, d, x, y)
}

type blockingRollbackIsolation struct {
	transportIsolation
	release, done chan struct{}
}

func (i *blockingRollbackIsolation) RollbackLaunch(context.Context, *exec.Cmd) error {
	<-i.release
	close(i.done)
	return nil
}
func TestTransportBoundsUncooperativeRollback(t *testing.T) {
	i := &blockingRollbackIsolation{transportIsolation: transportIsolation{prepareErr: errors.New("prepare")}, release: make(chan struct{}), done: make(chan struct{})}
	start := time.Now()
	e := startUniVPNContained(context.Background(), protectedTransportCmd(t), i, func() error { t.Fatal("started"); return nil })
	close(i.release)
	<-i.done
	var cleanup *CleanupError
	if !errors.As(e, &cleanup) || time.Since(start) > 3*time.Second {
		t.Fatal("rollback not bounded/marked uncertain", e)
	}
}
