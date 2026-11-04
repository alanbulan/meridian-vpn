//go:build linux

package core

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Every FD below is an integer in a private fake kernel, never an OS descriptor.
// No process, pidfd, procfs, namespace, socket, bus, or host networking is touched.
type uniVPNPidfdFixtureFD struct {
	kind  int // 0 is pidfd; otherwise a namespace's CLONE_NEW* type.
	inode uint64
}

type uniVPNPidfdFixtureKernel struct {
	mu        sync.Mutex
	next      int
	fds       map[int]uniVPNPidfdFixtureFD
	closes    map[int]int
	requests  []uint
	fault     string
	failAt    int
	acquired  int
	change    bool
	before    func(int, uint)
	double    bool
	closeFail string
}

func newUniVPNPidfdFixtureKernel() *uniVPNPidfdFixtureKernel {
	return &uniVPNPidfdFixtureKernel{next: 100, fds: map[int]uniVPNPidfdFixtureFD{40: {}}, closes: make(map[int]int)}
}

func (k *uniVPNPidfdFixtureKernel) flags(fd int) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	f, ok := k.fds[fd]
	if !ok {
		return 0, syscall.EBADF
	}
	if k.fault == "original flags error" && fd == 40 || k.fault == "duplicate flags error" && fd != 40 && f.kind == 0 || k.fault == "namespace flags error" && f.kind != 0 {
		return 0, syscall.EIO
	}
	if k.fault == "original inheritable" && fd == 40 || k.fault == "duplicate inheritable" && fd != 40 && f.kind == 0 || k.fault == "namespace inheritable" && f.kind != 0 {
		return 0, nil
	}
	return syscall.FD_CLOEXEC, nil
}
func (k *uniVPNPidfdFixtureKernel) dup(fd int) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	f, ok := k.fds[fd]
	if !ok || k.fault == "dup" {
		return -1, syscall.EBADF
	}
	k.next++
	k.fds[k.next] = f
	return k.next, nil
}
func (k *uniVPNPidfdFixtureKernel) ioctl(fd int, request uint) (int, error) {
	if k.before != nil {
		k.before(fd, request)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	f, ok := k.fds[fd]
	if !ok {
		return -1, syscall.EBADF
	}
	if request == unix.NS_GET_NSTYPE {
		if k.fault == "type error" {
			return -1, syscall.ENOTTY
		}
		if k.fault == "wrong type" {
			return unix.CLONE_NEWIPC, nil
		}
		return f.kind, nil
	}
	if f.kind != 0 {
		return -1, syscall.ENOTTY
	}
	k.requests = append(k.requests, request)
	k.acquired++
	if k.failAt == k.acquired {
		switch k.fault {
		case "unsupported":
			return -1, syscall.ENOTTY
		case "absent namespace":
			return -1, syscall.EOPNOTSUPP
		case "permission":
			return -1, syscall.EPERM
		case "ptrace access":
			return -1, syscall.EACCES
		case "exit":
			return -1, syscall.ESRCH
		}
	}
	kind := map[uint]int{
		unix.PIDFD_GET_NET_NAMESPACE:  unix.CLONE_NEWNET,
		unix.PIDFD_GET_MNT_NAMESPACE:  unix.CLONE_NEWNS,
		unix.PIDFD_GET_USER_NAMESPACE: unix.CLONE_NEWUSER,
		unix.PIDFD_GET_PID_NAMESPACE:  unix.CLONE_NEWPID,
	}[request]
	if kind == 0 {
		return -1, syscall.EINVAL
	}
	k.next++
	inode := uint64(kind) + 10
	if k.change && k.acquired > 4 {
		inode++
	}
	k.fds[k.next] = uniVPNPidfdFixtureFD{kind: kind, inode: inode}
	return k.next, nil
}
func (k *uniVPNPidfdFixtureKernel) stat(fd int) (syscall.Stat_t, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	f, ok := k.fds[fd]
	if !ok || k.fault == "stat error" {
		return syscall.Stat_t{}, syscall.EBADF
	}
	s := syscall.Stat_t{Dev: 7, Ino: f.inode, Mode: syscall.S_IFREG | 0444}
	if k.fault == "directory" {
		s.Mode = syscall.S_IFDIR | 0555
	}
	if k.fault == "zero inode" {
		s.Ino = 0
	}
	return s, nil
}
func (k *uniVPNPidfdFixtureKernel) fs(fd int) (int64, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.fds[fd]; !ok || k.fault == "fs error" {
		return 0, syscall.EIO
	}
	if k.fault == "not nsfs" {
		return uniVPNProcMagic, nil
	}
	return uniVPNNSMagic, nil
}
func (k *uniVPNPidfdFixtureKernel) close(fd int) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	f, ok := k.fds[fd]
	k.closes[fd]++
	if !ok {
		k.double = true
		return syscall.EBADF
	}
	delete(k.fds, fd) // error never makes it safe to retry a close.
	if k.closeFail == "original" && fd == 40 || k.closeFail == "duplicate" && fd != 40 && f.kind == 0 || k.closeFail == "namespace" && f.kind != 0 {
		return syscall.EIO
	}
	return nil
}
func (k *uniVPNPidfdFixtureKernel) assertDrained(t *testing.T) {
	t.Helper()
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.fds) != 0 || k.double || k.closes[40] != 1 {
		t.Fatalf("descriptor ownership lost: live=%v closes=%v double=%v", k.fds, k.closes, k.double)
	}
	for fd, count := range k.closes {
		if count != 1 {
			t.Fatalf("descriptor %d closed %d times", fd, count)
		}
	}
}

func TestUniVPNProcessPidfdNamespaces(t *testing.T) {
	k := newUniVPNPidfdFixtureKernel()
	o := retainUniVPNCreationPidfd(40, 4321, k)
	got, err := o.observe(context.Background())
	if err != nil || got.PID != 4321 || got.Session != "" || got.NetworkNS.Inode != uint64(unix.CLONE_NEWNET)+10 || got.MountNS.Inode != uint64(unix.CLONE_NEWNS)+10 || got.UserNS.Inode != uint64(unix.CLONE_NEWUSER)+10 || got.PIDNS.Inode != uint64(unix.CLONE_NEWPID)+10 {
		t.Fatalf("unexpected namespace observations: %+v, %v", got, err)
	}
	if len(k.requests) != 8 || len(k.fds) != 1 {
		t.Fatalf("must read two full samples and retain only original: %v %v", k.requests, k.fds)
	}
	for i, request := range k.requests {
		want := []uint{unix.PIDFD_GET_NET_NAMESPACE, unix.PIDFD_GET_MNT_NAMESPACE, unix.PIDFD_GET_USER_NAMESPACE, unix.PIDFD_GET_PID_NAMESPACE}[i%4]
		if request != want {
			t.Fatalf("request %d: %x != %x", i, request, want)
		}
	}
	for _, value := range []any{got, &got} {
		if _, ok := value.(UniVPNNMHostAuthority); ok {
			t.Fatal("namespace observations granted host authority")
		}
		if _, ok := value.(UniVPNNMHostBinding); ok {
			t.Fatal("namespace observations granted host binding")
		}
	}
	if err := o.close(); err != nil {
		t.Fatal(err)
	}
	if err := o.close(); err != nil {
		t.Fatal(err)
	}
	k.assertDrained(t)
}

func TestUniVPNProcessPidfdRejectsPartialOrUnsafeSamples(t *testing.T) {
	for _, fault := range []string{
		"original flags error", "original inheritable", "duplicate flags error", "duplicate inheritable", "dup",
		"namespace flags error", "namespace inheritable", "not nsfs", "fs error", "stat error", "directory", "zero inode", "type error", "wrong type",
		"unsupported", "absent namespace", "permission", "ptrace access", "exit", "changed", "canceled",
	} {
		t.Run(fault, func(t *testing.T) {
			k := newUniVPNPidfdFixtureKernel()
			k.fault, k.failAt, k.change = fault, 4, fault == "changed"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if fault == "canceled" {
				k.before = func(int, uint) { cancel() }
			}
			o := retainUniVPNCreationPidfd(40, 4321, k)
			if got, err := o.observe(ctx); err == nil || got != (UniVPNNMNamespaceObservation{}) {
				t.Fatalf("partial/unsafe observation escaped: %+v, %v", got, err)
			}
			k.fault, k.change, k.before = "", false, nil
			if _, err := o.observe(context.Background()); err == nil {
				t.Fatal("observation failure was not sticky")
			}
			if err := o.close(); err != nil {
				t.Fatal(err)
			}
			k.assertDrained(t)
		})
	}
}

func TestUniVPNProcessPidfdCloseFailuresAreSticky(t *testing.T) {
	for _, which := range []string{"original", "namespace", "duplicate"} {
		t.Run(which, func(t *testing.T) {
			k := newUniVPNPidfdFixtureKernel()
			k.closeFail = which
			o := retainUniVPNCreationPidfd(40, 4321, k)
			got, err := o.observe(context.Background())
			if which != "original" && (err == nil || got != (UniVPNNMNamespaceObservation{})) {
				t.Fatal("successful sample hid close failure")
			}
			if which != "original" {
				var cleanup *CleanupError
				if !errors.As(err, &cleanup) {
					t.Fatalf("optional observation hid cleanup uncertainty: %v", err)
				}
			}
			for range 2 {
				var cleanup *CleanupError
				if err := o.close(); !errors.As(err, &cleanup) {
					t.Fatalf("cleanup uncertainty missing: %v", err)
				}
			}
			var cleanup *CleanupError
			if _, err := o.observe(context.Background()); !errors.As(err, &cleanup) {
				t.Fatalf("subsequent observation hid sticky cleanup uncertainty: %v", err)
			}
			k.assertDrained(t)
		})
	}
}

func TestUniVPNProcessPidfdConcurrentWait(t *testing.T) {
	k := newUniVPNPidfdFixtureKernel()
	o := retainUniVPNCreationPidfd(40, 4321, k)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	k.before = func(int, uint) { once.Do(func() { close(entered); <-release }) }
	done := make(chan error, 1)
	go func() { _, err := o.observe(context.Background()); done <- err }()
	<-entered
	p := &uniVPNExecProcess{cmd: &exec.Cmd{}, namespaces: o, exited: make(chan struct{}), contained: make(chan struct{}), isolation: uniVPNObservationIsolation{}}
	waited := make(chan error, 1)
	go func() { waited <- p.Wait() }() // Unstarted Cmd: no wait syscall occurs.
	select {
	case err := <-waited:
		var cleanup *CleanupError
		if !errors.As(err, &cleanup) || p.containmentErr == nil {
			t.Fatalf("in-flight descriptor cleanup uncertainty lost: %v", err)
		}
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("Wait blocked behind observation ioctl")
	}
	close(release)
	var cleanup *CleanupError
	if err := <-done; !errors.As(err, &cleanup) {
		t.Fatalf("Wait allowed stale success or hid cleanup uncertainty: %v", err)
	}
	k.assertDrained(t)
}

func TestUniVPNProcessPidfdConcurrentFailureInvalidates(t *testing.T) {
	k := newUniVPNPidfdFixtureKernel()
	o := retainUniVPNCreationPidfd(40, 4321, k)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	k.before = func(fd int, _ uint) {
		if fd == 101 { // First operation's private duplicate only.
			once.Do(func() { close(entered); <-release })
		}
	}
	done := make(chan error, 1)
	go func() { _, err := o.observe(context.Background()); done <- err }()
	<-entered
	k.mu.Lock()
	k.fault, k.failAt = "unsupported", 1
	k.mu.Unlock()
	if _, err := o.observe(context.Background()); err == nil {
		t.Fatal("unsupported parallel observation succeeded")
	}
	k.mu.Lock()
	k.fault = ""
	k.mu.Unlock()
	close(release)
	if err := <-done; err == nil {
		t.Fatal("parallel successful read ignored sticky generation failure")
	}
	if err := o.close(); err != nil {
		t.Fatal(err)
	}
	k.assertDrained(t)
}

func TestUniVPNProcessPidfdWaitCloseFailure(t *testing.T) {
	k := newUniVPNPidfdFixtureKernel()
	k.closeFail = "original"
	p := &uniVPNExecProcess{cmd: &exec.Cmd{}, namespaces: retainUniVPNCreationPidfd(40, 4321, k), exited: make(chan struct{}), contained: make(chan struct{}), isolation: uniVPNObservationIsolation{}}
	var cleanup *CleanupError
	if err := p.Wait(); !errors.As(err, &cleanup) || p.containmentErr == nil {
		t.Fatalf("Wait lost pidfd close uncertainty: %v", err)
	}
	k.assertDrained(t)
}

func TestUniVPNProcessPidfdCaptureAtStart(t *testing.T) {
	for _, mode := range []string{"success", "no pidfd", "prepare error", "cancel", "start error", "failed exec cleaned", "partial start", "start close failure", "pointer mutation", "slot mutation"} {
		t.Run(mode, func(t *testing.T) {
			k := newUniVPNPidfdFixtureKernel()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			i := &transportIsolation{}
			p := &uniVPNExecProcess{cmd: &exec.Cmd{SysProcAttr: &syscall.SysProcAttr{Setpgid: true}}, isolation: i}
			prepared := false
			i.mutate = func(cmd *exec.Cmd) {
				prepared = cmd.SysProcAttr.PidFD != nil && *cmd.SysProcAttr.PidFD == -1
				switch mode {
				case "cancel":
					cancel()
				case "pointer mutation":
					other := -1
					cmd.SysProcAttr.PidFD = &other
				case "slot mutation":
					*cmd.SysProcAttr.PidFD = 40
				}
			}
			if mode == "prepare error" {
				i.prepareErr = errors.New("synthetic prepare failure")
			}
			started := false
			err := startUniVPNProcessWithPidfd(ctx, p, func() error {
				started = true
				if !prepared || p.cmd.SysProcAttr.PidFD == nil || *p.cmd.SysProcAttr.PidFD != -1 {
					t.Fatal("capture not reserved before Start")
				}
				// Mirror Group.Start copying attrs before invoking cmd.Start.
				attr := *p.cmd.SysProcAttr
				p.cmd.SysProcAttr = &attr
				if mode != "no pidfd" {
					*attr.PidFD = 40
				}
				if mode == "failed exec cleaned" {
					// Mirror syscall.forkAndExecFailureCleanup: the Go runtime
					// already closed its returned fd and reset the output slot.
					_ = k.close(*attr.PidFD)
					*attr.PidFD = -1
					return errors.New("synthetic failed exec already cleaned")
				}
				if mode == "start error" || mode == "start close failure" {
					if mode == "start close failure" {
						k.closeFail = "original"
					}
					return errors.New("synthetic failed Start with owned fd")
				}
				// Only a label, never passed to os.Process.Wait/Signal or a syscall.
				p.cmd.Process = &os.Process{Pid: 4321}
				if mode == "partial start" {
					return errors.New("synthetic partial provider Start")
				}
				return nil
			}, k)
			if mode == "success" || mode == "no pidfd" {
				if err != nil || !started || i.rollbacks != 0 {
					t.Fatalf("successful Start failed: %v", err)
				}
				_, observationErr := p.namespaces.observe(context.Background())
				if (mode == "no pidfd") != (observationErr != nil) {
					t.Fatalf("unexpected capture availability: %v", observationErr)
				}
			} else if err == nil || i.rollbacks != 1 {
				t.Fatalf("failed Start missed rollback: %v, %d", err, i.rollbacks)
			}
			if mode == "start close failure" {
				var cleanup *CleanupError
				if !errors.As(err, &cleanup) {
					t.Fatal("launch lost fd cleanup failure")
				}
			}
			if mode == "partial start" && (p.cmd.Process == nil || !p.namespaces.closed) {
				t.Fatal("partial Start lost child or left observations valid")
			}
			if mode != "pointer mutation" && p.cmd.SysProcAttr.PidFD != nil {
				t.Fatal("capture output pointer escaped after transfer")
			}
			_ = p.namespaces.close()
			if !started && mode != "slot mutation" || mode == "no pidfd" {
				// No synthetic descriptor was returned, so its fixture owner closes.
				if k.closes[40] != 0 {
					t.Fatal("closed a descriptor that was never returned")
				}
				_ = k.close(40)
			}
			k.assertDrained(t)
		})
	}
}

func TestUniVPNProcessPidfdBrokerGate(t *testing.T) {
	for _, state := range []string{"live", "not bound", "stopping", "uncertain", "exited", "session", "missing pidfd", "launch failure", "changed during read", "namespace close failure", "duplicate close failure"} {
		t.Run(state, func(t *testing.T) {
			k := newUniVPNPidfdFixtureKernel()
			o := retainUniVPNCreationPidfd(40, 4321, k)
			session := strings.Repeat("a", 32)
			p := &uniVPNExecProcess{namespaces: o, observation: &uniVPNProcessObservation{}, exited: make(chan struct{}), sessionID: session}
			b := &UniVPNNMBroker{gate: make(chan struct{}, 1), process: p, launcher: &UniVPNExecLauncher{}, run: context.Background(), prepared: true, bound: true, waitDone: make(chan struct{})}
			b.gate <- struct{}{}
			b.binding.Identity.Session, b.offer.Session = session, session
			switch state {
			case "not bound":
				b.bound = false
			case "stopping":
				b.stopTried = true
			case "uncertain":
				b.uncertain = true
			case "exited":
				close(p.exited)
			case "session":
				p.sessionID = strings.Repeat("b", 32)
			case "missing pidfd":
				p.namespaces = nil
			case "launch failure":
				p.launchCleanupErr = errors.New("launch failed")
			case "namespace close failure":
				k.closeFail = "namespace"
			case "duplicate close failure":
				k.closeFail = "duplicate"
			case "changed during read":
				k.before = func(int, uint) {
					<-b.gate
					b.stopTried = true
					b.gate <- struct{}{}
				}
			}
			got, err := b.ObserveNativeNamespaces(context.Background())
			if state == "live" {
				if err != nil || got.Session != session {
					t.Fatalf("bound child rejected: %+v, %v", got, err)
				}
			} else if err == nil || got != (UniVPNNMNamespaceObservation{}) {
				t.Fatalf("invalid lifecycle accepted: %+v, %v", got, err)
			}
			if strings.Contains(state, "close failure") {
				var cleanup *CleanupError
				if !errors.As(err, &cleanup) {
					t.Fatalf("broker hid optional observation cleanup uncertainty: %v", err)
				}
			}
			_ = o.close()
			k.assertDrained(t)
		})
	}
}

type uniVPNPidfdPartialLaunchProcess struct {
	stopped, waited chan struct{}
	waits, stops    atomic.Int32
}

func (p *uniVPNPidfdPartialLaunchProcess) Stop() error {
	p.stops.Add(1)
	close(p.stopped)
	return nil
}
func (p *uniVPNPidfdPartialLaunchProcess) Wait() error {
	p.waits.Add(1)
	<-p.stopped
	close(p.waited)
	return nil
}

type uniVPNPidfdPartialLauncher struct {
	p *uniVPNPidfdPartialLaunchProcess
}

func (l uniVPNPidfdPartialLauncher) Launch(context.Context, string, []string, []byte) (UniVPNNativeProcess, error) {
	return l.p, errors.New("synthetic partial launch")
}

func TestUniVPNProcessPidfdPartialLaunchBrokerRetainsWait(t *testing.T) {
	b, _, n := brokerFixture()
	p := &uniVPNPidfdPartialLaunchProcess{stopped: make(chan struct{}), waited: make(chan struct{})}
	b.Launcher = uniVPNPidfdPartialLauncher{p}
	session, err := b.Start(context.Background(), b.Executable, brokerArgs(), []byte("synthetic"))
	var cleanup *CleanupError
	if session != nil || !errors.As(err, &cleanup) || b.Available() {
		t.Fatalf("partial launch became ready/reusable: %v %v", session, err)
	}
	select {
	case <-n.cleaned:
	case <-time.After(2 * time.Second):
		t.Fatal("partial launch lost owned teardown")
	}
	if p.waits.Load() != 1 || p.stops.Load() != 1 || len(n.ready) != 0 {
		t.Fatal("partial launch did not have exactly one Stop and Wait")
	}
}
