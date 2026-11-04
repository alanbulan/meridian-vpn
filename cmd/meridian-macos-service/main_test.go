package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mygo-vpn/internal/core"
	"mygo-vpn/internal/macosvpn"
)

const privateID = "private-service-ID"
const privateGateway = "private-gateway.example"

func validArgs() []string {
	return []string{"--connect-existing-service", "--service-id", privateID, "--expected-gateway", privateGateway,
		"--target", "10.23.45.67", "--allow-network-changes", "--allow-saved-system-credentials", "--allow-shared-system-service", "--accept-limited-verification"}
}
func replaceArg(args []string, flag, value string) []string {
	copy := append([]string(nil), args...)
	for i := range copy {
		if copy[i] == flag {
			copy[i+1] = value
			return copy
		}
	}
	panic("missing flag")
}
func removeArg(args []string, flag string) []string {
	var out []string
	for _, arg := range args {
		if arg != flag {
			out = append(out, arg)
		}
	}
	return out
}

type fakeAdapter struct {
	profile   core.Profile
	scope     string
	available bool
	start     func(context.Context, core.Profile, []byte) (core.Session, error)
	starts    atomic.Int32
}

func (a *fakeAdapter) Capability() core.Capability {
	return core.Capability{Available: a.available, Message: "private-capability-secret"}
}
func (a *fakeAdapter) VerificationScope() string             { return a.scope }
func (a *fakeAdapter) LimitedProfile() (core.Profile, error) { return a.profile, nil }
func (a *fakeAdapter) Start(ctx context.Context, p core.Profile, password []byte) (core.Session, error) {
	a.starts.Add(1)
	return a.start(ctx, p, password)
}

type fakeSession struct {
	ready, done chan error
	scope       string
	stop        func(int32) error
	stops       atomic.Int32
}

func newSession() *fakeSession {
	return &fakeSession{ready: make(chan error, 1), done: make(chan error, 1), scope: core.SystemServiceTargetRoutes, stop: func(int32) error { return nil }}
}
func (s *fakeSession) Ready() <-chan error       { return s.ready }
func (s *fakeSession) Done() <-chan error        { return s.done }
func (s *fakeSession) VerificationScope() string { return s.scope }
func (s *fakeSession) Stop() error               { return s.stop(s.stops.Add(1)) }

type capture struct {
	mu    sync.Mutex
	text  bytes.Buffer
	lines chan string
}

func newCapture() *capture { return &capture{lines: make(chan string, 100)} }
func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	n, err := c.text.Write(p)
	c.mu.Unlock()
	c.lines <- string(p)
	return n, err
}
func (c *capture) String() string { c.mu.Lock(); defer c.mu.Unlock(); return c.text.String() }
func waitLine(t *testing.T, c *capture, needle string) {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case line := <-c.lines:
			if strings.Contains(line, needle) {
				return
			}
		case <-timer.C:
			t.Fatalf("missing output %q, got %q", needle, c.String())
		}
	}
}
func waitCode(t *testing.T, result <-chan int, want int) {
	t.Helper()
	select {
	case got := <-result:
		if got != want {
			t.Fatalf("exit=%d, want %d", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runner did not finish")
	}
}
func assertRetained(t *testing.T, result <-chan int) {
	t.Helper()
	select {
	case code := <-result:
		t.Fatalf("dropped quarantined owner: %d", code)
	default:
	}
}
func assertPrivate(t *testing.T, text string) {
	t.Helper()
	for _, secret := range []string{privateID, privateGateway, "private-native-secret", "private-capability-secret", "10.23.45.67"} {
		if strings.Contains(text, secret) {
			t.Fatalf("private output: %q", text)
		}
	}
}

func fixture(t *testing.T, s *fakeSession) (*fakeAdapter, dependencies, chan os.Signal) {
	t.Helper()
	o, ok, _ := parse(validArgs(), &bytes.Buffer{})
	if !ok {
		t.Fatal("valid fixture args rejected")
	}
	a := &fakeAdapter{profile: expectedProfile(o), scope: core.SystemServiceTargetRoutes, available: true}
	a.start = func(_ context.Context, p core.Profile, password []byte) (core.Session, error) {
		if len(password) != 0 || !reflect.DeepEqual(p, a.profile) {
			t.Error("credentials or wrong bound profile")
		}
		return s, nil
	}
	signals := make(chan os.Signal, 10)
	d := dependencies{platform: "darwin", signals: signals, selectService: func(_ context.Context, id string) (selectedService, error) {
		if id != privateID {
			t.Errorf("selected wrong service %q", id)
		}
		return selectedService{configuration: macosvpn.ServiceConfiguration{ServiceID: privateID, Gateway: privateGateway}, backend: func(c macosvpn.ExistingServiceConsent, targets []netip.Addr) limitedAdapter {
			if !c.NetworkChanges || !c.SavedSystemCredentials || !c.SharedSystemService || !c.LimitedVerification {
				t.Error("incomplete consent")
			}
			if len(targets) != 1 || targets[0].String() != "10.23.45.67" {
				t.Error("wrong targets")
			}
			return a
		}}, nil
	}}
	return a, d, signals
}
func launch(args []string, d dependencies) (*capture, <-chan int) {
	out := newCapture()
	result := make(chan int, 1)
	go func() { result <- run(args, out, d) }()
	return out, result
}

func TestDefaultHelpAndInvalidFlagsNeverSelect(t *testing.T) {
	cases := []struct {
		name string
		args []string
		code int
	}{
		{"default", nil, 0}, {"help", []string{"--help"}, 0}, {"unknown", []string{"--private-secret"}, 2},
		{"extra", append(validArgs(), "private-secret"), 2}, {"no-connect", removeArg(validArgs(), "--connect-existing-service"), 2},
		{"invalid-id", replaceArg(validArgs(), "--service-id", "secret/invalid"), 2},
		{"empty-id", replaceArg(validArgs(), "--service-id", ""), 2},
		{"url-gateway", replaceArg(validArgs(), "--expected-gateway", "https://secret:password@example.test"), 2},
		{"zone-gateway", replaceArg(validArgs(), "--expected-gateway", "fe80::1%en0"), 2},
	}
	for _, flag := range []string{"--allow-network-changes", "--allow-saved-system-credentials", "--allow-shared-system-service", "--accept-limited-verification"} {
		cases = append(cases, struct {
			name string
			args []string
			code int
		}{flag, removeArg(validArgs(), flag), 2})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			got := run(tc.args, &out, dependencies{platform: "darwin", signals: make(chan os.Signal), selectService: func(context.Context, string) (selectedService, error) {
				t.Error("implicit system read")
				return selectedService{}, errors.New("private-native-secret")
			}})
			if got != tc.code {
				t.Errorf("exit=%d want=%d", got, tc.code)
			}
			assertPrivate(t, out.String())
		})
	}
}

func TestInvalidTargetsNeverSelect(t *testing.T) {
	for _, target := range []string{"", "example.test", "0.0.0.0", "::", "::ffff:10.0.0.1", "169.254.1.2", "fe80::1", "fe80::1%en0", "224.0.0.1", "ff02::1", "127.0.0.1", "::1", "255.255.255.255", "10.0.0.1/32"} {
		t.Run(target, func(t *testing.T) {
			var out bytes.Buffer
			code := run(replaceArg(validArgs(), "--target", target), &out, dependencies{platform: "darwin", signals: make(chan os.Signal), selectService: func(context.Context, string) (selectedService, error) {
				t.Error("read invalid target")
				return selectedService{}, nil
			}})
			if code != 2 {
				t.Errorf("accepted invalid target: %q", target)
			}
		})
	}
	for _, args := range [][]string{append(validArgs(), "--target", "10.23.45.67"), append(replaceArg(validArgs(), "--target", "2001:db8::1"), "--target", "2001:db8:0:0::1")} {
		if _, ok, _ := parse(args, &bytes.Buffer{}); ok {
			t.Fatal("accepted duplicate target")
		}
	}
	args := validArgs()
	for i := 2; i <= 16; i++ {
		args = append(args, "--target", fmt.Sprintf("10.1.2.%d", i))
	}
	if o, ok, _ := parse(args, &bytes.Buffer{}); !ok || len(o.targets) != 16 {
		t.Fatal("16 valid targets rejected")
	}
	args = append(args, "--target", "10.1.2.17")
	if _, ok, _ := parse(args, &bytes.Buffer{}); ok {
		t.Fatal("accepted 17 targets")
	}
}

func TestWrongPlatformNeverSelect(t *testing.T) {
	var out bytes.Buffer
	if run(validArgs(), &out, dependencies{platform: "linux", signals: make(chan os.Signal), selectService: func(context.Context, string) (selectedService, error) {
		t.Error("system read off Darwin")
		return selectedService{}, nil
	}}) != 1 {
		t.Fatal("platform gate missing")
	}
}

func TestSelectionGatewayBindingStopsBeforeBackend(t *testing.T) {
	for _, gateway := range []string{"other.example", "PRIVATE-GATEWAY.example", privateGateway + "."} {
		var built atomic.Int32
		d := dependencies{platform: "darwin", signals: make(chan os.Signal), selectService: func(context.Context, string) (selectedService, error) {
			return selectedService{configuration: macosvpn.ServiceConfiguration{ServiceID: privateID, Gateway: gateway}, backend: func(macosvpn.ExistingServiceConsent, []netip.Addr) limitedAdapter { built.Add(1); return nil }}, nil
		}}
		out, result := launch(validArgs(), d)
		waitCode(t, result, 1)
		if built.Load() != 0 {
			t.Fatal("built backend for non-exact gateway")
		}
		assertPrivate(t, out.String())
	}
}

func TestAdapterAndProfileMismatchNeverStart(t *testing.T) {
	for _, scenario := range []string{"scope", "unavailable", "profile-id", "profile-gateway", "profile-targets", "profile-service"} {
		t.Run(scenario, func(t *testing.T) {
			a, d, _ := fixture(t, newSession())
			switch scenario {
			case "scope":
				a.scope = ""
			case "unavailable":
				a.available = false
			case "profile-id":
				a.profile.ID = "other"
			case "profile-gateway":
				a.profile.Gateway = "other.example"
			case "profile-targets":
				a.profile.SystemService.Targets = []string{"10.1.2.3"}
			case "profile-service":
				a.profile.SystemService.ServiceID = "other"
			}
			out, result := launch(validArgs(), d)
			waitCode(t, result, 1)
			if a.starts.Load() != 0 {
				t.Fatal("started mismatched backend/profile")
			}
			assertPrivate(t, out.String())
		})
	}
}

func TestForegroundReadyAndScopedCleanup(t *testing.T) {
	s := newSession()
	s.ready <- nil
	a, d, signals := fixture(t, s)
	out, result := launch(validArgs(), d)
	waitLine(t, out, msgReady)
	assertRetained(t, result)
	signals <- os.Interrupt
	waitCode(t, result, 0)
	if a.starts.Load() != 1 || s.stops.Load() != 1 {
		t.Fatal("unexpected activation/cleanup count")
	}
	if !strings.Contains(out.String(), msgStopped) {
		t.Fatal("no scoped cleanup notice")
	}
	assertPrivate(t, out.String())
}

func TestSessionScopeMismatchNeverReady(t *testing.T) {
	s := newSession()
	s.scope = ""
	s.ready <- nil
	_, d, _ := fixture(t, s)
	out, result := launch(validArgs(), d)
	waitCode(t, result, 1)
	if strings.Contains(out.String(), msgReady) || s.stops.Load() != 1 {
		t.Fatal("bad session scope accepted")
	}
}

func TestTerminalResultWinsQueuedReady(t *testing.T) {
	for _, terminal := range []error{nil, errors.New("private-native-secret")} {
		s := newSession()
		s.ready <- nil
		s.done <- terminal
		_, d, _ := fixture(t, s)
		out, result := launch(validArgs(), d)
		waitCode(t, result, 1)
		if strings.Contains(out.String(), msgReady) || s.stops.Load() != 1 {
			t.Fatal("terminal result overwritten by Ready")
		}
		assertPrivate(t, out.String())
	}
}

func TestCancellationDuringSelectionNeverStarts(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	signals := make(chan os.Signal, 1)
	d := dependencies{platform: "darwin", signals: signals, selectService: func(ctx context.Context, _ string) (selectedService, error) {
		close(started)
		<-release
		if ctx.Err() == nil {
			t.Error("selection not cancelled")
		}
		return selectedService{}, ctx.Err()
	}}
	out, result := launch(validArgs(), d)
	<-started
	signals <- os.Interrupt
	waitLine(t, out, msgCancel)
	assertRetained(t, result)
	close(release)
	waitCode(t, result, 0)
}

func TestCancellationDuringStartRetainsWorkerUntilReturn(t *testing.T) {
	s := newSession()
	a, d, signals := fixture(t, s)
	entered, release := make(chan struct{}), make(chan struct{})
	a.start = func(ctx context.Context, _ core.Profile, _ []byte) (core.Session, error) {
		close(entered)
		<-release
		if ctx.Err() == nil {
			t.Error("start not cancelled")
		}
		return s, nil
	}
	out, result := launch(validArgs(), d)
	<-entered
	signals <- os.Interrupt
	waitLine(t, out, msgCancel)
	assertRetained(t, result)
	if s.stops.Load() != 0 {
		t.Fatal("Stop raced with pending Start")
	}
	close(release)
	waitCode(t, result, 0)
	if s.stops.Load() != 1 || strings.Contains(out.String(), msgReady) {
		t.Fatal("bad cancellation cleanup")
	}
}

func TestCleanupFailureRetainsSessionUntilNewSignal(t *testing.T) {
	s := newSession()
	s.ready <- nil
	s.stop = func(n int32) error {
		if n == 1 {
			return errors.New("private-native-secret")
		}
		return nil
	}
	a, d, signals := fixture(t, s)
	out, result := launch(validArgs(), d)
	waitLine(t, out, msgReady)
	signals <- os.Interrupt
	waitLine(t, out, msgQuarantine)
	assertRetained(t, result)
	if s.stops.Load() != 1 || a.starts.Load() != 1 {
		t.Fatal("automatic retry/reconnection")
	}
	signals <- os.Interrupt
	waitCode(t, result, 0)
	if s.stops.Load() != 2 || a.starts.Load() != 1 {
		t.Fatal("did not retry same retained session exactly once")
	}
	assertPrivate(t, out.String())
}

func TestQueuedCleanupErrorCannotBeErasedByInitialStop(t *testing.T) {
	s := newSession()
	s.ready <- nil
	s.stop = func(n int32) error {
		if n == 1 {
			s.done <- &core.CleanupError{}
		}
		return nil
	}
	_, d, signals := fixture(t, s)
	out, result := launch(validArgs(), d)
	waitLine(t, out, msgReady)
	signals <- os.Interrupt
	waitLine(t, out, msgQuarantine)
	assertRetained(t, result)
	if strings.Contains(out.String(), msgStopped) {
		t.Fatal("claimed cleanup with queued uncertainty")
	}
	signals <- os.Interrupt
	waitCode(t, result, 0)
	if s.stops.Load() != 2 {
		t.Fatal("fresh explicit cleanup missing")
	}
}

func TestBackendCleanupNotificationRequiresExplicitRetry(t *testing.T) {
	s := newSession()
	s.ready <- &core.CleanupError{}
	s.done <- &core.CleanupError{}
	_, d, signals := fixture(t, s)
	out, result := launch(validArgs(), d)
	waitLine(t, out, msgQuarantine)
	assertRetained(t, result)
	if s.stops.Load() != 0 {
		t.Fatal("automatic retry after backend cleanup failure")
	}
	signals <- os.Interrupt
	waitCode(t, result, 0)
	if s.stops.Load() != 1 || strings.Contains(out.String(), msgReady) {
		t.Fatal("bad explicit recovery")
	}
}

func TestRepeatedSignalsNeverOverlapStop(t *testing.T) {
	s := newSession()
	s.ready <- nil
	entered, release := make(chan struct{}), make(chan struct{})
	s.stop = func(int32) error { close(entered); <-release; return nil }
	_, d, signals := fixture(t, s)
	out, result := launch(validArgs(), d)
	waitLine(t, out, msgReady)
	signals <- os.Interrupt
	<-entered
	signals <- os.Interrupt
	waitLine(t, out, msgCancel)
	if s.stops.Load() != 1 {
		t.Fatal("overlapping Stop")
	}
	assertRetained(t, result)
	close(release)
	waitCode(t, result, 0)
}

func TestStartErrorWithSessionMustClean(t *testing.T) {
	s := newSession()
	a, d, _ := fixture(t, s)
	a.start = func(context.Context, core.Profile, []byte) (core.Session, error) {
		return s, errors.New("private-native-secret")
	}
	out, result := launch(validArgs(), d)
	waitCode(t, result, 1)
	if s.stops.Load() != 1 || strings.Contains(out.String(), msgReady) {
		t.Fatal("failed start dropped session")
	}
	assertPrivate(t, out.String())
}

func TestCleanupClassificationsRetainOwner(t *testing.T) {
	for _, terminal := range []error{
		&core.CleanupError{},
		fmt.Errorf("private-native-secret: %w", &core.CleanupError{}),
		core.NewConnectionError(core.FailureCleanup),
		errors.Join(core.NewConnectionError(core.FailureTransport), core.NewConnectionError(core.FailureCleanup)),
	} {
		s := newSession()
		s.done <- terminal
		_, d, signals := fixture(t, s)
		out, result := launch(validArgs(), d)
		waitLine(t, out, msgQuarantine)
		assertRetained(t, result)
		if s.stops.Load() != 0 {
			t.Fatal("automatic cleanup retry")
		}
		signals <- os.Interrupt
		waitCode(t, result, 0)
		assertPrivate(t, out.String())
	}
}

func TestFailedExplicitRetryStaysQuarantined(t *testing.T) {
	s := newSession()
	s.ready <- nil
	s.stop = func(n int32) error {
		if n <= 2 {
			return errors.New("private-native-secret")
		}
		return nil
	}
	a, d, signals := fixture(t, s)
	out, result := launch(validArgs(), d)
	waitLine(t, out, msgReady)
	for want := int32(1); want <= 2; want++ {
		signals <- os.Interrupt
		waitLine(t, out, msgQuarantine)
		assertRetained(t, result)
		if s.stops.Load() != want || a.starts.Load() != 1 {
			t.Fatal("unrequested retry or reconnect")
		}
	}
	signals <- os.Interrupt
	waitCode(t, result, 0)
	if s.stops.Load() != 3 {
		t.Fatal("missing final explicit retry")
	}
}

func TestNoTargetsRejectedAndNoConsentPersists(t *testing.T) {
	args := validArgs()
	for i, arg := range args {
		if arg == "--target" {
			args = append(args[:i], args[i+2:]...)
			break
		}
	}
	if _, ok, _ := parse(args, &bytes.Buffer{}); ok {
		t.Fatal("accepted no targets")
	}
	if _, ok, _ := parse(validArgs(), &bytes.Buffer{}); !ok {
		t.Fatal("valid run rejected")
	}
	if _, ok, _ := parse(removeArg(validArgs(), "--allow-saved-system-credentials"), &bytes.Buffer{}); ok {
		t.Fatal("consent persisted between attempts")
	}
}
