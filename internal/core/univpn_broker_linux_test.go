//go:build linux

package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"
)

type mockUniVPNProcess struct {
	done chan error
	once sync.Once
}

func (p *mockUniVPNProcess) Wait() error { return <-p.done }
func (p *mockUniVPNProcess) Stop() error { p.once.Do(func() { p.done <- nil }); return nil }

type mockUniVPNLauncher struct {
	p        *mockUniVPNProcess
	retained []byte
	password string
}

func (l *mockUniVPNLauncher) Launch(_ context.Context, _ string, _ []string, p []byte) (UniVPNNativeProcess, error) {
	l.retained = p
	l.password = string(p)
	return l.p, nil
}

type mockUniVPNNetwork struct {
	ready        chan error
	cleaned      chan struct{}
	cleanupError error
}

func (n *mockUniVPNNetwork) WaitReady(ctx context.Context, _ UniVPNNativeProcess) error {
	select {
	case e := <-n.ready:
		return e
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (n *mockUniVPNNetwork) Cleanup(context.Context, UniVPNNativeProcess) error {
	close(n.cleaned)
	return n.cleanupError
}
func brokerFixture() (*UniVPNBrokerBackend, *mockUniVPNLauncher, *mockUniVPNNetwork) {
	l := &mockUniVPNLauncher{p: &mockUniVPNProcess{done: make(chan error, 1)}}
	n := &mockUniVPNNetwork{ready: make(chan error, 1), cleaned: make(chan struct{})}
	return &UniVPNBrokerBackend{Executable: "/usr/libexec/univpn-native", AllowedGateways: map[string]bool{"https://gateway.invalid": true}, Launcher: l, Network: n, StartupTimeout: time.Second}, l, n
}
func brokerArgs() []string {
	return []string{"--protocol=univpn", "--non-inter", "--passwd-on-stdin", "--no-proxy", "--no-dtls", "--user=test", "--", "https://gateway.invalid"}
}
func awaitBroker(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(2 * time.Second):
		t.Fatal("broker event timed out")
		return nil
	}
}
func TestUniVPNBrokerContinuousLifecycle(t *testing.T) {
	b, l, n := brokerFixture()
	secret := []byte("mock-only")
	s, e := b.Start(context.Background(), b.Executable, brokerArgs(), secret)
	if e != nil {
		t.Fatal(e)
	}
	if l.password != "mock-only" || string(secret) != "mock-only" || !bytes.Equal(l.retained, make([]byte, len(l.retained))) {
		t.Fatal("password ownership/clearing failed")
	}
	select {
	case <-s.Ready():
		t.Fatal("process launch is not readiness")
	default:
	}
	if _, e = b.Start(context.Background(), b.Executable, brokerArgs(), secret); e == nil {
		t.Fatal("parallel session accepted")
	}
	n.ready <- nil
	if e = awaitBroker(t, s.Ready()); e != nil {
		t.Fatal(e)
	}
	select {
	case <-s.Done():
		t.Fatal("authenticated process not retained")
	default:
	}
	s.Stop()
	awaitBroker(t, s.Done())
	select {
	case <-n.cleaned:
	default:
		t.Fatal("cleanup missing")
	}
}
func TestUniVPNBrokerFailedVerificationCleansUp(t *testing.T) {
	b, _, n := brokerFixture()
	n.ready <- errors.New("untrusted state")
	n.cleanupError = errors.New("mock cleanup error")
	s, e := b.Start(context.Background(), b.Executable, brokerArgs(), []byte("mock"))
	if e != nil {
		t.Fatal(e)
	}
	if awaitBroker(t, s.Ready()) == nil {
		t.Fatal("failure became ready")
	}
	if awaitBroker(t, s.Done()) == nil {
		t.Fatal("cleanup failure lost")
	}
}
func TestUniVPNBrokerExitBeforeReady(t *testing.T) {
	b, l, n := brokerFixture()
	s, e := b.Start(context.Background(), b.Executable, brokerArgs(), []byte("mock"))
	if e != nil {
		t.Fatal(e)
	}
	l.p.Stop()
	if awaitBroker(t, s.Ready()) == nil {
		t.Fatal("early exit became ready")
	}
	awaitBroker(t, s.Done())
	<-n.cleaned
}
func TestUniVPNBrokerRejectsOptions(t *testing.T) {
	for _, option := range []string{"--script=/tmp/evil", "--servercert=pin", "--cafile=/tmp/ca", "--user=second", "--mtu=1", "--background"} {
		t.Run(option, func(t *testing.T) {
			args := brokerArgs()
			args = append(args[:6], append([]string{option}, args[6:]...)...)
			if validateUniVPNBrokerArgs(args, nil) == nil {
				t.Fatal("unsafe option accepted")
			}
		})
	}
	args := brokerArgs()
	args[len(args)-1] = "https://user:pass@gateway.invalid"
	if validateUniVPNBrokerArgs(args, nil) == nil {
		t.Fatal("userinfo accepted")
	}
}
func TestUniVPNBrokerFrameLimits(t *testing.T) {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint32(uniVPNFrameLimit+1))
	var r uniVPNRequest
	if uniVPNRead(&b, &r) == nil {
		t.Fatal("oversize accepted")
	}
	b.Reset()
	r = uniVPNRequest{Executable: "safe", Args: brokerArgs(), Password: []byte("mock")}
	if e := uniVPNWrite(&b, r); e != nil {
		t.Fatal(e)
	}
	var got uniVPNRequest
	if e := uniVPNRead(&b, &got); e != nil || string(got.Password) != "mock" {
		t.Fatal("frame round trip", e)
	}
}
func TestUniVPNBrokerMissingDependenciesFailClosed(t *testing.T) {
	b := &UniVPNBrokerBackend{Executable: "/usr/bin/native"}
	if b.Available() {
		t.Fatal("missing verifier advertised available")
	}
	if _, e := b.Start(context.Background(), b.Executable, brokerArgs(), []byte("mock")); e == nil {
		t.Fatal("missing dependencies accepted")
	}
}
func TestUniVPNBrokerCleanupFailureLatchesUnavailable(t *testing.T) {
	b, _, n := brokerFixture()
	n.cleanupError = errors.New("mock failed rollback")
	n.ready <- nil
	s, e := b.Start(context.Background(), b.Executable, brokerArgs(), []byte("mock"))
	if e != nil {
		t.Fatal(e)
	}
	awaitBroker(t, s.Ready())
	var cleanup *CleanupError
	if e = s.Stop(); !errors.As(e, &cleanup) {
		t.Fatalf("Stop did not report CleanupError: %v", e)
	}
	if e = awaitBroker(t, s.Done()); !errors.As(e, &cleanup) {
		t.Fatalf("Done did not report CleanupError: %v", e)
	}
	if b.Available() {
		t.Fatal("dirty backend advertised available")
	}
	if _, e = b.Start(context.Background(), b.Executable, brokerArgs(), []byte("mock")); e == nil {
		t.Fatal("dirty backend restarted")
	}
}

type orderedUniVPNNetwork struct {
	verified chan struct{}
	cleaned  chan bool
}

func (n *orderedUniVPNNetwork) WaitReady(ctx context.Context, _ UniVPNNativeProcess) error {
	<-ctx.Done()
	time.Sleep(10 * time.Millisecond)
	close(n.verified)
	return ctx.Err()
}
func (n *orderedUniVPNNetwork) Cleanup(context.Context, UniVPNNativeProcess) error {
	select {
	case <-n.verified:
		n.cleaned <- true
	default:
		n.cleaned <- false
	}
	return nil
}
func TestUniVPNBrokerJoinsVerifierBeforeCleanup(t *testing.T) {
	b, _, _ := brokerFixture()
	n := &orderedUniVPNNetwork{verified: make(chan struct{}), cleaned: make(chan bool, 1)}
	b.Network = n
	s, e := b.Start(context.Background(), b.Executable, brokerArgs(), []byte("mock"))
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Stop(); e != nil {
		t.Fatal(e)
	}
	if !<-n.cleaned {
		t.Fatal("cleanup raced pending verifier")
	}
}
func TestUniVPNBrokerLauncherRefusesMissingContainment(t *testing.T) {
	l := UniVPNExecLauncher{Executable: "/never-executed", Hook: "/never-executed-hook"}
	if _, err := l.Launch(context.Background(), l.Executable, brokerArgs(), []byte("mock")); err == nil {
		t.Fatal("launcher accepted missing descendant containment")
	}
}
func TestUniVPNBrokerGatewayPolicyPrecedesLaunch(t *testing.T) {
	b, l, _ := brokerFixture()
	args := brokerArgs()
	args[len(args)-1] = "https://unapproved.invalid"
	if _, err := b.Start(context.Background(), b.Executable, args, []byte("mock")); err == nil {
		t.Fatal("unapproved gateway launched")
	}
	if l.password != "" {
		t.Fatal("launcher reached before gateway authorization")
	}
	b.AllowedGateways = nil
	if b.Available() {
		t.Fatal("missing gateway policy advertised available")
	}
	if _, err := b.Start(context.Background(), b.Executable, brokerArgs(), []byte("mock")); err == nil {
		t.Fatal("missing gateway policy launched")
	}
	if l.password != "" {
		t.Fatal("launcher reached without gateway policy")
	}
}
func TestUniVPNBrokerShutdownJoinsHandlers(t *testing.T) {
	var handlers sync.WaitGroup
	handlers.Add(1)
	result := make(chan error, 1)
	go func() { result <- waitUniVPNHandlers(&handlers, time.Second) }()
	select {
	case <-result:
		t.Fatal("shutdown returned before handler cleanup")
	case <-time.After(10 * time.Millisecond):
	}
	handlers.Done()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	handlers.Add(1)
	var cleanup *CleanupError
	if err := waitUniVPNHandlers(&handlers, time.Millisecond); !errors.As(err, &cleanup) {
		t.Fatalf("shutdown uncertainty not CleanupError: %v", err)
	}
	handlers.Done()
}
