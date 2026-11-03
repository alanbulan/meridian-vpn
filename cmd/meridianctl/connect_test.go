package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mygo-vpn/internal/core"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type cliSession struct {
	ready, done chan error
	stopped chan struct{}
	release <-chan struct{}
	stopErr error
	once sync.Once
}

func (s *cliSession) Ready() <-chan error { return s.ready }
func (s *cliSession) Done() <-chan error { return s.done }
func (s *cliSession) Stop() error {
	s.once.Do(func() {
		close(s.stopped)
		if s.release != nil { <-s.release }
	})
	return s.stopErr
}

type cliAdapter struct {
	s *cliSession
	started chan struct{}
}

func (a cliAdapter) Capability() core.Capability { return core.Capability{Available: true} }
func (a cliAdapter) Start(context.Context, core.Profile, []byte) (core.Session, error) {
	close(a.started)
	return a.s, nil
}

func cliFixture(t *testing.T) (application, string, *cliSession, <-chan struct{}) {
	t.Helper()
	a := testApplication(t)
	a.vpnSupported = func() bool { return true }
	s := &cliSession{ready: make(chan error, 1), done: make(chan error, 1), stopped: make(chan struct{})}
	started := make(chan struct{})
	a.vpnAdapter = func() core.Adapter { return cliAdapter{s, started} }
	a.credentials = func(context.Context) (core.Credentials, error) { return core.Credentials{Password: []byte("private-password")}, nil }
	cfg := sampleConfig()
	cfg.Profiles[0].InteractiveAuth = false
	path := filepath.Join(t.TempDir(), "profiles.json")
	writeConfig(t, path, cfg)
	return a, path, s, started
}

func connectArgs(path string) []string {
	return []string{"--config", path, "connect", "--profile", "1", "--authorize-network", "--credentials-stdin"}
}

func waitCLI(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5*time.Second): t.Fatal("CLI lifecycle timed out")
	}
}

func TestForegroundRequiresExplicitAuthorizationAndSecretInput(t *testing.T) {
	a, path, _, _ := cliFixture(t)
	a.credentials = func(context.Context) (core.Credentials, error) { t.Fatal("read secrets before permission"); return core.Credentials{}, nil }
	a.vpnAdapter = func() core.Adapter { t.Fatal("created backend before permission"); return nil }
	for _, flags := range [][]string{
		{"--profile", "1", "--credentials-stdin"},
		{"--profile", "1", "--authorize-network"},
		{"--profile", "0", "--authorize-network", "--credentials-stdin"},
		{"--profile", "1", "--authorize-network", "--credentials-stdin", "--password", "private-password"},
	} {
		code, out, errOut := runCLI(a, append([]string{"--config", path, "connect"}, flags...)...)
		if code != 2 { t.Fatalf("unapproved invocation accepted: %d", code) }
		if strings.Contains(out+errOut, "private-password") { t.Fatal("argument secret leaked") }
	}
}

func TestForegroundUnsupportedPlatformAndMFAFailClosed(t *testing.T) {
	for _, mfa := range []bool{false, true} {
		a, path, _, _ := cliFixture(t)
		if mfa {
			cfg := readConfig(t, path); cfg.Profiles[0].InteractiveAuth = true; writeConfig(t, path, cfg)
		} else { a.vpnSupported = func() bool { return false } }
		a.credentials = func(context.Context) (core.Credentials, error) { t.Fatal("read secrets for unsupported flow"); return core.Credentials{}, nil }
		code, _, _ := runCLI(a, connectArgs(path)...)
		if code != 1 { t.Fatalf("unsupported flow accepted: %d", code) }
	}
}

func TestForegroundCancellationWaitsForOwnedCleanup(t *testing.T) {
	a, path, s, started := cliFixture(t)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }; defer unblock()
	s.release = release
	ctx, cancel := context.WithCancel(context.Background()); defer cancel()
	var out, errOut bytes.Buffer
	result := make(chan int, 1)
	go func() { result <- a.run(ctx, connectArgs(path), &out, &errOut) }()
	waitCLI(t, started)
	cancel()
	waitCLI(t, s.stopped)
	select { case <-result: t.Fatal("exited before cleanup confirmation"); default: }
	unblock()
	select {
	case code := <-result:
		if code != 0 || !strings.Contains(out.String(), core.Disconnected) { t.Fatalf("cancellation failed: %d %s", code, errOut.String()) }
		assertNoProfileData(t, out.String()+errOut.String())
	case <-time.After(5*time.Second): t.Fatal("did not finish cleanup")
	}
}

func TestForegroundCleanupFailureIsNonzeroAndRedacted(t *testing.T) {
	a, path, s, started := cliFixture(t)
	s.stopErr = errors.New("private-password backend output")
	ctx, cancel := context.WithCancel(context.Background()); defer cancel()
	var out, errOut bytes.Buffer
	result := make(chan int, 1)
	go func() { result <- a.run(ctx, connectArgs(path), &out, &errOut) }()
	waitCLI(t, started); cancel()
	select {
	case code := <-result:
		if code != 1 || !strings.Contains(errOut.String(), "cleanup could not be confirmed") { t.Fatalf("cleanup failure hidden: %d %s", code, errOut.String()) }
		if strings.Contains(out.String()+errOut.String(), "private-password") { t.Fatal("secret leaked") }
	case <-time.After(5*time.Second): t.Fatal("cleanup failed to finish")
	}
}

func TestForegroundInvalidCredentialsNeverStart(t *testing.T) {
	for _, c := range []core.Credentials{
		{Password: []byte("line\nbreak")},
		{IPsecPSK: []byte("wrong-protocol")},
		{KeyPassword: []byte("no-client-certificate")},
	} {
		a, path, _, started := cliFixture(t)
		a.credentials = func(context.Context) (core.Credentials, error) { return c, nil }
		code, _, _ := runCLI(a, connectArgs(path)...)
		if code != 1 { t.Fatal("invalid credentials accepted") }
		select { case <-started: t.Fatal("backend started with invalid credentials"); default: }
		if bytes.Count(c.Password, []byte{0}) != len(c.Password) || bytes.Count(c.IPsecPSK, []byte{0}) != len(c.IPsecPSK) || bytes.Count(c.KeyPassword, []byte{0}) != len(c.KeyPassword) { t.Fatal("owned credentials not cleared") }
	}
}

func TestDecodeCredentialInputStrictAndBounded(t *testing.T) {
	for _, input := range []string{"null", "[]", `{"password":null}`, `{"password":"a","password":"b"}`, `{"unknown":"secret"}`, `{"password":{}}`, `{} {}`, `{"password":"`+strings.Repeat("a",4097)+`"}`, strings.Repeat(" ",16385)} {
		if c, err := decodeCredentials([]byte(input)); err == nil { clearCredentials(c); t.Fatalf("accepted malformed credential input of length %d", len(input)) }
	}
	c, err := decodeCredentials([]byte(`{"password":"password","ipsec_psk":"psk","key_password":"key"}`))
	defer clearCredentials(c)
	if err != nil || string(c.Password) != "password" || string(c.IPsecPSK) != "psk" || string(c.KeyPassword) != "key" { t.Fatal("valid credentials rejected") }
}

func TestCredentialPipeCancellation(t *testing.T) {
	r, w, err := os.Pipe(); if err != nil { t.Fatal(err) }; defer r.Close(); defer w.Close()
	ctx, cancel := context.WithCancel(context.Background()); defer cancel()
	result := make(chan error, 1)
	go func() { _, err := readCredentialInput(ctx, r); result <- err }()
	cancel()
	select { case err := <-result: if err == nil { t.Fatal("cancel ignored") }; case <-time.After(5*time.Second): t.Fatal("credential read ignored cancellation") }
}

func TestCredentialPipeBoundAndDecode(t *testing.T) {
	for _, input := range []string{`{"password":"pipe-only"}`, strings.Repeat("x",16385)} {
		path := filepath.Join(t.TempDir(), "input")
		if err := os.WriteFile(path, []byte(input), 0600); err != nil { t.Fatal(err) }
		f, err := os.Open(path); if err != nil { t.Fatal(err) }
		c, readErr := readCredentialInput(context.Background(), f); f.Close(); clearCredentials(c)
		if (len(input)>16384) != (readErr!=nil) { t.Fatal("credential input bound incorrect") }
	}
}

func TestForegroundOutputFailureCleansSession(t *testing.T) {
	s := &cliSession{ready: make(chan error), done: make(chan error), stopped: make(chan struct{})}
	e := core.NewEngine(cliAdapter{s, make(chan struct{})})
	p := sampleProfile(); p.InteractiveAuth = false
	if err := e.Connect(p, "", true); err != nil { t.Fatal(err) }
	if runForegroundSession(context.Background(), e, failingCLIWriter{}, io.Discard) != 1 { t.Fatal("output error hidden") }
	waitCLI(t, s.stopped)
	if e.Snapshot().State != core.Disconnected { t.Fatal("output failure leaked tunnel") }
}

type failingCLIWriter struct{}
func (failingCLIWriter) Write([]byte) (int,error) { return 0, errors.New("output unavailable") }

func TestForegroundUnexpectedTerminationFails(t *testing.T) {
	s := &cliSession{ready: make(chan error, 1), done: make(chan error, 1), stopped: make(chan struct{})}
	e := core.NewEngine(cliAdapter{s, make(chan struct{})})
	p := sampleProfile()
	p.InteractiveAuth = false
	if err := e.Connect(p, "", true); err != nil { t.Fatal(err) }
	s.ready <- nil
	deadline := time.Now().Add(5 * time.Second)
	for e.Snapshot().State != core.Connected {
		if time.Now().After(deadline) { t.Fatal("readiness timed out") }
		time.Sleep(time.Millisecond)
	}
	s.done <- nil
	var errOut bytes.Buffer
	if runForegroundSession(context.Background(), e, io.Discard, &errOut) != 1 { t.Fatal("unexpected termination reported success") }
	if !strings.Contains(errOut.String(), "fresh authentication") { t.Fatal("missing recovery guidance") }
	waitCLI(t, s.stopped)
}

func TestForegroundL2TPRequiresBothSecrets(t *testing.T) {
	for _, c := range []core.Credentials{{Password: []byte("password")}, {IPsecPSK: []byte("psk")}} {
		a, path, _, started := cliFixture(t)
		cfg := readConfig(t, path)
		cfg.Profiles[0].Protocol = "l2tp"
		cfg.Profiles[0].Gateway = "private.example"
		cfg.Profiles[0].AuthGroup = ""
		cfg.Profiles[0].CAFile = ""
		cfg.Profiles[0].ProxyURL = ""
		cfg.Profiles[0].DisableUDP = false
		writeConfig(t, path, cfg)
		a.credentials = func(context.Context) (core.Credentials, error) { return c, nil }
		code, _, _ := runCLI(a, connectArgs(path)...)
		if code != 1 { t.Fatal("L2TP accepted incomplete credentials") }
		select { case <-started: t.Fatal("L2TP started with incomplete credentials"); default: }
	}
}

type credentialCLIAdapter struct {
	cliAdapter
	captured chan core.Credentials
}

func (a credentialCLIAdapter) StartWithCredentials(ctx context.Context, p core.Profile, c core.Credentials) (core.Session, error) {
	a.captured <- core.Credentials{Password: bytes.Clone(c.Password), IPsecPSK: bytes.Clone(c.IPsecPSK), KeyPassword: bytes.Clone(c.KeyPassword)}
	return a.Start(ctx, p, c.Password)
}

func TestForegroundOwnedCredentialBuffersAreCleared(t *testing.T) {
	a, path, s, _ := cliFixture(t)
	cfg := readConfig(t, path)
	cfg.Profiles[0].Protocol = "l2tp"
	cfg.Profiles[0].Gateway = "private.example"
	cfg.Profiles[0].AuthGroup = ""
	cfg.Profiles[0].CAFile = ""
	cfg.Profiles[0].ProxyURL = ""
	cfg.Profiles[0].DisableUDP = false
	writeConfig(t, path, cfg)
	original := core.Credentials{Password: []byte("private-password"), IPsecPSK: []byte("private-psk")}
	a.credentials = func(context.Context) (core.Credentials, error) { return original, nil }
	captured := make(chan core.Credentials, 1)
	a.vpnAdapter = func() core.Adapter { return credentialCLIAdapter{cliAdapter{s, make(chan struct{})}, captured} }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, errOut bytes.Buffer
	result := make(chan int, 1)
	go func() { result <- a.run(ctx, connectArgs(path), &out, &errOut) }()
	select {
	case c := <-captured:
		if string(c.Password) != "private-password" || string(c.IPsecPSK) != "private-psk" { t.Fatal("credential channel did not preserve the secrets") }
		clearCredentials(c)
	case <-time.After(5*time.Second): t.Fatal("backend did not receive credentials")
	}
	cancel()
	select {
	case code := <-result:
		if code != 0 { t.Fatalf("session failed: %s", errOut.String()) }
	case <-time.After(5*time.Second): t.Fatal("session did not finish")
	}
	if bytes.Count(original.Password, []byte{0}) != len(original.Password) || bytes.Count(original.IPsecPSK, []byte{0}) != len(original.IPsecPSK) { t.Fatal("credential buffers retained after completion") }
	if strings.Contains(out.String()+errOut.String(), "private-password") || strings.Contains(out.String()+errOut.String(), "private-psk") { t.Fatal("credential output leaked") }
}
