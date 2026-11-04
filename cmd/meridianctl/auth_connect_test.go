package main

import (
	"bytes"
	"context"
	"errors"
	"mygo-vpn/internal/core"
	"strings"
	"testing"
	"time"
)

type fakeAuthTerminal struct {
	prompt core.AuthPrompt
	closed bool
	closeErr error
}
func (t *fakeAuthTerminal) Prompt(ctx context.Context, ch core.AuthChallenge) (core.AuthAnswer, error) { return t.prompt(ctx, ch) }
func (t *fakeAuthTerminal) Close() error { t.closed = true; return t.closeErr }

type promptCLIAdapter struct {
	cliAdapter
	prompt core.AuthPrompt
}
func (a *promptCLIAdapter) SetAuthPrompt(prompt core.AuthPrompt) { a.prompt = prompt }
func (a *promptCLIAdapter) StartWithCredentials(ctx context.Context, _ core.Profile, c core.Credentials) (core.Session, error) {
	if a.prompt == nil || string(c.Password) != "private-password" { return nil, errors.New("incomplete setup") }
	answer, err := a.prompt(ctx, cliChallenge())
	for _, v := range answer.Values { clear(v) }
	if err != nil { return nil, err }
	return a.Start(ctx, core.Profile{}, nil)
}

func interactiveCLIFixture(t *testing.T) (application, string, *cliSession, *promptCLIAdapter) {
	a, path, s, _ := cliFixture(t)
	cfg := readConfig(t, path); cfg.Profiles[0].InteractiveAuth = true; writeConfig(t, path, cfg)
	adapter := &promptCLIAdapter{cliAdapter: cliAdapter{s: s, started: make(chan struct{})}}
	a.vpnAdapter = func() core.Adapter { return adapter }
	return a, path, s, adapter
}

func TestForegroundMFARequiresExplicitTerminalConsent(t *testing.T) {
	a, path, _, _ := interactiveCLIFixture(t)
	a.authTerminal = func() (authTerminal, error) { t.Fatal("terminal opened without consent"); return nil, nil }
	a.credentials = func(context.Context) (core.Credentials, error) { t.Fatal("read before consent"); return core.Credentials{}, nil }
	if code, _, _ := runCLI(a, connectArgs(path)...); code != 1 { t.Fatal("missing interactive consent accepted") }
}

func TestForegroundMFAMissingTerminalFailsBeforeCredentials(t *testing.T) {
	a, path, _, _ := interactiveCLIFixture(t)
	a.authTerminal = func() (authTerminal, error) { return nil, errors.New("private-path") }
	a.credentials = func(context.Context) (core.Credentials, error) { t.Fatal("read before terminal validation"); return core.Credentials{}, nil }
	code, out, errOut := runCLI(a, append(connectArgs(path), "--interactive-auth")...)
	if code != 1 || strings.Contains(out+errOut, "private-path") { t.Fatal("terminal failure not redacted") }
}

func TestForegroundMFAUsesPromptAndClearsOwnedSession(t *testing.T) {
	a, path, s, adapter := interactiveCLIFixture(t)
	terminal := &fakeAuthTerminal{prompt: func(_ context.Context, ch core.AuthChallenge) (core.AuthAnswer, error) {
		return core.AuthAnswer{SessionID: ch.SessionID, Round: ch.Round, Values: map[string][]byte{"otp": []byte("private-otp"), "method": []byte("totp")}}, nil
	}}
	a.authTerminal = func() (authTerminal, error) { return terminal, nil }
	ctx, cancel := context.WithCancel(context.Background()); defer cancel()
	var out, errOut bytes.Buffer
	result := make(chan int, 1)
	go func() { result <- a.run(ctx, append(connectArgs(path), "--interactive-auth"), &out, &errOut) }()
	waitCLI(t, adapter.started)
	cancel()
	select {
	case code := <-result:
		if code != 0 || !terminal.closed { t.Fatal("interactive session or terminal not cleaned") }
		select { case <-s.stopped: default: t.Fatal("owned session retained") }
		if strings.Contains(out.String()+errOut.String(), "private-") { t.Fatal("interactive credentials leaked") }
	case <-time.After(5*time.Second): t.Fatal("interactive shutdown blocked")
	}
}

func TestForegroundMFACancellationWaitsForPromptRestoration(t *testing.T) {
	for _, restoreFail := range []bool{false, true} {
		a, path, _, _ := interactiveCLIFixture(t)
		prompted, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		terminal := &fakeAuthTerminal{prompt: func(ctx context.Context, _ core.AuthChallenge) (core.AuthAnswer, error) {
			close(prompted); <-ctx.Done(); close(canceled); <-release; return core.AuthAnswer{}, ctx.Err()
		}}
		if restoreFail { terminal.closeErr = errors.New("private-terminal-failure") }
		a.authTerminal = func() (authTerminal, error) { return terminal, nil }
		ctx, cancel := context.WithCancel(context.Background())
		var out, errOut bytes.Buffer
		result := make(chan int, 1)
		go func() { result <- a.run(ctx, append(connectArgs(path), "--interactive-auth"), &out, &errOut) }()
		waitCLI(t, prompted); cancel(); waitCLI(t, canceled)
		select { case <-result: t.Fatal("returned before authentication cleanup"); default: }
		close(release)
		select {
		case code := <-result:
			if (code == 1) != restoreFail || !terminal.closed { t.Fatal("restoration failure or cleanup ordering lost") }
			if strings.Contains(out.String()+errOut.String(), "private-") { t.Fatal("error details leaked") }
		case <-time.After(5*time.Second): t.Fatal("prompt cancellation blocked")
		}
	}
}
