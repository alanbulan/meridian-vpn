package core

import (
	"context"
	"errors"
	"mygo-vpn/internal/windowsvpn"
	"runtime"
	"sync"
	"time"
)

const WindowsBorrowedObservedInterface = "windows-borrowed-observed-interface"

type WindowsBorrowedAdapter struct{}

func (*WindowsBorrowedAdapter) VerificationScope() string { return WindowsBorrowedObservedInterface }
func (*windowsEngineSession) VerificationScope() string   { return WindowsBorrowedObservedInterface }

func NewWindowsBorrowedAdapter() *WindowsBorrowedAdapter { return &WindowsBorrowedAdapter{} }
func (*WindowsBorrowedAdapter) Capability() Capability {
	return Capability{Available: runtime.GOOS == "windows", Message: "Experimental existing Windows VPN mode: no exclusive ownership, kill switch or full route/DNS leak protection. Real gateway acceptance remains required."}
}
func (*WindowsBorrowedAdapter) SupportsProtocol(p string) bool {
	return runtime.GOOS == "windows" && p == WindowsBorrowedProtocol
}
func (*WindowsBorrowedAdapter) Start(context.Context, Profile, []byte) (Session, error) {
	return nil, errors.New("existing Windows VPN requires explicit per-use authorization")
}
func (*WindowsBorrowedAdapter) StartWithAuthorization(ctx context.Context, p Profile, c Credentials, a SessionAuthorization) (Session, error) {
	if p.Protocol != WindowsBorrowedProtocol || ValidateProfile(p) != nil || validateCredentials(p, c) != nil {
		return nil, NewConnectionError(FailureConfiguration)
	}
	if !a.NetworkChanges || !a.WindowsCredentialPersistence || !a.WindowsSharedReference {
		return nil, errors.New("fresh Windows VPN authorization is required")
	}
	options := p.WindowsBorrowed
	native, err := windowsvpn.StartSystemBorrowed(ctx, windowsvpn.BorrowedRequest{Entry: windowsvpn.PhonebookEntry{PhonebookPath: options.PhonebookPath, Name: options.EntryName}, Gateway: p.Gateway, Username: p.Username, Domain: options.Domain, Password: c.Password, Authorization: windowsvpn.BorrowedAuthorization{NetworkChanges: true, CredentialPersistence: true, SharedReference: true}})
	if err != nil {
		return nil, windowsBorrowedError(err)
	}
	s := &windowsEngineSession{native: native, ready: make(chan error, 1), done: make(chan error, 1), relayed: make(chan struct{})}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		err := windowsBorrowedError(<-native.Ready())
		s.readyOnce.Do(func() { s.ready <- err })
	}()
	go func() {
		defer wg.Done()
		err := windowsBorrowedError(<-native.Done())
		s.doneOnce.Do(func() { s.done <- err })
	}()
	go func() { wg.Wait(); close(s.relayed) }()
	return s, nil
}
func windowsBorrowedError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, windowsvpn.ErrCleanup) {
		return &CleanupError{scope: WindowsBorrowedObservedInterface}
	}
	return NewConnectionError(FailureReadiness)
}

type windowsEngineSession struct {
	native              *windowsvpn.BorrowedSession
	ready, done         chan error
	readyOnce, doneOnce sync.Once
	relayed             chan struct{}
}

func (s *windowsEngineSession) Ready() <-chan error { return s.ready }
func (s *windowsEngineSession) Done() <-chan error  { return s.done }
func (s *windowsEngineSession) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := windowsBorrowedError(s.native.Stop(ctx))
	if err != nil {
		s.doneOnce.Do(func() { s.done <- err })
		return err
	}
	<-s.relayed
	return nil
}
func (s *windowsEngineSession) RetryCleanup(ctx context.Context) error {
	return windowsBorrowedError(s.native.RetryCleanup(ctx))
}
