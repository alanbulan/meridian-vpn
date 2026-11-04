package windowsvpn

import (
	"bytes"
	"context"
	"sync"
	"time"
)

type BorrowedAuthorization struct{ NetworkChanges, CredentialPersistence, SharedReference bool }
type BorrowedRequest struct {
	Entry                     PhonebookEntry
	Gateway, Username, Domain string
	Password                  []byte                `json:"-"`
	Authorization             BorrowedAuthorization `json:"-"`
}

// BorrowedSession represents limited observed RAS connectivity, not exclusive
// ownership, a kill switch or route/DNS leak protection. Stop failure retains
// cleanup ownership and pinned input storage until RetryCleanup confirms it.
type BorrowedSession struct {
	coordinator         *borrowedCoordinator
	cancel              context.CancelFunc
	ready, done         chan error
	finished            chan struct{}
	readyOnce, doneOnce sync.Once
}

func (s *BorrowedSession) Ready() <-chan error    { return s.ready }
func (s *BorrowedSession) Done() <-chan error     { return s.done }
func (s *BorrowedSession) publishReady(err error) { s.readyOnce.Do(func() { s.ready <- err }) }
func (s *BorrowedSession) publishDone(err error)  { s.doneOnce.Do(func() { s.done <- err }) }
func (s *BorrowedSession) Stop(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrCleanup
	}
	s.cancel()
	select {
	case <-s.finished:
	case <-ctx.Done():
		return ErrCleanup
	}
	return s.coordinator.stop(ctx)
}
func (s *BorrowedSession) RetryCleanup(ctx context.Context) error { return s.Stop(ctx) }

// Validation precedes the injected resolver. An invalid/unauthorized request
// cannot load RAS, inspect a profile, or start its service.
func startBorrowedSession(ctx context.Context, request BorrowedRequest, create func() (*borrowedCoordinator, error), inspect func(PhonebookEntry, string) (EntryEvidence, error)) (*BorrowedSession, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrOperation
	}
	a := request.Authorization
	if !a.NetworkChanges || !a.CredentialPersistence || !a.SharedReference {
		return nil, ErrAuthorization
	}
	if ValidateBorrowedSelection(request.Entry, request.Gateway, request.Username, request.Domain) != nil || ValidateBorrowedPassword(request.Password) != nil || create == nil || inspect == nil {
		return nil, ErrVerification
	}
	var coordinator *borrowedCoordinator
	err := guardedError(func() error { var err error; coordinator, err = create(); return err })
	if err != nil {
		return nil, ErrUnavailable
	}
	if coordinator == nil {
		return nil, ErrUnavailable
	}
	// Copy before returning to the engine, which erases its attempt copy.
	secret := bytes.Clone(request.Password)
	request.Password = nil
	run, cancel := context.WithCancel(ctx)
	s := &BorrowedSession{coordinator: coordinator, cancel: cancel, ready: make(chan error, 1), done: make(chan error, 1), finished: make(chan struct{})}
	go func() {
		defer close(s.finished)
		defer clear(secret)
		defer cancel()
		var entry EntryEvidence
		err := run.Err()
		if err == nil {
			err = guardedError(func() error { var err error; entry, err = inspect(request.Entry, request.Gateway); return err })
		}
		if err == nil && run.Err() != nil {
			err = run.Err()
		}
		if err == nil {
			err = coordinator.start(run, entry, request.Username, request.Domain, secret, borrowedConsent{true, true, true})
		}
		clear(secret)
		if err != nil {
			s.publishReady(err)
			s.publishDone(err)
			return
		}
		s.publishReady(nil)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-run.Done():
				cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				err := coordinator.stop(cleanup)
				cancel()
				s.publishDone(err)
				return
			case <-ticker.C:
				if err := coordinator.check(run); err != nil {
					s.publishDone(err)
					return
				}
			}
		}
	}()
	return s, nil
}
