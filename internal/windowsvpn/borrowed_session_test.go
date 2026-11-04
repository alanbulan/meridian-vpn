package windowsvpn

import (
	"context"
	"testing"
	"time"
)

func fixtureBorrowedRequest() BorrowedRequest {
	return BorrowedRequest{Entry: fixtureEntry(), Gateway: "vpn.example.test", Username: "user", Password: []byte("secret"), Authorization: BorrowedAuthorization{true, true, true}}
}
func TestBorrowedFacadeRejectsBeforeResolver(t *testing.T) {
	calls := 0
	create := func() (*borrowedCoordinator, error) { calls++; return nil, ErrUnavailable }
	inspect := func(PhonebookEntry, string) (EntryEvidence, error) { calls++; return EntryEvidence{}, ErrVerification }
	for _, kind := range []string{"no consent", "no password", "bad path", "canceled"} {
		req := fixtureBorrowedRequest()
		ctx := context.Background()
		switch kind {
		case "no consent":
			req.Authorization.SharedReference = false
		case "no password":
			req.Password = nil
		case "bad path":
			req.Entry.PhonebookPath = "relative.pbk"
		case "canceled":
			c, cancel := context.WithCancel(ctx)
			cancel()
			ctx = c
		}
		if _, err := startBorrowedSession(ctx, req, create, inspect); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	if calls != 0 {
		t.Fatal("invalid request reached resolver")
	}
}
func TestBorrowedFacadeOwnsWorkerAndRetry(t *testing.T) {
	f := newBoundNativeFixture(t)
	f.shared = true
	req := fixtureBorrowedRequest()
	s, err := startBorrowedSession(context.Background(), req, func() (*borrowedCoordinator, error) { return f.c, nil }, func(PhonebookEntry, string) (EntryEvidence, error) { return borrowedTestEntry(), nil })
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-s.Ready():
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("no readiness")
	}
	if string(req.Password) != "secret" {
		t.Fatal("caller password erased")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != ErrCleanup {
		t.Fatal("shared reference cleanup accepted", err)
	}
	if f.hangs != 1 {
		t.Fatal("release repeated")
	}
	f.deleted = true
	if err := s.RetryCleanup(ctx); err != nil || f.hangs != 1 {
		t.Fatal("later deletion retry failed", err)
	}
	if string(req.Password) != "secret" {
		t.Fatal("caller password changed")
	}
}
