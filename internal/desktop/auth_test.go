package desktop

import (
	"context"
	"mygo-vpn/internal/core"
	"path/filepath"
	"testing"
	"time"
)

func TestAuthChallengeCancelAndFreshResponse(t *testing.T) {
	a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), unavailableTestAdapter{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := a.requestAuth(ctx, core.AuthChallenge{SessionID: "old", Round: 1}); done <- err }()
	deadline := time.Now().Add(time.Second)
	for a.authCurrent == nil && time.Now().Before(deadline) {
		a.pollAuth()
		time.Sleep(time.Millisecond)
	}
	if a.authCurrent == nil {
		t.Fatal("challenge not delivered")
	}
	a.authValues["password"] = "synthetic-secret"
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancel not propagated")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel hung")
	}
	a.pollAuth()
	if a.authCurrent != nil || a.authValues != nil {
		t.Fatal("canceled challenge retained secret")
	}
	answers := make(chan core.AuthAnswer, 1)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go func() {
		answer, err := a.requestAuth(ctx2, core.AuthChallenge{SessionID: "new", Round: 2})
		if err == nil {
			answers <- answer
		}
	}()
	deadline = time.Now().Add(time.Second)
	for a.authCurrent == nil && time.Now().Before(deadline) {
		a.pollAuth()
		time.Sleep(time.Millisecond)
	}
	if a.authCurrent == nil {
		t.Fatal("fresh challenge not delivered")
	}
	a.authValues["token"] = "654321"
	for a.authCurrent != nil && time.Now().Before(deadline) {
		a.submitAuth()
		time.Sleep(time.Millisecond)
	}
	select {
	case answer := <-answers:
		if answer.SessionID != "new" || answer.Round != 2 || string(answer.Values["token"]) != "654321" {
			t.Fatal("response binding lost")
		}
		for _, value := range answer.Values {
			clear(value)
		}
	case <-time.After(time.Second):
		t.Fatal("response hung")
	}
	if a.authValues != nil {
		t.Fatal("submitted secrets retained")
	}
}
func TestShutdownDiscardsAuthentication(t *testing.T) {
	a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), unavailableTestAdapter{})
	a.authCurrent = &authRequest{ctx: context.Background()}
	a.authValues = map[string]string{"password": "synthetic"}
	a.Password = "synthetic"
	a.KeyPassword = "synthetic"
	a.SwitchPending = true
	a.BeginShutdown()
	if a.authCurrent != nil || a.authValues != nil || a.Password != "" || a.KeyPassword != "" || a.SwitchPending {
		t.Fatal("shutdown retained authentication")
	}
}
