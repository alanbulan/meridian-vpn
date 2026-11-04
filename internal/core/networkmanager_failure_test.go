package core

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Only in-memory command outcomes are used. No NetworkManager process runs.
type classificationRunner struct {
	mockRunner
	authErr    error
	authOutput []byte
	failAdd    bool
}

func (r *classificationRunner) Run(ctx context.Context, path string, args []string, input []byte) ([]byte, error) {
	out, err := r.mockRunner.Run(ctx, path, args, input)
	if path == "oc" {
		if r.authErr != nil {
			return nil, r.authErr
		}
		if r.authOutput != nil {
			return r.authOutput, nil
		}
	}
	if r.failAdd && strings.Contains(strings.Join(args, " "), "connection add") {
		return nil, errors.New("secret add diagnostics")
	}
	return out, err
}

func TestNetworkManagerClassifiesOnlyObservedFacts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configure  func(*NetworkManager, *classificationRunner, *Profile)
		want       FailureKind
		noMutation bool
	}{
		{"unavailable", func(n *NetworkManager, _ *classificationRunner, _ *Profile) { n.cap = Capability{Message: "secret capability"} }, FailureBackendUnavailable, true},
		{"missing-plugin", func(n *NetworkManager, _ *classificationRunner, _ *Profile) { n.oc = "" }, FailureBackendUnavailable, true},
		{"invalid-profile", func(_ *NetworkManager, _ *classificationRunner, p *Profile) { p.Gateway = "http://invalid" }, FailureConfiguration, true},
		{"auth-command", func(_ *NetworkManager, r *classificationRunner, _ *Profile) { r.authErr = errors.New("secret password certificate timeout") }, FailureUnknown, true},
		{"auth-response", func(_ *NetworkManager, r *classificationRunner, _ *Profile) { r.authOutput = []byte("secret malformed response") }, FailureUnknown, true},
		{"auth-trust", func(_ *NetworkManager, r *classificationRunner, _ *Profile) { r.authErr = errors.Join(NewConnectionError(FailureTransport), NewConnectionError(FailureTrust)) }, FailureTrust, true},
		{"add", func(_ *NetworkManager, r *classificationRunner, _ *Profile) { r.failAdd = true }, FailureStart, false},
		{"activate", func(_ *NetworkManager, r *classificationRunner, _ *Profile) { r.failUp = true }, FailureStart, false},
		{"readiness", func(_ *NetworkManager, r *classificationRunner, _ *Profile) { r.notReady = true }, FailureReadiness, false},
		{"cleanup", func(_ *NetworkManager, r *classificationRunner, _ *Profile) { r.failUp = true; r.failDelete = true }, FailureCleanup, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &classificationRunner{}
			n := testNM(&r.mockRunner)
			n.runner = r
			p := profile()
			tc.configure(n, r, &p)
			s, err := n.Start(context.Background(), p, []byte("synthetic-password"))
			if s != nil || err == nil || classifyFailure(err, FailureUnknown) != tc.want {
				t.Fatalf("unexpected result: session=%v error=%v", s, err)
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "synthetic-password") {
				t.Fatal("backend details escaped classification")
			}
			for _, call := range r.calls {
				args := strings.Join(call.args, " ")
				if tc.noMutation && strings.Contains(args, "connection ") {
					t.Fatal("preflight/auth failure started network changes")
				}
			}
		})
	}
}
