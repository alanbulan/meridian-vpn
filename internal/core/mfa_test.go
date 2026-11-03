package core

import (
	"bytes"
	"context"
	wire "encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testAuthChallenge() AuthChallenge {
	return AuthChallenge{SessionID: strings.Repeat("a", 32), Round: 2, Title: "MFA", Fields: []AuthField{{ID: "otp", Label: "Verification code", Kind: "password"}, {ID: "method", Label: "Method", Kind: "select", Choices: []AuthChoice{{ID: "totp", Label: "Authenticator"}, {ID: "backup", Label: "Recovery code"}}}}}
}
func challengeFrame(ch AuthChallenge) []byte {
	b := mfaHeader(2, ch.SessionID, ch.Round)
	b = mfaAppend(b, []byte(ch.Title))
	b = mfaAppend(b, []byte(ch.Message))
	b = wire.BigEndian.AppendUint16(b, uint16(len(ch.Fields)))
	for _, f := range ch.Fields {
		b = mfaAppend(b, []byte(f.ID))
		b = mfaAppend(b, []byte(f.Label))
		kind := byte(1)
		if f.Kind == "password" {
			kind = 2
		}
		if f.Kind == "select" {
			kind = 3
		}
		b = append(b, kind)
		b = wire.BigEndian.AppendUint16(b, uint16(len(f.Choices)))
		for _, c := range f.Choices {
			b = mfaAppend(b, []byte(c.ID))
			b = mfaAppend(b, []byte(c.Label))
		}
	}
	return b
}
func TestMFAFramedChallenge(t *testing.T) {
	ch := testAuthChallenge()
	b := challengeFrame(ch)
	var buf bytes.Buffer
	if err := mfaWrite(&buf, b); err != nil {
		t.Fatal(err)
	}
	raw, err := mfaRead(&buf)
	if err != nil {
		t.Fatal(err)
	}
	typ, round, r, err := mfaDecodeHeader(raw, ch.SessionID)
	if err != nil || typ != 2 || round != 2 {
		t.Fatal("header mismatch")
	}
	got, err := mfaChallenge(r, ch.SessionID, round)
	if err != nil || len(got.Fields) != 2 || got.Fields[1].Choices[0].ID != "totp" {
		t.Fatal("challenge mismatch", err)
	}
	if _, _, _, err = mfaDecodeHeader(raw, strings.Repeat("b", 32)); err == nil {
		t.Fatal("stale session accepted")
	}
}
func TestMFAAnswerValidationAndClearing(t *testing.T) {
	ch := testAuthChallenge()
	good := func() AuthAnswer {
		return AuthAnswer{SessionID: ch.SessionID, Round: ch.Round, Values: map[string][]byte{"otp": []byte("123456"), "method": []byte("totp")}}
	}
	a := good()
	b, err := mfaAnswer(ch, a)
	if err != nil {
		t.Fatal(err)
	}
	clear(b)
	secret := a.Values["otp"]
	clearAuthAnswer(a)
	if !bytes.Equal(secret, make([]byte, len(secret))) {
		t.Fatal("answer not cleared")
	}
	for _, mutate := range []func(*AuthAnswer){func(a *AuthAnswer) { a.Round++ }, func(a *AuthAnswer) { a.SessionID = "old" }, func(a *AuthAnswer) { delete(a.Values, "otp") }, func(a *AuthAnswer) { a.Values["extra"] = []byte("bad") }, func(a *AuthAnswer) { a.Values["method"] = []byte("unknown") }, func(a *AuthAnswer) { a.Values["otp"] = []byte("line\nbreak") }, func(a *AuthAnswer) { a.Values["otp"] = bytes.Repeat([]byte{'x'}, 4097) }} {
		a := good()
		mutate(&a)
		if b, err := mfaAnswer(ch, a); err == nil {
			clear(b)
			t.Fatal("invalid answer accepted")
		}
		clearAuthAnswer(a)
	}
}
func TestMFARejectsMalformedFrames(t *testing.T) {
	for _, n := range []uint32{0, 35, mfaMaxFrame + 1, ^uint32(0)} {
		b := wire.BigEndian.AppendUint32(nil, n)
		if _, e := mfaRead(bytes.NewReader(b)); e == nil {
			t.Fatal("invalid length accepted")
		}
	}
	ch := testAuthChallenge()
	cases := []AuthChallenge{ch, ch, ch, ch, ch}
	cases[0].Title = strings.Repeat("x", 2049)
	cases[1].Fields = []AuthField{{ID: "duplicate", Kind: "text"}, {ID: "duplicate", Kind: "password"}}
	cases[2].Fields = []AuthField{{ID: "bad\x00id", Kind: "text"}}
	cases[3].Fields = []AuthField{{ID: "choice", Kind: "select"}}
	cases[4].Fields = make([]AuthField, 17)
	for _, c := range cases {
		b := challengeFrame(c)
		_, _, r, e := mfaDecodeHeader(b, ch.SessionID)
		if e == nil {
			_, e = mfaChallenge(r, ch.SessionID, ch.Round)
		}
		if e == nil {
			t.Fatal("malformed challenge accepted")
		}
	}
	b := append(challengeFrame(ch), 0)
	_, _, r, _ := mfaDecodeHeader(b, ch.SessionID)
	if _, err := mfaChallenge(r, ch.SessionID, 2); err == nil {
		t.Fatal("trailing data accepted")
	}
}
func TestMFAInitialPasswordUsedOnlyOnce(t *testing.T) {
	ch := AuthChallenge{SessionID: strings.Repeat("a", 32), Round: 1, Fields: []AuthField{{ID: "username", Kind: "text"}, {ID: "password", Kind: "password"}}}
	p := Profile{Username: "synthetic-user"}
	c := Credentials{Password: []byte("synthetic-pass")}
	a, ok := initialMFAAnswer(ch, p, c)
	if !ok || string(a.Values["password"]) != "synthetic-pass" {
		t.Fatal("initial credentials not applied")
	}
	clearAuthAnswer(a)
	if string(c.Password) != "synthetic-pass" {
		t.Fatal("caller password mutated")
	}
	ch.Round = 2
	if _, ok = initialMFAAnswer(ch, p, c); ok {
		t.Fatal("initial password replayed into retry")
	}
	ch.Round = 1
	ch.Fields = append(ch.Fields, AuthField{ID: "otp", Kind: "password"})
	if _, ok = initialMFAAnswer(ch, p, c); ok {
		t.Fatal("MFA form silently answered")
	}
}
func TestMFAUnavailableFailsClosed(t *testing.T) {
	h := newMFAHelperAt(filepath.Join(t.TempDir(), "missing"))
	if h.Capability().Available {
		t.Fatal("missing helper available")
	}
	_, err := h.Authenticate(context.Background(), Profile{}, Credentials{}, nil)
	if err == nil {
		t.Fatal("unavailable helper accepted")
	}
}
func TestMFACancelClosesInheritedOutput(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux process cancellation test")
	}
	path := filepath.Join(t.TempDir(), "helper")
	// A descendant inheriting stdout must not defeat parent cancellation. Sleep
	// is bounded independently and does not read or persist credential input.
	script := "#!/bin/sh\nif [ \"${1:-}\" = --protocol-version ]; then printf 'meridian-auth-helper/1\\n'; exit; fi\n(sleep 2) &\nsleep 10\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	h := newMFAHelperAt(path)
	if !h.Capability().Available {
		t.Fatal("helper prerequisite")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := h.Authenticate(ctx, Profile{Name: "test", Gateway: "https://127.0.0.1", Protocol: "anyconnect"}, Credentials{}, func(context.Context, AuthChallenge) (AuthAnswer, error) {
		return AuthAnswer{}, errors.New("unexpected prompt")
	})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatal("cancel did not promptly terminate blocked output", err)
	}
}
func TestMFAPartialFrame(t *testing.T) {
	b := wire.BigEndian.AppendUint32(nil, 36)
	b = append(b, 1, 2)
	if _, err := mfaRead(bytes.NewReader(b)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("partial frame not rejected")
	}
}

func TestMFAResolverHint(t *testing.T) {
	for _, v := range []string{"", "vpn.example.com:192.0.2.1", "vpn.example.com:2001:db8::1"} {
		if !validMFAResolve("https://vpn.example.com:443/group", v) {
			t.Fatal("valid resolver hint rejected")
		}
	}
	for _, v := range []string{"other.example.com:192.0.2.1", "vpn.example.com:evil.example.com", "vpn.example.com:[2001:db8::1]", "vpn.example.com:192.0.2.1\n"} {
		if validMFAResolve("https://vpn.example.com", v) {
			t.Fatal("invalid resolver hint accepted")
		}
	}
}
func TestMFADiscoveryRejectsUnsafePaths(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux install-path checks")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "helper")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit\n"), 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0777); err != nil {
		t.Fatal(err)
	}
	if trustedMFAHelperPath(path) {
		t.Fatal("writable executable accepted")
	}
	link := filepath.Join(dir, "linked")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if trustedMFAHelperPath(link) {
		t.Fatal("symlink executable accepted")
	}
	if trustedMFAHelperPath("./helper") {
		t.Fatal("relative helper accepted")
	}
}

func TestMFADiscoveryTrustChain(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux install-path checks")
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(cwd, "mfa-path-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	child := filepath.Join(dir, "bin")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(child, "helper")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if !trustedMFAHelperPath(path) {
		t.Skip("repository itself has an untrusted ancestor; positive ownership fixture unavailable")
	}
	if err := os.Chmod(path, 0777); err != nil {
		t.Fatal(err)
	}
	if trustedMFAHelperPath(path) {
		t.Fatal("writable executable accepted")
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if trustedMFAHelperPath(path) {
		t.Fatal("writable grandparent accepted")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(child, "linked")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if trustedMFAHelperPath(link) {
		t.Fatal("symlink executable accepted")
	}
}
