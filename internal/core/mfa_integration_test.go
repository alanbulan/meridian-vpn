package core

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const mfaChallengeXML = `<?xml version="1.0" encoding="UTF-8"?><config-auth client="vpn" type="auth-request" aggregate-auth-version="2"><auth id="mfa"><message>Enter the code from your authenticator</message><form method="post" action="/"><input type="password" name="otp" label="One-time code:"/><select name="method" label="Verification method"><option value="totp">Authenticator app</option><option value="backup">Recovery code</option></select></form></auth></config-auth>`

func realMFAHelper(t *testing.T) *MFAHelper {
	t.Helper()
	path := os.Getenv("MERIDIAN_MFA_HELPER_TEST_BINARY")
	if path == "" {
		t.Skip("set MERIDIAN_MFA_HELPER_TEST_BINARY for real libopenconnect auth-only tests")
	}
	h := newMFAHelperAt(path)
	if !h.Capability().Available {
		t.Fatal("real libopenconnect helper prerequisite unavailable")
	}
	return h
}
func newMFAFixture(t *testing.T, custom string) (*fixture, *atomic.Int32) {
	t.Helper()
	f := newFixture(t, false)
	var verified atomic.Int32
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.Method == http.MethodConnect {
			f.connects.Add(1)
			http.Error(w, "no tunnel", 405)
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 65536))
		if err != nil {
			http.Error(w, "invalid", 400)
			return
		}
		defer clear(b)
		var req struct {
			Type string `xml:"type,attr"`
			Auth struct {
				Username string `xml:"username"`
				Password string `xml:"password"`
				OTP      string `xml:"otp"`
				Method   string `xml:"method"`
			} `xml:"auth"`
		}
		if xml.Unmarshal(b, &req) != nil {
			http.Error(w, "invalid XML", 400)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		if req.Type == "init" {
			io.WriteString(w, challenge)
			return
		}
		if req.Auth.Username == testUser && req.Auth.Password == testPassword {
			verified.Add(1)
			if custom != "" {
				io.WriteString(w, custom)
			} else {
				io.WriteString(w, mfaChallengeXML)
			}
			return
		}
		if verified.Load() > 0 && req.Auth.OTP == "123456" && req.Auth.Method == "totp" {
			verified.Add(1)
			http.SetCookie(w, &http.Cookie{Name: "webvpn", Value: testCookie, Path: "/", Secure: true, HttpOnly: true})
			io.WriteString(w, success)
			return
		}
		if verified.Load() > 0 {
			io.WriteString(w, mfaChallengeXML)
			return
		}
		http.Error(w, "rejected", 403)
	})
	return f, &verified
}
func mfaProfile(f *fixture) Profile {
	return Profile{Name: "MFA loopback", Protocol: "anyconnect", Gateway: f.server.URL, Username: testUser, CAFile: f.ca}
}
func mfaCredentials() Credentials { return Credentials{Password: []byte(testPassword)} }
func TestRealMFAChallengeRetry(t *testing.T) {
	h := realMFAHelper(t)
	f, verified := newMFAFixture(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	calls := 0
	var secrets [][]byte
	fields, err := h.Authenticate(ctx, mfaProfile(f), mfaCredentials(), func(ctx context.Context, ch AuthChallenge) (AuthAnswer, error) {
		calls++
		fieldMap := map[string]AuthField{}
		for _, field := range ch.Fields {
			fieldMap[field.ID] = field
		}
		if ch.Round != uint16(calls+1) || len(ch.Fields) != 2 || fieldMap["otp"].Kind != "password" || fieldMap["method"].Kind != "select" || len(fieldMap["method"].Choices) != 2 {
			t.Error("unexpected real structured challenge")
		}
		code := []byte("000000")
		if calls == 2 {
			code = []byte("123456")
		}
		secrets = append(secrets, code)
		return AuthAnswer{SessionID: ch.SessionID, Round: ch.Round, Values: map[string][]byte{"otp": code, "method": []byte("totp")}}, nil
	})
	if err != nil {
		t.Fatal("real libopenconnect MFA authentication failed", err)
	}
	if calls != 2 || verified.Load() != 2 || !strings.Contains(fields["COOKIE"], testCookie) || f.connects.Load() != 0 {
		t.Fatal("expected password, rejected OTP, accepted OTP, cookie; zero tunnels")
	}
	for _, secret := range secrets {
		for _, b := range secret {
			if b != 0 {
				t.Fatal("answer bytes not cleared")
			}
		}
	}
	t.Log("PASS: real libopenconnect form callback, password then OTP/select, invalid-code retry, session-bound answers, cookie; zero tunnel CONNECT")
}
func TestRealMFARejectsUntrustedCertificate(t *testing.T) {
	h := realMFAHelper(t)
	f, _ := newMFAFixture(t, "")
	p := mfaProfile(f)
	p.CAFile = ""
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	calls := 0
	_, err := h.Authenticate(ctx, p, mfaCredentials(), func(context.Context, AuthChallenge) (AuthAnswer, error) {
		calls++
		return AuthAnswer{}, errors.New("unexpected")
	})
	if err == nil || calls != 0 || f.requests.Load() != 0 || f.connects.Load() != 0 {
		t.Fatal("untrusted TLS certificate did not fail before credentials")
	}
	t.Log("PASS: TLS validation cannot be bypassed; no authentication request or tunnel")
}
func TestRealMFACancelPrompt(t *testing.T) {
	h := realMFAHelper(t)
	f, _ := newMFAFixture(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reached := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := h.Authenticate(ctx, mfaProfile(f), mfaCredentials(), func(ctx context.Context, ch AuthChallenge) (AuthAnswer, error) {
			close(reached)
			<-ctx.Done()
			return AuthAnswer{}, ctx.Err()
		})
		done <- err
	}()
	select {
	case <-reached:
		cancel()
	case err := <-done:
		t.Fatal("authentication ended before prompt", err)
	case <-time.After(10 * time.Second):
		t.Fatal("MFA prompt never reached")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancel not propagated", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancel did not terminate helper")
	}
	if f.connects.Load() != 0 {
		t.Fatal("tunnel attempted")
	}
	t.Log("PASS: pending MFA canceled, helper terminated, no tunnel")
}
func TestRealMFARoundBound(t *testing.T) {
	h := realMFAHelper(t)
	f, _ := newMFAFixture(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	calls := 0
	_, err := h.Authenticate(ctx, mfaProfile(f), mfaCredentials(), func(ctx context.Context, ch AuthChallenge) (AuthAnswer, error) {
		calls++
		return AuthAnswer{SessionID: ch.SessionID, Round: ch.Round, Values: map[string][]byte{"otp": []byte("wrong"), "method": []byte("totp")}}, nil
	})
	if err == nil || calls != 7 || f.connects.Load() != 0 {
		t.Fatal("authentication retry bound violated", calls, err)
	}
	t.Log("PASS: repeated challenges stop at eight forms, no tunnel")
}
func TestRealMFARejectsUnsupportedForm(t *testing.T) {
	h := realMFAHelper(t)
	for _, typ := range []string{"sso", "external-sso", "oversized"} {
		t.Run(typ, func(t *testing.T) {
			form := `<config-auth client="vpn" type="auth-request"><auth id="mfa"><form method="post" action="/"><input type="sso" name="sso-token" label="External SSO"/></form></auth></config-auth>`
			if typ == "external-sso" {
				form = strings.Replace(form, `<auth id="mfa">`, `<auth id="mfa"><sso-v2-browser-mode>external</sso-v2-browser-mode><sso-v2-login>https://127.0.0.1/browser-not-allowed</sso-v2-login>`, 1)
			}
			if typ == "oversized" {
				form = strings.Replace(mfaChallengeXML, "One-time code:", strings.Repeat("x", 2050), 1)
			}
			f, verified := newMFAFixture(t, form)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			calls := 0
			_, err := h.Authenticate(ctx, mfaProfile(f), mfaCredentials(), func(context.Context, AuthChallenge) (AuthAnswer, error) {
				calls++
				return AuthAnswer{}, errors.New("unexpected")
			})
			if err == nil || calls != 0 || verified.Load() != 1 || f.requests.Load() != 2 || f.connects.Load() != 0 {
				t.Fatal("unsupported form did not fail closed immediately after verified password")
			}
		})
	}
}
func TestRealMFAClientCertificate(t *testing.T) {
	h := realMFAHelper(t)
	for _, pass := range []string{"", "synthetic-encrypted-key"} {
		t.Run(map[bool]string{false: "PEM", true: "encrypted-PEM"}[pass != ""], func(t *testing.T) {
			p, cert, _ := clientIdentity(t, []byte(pass), time.Now().Add(time.Hour))
			f := newFixture(t, false, cert)
			p.Gateway = f.server.URL
			p.CAFile = f.ca
			p.Username = ""
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			calls := 0
			fields, err := h.Authenticate(ctx, p, Credentials{KeyPassword: []byte(pass)}, func(context.Context, AuthChallenge) (AuthAnswer, error) {
				calls++
				return AuthAnswer{}, errors.New("unexpected")
			})
			if err != nil || calls != 0 || !strings.Contains(fields["COOKIE"], testCookie) || f.connects.Load() != 0 {
				t.Fatal("certificate-only helper failed", err)
			}
		})
	}
}

func TestRealMFAHostnameResolution(t *testing.T) {
	h := realMFAHelper(t)
	f := newFixture(t, false)
	p := mfaProfile(f)
	p.Gateway = strings.Replace(p.Gateway, "127.0.0.1", "localhost", 1)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	fields, err := h.Authenticate(ctx, p, mfaCredentials(), func(context.Context, AuthChallenge) (AuthAnswer, error) {
		return AuthAnswer{}, errors.New("unexpected prompt")
	})
	if err != nil {
		t.Fatal("hostname authentication failed", err)
	}
	if fields["RESOLVE"] != "localhost:127.0.0.1" || !strings.Contains(fields["CONNECT_URL"], "localhost:") || f.connects.Load() != 0 {
		t.Fatal("authenticated hostname, numeric endpoint or tunnel invariant lost")
	}
	t.Log("PASS: real hostname TLS, original SNI/connect hostname and authenticated numeric RESOLVE retained; no tunnel")
}

func TestRealMFAConfiguredGroup(t *testing.T) {
	h := realMFAHelper(t)
	for _, group := range []string{"engineering", "Engineering", "missing"} {
		t.Run(group, func(t *testing.T) {
			f := newFixture(t, false)
			var authenticated atomic.Int32
			grouped := strings.Replace(challenge, `<input type="text"`, `<select name="group_list" label="Group"><option value="default">Default</option><option value="engineering">Engineering</option></select><input type="text"`, 1)
			f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				f.requests.Add(1)
				if r.Method == http.MethodConnect {
					f.connects.Add(1)
					http.Error(w, "no tunnel", 405)
					return
				}
				b, err := io.ReadAll(io.LimitReader(r.Body, 65536))
				if err != nil {
					http.Error(w, "invalid", 400)
					return
				}
				defer clear(b)
				var req struct {
					Type  string `xml:"type,attr"`
					Group string `xml:"group-select"`
					Auth  struct {
						Username string `xml:"username"`
						Password string `xml:"password"`
					} `xml:"auth"`
				}
				if xml.Unmarshal(b, &req) != nil {
					http.Error(w, "invalid", 400)
					return
				}
				w.Header().Set("Content-Type", "text/xml")
				if req.Type == "init" {
					io.WriteString(w, grouped)
					return
				}
				if req.Group != "engineering" || req.Auth.Username != testUser || req.Auth.Password != testPassword {
					http.Error(w, "rejected", 403)
					return
				}
				authenticated.Add(1)
				http.SetCookie(w, &http.Cookie{Name: "webvpn", Value: testCookie, Path: "/", Secure: true, HttpOnly: true})
				io.WriteString(w, success)
			})
			p := mfaProfile(f)
			p.AuthGroup = group
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			calls := 0
			fields, err := h.Authenticate(ctx, p, mfaCredentials(), func(context.Context, AuthChallenge) (AuthAnswer, error) {
				calls++
				return AuthAnswer{}, errors.New("unexpected group prompt")
			})
			if group == "missing" {
				if err == nil || authenticated.Load() != 0 || calls != 0 {
					t.Fatal("unknown configured group not rejected")
				}
				return
			}
			if err != nil || calls != 0 || authenticated.Load() != 1 || !strings.Contains(fields["COOKIE"], testCookie) || f.connects.Load() != 0 {
				t.Fatal("configured group not preserved through refresh", err)
			}
		})
	}
}
