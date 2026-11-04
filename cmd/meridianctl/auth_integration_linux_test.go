//go:build linux && (amd64 || arm64)

package main

import (
 "context"
 "encoding/pem"
 "encoding/xml"
 "io"
 "mygo-vpn/internal/core"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "sync/atomic"
 "testing"
 "time"
)

const cliFixturePassword = "synthetic-cli-fixture-password"
const cliFixtureCookie = "synthetic-cli-fixture-cookie"
const cliFixtureInitial = `<?xml version="1.0"?><config-auth client="vpn" type="auth-request" aggregate-auth-version="2"><auth id="main"><form method="post" action="/"><input type="text" name="username" label="Username:"/><input type="password" name="password" label="Password:"/></form></auth></config-auth>`
const cliFixtureMFA = `<?xml version="1.0"?><config-auth client="vpn" type="auth-request" aggregate-auth-version="2"><auth id="mfa"><form method="post" action="/"><input type="password" name="otp" label="One-time code:"/><select name="method" label="Verification method"><option value="totp">Authenticator app</option><option value="backup">Recovery code</option></select></form></auth></config-auth>`
const cliFixtureSuccess = `<?xml version="1.0"?><config-auth client="vpn" type="complete" aggregate-auth-version="2"><session-id>fixture-session</session-id><session-token>` + cliFixtureCookie + `</session-token><auth id="success"/><config/></config-auth>`

func TestRealCLIMFAChallengeRetry(t *testing.T) { realCLIMFATerminal(t, false) }
func TestRealCLIMFACancelPrompt(t *testing.T) { realCLIMFATerminal(t, true) }

// This intentionally exercises the real helper and real controlling terminal,
// but never constructs an adapter, invokes NetworkManager, or creates a tunnel.
func realCLIMFATerminal(t *testing.T, cancelPrompt bool) {
 t.Helper()
 path := os.Getenv("MERIDIAN_MFA_HELPER_TEST_BINARY")
 if path == "" { t.Skip("set MERIDIAN_MFA_HELPER_TEST_BINARY for real CLI MFA loopback tests") }
 if !filepath.IsAbs(path) || filepath.Base(path) != "meridian-auth-helper" { t.Fatal("real helper must be an absolute path named meridian-auth-helper") }
 if os.Getenv("MERIDIAN_TERMINAL_TEST_CHILD") == "" {
  s := startTerminalPTY(t, t.Name(), "real-helper")
  s.await(t, "Hidden answer: ")
  if cancelPrompt {
   s.write(t, "\x03")
  } else {
   s.write(t, "000000\n")
   s.await(t, "Choice number (hidden): "); s.write(t, "1\n")
   s.await(t, "Hidden answer: "); s.write(t, "123456\n")
   s.await(t, "Choice number (hidden): "); s.write(t, "1\n")
  }
  s.finish(t, "000000", "123456", cliFixturePassword, cliFixtureCookie)
  return
 }
 t.Setenv("PATH", filepath.Dir(path)+string(os.PathListSeparator)+os.Getenv("PATH"))
 helper := core.NewMFAHelper()
 if !helper.Capability().Available { t.Fatal("real MFA helper unavailable or its directory ancestry is untrusted") }
 actual, err := filepath.EvalSymlinks(helper.Capability().Executable)
 if err != nil { t.Fatal(err) }
 expected, err := filepath.EvalSymlinks(path)
 if err != nil || actual != expected { t.Fatal("discovered helper differs from explicit test prerequisite") }
 var passwords, rejected, accepted, connects atomic.Int32
 server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  if r.Method == http.MethodConnect { connects.Add(1); http.Error(w, "no tunnel", 405); return }
  body, err := io.ReadAll(io.LimitReader(r.Body, 65536)); if err != nil { http.Error(w, "invalid", 400); return }; defer clear(body)
  var req struct {
   Type string `xml:"type,attr"`
   Auth struct { Username string `xml:"username"`; Password string `xml:"password"`; OTP string `xml:"otp"`; Method string `xml:"method"` } `xml:"auth"`
  }
  if xml.Unmarshal(body, &req) != nil { http.Error(w, "invalid XML", 400); return }
  w.Header().Set("Content-Type", "text/xml")
  switch {
  case req.Type == "init": io.WriteString(w, cliFixtureInitial)
  case req.Auth.Username == "cli-fixture-user" && req.Auth.Password == cliFixturePassword:
   passwords.Add(1); io.WriteString(w, cliFixtureMFA)
  case passwords.Load() > 0 && req.Auth.OTP == "123456" && req.Auth.Method == "totp":
   accepted.Add(1)
   http.SetCookie(w, &http.Cookie{Name: "webvpn", Value: cliFixtureCookie, Path: "/", Secure: true, HttpOnly: true})
   io.WriteString(w, cliFixtureSuccess)
  case passwords.Load() > 0:
   rejected.Add(1); io.WriteString(w, cliFixtureMFA)
  default: http.Error(w, "rejected", 403)
  }
 }))
 defer server.Close()
 ca := filepath.Join(t.TempDir(), "loopback-ca.pem")
 if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil { t.Fatal(err) }
 before := terminalState(t)
 terminal, err := openAuthTerminal(); if err != nil { t.Fatal(err) }; defer terminal.Close()
 ctx, stop := commandSignalContext(context.Background()); defer stop()
 ctx, timeout := context.WithTimeout(ctx, 20*time.Second); defer timeout()
 calls := 0
 var answers [][]byte
 fields, authErr := helper.Authenticate(ctx, core.Profile{Name: "CLI localhost fixture", Gateway: server.URL, Protocol: "anyconnect", Username: "cli-fixture-user", CAFile: ca}, core.Credentials{Password: []byte(cliFixturePassword)}, func(ctx context.Context, challenge core.AuthChallenge) (core.AuthAnswer, error) {
  calls++
  answer, err := terminal.Prompt(ctx, challenge)
  for _, value := range answer.Values { answers = append(answers, value) }
  return answer, err
 })
 checkTerminalRestored(t, before)
 if terminal.Close() != nil { t.Fatal("terminal restoration failed") }
 if connects.Load() != 0 { t.Fatal("authentication attempted a tunnel") }
 if cancelPrompt {
  if authErr == nil || calls != 1 || accepted.Load() != 0 { t.Fatal("cancel did not stop helper authentication") }
 } else {
  if authErr != nil { t.Fatal("real helper terminal authentication failed:", authErr) }
  if calls != 2 || passwords.Load() != 1 || rejected.Load() != 1 || accepted.Load() != 1 || !strings.Contains(fields["COOKIE"], cliFixtureCookie) { t.Fatal("expected password, OTP rejection, retry, and authenticated cookie") }
 }
 for _, answer := range answers { for _, b := range answer { if b != 0 { t.Fatal("helper did not clear terminal answer") } } }
}
