// This file runs only explicitly enabled, loopback TLS authentication
// tests against a REAL OpenConnect binary. It never starts a tunnel or calls nmcli.
package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/xml"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testUser = "fixture-user"
const testPassword = "synthetic-one-use-password"
const testCookie = "synthetic-auth-cookie-not-a-real-session"
const challenge = `<?xml version="1.0" encoding="UTF-8"?><config-auth client="vpn" type="auth-request" aggregate-auth-version="2"><auth id="main"><title>Local authentication fixture</title><form method="post" action="/"><input type="text" name="username" label="Username:"/><input type="password" name="password" label="Password:"/></form></auth></config-auth>`
const success = `<?xml version="1.0" encoding="UTF-8"?><config-auth client="vpn" type="complete" aggregate-auth-version="2"><session-id>fixture-session</session-id><session-token>` + testCookie + `</session-token><auth id="success"/><config/></config-auth>`

type fixture struct {
	server             *httptest.Server
	ca                 string
	requests, connects atomic.Int32
	reached            chan struct{}
	hold               bool
	stop               chan struct{}
}

func newFixture(t *testing.T, hold bool, clientCertificates ...*x509.Certificate) *fixture {
	t.Helper()
	f := &fixture{hold: hold, reached: make(chan struct{}, 1), stop: make(chan struct{})}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.Method == http.MethodConnect {
			f.connects.Add(1)
			http.Error(w, "Tunnels are not implemented by this fixture", http.StatusMethodNotAllowed)
			return
		}
		select {
		case f.reached <- struct{}{}:
		default:
		}
		if f.hold {
			io.Copy(io.Discard, r.Body)
			select {
			case <-r.Context().Done():
			case <-f.stop:
			}
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 65536))
		if err != nil {
			http.Error(w, "invalid", 400)
			return
		}
		if len(clientCertificates) > 0 {
			if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 || !bytes.Equal(r.TLS.PeerCertificates[0].Raw, clientCertificates[0].Raw) {
				http.Error(w, "client certificate rejected", http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "text/xml")
			http.SetCookie(w, &http.Cookie{Name: "webvpn", Value: testCookie, Path: "/", Secure: true, HttpOnly: true})
			io.WriteString(w, success)
			return
		}
		var req struct {
			Type string `xml:"type,attr"`
			Auth struct {
				Username string `xml:"username"`
				Password string `xml:"password"`
			} `xml:"auth"`
		}
		if xml.Unmarshal(b, &req) != nil {
			http.Error(w, "invalid XML", 400)
			return
		}
		for i := range b {
			b[i] = 0
		}
		w.Header().Set("Content-Type", "text/xml")
		if req.Type == "init" {
			io.WriteString(w, challenge)
			return
		}
		if req.Type != "auth-reply" || req.Auth.Username != testUser || req.Auth.Password != testPassword {
			http.Error(w, "authentication rejected", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "webvpn", Value: testCookie, Path: "/", Secure: true, HttpOnly: true})
		io.WriteString(w, success)
	}))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Ephemeral auth-only fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, DNSNames: []string{"localhost"}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	f.server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	if len(clientCertificates) > 0 {
		f.server.TLS.ClientAuth = tls.RequireAndVerifyClientCert
		f.server.TLS.ClientCAs = x509.NewCertPool()
		f.server.TLS.ClientCAs.AddCert(clientCertificates[0])
	}
	f.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.server.StartTLS()
	t.Cleanup(func() { close(f.stop); f.server.Close() })
	f.ca = filepath.Join(t.TempDir(), "fixture-ca.pem")
	if err := os.WriteFile(f.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}
func openConnectTestBinary(t *testing.T) string {
	t.Helper()
	p := os.Getenv("MERIDIAN_OPENCONNECT_TEST_BINARY")
	if p == "" {
		t.Skip("auth-only integration opt-in: set MERIDIAN_OPENCONNECT_TEST_BINARY to a trusted OpenConnect executable")
	}
	p, e := filepath.Abs(p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(p); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	version, e := exec.CommandContext(ctx, p, "--version").CombinedOutput()
	if e != nil || !bytes.Contains(version, []byte("OpenConnect")) {
		t.Fatal("trusted OpenConnect binary prerequisite/version check failed")
	}
	return p
}
func command(t *testing.T, ctx context.Context, p string, f *fixture, password string, trust bool) *exec.Cmd {
	t.Helper()
	profile := Profile{Name: "Local auth fixture", Gateway: f.server.URL, Protocol: "anyconnect", Username: testUser}
	if trust {
		profile.CAFile = f.ca
	}
	args, err := OpenConnectArgs(profile)
	if err != nil {
		t.Fatal(err)
	}
	c := exec.CommandContext(ctx, p, append([]string{"--authenticate"}, args...)...)
	c.Stdin = strings.NewReader(password + "\n")
	c.Env = isolatedCommandEnvironment(os.Environ())
	c.WaitDelay = time.Second
	return c
}

func TestRealOpenConnectAuthenticationOnly(t *testing.T) {
	p := openConnectTestBinary(t)
	f := newFixture(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c := command(t, ctx, p, f, testPassword, true)
	var out, stderr bytes.Buffer
	c.Stdout = &out
	c.Stderr = &stderr
	err := c.Run()
	if err != nil {
		t.Fatalf("real client authentication failed (%v); diagnostics: %s", err, sanitize(stderr.String()))
	}
	defer func() {
		for i := range out.Bytes() {
			out.Bytes()[i] = 0
		}
	}()
	m, e := parseAuthentication(out.Bytes())
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(m["COOKIE"], testCookie) || m["CONNECT_URL"] == "" || m["FINGERPRINT"] == "" {
		t.Fatalf("expected authenticated tuple missing: cookie length=%d, gateway length=%d, fingerprint length=%d", len(m["COOKIE"]), len(m["CONNECT_URL"]), len(m["FINGERPRINT"]))
	}
	if !strings.HasPrefix(m["CONNECT_URL"], f.server.URL) {
		t.Fatal("authentication redirected outside fixture")
	}
	if f.requests.Load() < 2 || f.connects.Load() != 0 {
		t.Fatal("expected challenge/reply without tunnel CONNECT")
	}
	t.Log("PASS: real TLS challenge/reply, stdin password, cookie tuple; zero tunnel CONNECT requests")
}
func TestRealOpenConnectRejectsBadPassword(t *testing.T) {
	p := openConnectTestBinary(t)
	f := newFixture(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c := command(t, ctx, p, f, "wrong-synthetic-password", true)
	out, e := c.Output()
	if e == nil || bytes.Contains(out, []byte("COOKIE=")) {
		t.Fatal("wrong password unexpectedly authenticated")
	}
	if f.requests.Load() < 2 {
		t.Fatal("bad-password test did not reach real challenge/reply")
	}
	if f.connects.Load() != 0 {
		t.Fatal("tunnel attempted")
	}
	t.Log("PASS: invalid synthetic password rejected; no cookie and no tunnel")
}
func TestRealOpenConnectRejectsUntrustedCertificate(t *testing.T) {
	p := openConnectTestBinary(t)
	f := newFixture(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c := command(t, ctx, p, f, testPassword, false)
	out, e := c.Output()
	if e == nil || bytes.Contains(out, []byte("COOKIE=")) {
		t.Fatal("untrusted fixture certificate unexpectedly accepted")
	}
	exit, ok := e.(*exec.ExitError)
	if !ok || !strings.Contains(strings.ToLower(string(exit.Stderr)), "certificate") {
		t.Fatal("failure was not identified as certificate validation")
	}

	if f.requests.Load() != 0 {
		t.Fatal("credentials reached untrusted HTTPS server")
	}
	t.Log("PASS: untrusted CA rejected before HTTP credentials")
}
func TestRealOpenConnectCancellation(t *testing.T) {
	p := openConnectTestBinary(t)
	f := newFixture(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := command(t, ctx, p, f, testPassword, true)
	var out bytes.Buffer
	c.Stdout = &out
	if e := c.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case <-f.reached:
		cancel()
	case e := <-done:
		t.Fatalf("client exited before fixture request: %v", e)
	case <-time.After(15 * time.Second):
		cancel()
		t.Fatal("fixture request not reached")
	}
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancelled client returned success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled child did not terminate")
	}
	if bytes.Contains(out.Bytes(), []byte("COOKIE=")) || f.connects.Load() != 0 {
		t.Fatal("cancelled request authenticated or tunneled")
	}
	t.Log("PASS: cancellation terminated real client during pending authentication")
}
func sanitize(s string) string {
	for _, v := range []string{testUser, testPassword, testCookie} {
		s = strings.ReplaceAll(s, v, "[redacted]")
	}
	return s
}

func TestRealOpenConnectClientCertificate(t *testing.T) {
	executable := openConnectTestBinary(t)
	for _, encrypted := range []bool{false, true} {
		name := "PEM"
		var passphrase []byte
		if encrypted {
			name = "encrypted-PEM"
			passphrase = []byte("synthetic-key'\"#=passphrase")
		}
		t.Run(name, func(t *testing.T) {
			p, cert, _ := clientIdentity(t, passphrase, time.Now().Add(time.Hour))
			f := newFixture(t, false, cert)
			p.Gateway = f.server.URL
			p.CAFile = f.ca
			p.Username = ""
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			out, err := authenticateOpenConnect(ctx, execRunner{}, executable, p, Credentials{KeyPassword: passphrase})
			if err != nil {
				t.Fatal("real certificate authentication failed", err)
			}
			defer clear(out)
			tuple, err := parseAuthentication(out)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(tuple["COOKIE"], testCookie) || !strings.HasPrefix(tuple["CONNECT_URL"], f.server.URL) {
				t.Fatal("missing authenticated tuple")
			}
			if f.requests.Load() == 0 || f.connects.Load() != 0 {
				t.Fatal("client certificate not verified or tunnel attempted")
			}
			t.Log("PASS: real mTLS certificate-only authentication, inherited private FDs, no username/password, no tunnel")
		})
	}
}
func TestRealOpenConnectRejectsClientCertificate(t *testing.T) {
	executable := openConnectTestBinary(t)
	p, _, _ := clientIdentity(t, nil, time.Now().Add(time.Hour))
	_, expected, _ := clientIdentity(t, nil, time.Now().Add(time.Hour))
	f := newFixture(t, false, expected)
	p.Gateway = f.server.URL
	p.CAFile = f.ca
	p.Username = ""
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := authenticateOpenConnect(ctx, execRunner{}, executable, p, Credentials{})
	defer clear(out)
	if err == nil || bytes.Contains(out, []byte("COOKIE=")) {
		t.Fatal("unauthorized client certificate accepted")
	}
	if f.requests.Load() != 0 || f.connects.Load() != 0 {
		t.Fatal("HTTP credentials or tunnel reached gateway after certificate rejection")
	}
	t.Log("PASS: untrusted client certificate rejected at TLS; no cookie or tunnel")
}
func TestRealOpenConnectRejectsKeyPassphrase(t *testing.T) {
	executable := openConnectTestBinary(t)
	p, cert, _ := clientIdentity(t, []byte("synthetic-correct-key-passphrase"), time.Now().Add(time.Hour))
	f := newFixture(t, false, cert)
	p.Gateway = f.server.URL
	p.CAFile = f.ca
	p.Username = ""
	for _, passphrase := range []string{"", "synthetic-wrong-key-passphrase"} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		out, err := authenticateOpenConnect(ctx, execRunner{}, executable, p, Credentials{KeyPassword: []byte(passphrase)})
		cancel()
		clear(out)
		if err == nil {
			t.Fatal("wrong or missing private-key passphrase accepted")
		}
	}
	if f.requests.Load() != 0 || f.connects.Load() != 0 {
		t.Fatal("failed key unlock reached HTTP credentials or tunnel")
	}
	t.Log("PASS: missing/wrong encrypted-key passphrase rejected, no HTTP credentials or tunnel")
}
func TestRealOpenConnectClientCertificateCancellation(t *testing.T) {
	executable := openConnectTestBinary(t)
	p, cert, _ := clientIdentity(t, []byte("synthetic-key-passphrase"), time.Now().Add(time.Hour))
	f := newFixture(t, true, cert)
	p.Gateway = f.server.URL
	p.CAFile = f.ca
	p.Username = ""
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		out, err := authenticateOpenConnect(ctx, execRunner{}, executable, p, Credentials{KeyPassword: []byte("synthetic-key-passphrase")})
		clear(out)
		done <- err
	}()
	select {
	case <-f.reached:
		cancel()
	case err := <-done:
		t.Fatalf("client exited before fixture: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("certificate authentication did not reach fixture")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled authentication returned success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled certificate child did not terminate")
	}
	if f.connects.Load() != 0 {
		t.Fatal("tunnel attempted")
	}
	t.Log("PASS: cancelled pending certificate authentication promptly terminates real child")
}
