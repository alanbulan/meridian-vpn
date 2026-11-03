package core

import (
	"bytes"
	"context"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// This builder uses only freshly generated synthetic identities and a password
// on stdin. It never consults a system keyring or a hardware token.
func pkcs12Fixture(t *testing.T) (Profile, *x509.Certificate, []byte) {
	t.Helper()
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl unavailable for synthetic PFX generation")
	}
	p, cert, _ := clientIdentity(t, nil, time.Now().Add(time.Hour))
	bundle := filepath.Join(t.TempDir(), "synthetic.p12")
	file, err := os.OpenFile(bundle, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	password := []byte("synthetic-p12-passphrase")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, openssl, "pkcs12", "-export", "-in", p.ClientCertificate, "-inkey", p.ClientKey, "-out", bundle, "-passout", "stdin")
	input := append(bytes.Clone(password), '\n')
	defer clear(input)
	cmd.Stdin = bytes.NewReader(input)
	if err = cmd.Run(); err != nil {
		t.Fatal("synthetic PFX generation failed", err)
	}
	p.CertificateFormat = "pkcs12"
	p.ClientCertificate = bundle
	p.ClientKey = ""
	return p, cert, password
}
func TestGeneratedPKCS12Preflight(t *testing.T) {
	p, _, password := pkcs12Fixture(t)
	defer clear(password)
	if err := ValidateClientCertificate(p); err != nil {
		t.Fatal(err)
	}
}
func TestRealOpenConnectPKCS12(t *testing.T) {
	executable := openConnectTestBinary(t)
	p, cert, password := pkcs12Fixture(t)
	defer clear(password)
	f := newFixture(t, false, cert)
	p.Gateway = f.server.URL
	p.CAFile = f.ca
	p.Username = ""
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := authenticateOpenConnect(ctx, execRunner{}, executable, p, Credentials{KeyPassword: password})
	if err != nil {
		t.Fatal("PKCS#12 auth-only fixture failed", err)
	}
	defer clear(out)
	tuple, err := parseAuthentication(out)
	if err != nil || tuple["COOKIE"] == "" {
		t.Fatal("missing authentication result", err)
	}
	if f.requests.Load() == 0 || f.connects.Load() != 0 {
		t.Fatal("expected mTLS without tunnel")
	}
	for _, bad := range []string{"", "synthetic-wrong-password"} {
		out, err = authenticateOpenConnect(ctx, execRunner{}, executable, p, Credentials{KeyPassword: []byte(bad)})
		clear(out)
		if err == nil {
			t.Fatal("wrong or missing bundle password accepted")
		}
	}
}
