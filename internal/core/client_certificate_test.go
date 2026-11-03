package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func clientIdentity(t *testing.T, password []byte, expires time.Time) (Profile, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(21), Subject: pkix.Name{CommonName: "Synthetic client identity"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keyDER)
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}
	if len(password) != 0 {
		block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, keyDER, password, x509.PEMCipherAES256)
		if err != nil {
			t.Fatal(err)
		}
		block.Headers["DEK-Info"] = strings.ToUpper(block.Headers["DEK-Info"]) // OpenSSL uses uppercase IV hex; OpenConnect requires it.
	}
	p := profile()
	dir := t.TempDir()
	p.ClientCertificate = filepath.Join(dir, "client.pem")
	p.ClientKey = filepath.Join(dir, "key.pem")
	if err = os.WriteFile(p.ClientCertificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(block)
	defer clear(data)
	if err = os.WriteFile(p.ClientKey, data, 0600); err != nil {
		t.Fatal(err)
	}
	return p, cert, key
}
func TestClientCertificateValidation(t *testing.T) {
	p, _, _ := clientIdentity(t, nil, time.Now().Add(time.Hour))
	if runtime.GOOS == "windows" {
		if ValidateClientCertificate(p) == nil {
			t.Fatal("identity accepted without verified private-file permissions")
		}
		return
	}
	if err := ValidateClientCertificate(p); err != nil {
		t.Fatal(err)
	}
	keyData, _ := os.ReadFile(p.ClientKey)
	defer clear(keyData)
	certData, _ := os.ReadFile(p.ClientCertificate)
	t.Run("mismatched", func(t *testing.T) {
		other, _, _ := clientIdentity(t, nil, time.Now().Add(time.Hour))
		other.ClientCertificate = p.ClientCertificate
		if ValidateClientCertificate(other) == nil {
			t.Fatal("mismatched key accepted")
		}
	})
	t.Run("expired", func(t *testing.T) {
		expired, _, _ := clientIdentity(t, nil, time.Now().Add(-time.Minute))
		if ValidateClientCertificate(expired) == nil {
			t.Fatal("expired client certificate accepted")
		}
	})
	t.Run("private key permissions", func(t *testing.T) {
		os.Chmod(p.ClientKey, 0644)
		defer os.Chmod(p.ClientKey, 0600)
		if ValidateClientCertificate(p) == nil {
			t.Fatal("publicly readable key accepted")
		}
	})
	t.Run("certificate permissions", func(t *testing.T) {
		os.Chmod(p.ClientCertificate, 0666)
		defer os.Chmod(p.ClientCertificate, 0600)
		if ValidateClientCertificate(p) == nil {
			t.Fatal("writable certificate accepted")
		}
	})
	for _, which := range []string{"certificate", "key"} {
		t.Run(which+" invalid", func(t *testing.T) {
			path, restore := p.ClientCertificate, certData
			if which == "key" {
				path, restore = p.ClientKey, keyData
			}
			defer os.WriteFile(path, restore, 0600)
			for _, data := range [][]byte{nil, []byte("not PEM"), append([]byte("junk\n"), restore...), append(append([]byte{}, restore...), []byte("junk")...), bytes.Repeat([]byte("x"), maxClientCertificateBytes+1)} {
				os.WriteFile(path, data, 0600)
				if ValidateClientCertificate(p) == nil {
					t.Fatal("invalid file accepted")
				}
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		bad := p
		bad.ClientKey = filepath.Join(t.TempDir(), "missing")
		if ValidateClientCertificate(bad) == nil {
			t.Fatal("missing key accepted")
		}
	})
	t.Run("CA is not client", func(t *testing.T) {
		bad := p
		bad.ClientCertificate = caFixture(t)
		if ValidateClientCertificate(bad) == nil {
			t.Fatal("CA accepted as client identity")
		}
	})
}
func TestClientReferencesPersistWithoutSecrets(t *testing.T) {
	p, _, _ := clientIdentity(t, []byte("synthetic-key-passphrase"), time.Now().Add(time.Hour))
	p.AdditionalGateways = []string{"https://backup.example.com"}
	s := Store{filepath.Join(t.TempDir(), "profiles.json")}
	if err := s.Save(Config{Profiles: []Profile{p}}); err != nil {
		t.Fatal(err)
	}
	cfg, err := s.Load()
	if err != nil || !reflect.DeepEqual(cfg.Profiles[0], p) {
		t.Fatal("reference round trip failed", err)
	}
	data, _ := os.ReadFile(s.Path)
	if bytes.Contains(data, []byte("BEGIN")) || bytes.Contains(data, []byte("passphrase")) {
		t.Fatal("key contents or passphrase persisted")
	}
	data, _ = json.Marshal(Credentials{Password: []byte("sensitive"), KeyPassword: []byte("private")})
	if string(data) != "{}" {
		t.Fatal("runtime credentials serialized")
	}
	for _, field := range []string{"key_password", "password", "client_key_contents"} {
		injected := bytes.Replace(mustRead(t, s.Path), []byte(`"name": "Office"`), []byte(`"name": "Office", "`+field+`": "secret"`), 1)
		os.WriteFile(s.Path, injected, 0600)
		if _, err = s.Load(); err == nil {
			t.Fatal("secret field import accepted", field)
		}
		s.Save(Config{Profiles: []Profile{p}})
	}
}
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestAdditionalGatewaysValidation(t *testing.T) {
	p := profile()
	p.AdditionalGateways = []string{"https://backup.example.com:444/path"}
	if err := ValidateProfile(p); err != nil {
		t.Fatal(err)
	}
	for _, g := range [][]string{{p.Gateway}, {"https://backup.example.com", "https://backup.example.com"}, {"http://backup.example.com"}, {"https://u:p@backup.example.com"}, {"https://backup.example.com?secret=x"}, make([]string, 16)} {
		p.AdditionalGateways = g
		if ValidateProfile(p) == nil {
			t.Fatal("invalid gateway set accepted")
		}
	}
}
func TestKeyPassphraseRejectsConfigInjection(t *testing.T) {
	p := profile()
	p.ClientCertificate = "/safe/client.pem"
	p.ClientKey = "/safe/key.pem"
	for _, value := range []string{"line\nbreak", "line\rbreak", "nul\x00value", " leading", "\tleading", strings.Repeat("x", 4097)} {
		r := &mockRunner{}
		if _, err := testNM(r).StartWithCredentials(context.Background(), p, Credentials{KeyPassword: []byte(value)}); err == nil || len(r.calls) != 0 {
			t.Fatal("unsafe passphrase reached process")
		}
	}
	for _, value := range []string{"a'\"#=b", "safe\tinside", "é"} {
		if err := validateCredentials(p, Credentials{KeyPassword: []byte(value)}); err != nil {
			t.Fatal("literal safe passphrase rejected", err)
		}
	}
	p.ClientCertificate = ""
	p.ClientKey = ""
	if validateCredentials(p, Credentials{KeyPassword: []byte("unused")}) == nil {
		t.Fatal("unused key password accepted")
	}
}

type recordingFileRunner struct {
	*mockRunner
	files [][]byte
	args  []string
}

func (r *recordingFileRunner) RunWithFiles(ctx context.Context, p string, args []string, input []byte, files []*os.File) ([]byte, error) {
	r.args = append([]string(nil), args...)
	for _, f := range files {
		b, e := io.ReadAll(f)
		if e != nil {
			return nil, e
		}
		r.files = append(r.files, b)
	}
	return r.mockRunner.Run(ctx, p, args, input)
}
func TestNetworkManagerConsumesClientCertificateAndPrivateFD(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux inherited-file-descriptor authentication transport")
	}
	p, _, _ := clientIdentity(t, nil, time.Now().Add(time.Hour))
	p.Username = ""
	r := &recordingFileRunner{mockRunner: &mockRunner{}}
	n := testNM(r.mockRunner)
	n.runner = r
	s, e := n.StartWithCredentials(context.Background(), p, Credentials{KeyPassword: []byte("synthetic'#=key-secret")})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Stop()
	if len(r.files) != 3 || string(r.files[0]) != "key-password=synthetic'#=key-secret\n" {
		t.Fatal("private config FD missing or altered")
	}
	if !bytes.Equal(r.files[1], mustRead(t, p.ClientCertificate)) || !bytes.Equal(r.files[2], mustRead(t, p.ClientKey)) {
		t.Fatal("client files not passed")
	}
	for _, call := range r.calls {
		joined := strings.Join(call.args, " ")
		if strings.Contains(joined, p.ClientKey) || strings.Contains(joined, p.ClientCertificate) || strings.Contains(joined, "key-secret") {
			t.Fatal("client path or secret in argv")
		}
		if call.path == "nm" && (strings.Contains(call.input, "PRIVATE KEY") || strings.Contains(call.input, "key-secret")) {
			t.Fatal("private identity reached privileged backend")
		}
		if call.path == "oc" && call.input != "\n" {
			t.Fatal("certificate-only auth requires password")
		}
	}
	for _, b := range r.files {
		clear(b)
	}
}
func TestCertificateAuthenticationRequiresSecureRunner(t *testing.T) {
	p, _, _ := clientIdentity(t, nil, time.Now().Add(time.Hour))
	r := &mockRunner{}
	if _, e := testNM(r).Start(context.Background(), p, nil); e == nil || len(r.calls) != 0 {
		t.Fatal("insecure runner silently ignored certificate")
	}
}

type failingFileRunner struct{ mockRunner }

func (r *failingFileRunner) RunWithFiles(context.Context, string, []string, []byte, []*os.File) ([]byte, error) {
	return nil, errors.New("expected launch error")
}
func TestPrivateConfigPipeClosesOnLaunchFailure(t *testing.T) {
	p, _, _ := clientIdentity(t, nil, time.Now().Add(time.Hour))
	done := make(chan struct{})
	go func() {
		defer close(done)
		authenticateOpenConnect(context.Background(), &failingFileRunner{}, "nonexistent", p, Credentials{KeyPassword: bytes.Repeat([]byte("x"), 4096)})
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("private config writer leaked")
	}
}

type captureCredentialsAdapter struct{ started chan Credentials }

func (a captureCredentialsAdapter) Capability() Capability { return Capability{Available: true} }
func (a captureCredentialsAdapter) Start(context.Context, Profile, []byte) (Session, error) {
	return nil, errors.New("legacy method must not be called")
}
func (a captureCredentialsAdapter) StartWithCredentials(ctx context.Context, _ Profile, c Credentials) (Session, error) {
	a.started <- c
	<-ctx.Done()
	return nil, ctx.Err()
}
func TestEngineCopiesAndClearsCertificateCredentials(t *testing.T) {
	a := captureCredentialsAdapter{started: make(chan Credentials, 1)}
	e := NewEngine(a)
	p := profile()
	dir := t.TempDir()
	p.ClientCertificate = filepath.Join(dir, "certificate.pem")
	p.ClientKey = filepath.Join(dir, "private.pem")
	c := Credentials{Password: []byte("synthetic-login-copy"), KeyPassword: []byte("synthetic-key-copy")}
	if err := e.ConnectWithCredentials(p, c, true); err != nil {
		t.Fatal(err)
	}
	clear(c.Password)
	clear(c.KeyPassword)
	var captured Credentials
	select {
	case captured = <-a.started:
	case <-time.After(time.Second):
		t.Fatal("credential adapter not called")
	}
	if string(captured.Password) != "synthetic-login-copy" || string(captured.KeyPassword) != "synthetic-key-copy" {
		t.Fatal("caller mutation changed in-flight credentials")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{captured.Password, captured.KeyPassword} {
		for _, v := range secret {
			if v != 0 {
				t.Fatal("engine retained credential bytes after cancellation")
			}
		}
	}
	for _, entry := range e.Snapshot().Logs {
		if strings.Contains(entry.Message, "synthetic-") {
			t.Fatal("credentials reached logs")
		}
	}
}
func TestLegacyAdapterDoesNotIgnoreCertificateOrInteractiveAuthentication(t *testing.T) {
	for _, interactive := range []bool{false, true} {
		e := NewEngine(sessionAdapter{})
		p := profile()
		if interactive {
			p.InteractiveAuth = true
		} else {
			p.ClientCertificate = "/synthetic/client.pem"
			p.ClientKey = "/synthetic/key.pem"
		}
		if err := e.ConnectWithCredentials(p, Credentials{}, true); err == nil {
			t.Fatal("unsupported authentication silently ignored")
		}
	}
}

func TestClientCertificatePreflightBlocksAllCommands(t *testing.T) {
	p, _, _ := clientIdentity(t, nil, time.Now().Add(time.Hour))
	other, _, _ := clientIdentity(t, nil, time.Now().Add(time.Hour))
	for _, kind := range []string{"missing", "mismatched", "insecure"} {
		t.Run(kind, func(t *testing.T) {
			bad := p
			switch kind {
			case "missing":
				bad.ClientKey = filepath.Join(t.TempDir(), "missing.pem")
			case "mismatched":
				bad.ClientKey = other.ClientKey
			case "insecure":
				os.Chmod(p.ClientKey, 0644)
				defer os.Chmod(p.ClientKey, 0600)
			}
			r := &recordingFileRunner{mockRunner: &mockRunner{}}
			n := testNM(r.mockRunner)
			n.runner = r
			if _, err := n.StartWithCredentials(context.Background(), bad, Credentials{}); err == nil {
				t.Fatal("bad client identity reached authentication")
			}
			if len(r.calls) != 0 || len(r.files) != 0 {
				t.Fatal("process called before successful identity preflight")
			}
		})
	}
}
