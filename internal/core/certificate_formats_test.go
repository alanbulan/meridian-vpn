package core

import (
	"context"
	"encoding/asn1"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func syntheticPFX(t *testing.T) Profile {
	t.Helper()
	// Deliberately only an envelope, not a functioning identity. Backend crypto
	// validity is NOT established by these transport/unit tests.
	pfx := pfxEnvelope{Version: 3, AuthSafe: pfxContentInfo{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}, Content: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: []byte{4, 2, 48, 0}}}}
	pfx.MAC.DigestInfo.Algorithm.Algorithm = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	pfx.MAC.DigestInfo.Digest = make([]byte, 32)
	pfx.MAC.Salt = []byte("synthetic-salt")
	pfx.MAC.Iterations = 1
	data, e := asn1.Marshal(pfx)
	if e != nil {
		t.Fatal(e)
	}
	p := profile()
	p.CertificateFormat = "pkcs12"
	p.ClientCertificate = filepath.Join(t.TempDir(), "synthetic.p12")
	if e = os.WriteFile(p.ClientCertificate, data, 0600); e != nil {
		t.Fatal(e)
	}
	return p
}
func TestPKCS12EnvelopeAndPrivateFDTransport(t *testing.T) {
	p := syntheticPFX(t)
	if e := ValidateClientCertificate(p); e != nil {
		t.Fatal(e)
	}
	r := &recordingFileRunner{mockRunner: &mockRunner{}}
	if _, e := authenticateOpenConnect(context.Background(), r, "oc", p, Credentials{KeyPassword: []byte("synthetic-bundle-secret")}); e != nil {
		t.Fatal(e)
	}
	if len(r.files) != 2 || string(r.files[0]) != "key-password=synthetic-bundle-secret\n" {
		t.Fatal("bundle private transport missing")
	}
	args := strings.Join(r.args, " ")
	if strings.Contains(args, "sslkey") || strings.Contains(args, "synthetic") || !strings.Contains(args, "--certificate=/proc/self/fd/4") {
		t.Fatal("wrong bundle args")
	}
	files, _, cert, key, e := mfaFiles(p)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	if len(files) != 1 || cert != "/proc/self/fd/3" || key != "" {
		t.Fatal("wrong MFA bundle references")
	}
	os.Chmod(p.ClientCertificate, 0644)
	if ValidateClientCertificate(p) == nil {
		t.Fatal("publicly readable bundle accepted")
	}
	os.Chmod(p.ClientCertificate, 0600)
	for _, data := range [][]byte{[]byte("PEM is not PFX"), {48, 0}, append(mustRead(t, p.ClientCertificate), 0)} {
		if validatePKCS12Envelope(data) == nil {
			t.Fatal("malformed PFX accepted")
		}
	}
}
func TestPKCS11RejectsSecretsAndAmbiguity(t *testing.T) {
	for _, uri := range []string{"pkcs11:id=%01;type=cert", "pkcs11:token=My%20Token;object=Client;object-type=cert", "pkcs11:id=%00%ff"} {
		if e := validatePKCS11URI(uri, "cert"); e != nil {
			t.Fatal(uri, e)
		}
	}
	for _, uri := range []string{"pkcs11:", "pkcs11:token=all", "pkcs11:id=%xy", "pkcs11:id=x;id=y", "pkcs11:id=x;pin-value=1234", "pkcs11:id=x?pin-value=1234", "pkcs11:id=x;pin-source=file", "pkcs11:id=x?module-path=%2Ftmp%2Fevil.so", "pkcs11:id=x;module-name=evil", "pkcs11:id=x;type=private", "pkcs11:id=x;type=cert;object-type=cert", "pkcs11:object=line%0Abreak", "pkcs11:object=a\nb", "pkcs11:%70in-value=1234;id=x", "pkcs11:object=a b", "pkcs11:id=x#fragment"} {
		if validatePKCS11URI(uri, "cert") == nil {
			t.Fatal("unsafe URI accepted", uri)
		}
	}
}
func TestPKCS11PrivateTransportAndPersistence(t *testing.T) {
	p := profile()
	p.CertificateFormat = "pkcs11"
	p.ClientCertificate = "pkcs11:token=Synthetic;id=%01;type=cert"
	p.ClientKey = "pkcs11:token=Synthetic;id=%01;type=private"
	if e := ValidateClientCertificate(p); e != nil {
		t.Fatal(e)
	}
	r := &recordingFileRunner{mockRunner: &mockRunner{}}
	if _, e := authenticateOpenConnect(context.Background(), r, "oc", p, Credentials{KeyPassword: []byte("synthetic-PIN")}); e != nil {
		t.Fatal(e)
	}
	if len(r.files) != 1 || !strings.Contains(string(r.files[0]), "certificate="+p.ClientCertificate+"\n") || !strings.Contains(string(r.files[0]), "sslkey="+p.ClientKey+"\n") {
		t.Fatal("token selectors not privately transported")
	}
	if strings.Contains(strings.Join(r.args, " "), "Synthetic") || strings.Contains(strings.Join(r.args, " "), "PIN") {
		t.Fatal("token metadata in argv")
	}
	files, _, cert, key, e := mfaFiles(p)
	if e != nil || len(files) != 0 || cert != p.ClientCertificate || key != p.ClientKey {
		t.Fatal("wrong MFA token references", e)
	}
	s := Store{filepath.Join(t.TempDir(), "profiles.json")}
	if e = s.Save(Config{Profiles: []Profile{p}}); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(mustRead(t, s.Path)), "PIN") {
		t.Fatal("PIN persisted")
	}
	p.ClientKey = ""
	if e = ValidateProfile(p); e != nil {
		t.Fatal("implicit matching token key rejected", e)
	}
	p.ClientCertificate += "?pin-value=synthetic-PIN"
	if s.Save(Config{Profiles: []Profile{p}}) == nil {
		t.Fatal("PIN-bearing URI persisted")
	}
}
func TestCertificateFormatCombinations(t *testing.T) {
	for _, format := range []string{"unknown", "pkcs12", "pkcs11"} {
		p := profile()
		p.CertificateFormat = format
		if ValidateProfile(p) == nil {
			t.Fatal("missing or unknown identity accepted", format)
		}
	}
	p := syntheticPFX(t)
	p.ClientKey = "/synthetic/key.pem"
	if ValidateProfile(p) == nil {
		t.Fatal("separate key accepted with bundle")
	}
}

func TestPKCS12RejectsAbsentOrMalformedMAC(t *testing.T) {
	p := syntheticPFX(t)
	var parsed pfxEnvelope
	if _, err := asn1.Unmarshal(mustRead(t, p.ClientCertificate), &parsed); err != nil {
		t.Fatal(err)
	}
	noMAC, err := asn1.Marshal(struct {
		Version  int
		AuthSafe pfxContentInfo
	}{parsed.Version, parsed.AuthSafe})
	if err != nil {
		t.Fatal(err)
	}
	if validatePKCS12Envelope(noMAC) == nil {
		t.Fatal("MAC-less bundle accepted")
	}
	for _, which := range []string{"salt", "digest", "iterations"} {
		bad := parsed
		switch which {
		case "salt":
			bad.MAC.Salt = nil
		case "digest":
			bad.MAC.DigestInfo.Digest = nil
		case "iterations":
			bad.MAC.Iterations = -1
		}
		data, err := asn1.Marshal(bad)
		if err != nil {
			t.Fatal(err)
		}
		if validatePKCS12Envelope(data) == nil {
			t.Fatal("malformed MAC accepted", which)
		}
	}
}

// Simulate replacement after validation but before the child reads its FDs.
// Both password-only and certificate auth must retain the original trust roots.
type replaceCAFileRunner struct {
	recordingFileRunner
	caPath      string
	replacement []byte
}

func (r *replaceCAFileRunner) RunWithFiles(ctx context.Context, exe string, args []string, input []byte, files []*os.File) ([]byte, error) {
	if err := os.Remove(r.caPath); err != nil {
		return nil, err
	}
	if err := os.WriteFile(r.caPath, r.replacement, 0600); err != nil {
		return nil, err
	}
	return r.recordingFileRunner.RunWithFiles(ctx, exe, args, input, files)
}
func TestAuthenticationPinsValidatedCAFile(t *testing.T) {
	for _, bundle := range []bool{false, true} {
		p := profile()
		if bundle {
			p = syntheticPFX(t)
		}
		p.CAFile = caFixture(t)
		original := mustRead(t, p.CAFile)
		r := &replaceCAFileRunner{recordingFileRunner: recordingFileRunner{mockRunner: &mockRunner{}}, caPath: p.CAFile, replacement: []byte("replaced trust root")}
		if _, err := authenticateOpenConnect(context.Background(), r, "oc", p, Credentials{}); err != nil {
			t.Fatal(err)
		}
		if string(r.files[len(r.files)-1]) != string(original) {
			t.Fatal("path replacement changed validated trust roots")
		}
		for _, arg := range r.args {
			if strings.Contains(arg, p.CAFile) {
				t.Fatal("original CA path escaped pinned descriptor")
			}
		}
		if bundle && len(r.files) != 3 || !bundle && len(r.files) != 2 {
			t.Fatal("wrong descriptor count")
		}
	}
}

func TestCARejectsWritableTrustRoot(t *testing.T) {
	path := caFixture(t)
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if ValidateCAFile(path) == nil {
		t.Fatal("externally writable trust root accepted")
	}
}
