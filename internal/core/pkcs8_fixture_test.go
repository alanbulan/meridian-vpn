package core

// This fixture builder is test-only. Production delegates all encrypted-key
// cryptography to the installed OpenConnect TLS implementation.
import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"testing"
	"time"
)

func encryptedPKCS8Fixture(t *testing.T, key any, password []byte) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	salt := make([]byte, 16)
	iv := make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	if _, err = rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	secret, err := pbkdf2.Key(sha256.New, string(password), salt, 10000, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	block, err := aes.NewCipher(secret)
	if err != nil {
		t.Fatal(err)
	}
	pad := aes.BlockSize - len(der)%aes.BlockSize
	padded := append(append([]byte{}, der...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	defer clear(padded)
	encrypted := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, padded)
	kdf, err := asn1.Marshal(struct {
		Salt       []byte
		Iterations int
		KeyLength  int
		PRF        pkix.AlgorithmIdentifier
	}{salt, 10000, 32, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}, Parameters: asn1.NullRawValue}})
	if err != nil {
		t.Fatal(err)
	}
	ivDER, _ := asn1.Marshal(iv)
	params, err := asn1.Marshal(struct{ KDF, Encryption pkix.AlgorithmIdentifier }{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}, Parameters: asn1.RawValue{FullBytes: kdf}}, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}, Parameters: asn1.RawValue{FullBytes: ivDER}}})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}, Parameters: asn1.RawValue{FullBytes: params}}, encrypted})
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: envelope})
}
func TestRealOpenConnectEncryptedPKCS8(t *testing.T) {
	executable := openConnectTestBinary(t)
	password := []byte("synthetic-pkcs8'\"#=passphrase")
	p, cert, key := clientIdentity(t, nil, time.Now().Add(time.Hour))
	if err := os.WriteFile(p.ClientKey, encryptedPKCS8Fixture(t, key, password), 0600); err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, false, cert)
	p.Gateway = f.server.URL
	p.CAFile = f.ca
	p.Username = ""
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := authenticateOpenConnect(ctx, execRunner{}, executable, p, Credentials{KeyPassword: password})
	if err != nil {
		t.Fatal("encrypted PKCS#8 real authentication failed", err)
	}
	defer clear(out)
	tuple, err := parseAuthentication(out)
	if err != nil || tuple["COOKIE"] == "" {
		t.Fatal("encrypted PKCS#8 tuple missing", err)
	}
	if f.requests.Load() == 0 || f.connects.Load() != 0 {
		t.Fatal("expected mTLS without tunnel")
	}
	for _, bad := range []string{"", "synthetic-wrong-pkcs8-passphrase"} {
		out, err := authenticateOpenConnect(ctx, execRunner{}, executable, p, Credentials{KeyPassword: []byte(bad)})
		clear(out)
		if err == nil {
			t.Fatal("wrong/missing PKCS#8 passphrase accepted")
		}
	}
	other, _, _ := clientIdentity(t, nil, time.Now().Add(time.Hour))
	p.ClientCertificate = other.ClientCertificate
	before := f.requests.Load()
	out, err = authenticateOpenConnect(ctx, execRunner{}, executable, p, Credentials{KeyPassword: password})
	clear(out)
	if err == nil || f.requests.Load() != before {
		t.Fatal("encrypted mismatched key/certificate reached authenticated HTTP")
	}
	t.Log("PASS: real encrypted PKCS#8 mTLS with private FD passphrase; wrong/missing passphrase and mismatched certificate rejected")
}
