package core

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"time"
)

const maxClientCertificateBytes = 4 << 20

// ValidateClientCertificate checks external identity references without a passphrase.
// PKCS#12 checks are envelope-only; token existence is checked by the backend.
// Encrypted private-key unlocking and matching are performed by OpenConnect.
// Only path references are persisted; no certificate/key contents are stored.
func ValidateClientCertificate(p Profile) error {
	files, err := openClientCertificate(p)
	for _, f := range files {
		f.Close()
	}
	return err
}

func readClientPEM(path string, private bool) (*os.File, []byte, error) {
	bad := errors.New("client certificate/key must be a readable regular certificate/key file under 4 MiB; private keys must be owner-only and certificates must not be writable by other users")
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxClientCertificateBytes || st.Size() == 0 {
		return nil, nil, bad
	}
	f, err := openCAFile(path) // Linux O_NOFOLLOW and O_NONBLOCK prevent path/FIFO substitution.
	if err != nil {
		return nil, nil, bad
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	now, err := f.Stat()
	if err != nil || !now.Mode().IsRegular() || now.Size() > maxClientCertificateBytes || !os.SameFile(st, now) {
		return nil, nil, bad
	}
	if now.Mode().Perm()&0022 != 0 || (private && now.Mode().Perm()&0077 != 0) {
		return nil, nil, bad
	}
	data, err := io.ReadAll(io.LimitReader(f, maxClientCertificateBytes+1))
	if err != nil || len(data) > maxClientCertificateBytes {
		clear(data)
		return nil, nil, bad
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		clear(data)
		return nil, nil, bad
	}
	ok = true
	return f, data, nil
}

func openClientCertificate(p Profile) ([]*os.File, error) {
	if err := ValidateProfile(p); err != nil {
		return nil, err
	}
	if p.ClientCertificate == "" {
		return nil, nil
	}
	if p.CertificateFormat == "pkcs11" {
		return nil, nil
	}
	if p.CertificateFormat == "pkcs12" {
		f, data, err := readClientPEM(p.ClientCertificate, true)
		if err != nil {
			return nil, err
		}
		defer clear(data)
		if err = validatePKCS12Envelope(data); err != nil {
			f.Close()
			return nil, err
		}
		return []*os.File{f}, nil
	}
	certFile, certData, err := readClientPEM(p.ClientCertificate, false)
	if err != nil {
		return nil, err
	}
	defer clear(certData)
	keyFile, keyData, err := readClientPEM(p.ClientKey, true)
	if err != nil {
		certFile.Close()
		return nil, err
	}
	defer clear(keyData)
	files := []*os.File{certFile, keyFile}
	success := false
	defer func() {
		if !success {
			for _, f := range files {
				f.Close()
			}
		}
	}()
	var leaf *x509.Certificate
	rest := certData
	count := 0
	for len(bytes.TrimSpace(rest)) > 0 {
		rest = bytes.TrimSpace(rest)
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("client certificate file must contain only PEM certificates")
		}
		block, tail := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("invalid client certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid client certificate")
		}
		if leaf == nil {
			leaf = cert
		}
		count++
		if count > 32 {
			return nil, errors.New("client certificate chain exceeds 32 certificates")
		}
		rest = tail
	}
	if leaf == nil {
		return nil, errors.New("client certificate file is empty")
	}
	now := time.Now()
	if leaf.IsCA || now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, errors.New("client certificate must be a currently valid end-entity certificate")
	}
	if len(leaf.ExtKeyUsage) > 0 {
		client := false
		for _, usage := range leaf.ExtKeyUsage {
			if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
				client = true
			}
		}
		if !client {
			return nil, errors.New("certificate is not valid for client authentication")
		}
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, errors.New("client certificate cannot sign authentication requests")
	}
	if err := validateClientKey(keyData, leaf); err != nil {
		return nil, err
	}
	success = true
	return files, nil
}

func validateClientKey(data []byte, leaf *x509.Certificate) error {
	data = bytes.TrimSpace(data)
	if !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
		return errors.New("private key must be PEM")
	}
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("private-key file must contain exactly one PEM private key")
	}
	defer clear(block.Bytes)
	switch block.Type {
	case "RSA PRIVATE KEY", "EC PRIVATE KEY":
		if x509.IsEncryptedPEMBlock(block) {
			// OpenConnect's TLS implementation owns legacy PEM decryption and matching.
			if len(block.Headers) != 2 || block.Headers["Proc-Type"] != "4,ENCRYPTED" || len(block.Bytes) == 0 {
				return errors.New("invalid encrypted private-key PEM")
			}
			return nil
		}
	case "PRIVATE KEY":
	case "ENCRYPTED PRIVATE KEY":
		// Encrypted PKCS#8 is validated as an ASN.1 EncryptedPrivateKeyInfo envelope;
		// cryptography and cert/key matching remain the TLS implementation's job.
		var encrypted struct {
			Algorithm pkix.AlgorithmIdentifier
			Data      []byte
		}
		tail, err := asn1.Unmarshal(block.Bytes, &encrypted)
		if err != nil || len(tail) != 0 || len(encrypted.Algorithm.Algorithm) == 0 || len(encrypted.Data) == 0 || len(block.Headers) != 0 {
			return errors.New("invalid encrypted PKCS#8 private key")
		}
		return nil
	default:
		return errors.New("private key must be RSA, EC or PKCS#8 PEM; choose the explicit PKCS#12 or PKCS#11 format for other identities")
	}
	if len(block.Headers) != 0 {
		return errors.New("unsupported private-key PEM headers")
	}
	var key any
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	signer, ok := key.(crypto.Signer)
	if err != nil || !ok {
		return errors.New("invalid or unsupported client private key")
	}
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(pub, leaf.RawSubjectPublicKeyInfo) {
		return errors.New("client certificate does not match its private key")
	}
	return nil
}
