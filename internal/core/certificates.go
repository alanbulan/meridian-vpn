package core

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
)

// ValidateCAFile accepts only bounded regular PEM bundles of CA certificates.
// It never accepts a private key or weakens TLS verification. Existing profiles
// remain loadable if an external file disappears; connection preflight rejects it.
func ValidateCAFile(path string) error {
	f, err := openValidatedCAFile(path)
	if f != nil {
		f.Close()
	}
	return err
}

func openValidatedCAFile(path string) (*os.File, error) {
	if path == "" {
		return nil, nil
	}
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Size() > 4<<20 {
		return nil, errors.New("CA certificate must be a regular PEM file under 4 MiB, not writable by other users")
	}
	f, e := openCAFile(path)
	if e != nil {
		return nil, errors.New("CA certificate file cannot be opened")
	}
	success := false
	defer func() {
		if !success {
			f.Close()
		}
	}()
	initial := st
	st, e = f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > 4<<20 || st.Mode().Perm()&0022 != 0 || !os.SameFile(initial, st) {
		return nil, errors.New("CA certificate must be a regular PEM file under 4 MiB, not writable by other users")
	}
	data, e := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if e != nil || len(data) > 4<<20 {
		return nil, errors.New("CA certificate file cannot be read")
	}
	count := 0
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("CA file must contain only PEM certificates")
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("CA file must contain only PEM certificates")
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil || !cert.IsCA {
			return nil, errors.New("CA file contains an invalid or non-CA certificate")
		}
		count++
		data = rest
	}
	if count == 0 {
		return nil, errors.New("CA file contains no certificates")
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return nil, errors.New("CA certificate cannot be rewound")
	}
	success = true
	return f, nil
}
