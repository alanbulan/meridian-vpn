package core

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

// CertificateFormat is explicit: a PKCS#12 bundle must not be mistaken for a
// public certificate and opened with less restrictive permissions.
func validateCertificateReferences(p Profile) error {
	switch p.CertificateFormat {
	case "", "pem":
		if (p.ClientCertificate == "") != (p.ClientKey == "") {
			return errors.New("client certificate and private key must both be configured")
		}
	case "pkcs12":
		if p.ClientCertificate == "" || p.ClientKey != "" {
			return errors.New("PKCS#12 requires one bundle path and no separate private key")
		}
	case "pkcs11":
		if err := validatePKCS11URI(p.ClientCertificate, "cert"); err != nil {
			return err
		}
		if p.ClientKey != "" {
			return validatePKCS11URI(p.ClientKey, "private")
		}
		return nil
	default:
		return errors.New("unsupported client certificate format")
	}
	for _, path := range []string{p.ClientCertificate, p.ClientKey} {
		if path != "" && (!filepath.IsAbs(path) || len(path) > 4096 || hasControl(path) || !utf8.ValidString(path)) {
			return errors.New("client certificate and private key must use absolute paths without control characters")
		}
	}
	return nil
}

// Deliberately narrower than RFC 7512: no PINs, PIN sources, module loading,
// query parameters or vendor extensions may be persisted in a profile. Module
// configuration belongs to the user's installed PKCS#11 provider, not profiles.
func validatePKCS11URI(uri, objectType string) error {
	bad := errors.New("PKCS#11 requires a non-secret object URI; PIN, module, query and unknown attributes are prohibited")
	if !strings.HasPrefix(uri, "pkcs11:") || len(uri) > 4096 || strings.ContainsAny(uri, "?#") {
		return bad
	}
	seen := map[string]bool{}
	identified := false
	for _, attr := range strings.Split(strings.TrimPrefix(uri, "pkcs11:"), ";") {
		k, v, ok := strings.Cut(attr, "=")
		if !ok || seen[k] || v == "" {
			return bad
		}
		seen[k] = true
		switch k {
		case "token", "manufacturer", "serial", "model", "object", "id", "type", "object-type", "library-manufacturer", "library-description", "library-version", "slot-manufacturer", "slot-description", "slot-id":
		default:
			return bad
		}
		// Require URI-safe ASCII, with every other byte percent encoded. This also
		// prevents config-file injection and avoids double-decoding ambiguity.
		for i := 0; i < len(v); i++ {
			c := v[i]
			if c == '%' {
				if i+2 >= len(v) {
					return bad
				}
				if _, e := strconv.ParseUint(v[i+1:i+3], 16, 8); e != nil {
					return bad
				}
				i += 2
				continue
			}
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", rune(c))) {
				return bad
			}
		}
		decoded, e := url.PathUnescape(v)
		if e != nil {
			return bad
		}
		if k != "id" && (!utf8.ValidString(decoded) || hasControl(decoded)) {
			return bad
		}
		if k == "object" || k == "id" {
			identified = true
		}
		if (k == "type" || k == "object-type") && decoded != objectType {
			return bad
		}
	}
	if !identified || seen["type"] && seen["object-type"] {
		return bad
	}
	return nil
}

// Check the PFX envelope only. The TLS backend owns MAC verification,
// decryption, certificate validity, chain loading and private-key matching.
// Never decode keys into plaintext files or persist the bundle's password.
type pfxContentInfo struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"explicit,tag:0"`
}
type pfxMACData struct {
	DigestInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		Digest    []byte
	}
	Salt       []byte
	Iterations int `asn1:"optional,default:1"`
}
type pfxEnvelope struct {
	Version  int
	AuthSafe pfxContentInfo
	MAC      pfxMACData
}

func validatePKCS12Envelope(data []byte) error {
	var pfx pfxEnvelope
	rest, err := asn1.Unmarshal(data, &pfx)
	bad := errors.New("invalid or unsupported PKCS#12 PFX envelope; password integrity MAC is required")
	if err != nil || len(rest) != 0 || pfx.Version != 3 || !pfx.AuthSafe.Type.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}) || len(pfx.AuthSafe.Content.Bytes) == 0 {
		return bad
	}
	if len(pfx.MAC.DigestInfo.Algorithm.Algorithm) == 0 || len(pfx.MAC.DigestInfo.Digest) == 0 || len(pfx.MAC.Salt) == 0 || pfx.MAC.Iterations < 1 {
		return bad
	}
	var octets []byte
	rest, err = asn1.Unmarshal(pfx.AuthSafe.Content.Bytes, &octets)
	if err != nil || len(rest) != 0 || len(octets) == 0 {
		return bad
	}
	return nil
}
