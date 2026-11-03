package core

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"
)

// INIPreview is deliberately structural: no vendor schema is assumed and no
// values, names, credentials, or untrusted key strings leave the parser.
type INIPreview struct {
	SchemaVersion               int  `json:"schema_version"`
	ReadOnly                    bool `json:"read_only"`
	VendorCompatibilityVerified bool `json:"vendor_compatibility_verified"`
	Sections                    int  `json:"sections"`
	Entries                     int  `json:"entries"`
	CredentialFields            int  `json:"credential_fields"`
	UnknownFields               int  `json:"unknown_fields"`
}

// PreviewINI parses bounded UTF-8 INI without interpolation, expansion, fetching,
// decoding encrypted values, or inferring gateway protocols. Duplicate keys and
// sections fail closed because silently picking one can change network intent.
func PreviewINI(data []byte) (INIPreview, error) {
	r := INIPreview{SchemaVersion: 1, ReadOnly: true}
	invalid := func() (INIPreview, error) {
		return INIPreview{}, errors.New("INI input is invalid, ambiguous, or exceeds supported limits")
	}
	if len(data) > maxConfigBytes || !utf8.Valid(data) {
		return invalid()
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	section := ""
	sections := map[string]bool{}
	keys := map[string]bool{}
	for _, raw := range strings.Split(string(data), "\n") {
		if len(raw) > 16384 {
			return invalid()
		}
		line := strings.TrimSpace(raw)
		if strings.ContainsFunc(line, func(r rune) bool { return unicode.IsControl(r) && r != '\t' }) {
			return invalid()
		}
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") || strings.Count(line, "[") != 1 || strings.Count(line, "]") != 1 {
				return invalid()
			}
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "" || sections[section] || len(sections) >= MaxProfiles {
				return invalid()
			}
			sections[section] = true
			r.Sections++
			continue
		}
		key, _, ok := strings.Cut(line, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if !ok || key == "" || strings.ContainsAny(key, "[]") || r.Entries >= 4096 {
			return invalid()
		}
		identity := section + "\x00" + key
		if keys[identity] {
			return invalid()
		}
		keys[identity] = true
		r.Entries++
		// This count is advisory, not a claim to detect all secrets. All values and
		// unknown names remain undisclosed regardless of how their key is spelled.
		switch key {
		case "password", "passwd", "pwd", "psk", "cookie", "token", "pin", "secret", "privatekey", "private_key":
			r.CredentialFields++
		default:
			r.UnknownFields++
		}
	}
	if r.Entries == 0 {
		return invalid()
	}
	return r, nil
}

// PreviewINIFile reads only a regular, bounded file. On Linux the descriptor
// rejects symlinks and cannot block on a concurrently substituted FIFO.
func PreviewINIFile(path string) (INIPreview, error) {
	fail := func() (INIPreview, error) {
		return INIPreview{}, errors.New("INI file cannot be safely read or parsed")
	}
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxConfigBytes {
		return fail()
	}
	f, err := openCAFile(path)
	if err != nil {
		return fail()
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !actual.Mode().IsRegular() || !os.SameFile(st, actual) {
		return fail()
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return fail()
	}
	return PreviewINI(data)
}
