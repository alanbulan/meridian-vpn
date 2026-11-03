package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestINIPreviewRedactsAllInput(t *testing.T) {
	data := []byte("\xef\xbb\xbf[private-name]\r\nGateway=https://private.example\r\nPassword=private-secret\r\nunknown-secret-name=private-unknown\n")
	r, err := PreviewINI(data)
	if err != nil {
		t.Fatal(err)
	}
	if r.Sections != 1 || r.Entries != 3 || r.CredentialFields != 1 || r.UnknownFields != 2 || !r.ReadOnly || r.VendorCompatibilityVerified {
		t.Fatalf("unexpected result: %+v", r)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "private") {
		t.Fatal("private data leaked")
	}
}
func TestINIPreviewRejectsAmbiguityAndOversize(t *testing.T) {
	for _, s := range []string{"", "[x]\n", "[x]\na=1\nA=2", "[x]\na=1\n[X]\nb=2", "[x]trailing\na=1", "=x", "missing-equals", "a=\x00secret", "a=\xff", "a=" + strings.Repeat("x", 16385), strings.Repeat("x", maxConfigBytes+1)} {
		if _, err := PreviewINI([]byte(s)); err == nil {
			t.Fatalf("accepted invalid input of length %d", len(s))
		} else if strings.Contains(err.Error(), "secret") {
			t.Fatal("error leaks input")
		}
	}
}
func TestINIPreviewNoExpansion(t *testing.T) {
	r, err := PreviewINI([]byte("a=$(touch /tmp/no)\nb=${PASSWORD}\nc=https://example.invalid/\nd=first=second\n"))
	if err != nil || r.Entries != 4 {
		t.Fatalf("%+v %v", r, err)
	}
}
func TestINIPreviewFileReadOnlyAndRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private.ini")
	data := []byte("[x]\npassword=secret\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := PreviewINIFile(path); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(data) {
		t.Fatal("modified source")
	}
	link := filepath.Join(dir, "link.ini")
	if os.Symlink(path, link) == nil {
		if _, err := PreviewINIFile(link); err == nil {
			t.Fatal("accepted symlink")
		}
	}
	if _, err := PreviewINIFile(dir); err == nil {
		t.Fatal("accepted directory")
	}
}
