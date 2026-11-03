//go:build linux

package nmvpn

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testing.T.TempDir does not promise mode 0700 for its returned leaf directory.
// Establish the production precondition instead of weakening journal validation.
func privateJournalDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func journalFixture() Record {
	return Record{Version: 1, Phase: "intent", Identity: Identity{
		BootID: "01234567-89ab-4cde-8fab-0123456789ab", BusID: "abcdef0123456789abcdef0123456789", Owner: ":1.42",
		UUID:       "12345678-9abc-4def-8abc-123456789abc",
		ActivePath: "/org/freedesktop/NetworkManager/ActiveConnection/7",
		Session:    "0123456789abcdef0123456789abcdef", Interface: "meridian0",
	}}
}

func TestFileJournalRoundTripAndLifecycleLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	j, err := NewFileJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if r, err := j.Load(); err != nil || r != nil {
		t.Fatal("missing journal", r, err)
	}
	if second, err := NewFileJournal(dir); err == nil {
		second.Close()
		t.Fatal("second lifecycle owner admitted")
	}
	want := journalFixture()
	if err = j.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := j.Load()
	if err != nil || got == nil || *got != want {
		t.Fatal("roundtrip", got, err)
	}
	info, err := os.Stat(filepath.Join(dir, journalName))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("journal permissions", err)
	}
	want.Phase = "published"
	if err = j.Save(want); err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = j.Load(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("closed load", err)
	}
	if err = j.Save(want); !errors.Is(err, os.ErrClosed) {
		t.Fatal("closed save", err)
	}
	if err = j.Clear(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("closed clear", err)
	}
	if err = j.Close(); err != nil {
		t.Fatal("close not idempotent", err)
	}
	reopened, err := NewFileJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err = reopened.Load()
	if err != nil || got == nil || *got != want {
		t.Fatal("persistence", got, err)
	}
	if err = reopened.Clear(); err != nil {
		t.Fatal(err)
	}
	if err = reopened.Clear(); err != nil {
		t.Fatal(err)
	}
	if got, err = reopened.Load(); err != nil || got != nil {
		t.Fatal("clear", got, err)
	}
}

func TestFileJournalRejectsUnsafeDirectories(t *testing.T) {
	root := t.TempDir()
	unsafe := filepath.Join(root, "public")
	if err := os.Mkdir(unsafe, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(unsafe, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative", "/", unsafe, link, filepath.Join(link, "child"), root + "/../" + filepath.Base(root)} {
		j, err := NewFileJournal(path)
		if err == nil {
			j.Close()
			t.Fatalf("accepted unsafe path %q", path)
		}
	}
}

func TestFileJournalRejectsCorruptionWithoutRemoving(t *testing.T) {
	dir := privateJournalDir(t)
	j, err := NewFileJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	for _, data := range []string{"", "null", "{}", "{", `{"unexpected":true}`, `{"Version":1,"Version":2}`, `{} {}`, strings.Repeat("x", journalLimit+1)} {
		path := filepath.Join(dir, journalName)
		if err = os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = j.Load(); err == nil {
			t.Fatalf("accepted corrupt journal %q", data[:min(len(data), 80)])
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != data {
			t.Fatal("corrupt evidence changed", err)
		}
	}
}

func TestFileJournalRejectsUnsafeFiles(t *testing.T) {
	dir := privateJournalDir(t)
	j, err := NewFileJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	target := filepath.Join(t.TempDir(), "target")
	if err = os.WriteFile(target, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, journalName)
	if err = os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err = j.Load(); err == nil {
		t.Fatal("followed symlink")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Link(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err = j.Load(); err == nil {
		t.Fatal("accepted hardlink")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = j.Load(); err == nil {
		t.Fatal("accepted public journal")
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "untouched" {
		t.Fatal("target changed", err)
	}
}

func TestFileJournalRejectsInvalidSave(t *testing.T) {
	j, err := NewFileJournal(privateJournalDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err = j.Save(Record{}); err == nil {
		t.Fatal("saved invalid record")
	}
	if r, err := j.Load(); err != nil || r != nil {
		t.Fatal("invalid save created record", r, err)
	}
}

func TestFileJournalRejectsUnsafeLock(t *testing.T) {
	for _, kind := range []string{"symlink", "public"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateJournalDir(t)
			path := filepath.Join(dir, ".journal.lock")
			if kind == "symlink" {
				if err := os.Symlink(filepath.Join(dir, "target"), path); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(path, nil, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if j, err := NewFileJournal(dir); err == nil {
				j.Close()
				t.Fatal("accepted unsafe lifecycle lock")
			}
		})
	}
}

func TestFileJournalRejectsUnstableAncestor(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "writable")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	if j, err := NewFileJournal(filepath.Join(parent, "private")); err == nil {
		j.Close()
		t.Fatal("accepted writable non-sticky ancestor")
	}
}

func TestFileJournalRejectsDecoderKeyAliases(t *testing.T) {
	dir := privateJournalDir(t)
	j, err := NewFileJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	data, err := json.Marshal(journalFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"version", "Verſion", "VERSION"} {
		bad := strings.Replace(string(data), `"Version":1`, `"Version":1,"`+alias+`":1`, 1)
		if err := os.WriteFile(filepath.Join(dir, journalName), []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := j.Load(); err == nil {
			t.Fatalf("accepted alias %q", alias)
		}
	}
}
