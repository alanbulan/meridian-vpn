//go:build linux

package nmvpn

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func activationJournalFixture() ActivationRecord {
	return ActivationRecord{Version: 1, BootID: "01234567-89ab-4cde-8fab-0123456789ab", BusID: "abcdef0123456789abcdef0123456789", Owner: ":1.42", PluginOwner: ":1.43", UUID: "12345678-9abc-4def-8abc-123456789abc", Interface: "meridian0", Nonce: "0123456789abcdef0123456789abcdef", Phase: "add-intent"}
}

func TestActivationFileJournalDurablePhasesAndLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	j, err := NewFileActivationJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if r, err := j.LoadActivation(); err != nil || r != nil {
		t.Fatal("missing", r, err)
	}
	if other, err := NewFileActivationJournal(dir); err == nil {
		other.Close()
		t.Fatal("second activation manager acquired lifecycle lock")
	}
	if other, err := NewFileJournal(dir); err == nil {
		other.Close()
		t.Fatal("publication controller shared lifecycle lock")
	}
	want := activationJournalFixture()
	for _, phase := range []string{"add-intent", "added", "activate-intent", "activated", "correlated", "quarantine"} {
		want.Phase = phase
		if phase == "added" {
			want.ConnectionPath = "/org/freedesktop/NetworkManager/Settings/17"
		}
		if phase == "activated" {
			want.ActivePath = "/org/freedesktop/NetworkManager/ActiveConnection/23"
		}
		if err := j.SaveActivation(want); err != nil {
			t.Fatal(phase, err)
		}
		got, err := j.LoadActivation()
		if err != nil || got == nil || *got != want {
			t.Fatal("phase roundtrip", phase, got, err)
		}
	}
	info, err := os.Stat(filepath.Join(dir, journalName))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("permissions", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, journalName))
	if err != nil || strings.Contains(string(data), "password") || strings.Contains(string(data), "Username") {
		t.Fatal("unexpected secret-bearing journal", err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := j.LoadActivation(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("closed load", err)
	}
	if err := j.SaveActivation(want); !errors.Is(err, os.ErrClosed) {
		t.Fatal("closed save", err)
	}
	if err := j.Close(); err != nil {
		t.Fatal("non-idempotent close", err)
	}
	j, err = NewFileActivationJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	got, err := j.LoadActivation()
	if err != nil || got == nil || *got != want {
		t.Fatal("restart lost evidence", got, err)
	}
}

func TestActivationFileJournalRejectsCorruptionWithoutChangingEvidence(t *testing.T) {
	dir := privateJournalDir(t)
	j, err := NewFileActivationJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	data, err := json.Marshal(activationJournalFixture())
	if err != nil {
		t.Fatal(err)
	}
	valid := string(data)
	cases := []string{"", "null", "{}", "[]", "{", valid + " {}", strings.Repeat("x", journalLimit+1), strings.Replace(valid, `"Version":1`, `"Version":1,"Version":1`, 1), strings.Replace(valid, `"Nonce":`, `"nonce":`, 1), strings.Replace(valid, `"Version":`, `"Verſion":`, 1), strings.Replace(valid, `"Phase":"add-intent"`, `"Phase":null`, 1), strings.Replace(valid, `"ActivePath":"",`, "", 1), strings.Replace(valid, `"ActivePath":""`, `"ActivePath":[]`, 1), strings.Replace(valid, `"ActivePath":""`, `"ActivePath":"/org/freedesktop/NetworkManager/ActiveConnection/1"`, 1)}
	for i, bad := range cases {
		path := filepath.Join(dir, journalName)
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := j.LoadActivation(); err == nil {
			t.Fatalf("accepted corruption case %d", i)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != bad {
			t.Fatal("corrupt evidence changed", i, err)
		}
	}
}

func TestActivationFileJournalRejectsUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "public", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateJournalDir(t)
			j, err := NewFileActivationJournal(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			target := filepath.Join(t.TempDir(), "untouched")
			if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, journalName)
			switch kind {
			case "symlink":
				err = os.Symlink(target, path)
			case "hardlink":
				err = os.Link(target, path)
			case "public":
				err = os.WriteFile(path, []byte("{}"), 0644)
			case "fifo":
				err = syscall.Mkfifo(path, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := j.LoadActivation(); err == nil {
				t.Fatal("accepted unsafe file")
			}
			got, err := os.ReadFile(target)
			if err != nil || string(got) != "untouched" {
				t.Fatal("modified target", err)
			}
		})
	}
}

func TestActivationFileJournalRejectsOtherSchema(t *testing.T) {
	dir := privateJournalDir(t)
	publication, err := NewFileJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := publication.Save(journalFixture()); err != nil {
		t.Fatal(err)
	}
	if err := publication.Close(); err != nil {
		t.Fatal(err)
	}
	activation, err := NewFileActivationJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := activation.LoadActivation(); err == nil {
		t.Fatal("publication evidence treated as activation record")
	}
	if err := activation.Close(); err != nil {
		t.Fatal(err)
	}
	otherDir := privateJournalDir(t)
	activation, err = NewFileActivationJournal(otherDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := activation.SaveActivation(activationJournalFixture()); err != nil {
		t.Fatal(err)
	}
	if err := activation.Close(); err != nil {
		t.Fatal(err)
	}
	publication, err = NewFileJournal(otherDir)
	if err != nil {
		t.Fatal(err)
	}
	defer publication.Close()
	if _, err := publication.Load(); err == nil {
		t.Fatal("activation evidence treated as publication record")
	}
}

func TestActivationFileJournalRejectsInvalidSave(t *testing.T) {
	j, err := NewFileActivationJournal(privateJournalDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err := j.SaveActivation(ActivationRecord{}); err == nil {
		t.Fatal("saved invalid record")
	}
	if got, err := j.LoadActivation(); err != nil || got != nil {
		t.Fatal("invalid save created evidence", got, err)
	}
}
