//go:build linux

package autostart

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// Every filesystem mutation is under t.TempDir. No test starts Meridian or a
// desktop session, or touches the actual user's config/autostart directory.
func fixture(t *testing.T) (*Manager, string, string) {
	t.Helper()
	root := t.TempDir()
	exe := filepath.Join(root, "meridian")
	if err := os.WriteFile(exe, []byte("not an executable program; never run by tests"), 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "config")
	m, err := New(Options{ConfigDir: config, Executable: exe})
	if err != nil {
		t.Fatal(err)
	}
	return m, config, exe
}

func registrationPath(config string) string { return filepath.Join(config, "autostart", FileName) }

func TestReadOnlyAndLifecycle(t *testing.T) {
	m, config, exe := fixture(t)
	s, err := m.Status()
	if err != nil || !s.Supported || s.Enabled || s.Path != registrationPath(config) || s.Executable != exe {
		t.Fatalf("initial state: %+v %v", s, err)
	}
	preview, err := m.Preview()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Disable(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(config); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only operations created config: %v", err)
	}
	if err := m.Enable(); err != nil {
		t.Fatal(err)
	}
	if err := m.Enable(); err != nil {
		t.Fatalf("repeat enable: %v", err)
	}
	s, err = m.Status()
	if err != nil || !s.Enabled || s.RegisteredExecutable != exe {
		t.Fatalf("enabled state: %+v %v", s, err)
	}
	content, err := os.ReadFile(s.Path)
	if err != nil || !bytes.Equal(preview, content) {
		t.Fatalf("content differs from confirmed preview: %q %v", content, err)
	}
	info, err := os.Stat(s.Path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("entry permissions: %v %v", info, err)
	}
	for _, path := range []string{config, filepath.Dir(s.Path)} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatalf("directory permissions: %v %v", info, err)
		}
	}
	other := filepath.Join(filepath.Dir(s.Path), "other.desktop")
	if err := os.WriteFile(other, []byte("unrelated"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Disable(); err != nil {
		t.Fatal(err)
	}
	if err := m.Disable(); err != nil {
		t.Fatalf("repeat disable: %v", err)
	}
	if _, err := os.Stat(s.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("entry remains: %v", err)
	}
	if data, err := os.ReadFile(other); err != nil || string(data) != "unrelated" {
		t.Fatalf("modified unrelated entry: %q %v", data, err)
	}
}

func TestXDGDefaultsReadOnly(t *testing.T) {
	_, config, exe := fixture(t)
	t.Setenv("HOME", filepath.Dir(config))
	t.Setenv("XDG_CONFIG_HOME", config)
	m, err := New(Options{Executable: exe})
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.Status()
	if err != nil || s.Path != registrationPath(config) {
		t.Fatalf("XDG target: %+v %v", s, err)
	}
	if _, err := os.Stat(config); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created XDG config: %v", err)
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	m, err = New(Options{Executable: exe})
	if err != nil {
		t.Fatal(err)
	}
	s, err = m.Status()
	want := filepath.Join(filepath.Dir(config), ".config", "autostart", FileName)
	if err != nil || s.Path != want {
		t.Fatalf("HOME fallback: %+v %v", s, err)
	}
}

func TestDesktopExecEscapingAndNoArguments(t *testing.T) {
	exe := "/opt/Meridian app/percent%f quote\" slash\\ dollar$ back` apostrophe' semi;and&"
	content, err := desktopEntry(exe)
	if err != nil {
		t.Fatal(err)
	}
	want := `Exec="/opt/Meridian app/percent%%f quote\\" slash\\\\ dollar\\$ back\\` + "`" + ` apostrophe' semi;and&"`
	found := ""
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, "Exec=") {
			found = line
		}
	}
	if found != want {
		t.Fatalf("Exec escaping\ngot:  %s\nwant: %s", found, want)
	}
	parsed, err := ownedExecutable(content)
	if err != nil || parsed != exe {
		t.Fatalf("owned executable: %q %v", parsed, err)
	}
	for _, forbidden := range []string{"--config", "--connect", "--password", "/bin/sh", "/bin/bash", "TryExec=", "Hidden=", "DBusActivatable="} {
		if strings.Contains(string(content), forbidden) {
			t.Fatalf("unexpected argument or action: %q", forbidden)
		}
	}
}

func TestRejectUnsafeExecutableStrings(t *testing.T) {
	for _, path := range []string{"relative", "/tmp/../tmp/app", "/tmp/a=b", "/tmp/a\nb", "/tmp/a\rb", "/tmp/a\x00b", "/tmp/a\tb", "/tmp/a\x7fb", "/tmp/a\u0085b", string([]byte{'/', 'x', 0xff})} {
		if _, err := desktopEntry(path); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("accepted %q: %v", path, err)
		}
	}
}

func TestRejectInvalidConfigAndExecutables(t *testing.T) {
	_, config, exe := fixture(t)
	for _, path := range []string{"relative", "/tmp/injected\nExec=evil"} {
		if _, err := New(Options{ConfigDir: path, Executable: exe}); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("config %q: %v", path, err)
		}
	}
	for _, path := range []string{"relative", filepath.Join(config, "missing"), filepath.Dir(exe)} {
		if _, err := New(Options{ConfigDir: config, Executable: path}); err == nil {
			t.Errorf("accepted executable %q", path)
		}
	}
	if err := os.Chmod(exe, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{ConfigDir: config, Executable: exe}); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("nonexecutable: %v", err)
	}
	if err := os.Chmod(exe, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{ConfigDir: config, Executable: exe}); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("writable executable: %v", err)
	}
}

func TestExecutableSymlinkResolvedAndRechecked(t *testing.T) {
	m, config, exe := fixture(t)
	alias := exe + "-link"
	if err := os.Symlink(exe, alias); err != nil {
		t.Fatal(err)
	}
	m, err := New(Options{ConfigDir: config, Executable: alias})
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.Status()
	if err != nil || s.Executable != exe {
		t.Fatalf("did not resolve executable: %+v %v", s, err)
	}
	if err := os.Remove(exe); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(alias, exe); err != nil {
		t.Fatal(err)
	}
	if err := m.Enable(); err == nil {
		t.Fatal("accepted executable changed to a symlink")
	}
	if _, err := os.Stat(config); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mutation on invalid executable: %v", err)
	}
}

func TestForeignAndEditedEntriesPreserved(t *testing.T) {
	variants := map[string]func([]byte) []byte{
		"foreign":     func([]byte) []byte { return []byte("[Desktop Entry]\nExec=/bin/other\n") },
		"marker-only": func([]byte) []byte { return []byte(ownerMarker + "\nExec=/bin/other\n") },
		"extra-arg": func(b []byte) []byte {
			return bytes.Replace(b, []byte("\nTerminal="), []byte(" --connect secret\nTerminal="), 1)
		},
		"hidden":           func(b []byte) []byte { return append(b, []byte("Hidden=true\n")...) },
		"duplicate-owner":  func(b []byte) []byte { return append(b, []byte(ownerMarker+"\n")...) },
		"oversized":        func(b []byte) []byte { return append(b, bytes.Repeat([]byte("x"), maxEntrySize)...) },
		"malformed-marker": func(b []byte) []byte { return bytes.Replace(b, []byte(executableKey), []byte(executableKey+"!"), 1) },
	}
	for name, transform := range variants {
		t.Run(name, func(t *testing.T) {
			m, config, _ := fixture(t)
			content, err := m.Preview()
			if err != nil {
				t.Fatal(err)
			}
			content = transform(content)
			path := registrationPath(config)
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, content, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Status(); !errors.Is(err, ErrForeignEntry) {
				t.Fatalf("status: %v", err)
			}
			if err := m.Enable(); !errors.Is(err, ErrForeignEntry) {
				t.Fatalf("enable: %v", err)
			}
			if err := m.Disable(); !errors.Is(err, ErrForeignEntry) {
				t.Fatalf("disable: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, content) {
				t.Fatalf("modified conflict: %v", err)
			}
		})
	}
}

func TestForeignFileTypesPreserved(t *testing.T) {
	for _, kind := range []string{"symlink", "dangling-symlink", "directory", "fifo", "hardlink", "group-write"} {
		t.Run(kind, func(t *testing.T) {
			m, config, exe := fixture(t)
			path := registrationPath(config)
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			content, err := m.Preview()
			if err != nil {
				t.Fatal(err)
			}
			external := filepath.Join(filepath.Dir(exe), "external")
			if err := os.WriteFile(external, content, 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				err = os.Symlink(external, path)
			case "dangling-symlink":
				err = os.Symlink(external+"missing", path)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "fifo":
				err = syscall.Mkfifo(path, 0600)
			case "hardlink":
				err = os.Link(external, path)
			case "group-write":
				err = os.WriteFile(path, content, 0660)
			}
			if err != nil {
				t.Fatal(err)
			}
			if kind == "group-write" {
				if err := os.Chmod(path, 0660); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.Status(); !errors.Is(err, ErrForeignEntry) {
				t.Fatalf("status: %v", err)
			}
			if err := m.Enable(); !errors.Is(err, ErrForeignEntry) {
				t.Fatalf("enable: %v", err)
			}
			if err := m.Disable(); !errors.Is(err, ErrForeignEntry) {
				t.Fatalf("disable: %v", err)
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("changed unsafe entry: %v", err)
			}
			actual, err := os.ReadFile(external)
			if err != nil || !bytes.Equal(actual, content) {
				t.Fatalf("changed external file: %v", err)
			}
		})
	}
}

func TestUnsafeDirectoriesRejected(t *testing.T) {
	for _, kind := range []string{"config-symlink", "autostart-symlink", "config-group-write", "autostart-world-write", "ancestor-symlink", "ancestor-world-write"} {
		t.Run(kind, func(t *testing.T) {
			m, config, exe := fixture(t)
			outside := filepath.Join(filepath.Dir(exe), "outside")
			if err := os.Mkdir(outside, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(config, "autostart"), 0700); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "config-symlink":
				if err := os.RemoveAll(config); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, config); err != nil {
					t.Fatal(err)
				}
			case "autostart-symlink":
				p := filepath.Join(config, "autostart")
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, p); err != nil {
					t.Fatal(err)
				}
			case "config-group-write":
				if err := os.Chmod(config, 0770); err != nil {
					t.Fatal(err)
				}
			case "autostart-world-write":
				if err := os.Chmod(filepath.Join(config, "autostart"), 0777); err != nil {
					t.Fatal(err)
				}
			case "ancestor-symlink":
				p := filepath.Join(filepath.Dir(exe), "link")
				if err := os.Symlink(config, p); err != nil {
					t.Fatal(err)
				}
				m.configDir = filepath.Join(p, "nested")
			case "ancestor-world-write":
				if err := os.Chmod(config, 0777); err != nil {
					t.Fatal(err)
				}
				m.configDir = filepath.Join(config, "nested")
			}
			if _, err := m.Status(); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("status: %v", err)
			}
			if err := m.Enable(); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("enable: %v", err)
			}
			if err := m.Disable(); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("disable: %v", err)
			}
			entries, err := os.ReadDir(outside)
			if err != nil || len(entries) != 0 {
				t.Fatalf("outside path changed: %v %v", entries, err)
			}
		})
	}
}

func TestDifferentExecutableRequiresDisable(t *testing.T) {
	m, config, exe := fixture(t)
	if err := m.Enable(); err != nil {
		t.Fatal(err)
	}
	exe2 := exe + "2"
	if err := os.WriteFile(exe2, []byte("never run"), 0700); err != nil {
		t.Fatal(err)
	}
	n, err := New(Options{ConfigDir: config, Executable: exe2})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Enable(); !errors.Is(err, ErrDifferentExecutable) {
		t.Fatalf("replaced old installation: %v", err)
	}
	s, err := n.Status()
	if err != nil || !s.Enabled || s.Executable != exe2 || s.RegisteredExecutable != exe {
		t.Fatalf("wrong installed state: %+v %v", s, err)
	}
	if err := os.Remove(exe); err != nil {
		t.Fatal(err)
	}
	if err := n.Disable(); err != nil {
		t.Fatalf("cannot remove stale owned installation: %v", err)
	}
	if err := n.Enable(); err != nil {
		t.Fatal(err)
	}
	s, err = n.Status()
	if err != nil || s.RegisteredExecutable != exe2 {
		t.Fatalf("new installation: %+v %v", s, err)
	}
}

func TestConcurrentManagersPublishOnlyCompleteEntries(t *testing.T) {
	m, config, exe := fixture(t)
	const count = 20
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := New(Options{ConfigDir: config, Executable: exe})
			if err == nil {
				err = n.Enable()
			}
			if err == nil {
				_, err = n.Status()
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil && !errors.Is(err, ErrBusy) {
			t.Error(err)
		}
	}
	s, err := m.Status()
	if err != nil || !s.Enabled {
		t.Fatalf("final state: %+v %v", s, err)
	}
	entries, err := os.ReadDir(filepath.Dir(registrationPath(config)))
	if err != nil || len(entries) != 1 || entries[0].Name() != FileName {
		t.Fatalf("left temporary files: %+v %v", entries, err)
	}
}

func TestAtomicPublishNeverReplacesExistingDestination(t *testing.T) {
	root := t.TempDir()
	f, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.WriteFile(filepath.Join(root, "temp"), []byte("ours"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, FileName), []byte("theirs"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := linkAt(int(f.Fd()), "temp", FileName); !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("link unexpectedly succeeded: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(root, FileName))
	if err != nil || string(content) != "theirs" {
		t.Fatalf("overwrote existing file: %q %v", content, err)
	}
}

func TestDirectoryLockNeverBlocksStatusOrMutation(t *testing.T) {
	m, config, _ := fixture(t)
	if err := os.MkdirAll(filepath.Join(config, "autostart"), 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(filepath.Join(config, "autostart"))
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := syscall.Flock(int(dir.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Status(); !errors.Is(err, ErrBusy) {
		t.Fatalf("status did not report busy: %v", err)
	}
	if err := m.Enable(); !errors.Is(err, ErrBusy) {
		t.Fatalf("enable did not report busy: %v", err)
	}
	if err := m.Disable(); !errors.Is(err, ErrBusy) {
		t.Fatalf("disable did not report busy: %v", err)
	}
	if _, err := os.Stat(registrationPath(config)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created entry while locked: %v", err)
	}
}

func TestExecutableUnsafeAncestorRejected(t *testing.T) {
	m, config, exe := fixture(t)
	parent := filepath.Join(filepath.Dir(exe), "unsafe")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(parent, "meridian")
	if err := os.Rename(exe, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{ConfigDir: config, Executable: moved}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("accepted writable executable parent: %v", err)
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	m, err := New(Options{ConfigDir: config, Executable: moved})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(parent, parent+"-moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(parent+"-moved", parent); err != nil {
		t.Fatal(err)
	}
	if err := m.Enable(); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("followed replacement executable parent: %v", err)
	}
	if _, err := os.Stat(config); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created config after executable failure: %v", err)
	}
}

// Optional independent parser check. The supplied binary validates the file;
// it never launches the Exec target or registers desktop autostart.
func TestDesktopFileValidatorWhenRequested(t *testing.T) {
	validator := os.Getenv("MERIDIAN_DESKTOP_FILE_VALIDATE")
	if validator == "" {
		t.Skip("set MERIDIAN_DESKTOP_FILE_VALIDATE to an installed desktop-file-validate binary for an independent parser check")
	}
	if !filepath.IsAbs(validator) {
		t.Fatal("validator path must be absolute")
	}
	root := t.TempDir()
	executable := filepath.Join(root, "Meridian spaces percent%f dollar$ quote\" slash\\ tick` apostrophe' amp& semi;")
	if err := os.WriteFile(executable, []byte("never run"), 0700); err != nil {
		t.Fatal(err)
	}
	m, err := New(Options{ConfigDir: filepath.Join(root, "config"), Executable: executable})
	if err != nil {
		t.Fatal(err)
	}
	content, err := m.Preview()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, FileName)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(validator, path).CombinedOutput(); err != nil {
		t.Fatalf("desktop-file-validate failed: %v\n%s\n%s", err, output, content)
	}
}
