//go:build linux

package nmvpn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func hostFileFixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}

func hostFileFixture(t *testing.T, root, name, content string, mode os.FileMode) HostFilePin {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return HostFilePin{Path: path, SHA256: hex.EncodeToString(sum[:])}
}

// Fixtures anchor only their private temp subtree, never relax the production
// root walk, alter real host configuration, or need privileged chown/mounts.
func openHostFileFixture(ctx context.Context, root string, pins ...HostFilePin) (*HostFilePins, error) {
	return openHostFilePins(ctx, pins, hostFilePolicy{root: root, uid: uint32(os.Geteuid())})
}

func TestHostFilePinsReadOnlyCopiesAndLifecycle(t *testing.T) {
	root := hostFileFixtureRoot(t)
	pin := hostFileFixture(t, root, "config", "fixture configuration\n", 0600)
	before, err := os.Stat(pin.Path)
	if err != nil {
		t.Fatal(err)
	}
	input := []HostFilePin{pin}
	s, err := openHostFileFixture(context.Background(), root, input...)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	input[0].Path = "/not-the-pinned-path"
	got, err := s.Snapshot()
	if err != nil || len(got) != 1 || got[0].Path != pin.Path || got[0].SHA256 != pin.SHA256 || got[0].Size != before.Size() || got[0].OwnerUID != uint32(os.Geteuid()) || got[0].LinkCount != 1 {
		t.Fatal("snapshot metadata", got, err)
	}
	got[0].Path = "/changed-copy"
	again, err := s.Snapshot()
	if err != nil || again[0].Path != pin.Path {
		t.Fatal("snapshot aliases retained state", err)
	}
	for i := 0; i < 3; i++ {
		if err := s.Check(context.Background()); err != nil {
			t.Fatal("unchanged check", err)
		}
	}
	for _, node := range s.files[0].nodes {
		flags, err := unix.FcntlInt(node.file.Fd(), unix.F_GETFD, 0)
		if err != nil || flags&syscall.FD_CLOEXEC == 0 {
			t.Fatal("retained descriptor lacks close-on-exec", err)
		}
		flags, err = unix.FcntlInt(node.file.Fd(), unix.F_GETFL, 0)
		if err != nil || flags&syscall.O_ACCMODE != syscall.O_RDONLY || flags&syscall.O_NONBLOCK == 0 {
			t.Fatal("retained descriptor is not nonblocking read-only", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal("second close", err)
	}
	if err := s.Check(context.Background()); !errors.Is(err, os.ErrClosed) {
		t.Fatal("closed check", err)
	}
	if _, err := s.Snapshot(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("closed snapshot", err)
	}
	after, err := os.Stat(pin.Path)
	if err != nil || !hostFileSameStat(*before.Sys().(*syscall.Stat_t), *after.Sys().(*syscall.Stat_t)) {
		t.Fatal("observer changed file metadata", err)
	}
	if before.Sys().(*syscall.Stat_t).Atim != after.Sys().(*syscall.Stat_t).Atim {
		t.Fatal("observer changed read-atime metadata")
	}
	data, err := os.ReadFile(pin.Path)
	if err != nil || string(data) != "fixture configuration\n" {
		t.Fatal("observer changed file bytes", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatal("observer created files", err)
	}
}

func TestHostFilePinsZeroAndNilFailClosed(t *testing.T) {
	for _, s := range []*HostFilePins{nil, new(HostFilePins)} {
		if err := s.Check(context.Background()); !errors.Is(err, os.ErrClosed) {
			t.Fatal(err)
		}
		if _, err := s.Snapshot(); !errors.Is(err, os.ErrClosed) {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHostFilePinsProductionRequiresRootAndTrustedAncestors(t *testing.T) {
	root := hostFileFixtureRoot(t)
	pin := hostFileFixture(t, root, "config", "safe", 0600)
	if err := os.Chmod(root, 0777); err != nil {
		t.Fatal(err)
	}
	// Production must not inherit a fixture UID override; even when tests run
	// as root, this deliberately unsafe temporary ancestor must be rejected.
	s, err := OpenHostFilePins(context.Background(), []HostFilePin{pin})
	if err == nil {
		s.Close()
		t.Fatal("production trusted fixture ancestry")
	}
	if (os.Getuid() != 0 || os.Geteuid() != 0) && !strings.Contains(err.Error(), "root") {
		t.Fatal("missing production root requirement", err)
	}
}

func TestHostFilePinsRejectsMalformedManifest(t *testing.T) {
	root := hostFileFixtureRoot(t)
	pin := hostFileFixture(t, root, "config", "safe", 0600)
	cases := map[string][]HostFilePin{
		"empty": nil,
		"duplicate": {pin, pin},
		"relative": {{Path: "config", SHA256: pin.SHA256}},
		"root": {{Path: "/", SHA256: pin.SHA256}},
		"anchor": {{Path: root, SHA256: pin.SHA256}},
		"unclean": {{Path: root + "/./config", SHA256: pin.SHA256}},
		"trailing slash": {{Path: pin.Path + "/", SHA256: pin.SHA256}},
		"outside root": {{Path: filepath.Dir(root) + "/outside", SHA256: pin.SHA256}},
		"nul": {{Path: root + "/bad\x00name", SHA256: pin.SHA256}},
		"long path": {{Path: root + "/" + strings.Repeat("x", hostFileMaxPathBytes), SHA256: pin.SHA256}},
		"deep path": {{Path: root + strings.Repeat("/d", hostFileMaxDepth+1), SHA256: pin.SHA256}},
		"missing hash": {{Path: pin.Path}},
		"invalid hex": {{Path: pin.Path, SHA256: strings.Repeat("z", 64)}},
		"short hash": {{Path: pin.Path, SHA256: "00"}},
		"long hash": {{Path: pin.Path, SHA256: strings.Repeat("0", 10000)}},
		"uppercase hash": {{Path: pin.Path, SHA256: strings.ToUpper(pin.SHA256)}},
		"wrong hash": {{Path: pin.Path, SHA256: strings.Repeat("0", 64)}},
	}
	tooMany := make([]HostFilePin, hostFileMaxFiles+1)
	for i := range tooMany {
		tooMany[i] = pin
	}
	cases["too many"] = tooMany
	for name, pins := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := openHostFileFixture(context.Background(), root, pins...)
			if err == nil {
				s.Close()
				t.Fatal("accepted malformed manifest")
			}
		})
	}
	missing := pin
	missing.Path = filepath.Join(root, "absent")
	if s, err := openHostFileFixture(context.Background(), root, missing); err == nil {
		s.Close()
		t.Fatal("accepted missing file")
	}
	if _, err := os.Stat(missing.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("created missing file", err)
	}
}

func TestHostFilePinsAcceptsRootWriterAndScriptModes(t *testing.T) {
	for _, mode := range []os.FileMode{0400, 0444, 0600, 0644, 0700, 0755} {
		t.Run(fmt.Sprintf("%o", mode), func(t *testing.T) {
			root := hostFileFixtureRoot(t)
			pin := hostFileFixture(t, root, "config-or-hook", "never executed", mode)
			s, err := openHostFileFixture(context.Background(), root, pin)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err := s.Check(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHostFilePinsRejectsUnsafeFiles(t *testing.T) {
	cases := map[string]func(*testing.T, string, HostFilePin){
		"world writable": func(t *testing.T, root string, pin HostFilePin) {
			if err := os.Chmod(pin.Path, 0602); err != nil { t.Fatal(err) }
		},
		"group writable": func(t *testing.T, root string, pin HostFilePin) {
			if err := os.Chmod(pin.Path, 0620); err != nil { t.Fatal(err) }
		},
		"setuid": func(t *testing.T, root string, pin HostFilePin) {
			if err := os.Chmod(pin.Path, 0700|os.ModeSetuid); err != nil { t.Fatal(err) }
		},
		"setgid": func(t *testing.T, root string, pin HostFilePin) {
			if err := os.Chmod(pin.Path, 0700|os.ModeSetgid); err != nil { t.Fatal(err) }
		},
		"sticky": func(t *testing.T, root string, pin HostFilePin) {
			if err := os.Chmod(pin.Path, 0600|os.ModeSticky); err != nil { t.Fatal(err) }
		},
		"hardlink": func(t *testing.T, root string, pin HostFilePin) {
			if err := os.Link(pin.Path, filepath.Join(root, "alias")); err != nil { t.Fatal(err) }
		},
		"symlink": func(t *testing.T, root string, pin HostFilePin) {
			target := filepath.Join(root, "target")
			if err := os.Rename(pin.Path, target); err != nil { t.Fatal(err) }
			if err := os.Symlink(target, pin.Path); err != nil { t.Fatal(err) }
		},
		"directory": func(t *testing.T, root string, pin HostFilePin) {
			if err := os.Remove(pin.Path); err != nil { t.Fatal(err) }
			if err := os.Mkdir(pin.Path, 0700); err != nil { t.Fatal(err) }
		},
		"fifo": func(t *testing.T, root string, pin HostFilePin) {
			if err := os.Remove(pin.Path); err != nil { t.Fatal(err) }
			if err := syscall.Mkfifo(pin.Path, 0600); err != nil { t.Fatal(err) }
		},
		"socket": func(t *testing.T, root string, pin HostFilePin) {
			if err := os.Remove(pin.Path); err != nil { t.Fatal(err) }
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: pin.Path, Net: "unix"})
			if err != nil { t.Fatal(err) }
			t.Cleanup(func() { listener.Close() })
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			root := hostFileFixtureRoot(t)
			pin := hostFileFixture(t, root, "config", "safe", 0600)
			mutate(t, root, pin)
			s, err := openHostFileFixture(context.Background(), root, pin)
			if err == nil {
				s.Close()
				t.Fatal("accepted unsafe file")
			}
		})
	}
}

func TestHostFilePinsRejectsUnsafeAncestors(t *testing.T) {
	for _, name := range []string{"group writable", "world writable sticky", "symlink", "wrong owner"} {
		t.Run(name, func(t *testing.T) {
			root := hostFileFixtureRoot(t)
			dir := filepath.Join(root, "child")
			if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
			pin := hostFileFixture(t, dir, "config", "safe", 0600)
			policy := hostFilePolicy{root: root, uid: uint32(os.Geteuid())}
			switch name {
			case "group writable":
				if err := os.Chmod(dir, 0770); err != nil { t.Fatal(err) }
			case "world writable sticky":
				if err := os.Chmod(dir, 0777|os.ModeSticky); err != nil { t.Fatal(err) }
			case "symlink":
				if err := os.Rename(dir, dir+"-real"); err != nil { t.Fatal(err) }
				if err := os.Symlink(dir+"-real", dir); err != nil { t.Fatal(err) }
			case "wrong owner":
				policy.uid++
			}
			s, err := openHostFilePins(context.Background(), []HostFilePin{pin}, policy)
			if err == nil {
				s.Close()
				t.Fatal("accepted unsafe ancestor")
			}
		})
	}
}

func TestHostFilePinsRegularStatRejectsDevicesAndOwners(t *testing.T) {
	policy := hostFilePolicy{uid: 123}
	valid := syscall.Stat_t{Mode: syscall.S_IFREG | 0644, Uid: 123, Nlink: 1}
	for _, mode := range []uint32{syscall.S_IFCHR, syscall.S_IFBLK, syscall.S_IFIFO, syscall.S_IFSOCK, syscall.S_IFDIR, syscall.S_IFLNK} {
		st := valid
		st.Mode = mode | 0600
		if err := hostFileRegularStat(st, policy); err == nil { t.Fatalf("accepted type %o", mode) }
	}
	valid.Uid++
	if err := hostFileRegularStat(valid, policy); err == nil { t.Fatal("accepted wrong file owner") }
}

func TestHostFilePinsReadLimits(t *testing.T) {
	t.Run("empty and exact limits", func(t *testing.T) {
		root := hostFileFixtureRoot(t)
		pins := []HostFilePin{hostFileFixture(t, root, "empty", "", 0600)}
		for i := 0; i < hostFileMaxTotalBytes/hostFileMaxBytes; i++ {
			pins = append(pins, hostFileFixture(t, root, fmt.Sprintf("file-%d", i), strings.Repeat("x", hostFileMaxBytes), 0644))
		}
		s, err := openHostFileFixture(context.Background(), root, pins...)
		if err != nil { t.Fatal(err) }
		defer s.Close()
		if err := s.Check(context.Background()); err != nil { t.Fatal(err) }
	})
	t.Run("per file", func(t *testing.T) {
		root := hostFileFixtureRoot(t)
		pin := hostFileFixture(t, root, "large", strings.Repeat("x", hostFileMaxBytes+1), 0600)
		if s, err := openHostFileFixture(context.Background(), root, pin); err == nil {
			s.Close()
			t.Fatal("accepted oversized file")
		}
	})
	t.Run("aggregate", func(t *testing.T) {
		root := hostFileFixtureRoot(t)
		var pins []HostFilePin
		for i := 0; i <= hostFileMaxTotalBytes/hostFileMaxBytes; i++ {
			pins = append(pins, hostFileFixture(t, root, fmt.Sprintf("file-%d", i), strings.Repeat("x", hostFileMaxBytes), 0600))
		}
		if s, err := openHostFileFixture(context.Background(), root, pins...); err == nil {
			s.Close()
			t.Fatal("accepted oversized aggregate")
		}
	})
}

func TestHostFilePinsCheckRejectsChangesAndLatches(t *testing.T) {
	for _, change := range []string{"content", "mode", "hardlink", "remove", "replace", "ancestor mode", "ancestor rename", "unrelated child"} {
		t.Run(change, func(t *testing.T) {
			root := hostFileFixtureRoot(t)
			dir := filepath.Join(root, "child")
			if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
			pin := hostFileFixture(t, dir, "config", "safe", 0600)
			s, err := openHostFileFixture(context.Background(), root, pin)
			if err != nil { t.Fatal(err) }
			defer s.Close()
			switch change {
			case "content":
				err = os.WriteFile(pin.Path, []byte("evil"), 0600)
			case "mode":
				err = os.Chmod(pin.Path, 0644)
			case "hardlink":
				err = os.Link(pin.Path, filepath.Join(dir, "alias"))
			case "remove":
				err = os.Remove(pin.Path)
			case "replace":
				if err := os.Rename(pin.Path, pin.Path+"-old"); err != nil { t.Fatal(err) }
				err = os.WriteFile(pin.Path, []byte("safe"), 0600)
			case "ancestor mode":
				err = os.Chmod(dir, 0755)
			case "ancestor rename":
				err = os.Rename(dir, dir+"-old")
			case "unrelated child":
				err = os.WriteFile(filepath.Join(dir, "other"), []byte("other"), 0600)
			}
			if err != nil { t.Fatal(err) }
			if err := s.Check(context.Background()); err == nil { t.Fatal("accepted change") }
			if _, err := s.Snapshot(); err == nil { t.Fatal("returned invalid snapshot") }
			if err := s.Check(context.Background()); err == nil { t.Fatal("retried invalid set") }
		})
	}
}

// Refresh test-only metadata to isolate the re-walk/rehash checks from their
// additional fstat guards. Production never updates the accepted baseline.
func hostFileRefreshTestStats(t *testing.T, s *HostFilePins) {
	t.Helper()
	for i := range s.files {
		for j := range s.files[i].nodes {
			node := &s.files[i].nodes[j]
			if err := syscall.Fstat(int(node.file.Fd()), &node.stat); err != nil { t.Fatal(err) }
		}
	}
}

func TestHostFilePinsCheckRewalksAndRehashes(t *testing.T) {
	for _, change := range []string{"file replacement", "ancestor replacement", "root replacement", "same size content"} {
		t.Run(change, func(t *testing.T) {
			root := hostFileFixtureRoot(t)
			dir := filepath.Join(root, "child")
			if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
			pin := hostFileFixture(t, dir, "config", "safe", 0600)
			s, err := openHostFileFixture(context.Background(), root, pin)
			if err != nil { t.Fatal(err) }
			defer s.Close()
			switch change {
			case "file replacement":
				if err := os.Rename(pin.Path, pin.Path+"-old"); err != nil { t.Fatal(err) }
				hostFileFixture(t, dir, "config", "safe", 0600)
			case "ancestor replacement":
				if err := os.Rename(dir, dir+"-old"); err != nil { t.Fatal(err) }
				if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
				hostFileFixture(t, dir, "config", "safe", 0600)
			case "root replacement":
				if err := os.Rename(root, root+"-old"); err != nil { t.Fatal(err) }
				t.Cleanup(func() { os.RemoveAll(root+"-old") })
				if err := os.Mkdir(root, 0700); err != nil { t.Fatal(err) }
				if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
				hostFileFixture(t, dir, "config", "safe", 0600)
			case "same size content":
				if err := os.WriteFile(pin.Path, []byte("evil"), 0600); err != nil { t.Fatal(err) }
			}
			hostFileRefreshTestStats(t, s)
			if err := s.Check(context.Background()); err == nil { t.Fatal("only checked retained metadata") }
		})
	}
}

type hostFileHookContext struct {
	context.Context
	calls int
	at int
	hook func()
}

func (c *hostFileHookContext) Err() error {
	c.calls++
	if c.calls == c.at { c.hook() }
	return c.Context.Err()
}

func TestHostFilePinsCancellationAndReadMutation(t *testing.T) {
	root := hostFileFixtureRoot(t)
	pin := hostFileFixture(t, root, "config", strings.Repeat("x", 32*1024), 0600)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if s, err := openHostFileFixture(canceled, root, pin); !errors.Is(err, context.Canceled) {
		if s != nil { s.Close() }
		t.Fatal("canceled open", err)
	}
	if s, err := openHostFileFixture(nil, root, pin); err == nil {
		s.Close()
		t.Fatal("accepted nil context")
	}
	s, err := openHostFileFixture(context.Background(), root, pin)
	if err != nil { t.Fatal(err) }
	defer s.Close()
	node := s.files[0].nodes[len(s.files[0].nodes)-1]
	ctx, cancelRead := context.WithCancel(context.Background())
	defer cancelRead()
	hooked := &hostFileHookContext{Context: ctx, at: 3, hook: cancelRead}
	if _, n, err := hostFileHash(hooked, node, hostFileMaxBytes); !errors.Is(err, context.Canceled) || n > 16*1024 {
		t.Fatal("did not cancel between bounded chunks", n, err)
	}
	mutation := &hostFileHookContext{Context: context.Background(), at: 3, hook: func() {
		if err := os.WriteFile(pin.Path, []byte(strings.Repeat("y", 32*1024)), 0600); err != nil { t.Fatal(err) }
	}}
	if _, _, err := hostFileHash(mutation, node, hostFileMaxBytes); err == nil {
		t.Fatal("accepted mutation during hash")
	}
	if err := s.Check(canceled); !errors.Is(err, context.Canceled) { t.Fatal("canceled check", err) }
	if err := s.Check(context.Background()); !errors.Is(err, context.Canceled) { t.Fatal("cancellation not latched", err) }
}

func TestHostFileHashDetectsGrowthAtBound(t *testing.T) {
	root := hostFileFixtureRoot(t)
	pin := hostFileFixture(t, root, "config", strings.Repeat("x", hostFileMaxBytes), 0600)
	s, err := openHostFileFixture(context.Background(), root, pin)
	if err != nil { t.Fatal(err) }
	defer s.Close()
	node := s.files[0].nodes[len(s.files[0].nodes)-1]
	ctx := &hostFileHookContext{Context: context.Background(), at: 2, hook: func() {
		f, err := os.OpenFile(pin.Path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil { t.Fatal(err) }
		_, writeErr := f.Write([]byte("extra"))
		if err := errors.Join(writeErr, f.Close()); err != nil { t.Fatal(err) }
	}}
	if _, n, err := hostFileHash(ctx, node, hostFileMaxBytes); err == nil || n != hostFileMaxBytes+1 {
		t.Fatal("growth did not stop at bounded extra byte", n, err)
	}
}

func TestHostFilePinsConcurrentCheckSnapshotAndClose(t *testing.T) {
	root := hostFileFixtureRoot(t)
	pin := hostFileFixture(t, root, "config", "safe", 0600)
	s, err := openHostFileFixture(context.Background(), root, pin)
	if err != nil { t.Fatal(err) }
	defer s.Close()
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 12; j++ {
				var err error
				switch i % 3 {
				case 0: err = s.Check(context.Background())
				case 1: _, err = s.Snapshot()
				case 2: err = s.Close()
				}
				if err != nil && !errors.Is(err, os.ErrClosed) { t.Error(err) }
			}
		}(i)
	}
	wg.Wait()
}

func TestHostFilePinsNoDescriptorLeaks(t *testing.T) {
	root := hostFileFixtureRoot(t)
	pin := hostFileFixture(t, root, "config", "safe", 0600)
	bad := pin
	bad.SHA256 = strings.Repeat("0", 64)
	warmup, err := openHostFileFixture(context.Background(), root, pin)
	if err != nil { t.Fatal(err) }
	if err := warmup.Check(context.Background()); err != nil {
		warmup.Close()
		t.Fatal(err)
	}
	if err := warmup.Close(); err != nil { t.Fatal(err) }
	count := func() int {
		files, err := os.ReadDir("/proc/self/fd")
		if err != nil { t.Fatal("own descriptor inventory unavailable", err) }
		return len(files)
	}
	before := count()
	for i := 0; i < 30; i++ {
		if s, err := openHostFileFixture(context.Background(), root, bad); err == nil {
			s.Close()
			t.Fatal("accepted bad hash")
		}
		ctx, cancel := context.WithCancel(context.Background())
		hooked := &hostFileHookContext{Context: ctx, at: 4, hook: cancel}
		if s, err := openHostFileFixture(hooked, root, pin); !errors.Is(err, context.Canceled) {
			if s != nil { s.Close() }
			t.Fatal("mid-walk cancellation", err)
		}
		cancel()
		s, err := openHostFileFixture(context.Background(), root, pin)
		if err != nil { t.Fatal(err) }
		if err := s.Close(); err != nil { t.Fatal(err) }
	}
	if after := count(); after != before { t.Fatalf("descriptor count changed: %d -> %d", before, after) }
}
