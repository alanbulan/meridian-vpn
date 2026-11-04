//go:build linux

package nmvpn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func dispatcherFixture(t *testing.T, children ...string) (string, []string) {
	t.Helper()
	anchor := hostFileFixtureRoot(t)
	roots := []string{
		filepath.Join(anchor, "etc/NetworkManager/dispatcher.d"),
		filepath.Join(anchor, "usr/lib/NetworkManager/dispatcher.d"),
	}
	for _, root := range roots {
		if err := os.MkdirAll(root, 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range children {
			if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
				t.Fatal(err)
			}
		}
	}
	return anchor, roots
}

func openDispatcherFixture(ctx context.Context, anchor string) (*EmptyDispatcherObservation, error) {
	return openEmptyDispatcherObservation(ctx, hostFilePolicy{root: anchor, uid: uint32(os.Geteuid())})
}

func dispatcherFixtureStats(t *testing.T, anchor string) map[string]syscall.Stat_t {
	t.Helper()
	stats := make(map[string]syscall.Stat_t)
	if err := filepath.Walk(anchor, func(path string, info os.FileInfo, err error) error {
		if err == nil {
			stats[path] = *info.Sys().(*syscall.Stat_t)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Walk itself reads directories; capture atime only after that traversal.
	for path := range stats {
		var stat syscall.Stat_t
		if err := syscall.Stat(path, &stat); err != nil {
			t.Fatal(err)
		}
		stats[path] = stat
	}
	return stats
}

func TestEmptyDispatcherObservationReadOnlyAndLifecycle(t *testing.T) {
	for _, children := range [][]string{nil, {"pre-up.d", "pre-down.d", "no-wait.d", "device"}} {
		t.Run(fmt.Sprintf("children-%d", len(children)), func(t *testing.T) {
			anchor, roots := dispatcherFixture(t, children...)
			before := dispatcherFixtureStats(t, anchor)
			s, err := openDispatcherFixture(context.Background(), anchor)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			snap, err := s.Snapshot()
			if err != nil || len(snap) != 2*(1+len(children)) || snap[0].Path != roots[0] || snap[1+len(children)].Path != roots[1] {
				t.Fatal("unexpected directory snapshot", snap, err)
			}
			for _, dir := range snap {
				st := before[dir.Path]
				if dir.Device != uint64(st.Dev) || dir.Inode != uint64(st.Ino) || dir.Mode != st.Mode || dir.OwnerUID != uint32(os.Geteuid()) || dir.LinkCount != uint64(st.Nlink) {
					t.Fatal("unexpected snapshot identity", dir)
				}
			}
			snap[0].Path = "/modified-copy"
			again, err := s.Snapshot()
			if err != nil || again[0].Path != roots[0] {
				t.Fatal("snapshot aliases retained state", err)
			}
			for i := 0; i < 3; i++ {
				if err := s.Check(context.Background()); err != nil {
					t.Fatal("unchanged check", err)
				}
			}
			var retained []*os.File
			for _, root := range s.roots {
				nodes := append([]hostFileNode{}, root.nodes...)
				for _, child := range root.children {
					nodes = append(nodes, child.node)
				}
				for _, node := range nodes {
					retained = append(retained, node.file)
					flags, err := unix.FcntlInt(node.file.Fd(), unix.F_GETFD, 0)
					if err != nil || flags&syscall.FD_CLOEXEC == 0 {
						t.Fatal("descriptor lacks close-on-exec", err)
					}
					flags, err = unix.FcntlInt(node.file.Fd(), unix.F_GETFL, 0)
					if err != nil || flags&syscall.O_ACCMODE != syscall.O_RDONLY || flags&(syscall.O_NONBLOCK|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NOATIME) != syscall.O_NONBLOCK|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NOATIME {
						t.Fatal("unsafe directory descriptor", err)
					}
				}
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal("second close", err)
			}
			for _, file := range retained {
				if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatal("descriptor was not closed", err)
				}
			}
			if err := s.Check(context.Background()); !errors.Is(err, os.ErrClosed) {
				t.Fatal("closed check", err)
			}
			if _, err := s.Snapshot(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("closed snapshot", err)
			}
			for path, initial := range before {
				var after syscall.Stat_t
				if err := syscall.Stat(path, &after); err != nil || !hostFileSameStat(initial, after) || initial.Atim != after.Atim {
					t.Fatal("observer mutated directory metadata", path, err)
				}
			}
		})
	}
}

func TestEmptyDispatcherObservationZeroNilAndProductionBounds(t *testing.T) {
	for _, s := range []*EmptyDispatcherObservation{nil, new(EmptyDispatcherObservation)} {
		if err := s.Check(context.Background()); !errors.Is(err, os.ErrClosed) {
			t.Fatal(err)
		}
		if _, err := s.Snapshot(); !errors.Is(err, os.ErrClosed) {
			t.Fatal(err)
		}
		if err := s.Close(); (s == nil && err != nil) || (s != nil && !errors.Is(err, os.ErrClosed)) {
			t.Fatal(err)
		}
	}
	// Exercise the real API only with a pre-canceled context, never read the
	// machine's dispatcher configuration in tests. Its type has no override.
	var publicOpen func(context.Context) (*EmptyDispatcherObservation, error) = OpenEmptyDispatcherObservation
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := publicOpen(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("production ignored cancellation", err)
	}
	anchor, _ := dispatcherFixture(t)
	for name, policy := range map[string]hostFilePolicy{
		"production anchor override": {root: anchor, uid: 0, production: true},
		"production UID override":    {root: "/", uid: 1, production: true},
		"relative anchor":            {root: "relative"},
		"unclean anchor":             {root: anchor + "/./"},
		"oversized anchor":           {root: "/" + strings.Repeat("x", hostFileMaxPathBytes)},
	} {
		t.Run(name, func(t *testing.T) {
			if s, err := openEmptyDispatcherObservation(context.Background(), policy); err == nil {
				s.Close()
				t.Fatal("accepted invalid policy")
			}
		})
	}
	if _, err := openDispatcherFixture(nil, anchor); err == nil {
		t.Fatal("accepted nil context")
	}
}

func TestEmptyDispatcherObservationRequiresBothRoots(t *testing.T) {
	for _, which := range []int{0, 1} {
		t.Run(fmt.Sprint(which), func(t *testing.T) {
			anchor, roots := dispatcherFixture(t)
			if err := os.Remove(roots[which]); err != nil {
				t.Fatal(err)
			}
			if s, err := openDispatcherFixture(context.Background(), anchor); !errors.Is(err, os.ErrNotExist) {
				if s != nil {
					s.Close()
				}
				t.Fatal("missing root was not rejected", err)
			}
			if _, err := os.Stat(roots[which]); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("observer created root", err)
			}
		})
	}
}

func TestEmptyDispatcherObservationClosedEntryGrammar(t *testing.T) {
	for _, entry := range []string{"hook", ".hidden", "99-hook.disabled", "backup~", "unknown.d", "pre-up.d", "pre-down.d", "no-wait.d", "device"} {
		for _, which := range []int{0, 1} {
			t.Run(fmt.Sprintf("file-%d-%s", which, entry), func(t *testing.T) {
				anchor, roots := dispatcherFixture(t)
				if err := os.WriteFile(filepath.Join(roots[which], entry), []byte("never read or executed"), 0600); err != nil {
					t.Fatal(err)
				}
				if s, err := openDispatcherFixture(context.Background(), anchor); err == nil {
					s.Close()
					t.Fatal("accepted hook file")
				}
			})
		}
	}
	for _, child := range []string{"pre-up.d", "pre-down.d", "no-wait.d", "device"} {
		for _, nested := range []string{"hook", "pre-up.d"} {
			t.Run(child+"/"+nested, func(t *testing.T) {
				anchor, roots := dispatcherFixture(t, child)
				path := filepath.Join(roots[0], child, nested)
				if nested == "hook" {
					if err := os.WriteFile(path, nil, 0600); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				if s, err := openDispatcherFixture(context.Background(), anchor); err == nil {
					s.Close()
					t.Fatal("accepted nonempty child")
				}
			})
		}
	}
	t.Run("unknown empty directory", func(t *testing.T) {
		anchor, roots := dispatcherFixture(t)
		if err := os.Mkdir(filepath.Join(roots[1], "unknown"), 0700); err != nil {
			t.Fatal(err)
		}
		if s, err := openDispatcherFixture(context.Background(), anchor); err == nil {
			s.Close()
			t.Fatal("accepted unknown directory")
		}
	})
	t.Run("entry bound", func(t *testing.T) {
		anchor, roots := dispatcherFixture(t, "pre-up.d", "pre-down.d", "no-wait.d", "device")
		for i := 0; i < 64; i++ {
			if err := os.WriteFile(filepath.Join(roots[1], fmt.Sprint(i)), nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if s, err := openDispatcherFixture(context.Background(), anchor); err == nil || !strings.Contains(err.Error(), "entry limit") {
			if s != nil {
				s.Close()
			}
			t.Fatal("did not enforce entry bound", err)
		}
	})
}

func TestEmptyDispatcherObservationRejectsUnsafeDirectories(t *testing.T) {
	for _, target := range []string{"anchor", "ancestor", "root", "child"} {
		for _, mode := range []os.FileMode{0770, 0702, 0700 | os.ModeSticky, 0700 | os.ModeSetuid, 0700 | os.ModeSetgid, 0300, 0600} {
			t.Run(fmt.Sprintf("%s-%o", target, mode), func(t *testing.T) {
				anchor, roots := dispatcherFixture(t, "device")
				path := map[string]string{"anchor": anchor, "ancestor": filepath.Dir(roots[0]), "root": roots[0], "child": filepath.Join(roots[1], "device")}[target]
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.Chmod(path, 0700) })
				if s, err := openDispatcherFixture(context.Background(), anchor); err == nil {
					s.Close()
					t.Fatal("accepted unsafe directory mode")
				}
			})
		}
	}
	t.Run("untrusted owner", func(t *testing.T) {
		anchor, _ := dispatcherFixture(t)
		if s, err := openEmptyDispatcherObservation(context.Background(), hostFilePolicy{root: anchor, uid: uint32(os.Geteuid()) + 1}); err == nil {
			s.Close()
			t.Fatal("accepted untrusted owner")
		}
	})
	for _, mode := range []uint32{syscall.S_IFREG, syscall.S_IFCHR, syscall.S_IFBLK, syscall.S_IFIFO, syscall.S_IFSOCK, syscall.S_IFLNK} {
		if err := dispatcherDirectoryStat(syscall.Stat_t{Mode: mode | 0700, Uid: 123, Nlink: 1}, hostFilePolicy{uid: 123}); err == nil {
			t.Fatalf("accepted unsafe directory type %o", mode)
		}
	}
}

func TestEmptyDispatcherObservationRejectsSymlinksAndSpecialEntries(t *testing.T) {
	for _, target := range []string{"anchor", "ancestor", "root", "child"} {
		t.Run(target+" symlink", func(t *testing.T) {
			anchor, roots := dispatcherFixture(t, "device")
			path := map[string]string{"anchor": anchor, "ancestor": filepath.Dir(roots[0]), "root": roots[0], "child": filepath.Join(roots[1], "device")}[target]
			if err := os.Rename(path, path+"-real"); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(path + "-real") })
			if err := os.Symlink(path+"-real", path); err != nil {
				t.Fatal(err)
			}
			if s, err := openDispatcherFixture(context.Background(), anchor); err == nil {
				s.Close()
				t.Fatal("followed symlink")
			}
		})
	}
	for _, kind := range []string{"fifo", "broken symlink"} {
		t.Run(kind, func(t *testing.T) {
			anchor, roots := dispatcherFixture(t)
			path := filepath.Join(roots[0], "device")
			switch kind {
			case "fifo":
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "broken symlink":
				if err := os.Symlink("missing", path); err != nil {
					t.Fatal(err)
				}
			}
			if s, err := openDispatcherFixture(context.Background(), anchor); err == nil {
				s.Close()
				t.Fatal("accepted special entry")
			}
		})
	}
}

func TestEmptyDispatcherObservationCheckRejectsDriftAndLatches(t *testing.T) {
	for _, change := range []string{"add hook", "add child", "remove child", "remove root", "root mode", "child mode", "ancestor mode", "unrelated ancestor entry", "transient hook"} {
		t.Run(change, func(t *testing.T) {
			anchor, roots := dispatcherFixture(t, "device")
			s, err := openDispatcherFixture(context.Background(), anchor)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			switch change {
			case "add hook":
				err = os.WriteFile(filepath.Join(roots[1], "device/hook"), nil, 0600)
			case "add child":
				err = os.Mkdir(filepath.Join(roots[0], "pre-up.d"), 0700)
			case "remove child":
				err = os.Remove(filepath.Join(roots[0], "device"))
			case "remove root":
				err = os.RemoveAll(roots[1])
			case "root mode":
				err = os.Chmod(roots[0], 0755)
			case "child mode":
				err = os.Chmod(filepath.Join(roots[0], "device"), 0755)
			case "ancestor mode":
				err = os.Chmod(filepath.Dir(roots[0]), 0755)
			case "unrelated ancestor entry":
				err = os.WriteFile(filepath.Join(anchor, "unrelated"), nil, 0600)
			case "transient hook":
				path := filepath.Join(roots[0], "hook")
				if err := os.WriteFile(path, nil, 0600); err != nil {
					t.Fatal(err)
				}
				err = os.Remove(path)
			}
			if err != nil {
				t.Fatal(err)
			}
			first := s.Check(context.Background())
			if first == nil {
				t.Fatal("accepted drift")
			}
			if err := s.Check(context.Background()); err != first {
				t.Fatal("did not latch the original error", first, err)
			}
			if _, err := s.Snapshot(); err != first {
				t.Fatal("returned invalid snapshot", err)
			}
		})
	}
}

// Test-only refresh isolates path rewalk and directory re-enumeration from the
// additional metadata guards. Production never refreshes its accepted baseline.
func dispatcherRefreshTestStats(t *testing.T, s *EmptyDispatcherObservation) {
	t.Helper()
	for i := range s.roots {
		root := &s.roots[i]
		for j := range root.nodes {
			node := &root.nodes[j]
			if err := syscall.Fstat(int(node.file.Fd()), &node.stat); err != nil {
				t.Fatal(err)
			}
		}
		for j := range root.children {
			node := &root.children[j].node
			if err := syscall.Fstat(int(node.file.Fd()), &node.stat); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestEmptyDispatcherObservationRewalksAndReenumerates(t *testing.T) {
	for _, change := range []string{"anchor replacement", "ancestor replacement", "root replacement", "child replacement", "added child", "removed child", "renamed child", "root hook", "child hook"} {
		t.Run(change, func(t *testing.T) {
			anchor, roots := dispatcherFixture(t, "device")
			s, err := openDispatcherFixture(context.Background(), anchor)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			switch change {
			case "anchor replacement", "ancestor replacement", "root replacement", "child replacement":
				path := map[string]string{"anchor replacement": anchor, "ancestor replacement": filepath.Dir(roots[0]), "root replacement": roots[0], "child replacement": filepath.Join(roots[0], "device")}[change]
				// Keep displaced entries outside the closed dispatcher grammar.
				backup := filepath.Join(t.TempDir(), "old")
				if err := os.Rename(path, backup); err != nil {
					t.Fatal(err)
				}
				for _, root := range roots {
					if err := os.MkdirAll(filepath.Join(root, "device"), 0700); err != nil {
						t.Fatal(err)
					}
				}
			case "added child":
				err = os.Mkdir(filepath.Join(roots[1], "pre-up.d"), 0700)
			case "removed child":
				err = os.Remove(filepath.Join(roots[1], "device"))
			case "renamed child":
				err = os.Rename(filepath.Join(roots[1], "device"), filepath.Join(roots[1], "pre-up.d"))
			case "root hook":
				err = os.WriteFile(filepath.Join(roots[0], ".hidden"), nil, 0600)
			case "child hook":
				err = os.WriteFile(filepath.Join(roots[1], "device/hook"), nil, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			dispatcherRefreshTestStats(t, s)
			if err := s.Check(context.Background()); err == nil {
				t.Fatal("did not rewalk and enumerate the original namespace")
			}
		})
	}
}

func TestEmptyDispatcherObservationCancellationAndCloseErrors(t *testing.T) {
	for _, nilContext := range []bool{false, true} {
		t.Run(fmt.Sprintf("nil-%t", nilContext), func(t *testing.T) {
			anchor, _ := dispatcherFixture(t)
			s, err := openDispatcherFixture(context.Background(), anchor)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if nilContext {
				ctx = nil
			}
			first := s.Check(ctx)
			if first == nil || (!nilContext && !errors.Is(first, context.Canceled)) {
				t.Fatal("accepted invalid context", first)
			}
			if err := s.Check(context.Background()); err != first {
				t.Fatal("context failure did not latch", err)
			}
		})
	}
	t.Run("close all despite first failure", func(t *testing.T) {
		anchor, _ := dispatcherFixture(t, "device")
		s, err := openDispatcherFixture(context.Background(), anchor)
		if err != nil {
			t.Fatal(err)
		}
		first := s.roots[1].children[0].node.file
		remaining := s.roots[0].nodes[0].file
		if err := first.Close(); err != nil {
			t.Fatal(err)
		}
		if err := s.Check(context.Background()); !errors.Is(err, os.ErrClosed) && !errors.Is(err, syscall.EBADF) {
			t.Fatal("lost check descriptor error", err)
		}
		if err := s.Close(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("lost close error", err)
		}
		if _, err := remaining.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("close stopped at the first error", err)
		}
		if err := s.Close(); err != nil {
			t.Fatal("retried uncertain descriptor close", err)
		}
	})
}

func TestEmptyDispatcherObservationConcurrentLifecycle(t *testing.T) {
	anchor, _ := dispatcherFixture(t, "pre-up.d", "pre-down.d", "no-wait.d", "device")
	s, err := openDispatcherFixture(context.Background(), anchor)
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if err := s.Check(context.Background()); err != nil && !errors.Is(err, os.ErrClosed) {
					t.Error(err)
				}
				snapshot, err := s.Snapshot()
				if err != nil && !errors.Is(err, os.ErrClosed) {
					t.Error(err)
				} else if err == nil && !reflect.DeepEqual(snapshot, before) {
					t.Error("changed snapshot")
				}
			}
		}()
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func TestEmptyDispatcherObservationRejectsCopiesBeforeSharedState(t *testing.T) {
	anchor, _ := dispatcherFixture(t, "device")
	s, err := openDispatcherFixture(context.Background(), anchor)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	retained := s.roots[0].nodes[0].file
	// Deliberately copy the public value before invalidation. Reflection makes
	// this misuse regression explicit without a vet copylocks warning.
	var copied EmptyDispatcherObservation
	reflect.ValueOf(&copied).Elem().Set(reflect.ValueOf(s).Elem())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Check(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("original did not invalidate", err)
	}
	// A copied lock may itself be unusable. Identity must be checked before
	// locking or touching shared descriptors, regardless of its stale state.
	copied.mu.Lock()
	defer copied.mu.Unlock()
	if err := copied.Check(context.Background()); !errors.Is(err, os.ErrClosed) {
		t.Fatal("copied observation bypassed sticky failure", err)
	}
	if _, err := copied.Snapshot(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("copied observation returned a snapshot", err)
	}
	if err := copied.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("copied Close was not rejected", err)
	}
	if _, err := retained.Stat(); err != nil {
		t.Fatal("copied Close released an original descriptor", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal("original lost descriptor ownership", err)
	}
	if _, err := retained.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("original did not close its descriptor", err)
	}
}
