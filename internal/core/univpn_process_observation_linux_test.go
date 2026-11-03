//go:build linux

package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"mygo-vpn/internal/nmvpn"
)

// These fixtures use temporary files only. They never start/reap a real worker,
// read a user-selected PID, access the system bus, or change any host setting.
type uniVPNProcFixture struct {
	path   string
	pid    int
	digest string
	obs    *uniVPNProcessObservation
}

func uniVPNFixtureStat(pid int, comm, state string, start uint64) string {
	return fmt.Sprintf("%d (%s) %s %s%d%s\n", pid, comm, state, strings.Repeat("0 ", 18), start, strings.Repeat(" 0", 30))
}

func uniVPNFixtureStatus(pid int) string {
	return fmt.Sprintf("Name:\tsynthetic\nTgid:\t%d\nPid:\t%d\nNSpid:\t%d\nUid:\t65532\t65532\t65532\t65532\nGid:\t65532\t65532\t65532\t65532\n", pid, pid, pid)
}

func uniVPNFixtureRead(ctx context.Context, dir *os.File, pid int) (UniVPNNMProcessObservation, error) {
	return readUniVPNProcessSample(ctx, dir, pid, false)
}

func newUniVPNProcFixture(t *testing.T) *uniVPNProcFixture {
	t.Helper()
	f := &uniVPNProcFixture{path: filepath.Join(t.TempDir(), "process"), pid: 4321}
	if err := os.MkdirAll(filepath.Join(f.path, "ns"), 0700); err != nil {
		t.Fatal(err)
	}
	f.write(t, "stat", uniVPNFixtureStat(f.pid, "native (synthetic)", "S", 123456))
	f.write(t, "status", uniVPNFixtureStatus(f.pid))
	image := []byte("synthetic executable bytes, never executed\n")
	if err := os.WriteFile(filepath.Join(f.path, "image"), image, 0555); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("image", filepath.Join(f.path, "exe")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"net", "mnt", "user", "pid"} {
		f.write(t, filepath.Join("ns", name), "synthetic namespace identity")
	}
	sum := sha256.Sum256(image)
	f.digest = hex.EncodeToString(sum[:])
	dir, err := os.Open(f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.obs = newUniVPNProcessObservation(dir, f.pid, uniVPNFixtureRead)
	if f.obs.err != nil {
		t.Fatal(f.obs.err)
	}
	t.Cleanup(func() { _ = f.obs.close() })
	return f
}

func (f *uniVPNProcFixture) write(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.path, name), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestUniVPNProcessObservationPrivateFixture(t *testing.T) {
	f := newUniVPNProcFixture(t)
	got, err := f.obs.observe(context.Background(), f.digest)
	if err != nil || got.PID != f.pid || got.StartTimeTicks != 123456 || got.UID != [4]uint32{65532, 65532, 65532, 65532} || got.Executable.SHA256 != f.digest || got.NetworkNS.Inode == 0 || got.Session != "" {
		t.Fatalf("unexpected observation: %+v, %v", got, err)
	}
	if uniVPNObservedFilesystem(int(f.obs.dir.Fd()), uniVPNProcMagic) {
		t.Fatal("ordinary fixture unexpectedly accepted as real procfs")
	}
	if _, err = readUniVPNRealProcess(context.Background(), f.obs.dir, f.pid); err == nil {
		t.Fatal("production reader accepted ordinary namespace fixtures")
	}
	if _, err = f.obs.observe(context.Background(), strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong frozen executable digest accepted")
	}
}

func TestUniVPNProcessObservationStatParser(t *testing.T) {
	for _, comm := range []string{"native", "native with spaces", "odd ) ( process)", "name\nwith newline"} {
		if start, err := parseUniVPNProcStat([]byte(uniVPNFixtureStat(99, comm, "S", 777)), 99); err != nil || start != 777 {
			t.Fatalf("comm %q: %d, %v", comm, start, err)
		}
	}
	for name, data := range map[string]string{
		"wrong PID": uniVPNFixtureStat(98, "native", "S", 777),
		"zombie": uniVPNFixtureStat(99, "native", "Z", 777),
		"dead": uniVPNFixtureStat(99, "native", "X", 777),
		"unknown state": uniVPNFixtureStat(99, "native", "?", 777),
		"zero start": uniVPNFixtureStat(99, "native", "S", 0),
		"short": "99 (native) S 1 2\n",
		"truncated after starttime": "99 (native) S " + strings.Repeat("0 ", 18) + "777\n",
		"missing newline": strings.TrimSuffix(uniVPNFixtureStat(99, "native", "S", 777), "\n"),
		"overflow": strings.Replace(uniVPNFixtureStat(99, "native", "S", 777), "777", "18446744073709551616", 1),
		"oversize": uniVPNFixtureStat(99, strings.Repeat("x", uniVPNProcStatLimit), "S", 777),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseUniVPNProcStat([]byte(data), 99); err == nil {
				t.Fatal("invalid stat accepted")
			}
		})
	}
}

func TestUniVPNProcessObservationStatusParser(t *testing.T) {
	good := uniVPNFixtureStatus(99)
	if _, _, err := parseUniVPNProcStatus([]byte(good), 99); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"duplicate UID": good + "Uid:\t0 0 0 0\n",
		"duplicate PID": good + "Pid:\t99\n",
		"wrong PID": strings.Replace(good, "Pid:\t99\n", "Pid:\t98\n", 1),
		"wrong leader": strings.Replace(good, "Tgid:\t99\n", "Tgid:\t98\n", 1),
		"missing UID": strings.Replace(good, "Uid:", "NoUID:", 1),
		"short UID": strings.Replace(good, "Uid:\t65532\t65532\t65532\t65532", "Uid:\t0 0 0", 1),
		"negative UID": strings.Replace(good, "Uid:\t65532", "Uid:\t-1", 1),
		"overflow UID": strings.Replace(good, "Uid:\t65532", "Uid:\t4294967296", 1),
		"truncated": strings.TrimSuffix(good, "\n"),
		"oversized": good + strings.Repeat("x", uniVPNProcStatusLimit),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseUniVPNProcStatus([]byte(data), 99); err == nil {
				t.Fatal("invalid status accepted")
			}
		})
	}
}

func TestUniVPNProcessObservationNamespaceViewGuard(t *testing.T) {
	good := uniVPNFixtureStatus(99)
	if !validUniVPNProcSelfStatus([]byte(good), 99) {
		t.Fatal("single matching namespace PID rejected")
	}
	for name, data := range map[string]string{
		"missing": strings.Replace(good, "NSpid:\t99\n", "", 1),
		"outer namespace": strings.Replace(good, "NSpid:\t99", "NSpid:\t99 7", 1),
		"wrong PID": strings.Replace(good, "NSpid:\t99", "NSpid:\t98", 1),
		"duplicate": good + "NSpid:\t99\n",
		"empty": strings.Replace(good, "NSpid:\t99", "NSpid:\t", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if validUniVPNProcSelfStatus([]byte(data), 99) {
				t.Fatal("ambiguous PID namespace accepted")
			}
		})
	}
}

func TestUniVPNProcessObservationRejectsResourceChanges(t *testing.T) {
	for _, what := range []string{"start", "PID", "UID", "executable", "namespace", "gone", "closed", "canceled"} {
		t.Run(what, func(t *testing.T) {
			f := newUniVPNProcFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			f.obs.read = func(ctx context.Context, dir *os.File, pid int) (UniVPNNMProcessObservation, error) {
				result, err := uniVPNFixtureRead(ctx, dir, pid)
				calls++
				if calls == 1 {
					switch what {
					case "start":
						f.write(t, "stat", uniVPNFixtureStat(pid, "native", "S", 654321))
					case "PID":
						f.write(t, "stat", uniVPNFixtureStat(pid+1, "native", "S", 123456))
					case "UID":
						f.write(t, "status", strings.Replace(uniVPNFixtureStatus(pid), "Uid:\t65532", "Uid:\t0", 1))
					case "executable":
						if err := os.WriteFile(filepath.Join(f.path, "replacement"), []byte("other image"), 0555); err != nil {
							t.Fatal(err)
						}
						if err := os.Rename(filepath.Join(f.path, "replacement"), filepath.Join(f.path, "image")); err != nil {
							t.Fatal(err)
						}
					case "namespace":
						f.write(t, "new-ns", "different namespace inode")
						if err := os.Rename(filepath.Join(f.path, "new-ns"), filepath.Join(f.path, "ns", "net")); err != nil {
							t.Fatal(err)
						}
					case "gone":
						if err := os.Remove(filepath.Join(f.path, "stat")); err != nil {
							t.Fatal(err)
						}
					case "closed":
						if err := f.obs.close(); err != nil {
							t.Fatal(err)
						}
					case "canceled":
						cancel()
					}
				}
				return result, err
			}
			if _, err := f.obs.observe(ctx, f.digest); err == nil {
				t.Fatal("changed or invalidated process accepted")
			}
		})
	}
}

func TestUniVPNProcessObservationRetainsDirectory(t *testing.T) {
	f := newUniVPNProcFixture(t)
	moved := f.path + "-original"
	if err := os.Rename(f.path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.path, 0700); err != nil {
		t.Fatal(err)
	}
	// Reuse the numeric-path analogue with a distinct process. Reads through
	// the retained handle must still refer to the original directory.
	f.write(t, "stat", uniVPNFixtureStat(f.pid, "reused", "S", 999999))
	got, err := f.obs.observe(context.Background(), f.digest)
	if err != nil || got.StartTimeTicks != 123456 {
		t.Fatalf("retained directory followed replacement: %+v, %v", got, err)
	}
}

func TestUniVPNProcessObservationRejectsUnsafeFiles(t *testing.T) {
	for _, what := range []string{"stat symlink", "stat FIFO", "status oversize", "executable directory", "namespace missing", "stat dead", "start changed"} {
		t.Run(what, func(t *testing.T) {
			f := newUniVPNProcFixture(t)
			switch what {
			case "stat symlink", "stat FIFO":
				if err := os.Remove(filepath.Join(f.path, "stat")); err != nil {
					t.Fatal(err)
				}
				var err error
				if what == "stat symlink" {
					err = os.Symlink("status", filepath.Join(f.path, "stat"))
				} else {
					err = syscall.Mkfifo(filepath.Join(f.path, "stat"), 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "status oversize":
				f.write(t, "status", strings.Repeat("x", uniVPNProcStatusLimit+1))
			case "executable directory":
				if err := os.Remove(filepath.Join(f.path, "exe")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("ns", filepath.Join(f.path, "exe")); err != nil {
					t.Fatal(err)
				}
			case "namespace missing":
				if err := os.Remove(filepath.Join(f.path, "ns", "net")); err != nil {
					t.Fatal(err)
				}
			case "stat dead":
				f.write(t, "stat", uniVPNFixtureStat(f.pid, "dead", "Z", 123456))
			case "start changed":
				f.write(t, "stat", uniVPNFixtureStat(f.pid, "other", "S", 123457))
			}
			if _, err := f.obs.observe(context.Background(), f.digest); err == nil {
				t.Fatal("unsafe or changed resource accepted")
			}
		})
	}
}

func uniVPNFixtureBroker(f *uniVPNProcFixture) (*UniVPNNMBroker, *uniVPNExecProcess) {
	session := strings.Repeat("a", 32)
	// The fixture remains unprivileged on CI. Only its private reader reports
	// a provisioned root owner; production never offers this substitution.
	read := f.obs.read
	f.obs.read = func(ctx context.Context, dir *os.File, pid int) (UniVPNNMProcessObservation, error) {
		result, err := read(ctx, dir, pid)
		result.Executable.UID = 0
		return result, err
	}
	p := &uniVPNExecProcess{cmd: &exec.Cmd{}, exited: make(chan struct{}), observation: f.obs, sessionID: session, isolation: uniVPNObservationIsolation{}}
	b := &UniVPNNMBroker{gate: make(chan struct{}, 1), process: p, launcher: &UniVPNExecLauncher{ExecutableSHA256: f.digest}, run: context.Background(), bound: true, prepared: true, waitDone: make(chan struct{})}
	b.binding.Identity.Session = session
	b.offer.Session = session
	b.gate <- struct{}{}
	return b, p
}

type uniVPNObservationIsolation struct{}

func (uniVPNObservationIsolation) Prepare(*exec.Cmd) error { return nil }
func (uniVPNObservationIsolation) WaitEmpty(context.Context, *exec.Cmd) error { return nil }

func TestUniVPNProcessObservationBrokerGate(t *testing.T) {
	f := newUniVPNProcFixture(t)
	b, p := uniVPNFixtureBroker(f)
	got, err := b.ObserveNativeProcess(context.Background())
	if err != nil || got.Session != p.sessionID {
		t.Fatalf("bound original process rejected: %+v, %v", got, err)
	}
	for _, what := range []string{"not prepared", "not bound", "stopping", "stopped", "uncertain", "session mismatch", "offer mismatch", "wrong hash", "foreign process", "nil process", "exited", "waited", "capture unavailable", "canceled", "image writable", "image foreign owner", "image set-ID", "image sticky"} {
		t.Run(what, func(t *testing.T) {
			f := newUniVPNProcFixture(t)
			b, p := uniVPNFixtureBroker(f)
			ctx := context.Background()
			switch what {
			case "not prepared":
				b.prepared = false
			case "not bound":
				b.bound = false
			case "stopping":
				b.stopTried = true
			case "stopped":
				b.stopped = true
			case "uncertain":
				b.uncertain = true
			case "session mismatch":
				p.sessionID = strings.Repeat("b", 32)
			case "offer mismatch":
				b.offer.Session = strings.Repeat("b", 32)
			case "wrong hash":
				b.launcher.ExecutableSHA256 = strings.Repeat("0", 64)
			case "foreign process":
				b.process = &nmBridgeProcess{}
			case "nil process":
				b.process = (*uniVPNExecProcess)(nil)
			case "exited":
				close(p.exited)
			case "waited":
				close(b.waitDone)
			case "capture unavailable":
				p.observation = pinUniVPNOriginalProcess(p) // cmd has never started
			case "image writable", "image foreign owner", "image set-ID", "image sticky":
				read := f.obs.read
				f.obs.read = func(ctx context.Context, dir *os.File, pid int) (UniVPNNMProcessObservation, error) {
					result, err := read(ctx, dir, pid)
					switch what {
					case "image writable":
						result.Executable.Mode |= 0020
					case "image foreign owner":
						result.Executable.UID = 1234
					case "image set-ID":
						result.Executable.Mode |= syscall.S_ISUID
					case "image sticky":
						result.Executable.Mode |= syscall.S_ISVTX
					}
					return result, err
				}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := b.ObserveNativeProcess(ctx); err == nil {
				t.Fatal("invalid broker lifecycle accepted")
			}
		})
	}
}

func TestUniVPNProcessObservationWaitInvalidates(t *testing.T) {
	f := newUniVPNProcFixture(t)
	b, p := uniVPNFixtureBroker(f)
	// Cmd was never started: Wait returns an error without a process syscall.
	// The lifecycle hook must still invalidate and close the retained fixture.
	if err := p.Wait(); err == nil {
		t.Fatal("unstarted synthetic command unexpectedly waited successfully")
	}
	if _, err := f.obs.observe(context.Background(), f.digest); err == nil {
		t.Fatal("observation survived Wait")
	}
	if _, err := b.ObserveNativeProcess(context.Background()); err == nil {
		t.Fatal("broker accepted exited process")
	}
	if f.obs.dir != nil || !f.obs.closed {
		t.Fatal("retained observation not invalidated")
	}
}

func TestUniVPNProcessObservationConcurrentClose(t *testing.T) {
	f := newUniVPNProcFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.obs.read = func(ctx context.Context, dir *os.File, pid int) (UniVPNNMProcessObservation, error) {
		once.Do(func() {
			close(entered)
			<-release
		})
		return uniVPNFixtureRead(ctx, dir, pid)
	}
	done := make(chan error, 1)
	go func() {
		_, err := f.obs.observe(context.Background(), f.digest)
		done <- err
	}()
	<-entered
	// This must not block behind the reader or close its duplicate descriptor.
	closed := make(chan error, 1)
	go func() { closed <- f.obs.close() }()
	select {
	case err := <-closed:
		if err != nil {
			close(release)
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("invalidation blocked behind the observation reader")
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("closed observation returned stale success")
	}
}

func TestUniVPNProcessObservationIsNotHostAuthority(t *testing.T) {
	f := newUniVPNProcFixture(t)
	b, _ := uniVPNFixtureBroker(f)
	observed, err := b.ObserveNativeProcess(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Successful process metadata cannot satisfy the missing trusted adapter.
	// Interface membership of the other observation types is likewise
	// independent of their fields or whether an observation succeeded.
	for _, value := range []any{observed, &observed, nmvpn.HostObservation{}, &nmvpn.HostObservation{}, &nmvpn.HostFilePins{}} {
		if _, ok := value.(UniVPNNMHostAuthority); ok {
			t.Fatalf("%T unexpectedly implements host authority", value)
		}
		if _, ok := value.(UniVPNNMHostBinding); ok {
			t.Fatalf("%T unexpectedly implements host binding", value)
		}
	}
}
