//go:build linux

package packetrelay

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// No test opens /dev/net/tun or calls a real TUN ioctl. These callbacks model
// descriptor ownership and failures, not Linux compatibility or network cleanup.
type fakeTUNDevice struct {
	createCalls, observeCalls, pollCalls, closeCalls int
	createErr, observeErr, pollErr, closeErr         error
	value                                            TUNObservation
	onCreate, onObserve, onPoll                      func()
}

func newFakeTUN() *fakeTUNDevice {
	return &fakeTUNDevice{value: TUNObservation{Name: "mrd0", Flags: tunPacketFlags}}
}
func (d *fakeTUNDevice) create(name string) error {
	d.createCalls++
	if name != "mrd0" {
		return errTUNResource
	}
	if d.onCreate != nil {
		d.onCreate()
	}
	return d.createErr
}
func (d *fakeTUNDevice) observe() (TUNObservation, error) {
	d.observeCalls++
	if d.onObserve != nil {
		d.onObserve()
	}
	return d.value, d.observeErr
}
func (d *fakeTUNDevice) pollable() error {
	d.pollCalls++
	if d.onPoll != nil {
		d.onPoll()
	}
	return d.pollErr
}
func (d *fakeTUNDevice) close() error {
	d.closeCalls++
	return d.closeErr
}
func acquireFakeTUN(ctx context.Context, d *fakeTUNDevice) (*TUNResource, error) {
	return acquireTUN(ctx, "mrd0", func() (tunResourceDevice, error) { return d, nil })
}

func TestTUNResourceRejectsBeforeOpening(t *testing.T) {
	for _, name := range []string{"", "tun%d", "mrd/0", "mrd.0", "mrd:0", "0mrd", "mrd\x00", "mrd\n", "a123456789012345", "隧道"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			r, err := acquireTUN(context.Background(), name, func() (tunResourceDevice, error) {
				calls++
				return newFakeTUN(), nil
			})
			if r != nil || err == nil || calls != 0 {
				t.Fatal("invalid name reached open")
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled} {
		if r, err := acquireTUN(ctx, "mrd0", func() (tunResourceDevice, error) { t.Fatal("opened after cancellation"); return nil, nil }); r != nil || err == nil {
			t.Fatal("invalid context accepted")
		}
	}
	if r, err := acquireTUN(context.Background(), "mrd0", nil); r != nil || err == nil {
		t.Fatal("missing opener accepted")
	}
	for _, name := range []string{"a", "tun0", "mrd_0-x", "a12345678901234"} {
		if !tunResourceName.MatchString(name) {
			t.Fatal("supported exact name rejected")
		}
	}
}

func TestTUNResourceSuccessfulRetainedObservation(t *testing.T) {
	d := newFakeTUN()
	r, err := acquireFakeTUN(context.Background(), d)
	if err != nil || r == nil || d.createCalls != 1 || d.observeCalls != 2 || d.pollCalls != 1 || d.closeCalls != 0 {
		t.Fatalf("acquisition: %v %+v", err, d)
	}
	initial, err := r.InitialObservation()
	if err != nil || initial != d.value {
		t.Fatal("initial evidence lost")
	}
	initial.Name = "replacement"
	if value, err := r.Observe(context.Background()); err != nil || value != d.value {
		t.Fatal("snapshot mutation changed retained evidence")
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil || d.closeCalls != 1 {
		t.Fatal("close repeated")
	}
	if _, err = r.Observe(context.Background()); err == nil || d.observeCalls != 3 {
		t.Fatal("observation after close accessed replacement")
	}
	if value, err := r.InitialObservation(); err != nil || value != d.value {
		t.Fatal("close erased historical evidence")
	}
}

func TestTUNResourceFailureRetainsCleanup(t *testing.T) {
	for _, phase := range []string{"open", "create-collision", "create-uncertain", "observe", "wrong-name", "wrong-mode", "poll", "changed-second"} {
		t.Run(phase, func(t *testing.T) {
			d := newFakeTUN()
			var openErr error
			switch phase {
			case "open":
				openErr = os.ErrPermission
			case "create-collision":
				d.createErr = syscall.EBUSY
			case "create-uncertain":
				d.createErr = syscall.EFAULT // ioctl reply can fail after mutation
			case "observe":
				d.observeErr = os.ErrPermission
			case "wrong-name":
				d.value.Name = "other"
			case "wrong-mode":
				d.value.Flags |= unix.IFF_PERSIST
			case "poll":
				d.pollErr = os.ErrNoDeadline
			case "changed-second":
				d.onObserve = func() {
					if d.observeCalls == 2 {
						d.value.Name = "renamed"
					}
				}
			}
			r, err := acquireTUN(context.Background(), "mrd0", func() (tunResourceDevice, error) { return d, openErr })
			if r == nil || err == nil || d.closeCalls != 1 {
				t.Fatalf("failure discarded handle or leaked it: %v %+v", err, d)
			}
			if phase == "open" && d.createCalls != 0 {
				t.Fatal("created after failed open checks")
			}
			if d.createCalls > 1 || (d.createErr != nil && d.observeCalls != 0) {
				t.Fatal("uncertain creation replayed or adopted")
			}
			if r.Close() != nil || d.closeCalls != 1 {
				t.Fatal("closed failed acquisition twice")
			}
		})
	}
	for _, openErr := range []error{nil, os.ErrPermission, ErrCleanup} {
		if r, err := acquireTUN(context.Background(), "mrd0", func() (tunResourceDevice, error) { return nil, openErr }); r != nil || err == nil {
			t.Fatal("missing handle accepted")
		}
	}
}

func TestTUNResourceCancellationClosesAcquisition(t *testing.T) {
	for _, phase := range []string{"open", "create", "first-read", "poll", "second-read"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			d := newFakeTUN()
			switch phase {
			case "create":
				d.onCreate = cancel
			case "first-read", "second-read":
				d.onObserve = func() {
					if phase == "first-read" || d.observeCalls == 2 {
						cancel()
					}
				}
			case "poll":
				d.onPoll = cancel
			}
			r, err := acquireTUN(ctx, "mrd0", func() (tunResourceDevice, error) {
				if phase == "open" {
					cancel()
				}
				return d, nil
			})
			if r == nil || err == nil || d.closeCalls != 1 {
				t.Fatal("cancellation lost acquired handle")
			}
			if phase == "open" && d.createCalls != 0 {
				t.Fatal("mutation after cancellation")
			}
		})
	}
}

func TestTUNResourceRejectsAllUnsupportedModes(t *testing.T) {
	for _, flags := range []uint16{0, unix.IFF_TAP | unix.IFF_NO_PI, unix.IFF_TUN, tunCreateFlags, tunPacketFlags | unix.IFF_PERSIST, tunPacketFlags | unix.IFF_MULTI_QUEUE, tunPacketFlags | unix.IFF_VNET_HDR, tunPacketFlags | unix.IFF_NAPI, tunPacketFlags | unix.IFF_DETACH_QUEUE, tunPacketFlags | unix.IFF_ONE_QUEUE} {
		d := newFakeTUN()
		d.value.Flags = flags
		if r, err := acquireFakeTUN(context.Background(), d); r == nil || err == nil || d.closeCalls != 1 {
			t.Fatalf("unsupported flags %#x accepted", flags)
		}
	}
}

func TestTUNResourceObservationFailureIsPermanent(t *testing.T) {
	for _, reason := range []string{"rename", "mode", "error", "nil-context", "canceled", "during-read"} {
		t.Run(reason, func(t *testing.T) {
			d := newFakeTUN()
			r, err := acquireFakeTUN(context.Background(), d)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch reason {
			case "rename":
				d.value.Name = "new"
			case "mode":
				d.value.Flags |= unix.IFF_PERSIST
			case "error":
				d.observeErr = os.ErrPermission
			case "nil-context":
				ctx = nil
			case "canceled":
				cancel()
			case "during-read":
				d.onObserve = cancel
			}
			if _, err = r.Observe(ctx); err == nil || d.closeCalls != 1 {
				t.Fatal("changed observation not fenced")
			}
			calls := d.observeCalls
			d.value, d.observeErr = TUNObservation{Name: "mrd0", Flags: tunPacketFlags}, nil
			if _, err = r.Observe(context.Background()); err == nil || d.observeCalls != calls {
				t.Fatal("failed observation retried or recovered")
			}
		})
	}
}

func TestTUNResourceStickyCloseFailure(t *testing.T) {
	for _, failedAcquire := range []bool{false, true} {
		d := newFakeTUN()
		d.closeErr = syscall.EIO
		if failedAcquire {
			d.createErr = syscall.EFAULT
		}
		r, err := acquireFakeTUN(context.Background(), d)
		if r == nil || (failedAcquire && !errors.Is(err, ErrCleanup)) {
			t.Fatal("uncertain acquisition cleanup discarded")
		}
		for i := 0; i < 2; i++ {
			if err = r.Close(); !errors.Is(err, ErrCleanup) || !errors.Is(err, syscall.EIO) {
				t.Fatal("cleanup uncertainty lost")
			}
		}
		if d.closeCalls != 1 {
			t.Fatal("numeric descriptor close replayed")
		}
	}
}

func TestTUNResourceRetainsOpenerCleanupError(t *testing.T) {
	d := newFakeTUN()
	inherited := errors.Join(ErrCleanup, syscall.EIO)
	r, err := acquireTUN(context.Background(), "mrd0", func() (tunResourceDevice, error) { return d, inherited })
	if r == nil || !errors.Is(err, ErrCleanup) || d.createCalls != 0 || d.closeCalls != 1 {
		t.Fatal("unsafe opener outcome lost")
	}
	if err = r.Close(); !errors.Is(err, ErrCleanup) || !errors.Is(err, syscall.EIO) || d.closeCalls != 1 {
		t.Fatal("inherited cleanup error was not sticky")
	}
	if _, err = r.Observe(context.Background()); !errors.Is(err, ErrCleanup) {
		t.Fatal("observation discarded cleanup uncertainty")
	}
}

func TestTUNResourceConcurrentCloseAndObserve(t *testing.T) {
	d := newFakeTUN()
	r, err := acquireFakeTUN(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_, _ = r.Observe(context.Background())
			_ = r.Close()
			_, _ = r.InitialObservation()
		}()
	}
	group.Wait()
	if d.closeCalls != 1 || d.createCalls != 1 {
		t.Fatal("concurrent operation repeated ownership transfer")
	}
}

func TestTUNResourceExactCreationIoctl(t *testing.T) {
	for _, syscallErr := range []error{nil, syscall.EBUSY, syscall.EFAULT} {
		calls := 0
		err := createTUNOnDescriptor(&fakeRaw{}, "mrd0", func(_ int, request uint, value *unix.Ifreq) error {
			calls++
			if request != unix.TUNSETIFF || value.Name() != "mrd0" || value.Uint16() != unix.IFF_TUN|unix.IFF_NO_PI|unix.IFF_TUN_EXCL {
				t.Fatal("wrong ioctl or permissive acquisition flags")
			}
			return syscallErr
		})
		if (err == nil) != (syscallErr == nil) || calls != 1 {
			t.Fatal("ioctl retried or error hidden")
		}
	}
	calls := 0
	ioctl := func(_ int, _ uint, _ *unix.Ifreq) error { calls++; return nil }
	if createTUNOnDescriptor(&fakeRaw{err: os.ErrClosed}, "mrd0", ioctl) == nil || calls != 0 {
		t.Fatal("ioctl ran outside descriptor lifetime")
	}
	if createTUNOnDescriptor(&fakeRaw{}, "tun%d", ioctl) == nil || calls != 0 {
		t.Fatal("automatic device name accepted")
	}
	if createTUNOnDescriptor(&fakeRaw{}, "mrd0", func(_ int, _ uint, value *unix.Ifreq) error {
		replacement, _ := unix.NewIfreq("other")
		*value = *replacement
		return nil
	}) == nil {
		t.Fatal("kernel-returned unexpected name accepted")
	}
	if tunOpenFlags != unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW || tunDirectoryFlags != unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW {
		t.Fatal("unsafe open flags")
	}
}

func TestTUNResourceDeviceNodeTrust(t *testing.T) {
	directory := unix.Stat_t{Mode: unix.S_IFDIR | 0755, Uid: 0}
	if !validTUNDirectory(directory) {
		t.Fatal("trusted directory rejected")
	}
	for _, mode := range []uint32{unix.S_IFLNK | 0777, unix.S_IFDIR | 0775, unix.S_IFDIR | 0777, unix.S_IFREG | 0755} {
		changed := directory
		changed.Mode = mode
		if validTUNDirectory(changed) {
			t.Fatal("unsafe directory accepted")
		}
	}
	directory.Uid = 1000
	if validTUNDirectory(directory) {
		t.Fatal("non-root ancestor accepted")
	}
	node := unix.Stat_t{Mode: unix.S_IFCHR | 0666, Uid: 0, Nlink: 1, Rdev: unix.Mkdev(10, 200)}
	if !validTUNNode(node) {
		t.Fatal("normal root-owned TUN node rejected")
	}
	for _, field := range []string{"mode", "uid", "links", "major", "minor"} {
		changed := node
		switch field {
		case "mode":
			changed.Mode = unix.S_IFREG | 0600
		case "uid":
			changed.Uid = 1000
		case "links":
			changed.Nlink = 2
		case "major":
			changed.Rdev = unix.Mkdev(11, 200)
		case "minor":
			changed.Rdev = unix.Mkdev(10, 201)
		}
		if validTUNNode(changed) {
			t.Fatal("unsafe node accepted:", field)
		}
	}
}

func TestTUNResourceZeroValue(t *testing.T) {
	for _, r := range []*TUNResource{nil, {}} {
		if _, err := r.InitialObservation(); err == nil {
			t.Fatal("zero historical evidence accepted")
		}
		if _, err := r.Observe(context.Background()); err == nil {
			t.Fatal("zero live evidence accepted")
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTUNResourceDescriptorObservationSyscalls(t *testing.T) {
	for _, failure := range []string{"", "raw", "getfd-error", "cloexec", "getfl-error", "blocking", "readonly", "ioctl"} {
		t.Run(failure, func(t *testing.T) {
			raw := &fakeRaw{}
			if failure == "raw" {
				raw.err = os.ErrClosed
			}
			var calls []string
			value, err := observeTUNDescriptor(raw, func(_ uintptr, command, arg int) (int, error) {
				if arg != 0 {
					t.Fatal("mutating fcntl argument")
				}
				switch command {
				case unix.F_GETFD:
					calls = append(calls, "getfd")
					if failure == "getfd-error" {
						return 0, syscall.EIO
					}
					if failure == "cloexec" {
						return 0, nil
					}
					return unix.FD_CLOEXEC, nil
				case unix.F_GETFL:
					calls = append(calls, "getfl")
					if failure == "getfl-error" {
						return 0, syscall.EIO
					}
					if failure == "blocking" {
						return unix.O_RDWR, nil
					}
					if failure == "readonly" {
						return unix.O_NONBLOCK, nil
					}
					return unix.O_RDWR | unix.O_NONBLOCK, nil
				default:
					t.Fatal("unapproved fcntl command")
					return 0, syscall.EINVAL
				}
			}, func(_ int, command uint, value *unix.Ifreq) error {
				calls = append(calls, "ioctl")
				if command != unix.TUNGETIFF || value.Name() != "" {
					t.Fatal("non-read-only observation")
				}
				if failure == "ioctl" {
					return syscall.EIO
				}
				actual, _ := unix.NewIfreq("mrd0")
				actual.SetUint16(tunPacketFlags)
				*value = *actual
				return nil
			})
			if (err == nil) != (failure == "") {
				t.Fatal("wrong observation outcome", err)
			}
			want := 3
			switch failure {
			case "raw":
				want = 0
			case "getfd-error", "cloexec":
				want = 1
			case "getfl-error", "blocking", "readonly":
				want = 2
			}
			if len(calls) != want {
				t.Fatal("continued after failed descriptor check", calls)
			}
			for i, call := range calls {
				if call != []string{"getfd", "getfl", "ioctl"}[i] {
					t.Fatal("wrong syscall order", calls)
				}
			}
			if failure == "" && value != (TUNObservation{Name: "mrd0", Flags: tunPacketFlags}) {
				t.Fatal("readback changed")
			}
		})
	}
}

func TestTUNResourceTrustedOpenAndPartialCleanup(t *testing.T) {
	for _, failure := range []string{"", "open-root", "stat-root", "unsafe-root", "open-dev", "stat-dev", "unsafe-dev", "open-net", "stat-net", "unsafe-net", "open-tun", "stat-tun", "unsafe-tun", "close-net", "close-dev", "close-root"} {
		t.Run(failure, func(t *testing.T) {
			labels := []string{"root", "dev", "net", "tun"}
			opened := map[int]bool{}
			var closed []int
			open := func(index, flags int) (int, error) {
				want := tunDirectoryFlags
				if index == 3 {
					want = tunOpenFlags
				}
				if flags != want {
					t.Fatal("unsafe open flags")
				}
				if failure == "open-"+labels[index] {
					return -1, syscall.EACCES
				}
				fd := 100 + index
				opened[fd] = true
				return fd, nil
			}
			ops := tunPathOps{
				open: func(path string, flags int, mode uint32) (int, error) {
					if path != "/" || mode != 0 {
						t.Fatal("unexpected root or creation mode")
					}
					return open(0, flags)
				},
				openat: func(parent int, path string, flags int, mode uint32) (int, error) {
					index := parent - 100 + 1
					if index < 1 || index > 3 || !opened[parent] || path != labels[index] || mode != 0 {
						t.Fatal("untrusted pathname or parent used")
					}
					return open(index, flags)
				},
				fstat: func(fd int, st *unix.Stat_t) error {
					index := fd - 100
					if !opened[fd] {
						t.Fatal("stat of unowned descriptor")
					}
					if failure == "stat-"+labels[index] {
						return syscall.EIO
					}
					*st = unix.Stat_t{Mode: unix.S_IFDIR | 0755, Uid: 0, Nlink: 1}
					if index == 3 {
						st.Mode, st.Rdev = unix.S_IFCHR|0666, unix.Mkdev(10, 200)
					}
					if failure == "unsafe-"+labels[index] {
						st.Uid = 1000
					}
					return nil
				},
				close: func(fd int) error {
					if !opened[fd] || fd == 103 {
						t.Fatal("closed unowned or transferred node descriptor")
					}
					delete(opened, fd)
					closed = append(closed, fd)
					if failure == "close-"+labels[fd-100] {
						return syscall.EIO
					}
					return nil
				},
			}
			node, err := openTUNPath(ops)
			if (err == nil) != (failure == "") {
				t.Fatal("wrong open result", err)
			}
			if len(failure) >= 6 && failure[:6] == "close-" && !errors.Is(err, ErrCleanup) {
				t.Fatal("directory cleanup uncertainty lost")
			}
			for i, fd := range closed {
				if i > 0 && fd >= closed[i-1] {
					t.Fatal("directories not closed once in reverse order")
				}
			}
			if node == 103 {
				if !opened[103] || len(opened) != 1 {
					t.Fatal("node ownership lost")
				}
			} else if node != -1 || len(opened) != 0 {
				t.Fatal("partial open leaked unreturned resource")
			}
		})
	}
}
