//go:build linux

package packetrelay

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sync"
	"testing"
)

// Namespace files are opaque test tokens. None of these callbacks execute an
// ioctl, open a namespace or netlink socket, or change the host's networking.
type tunKernelFixture struct {
	r                      *TUNResource
	d                      *fakeTUNDevice
	ops                    tunKernelObservationOps
	opens, inspects, links int
	files                  []*os.File
	closes                 map[*os.File]int
	value                  KernelLinkObservation
}

func newTUNKernelFixture(t *testing.T) *tunKernelFixture {
	t.Helper()
	f := &tunKernelFixture{d: newFakeTUN(), closes: make(map[*os.File]int), value: KernelLinkObservation{Index: 12, Name: "mrd0", MTU: 1500}}
	var err error
	f.r, err = acquireFakeTUN(context.Background(), f.d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.r.Close() })
	f.ops = tunKernelObservationOps{
		openNamespace: func() (*os.File, KernelNamespaceIdentity, error) {
			f.opens++
			token := new(os.File)
			f.files = append(f.files, token)
			return token, KernelNamespaceIdentity{7, 9}, nil
		},
		inspectNamespace: func(token *os.File) (KernelNamespaceIdentity, error) {
			f.inspects++
			if len(f.files) == 0 || token != f.files[0] {
				panic("wrong retained namespace")
			}
			return KernelNamespaceIdentity{7, 9}, nil
		},
		link: func(_ context.Context, ns KernelNamespaceIdentity, name string) (KernelLinkObservation, error) {
			f.links++
			if ns != (KernelNamespaceIdentity{7, 9}) || name != "mrd0" {
				panic("foreign namespace or name")
			}
			return f.value, nil
		},
		closeFile: func(token *os.File) error {
			f.closes[token]++
			if f.closes[token] != 1 {
				panic("retried namespace close")
			}
			return nil
		},
	}
	return f
}
func TestTUNResourceKernelObservationRetention(t *testing.T) {
	f := newTUNKernelFixture(t)
	if _, err := f.r.InitialKernelObservation(); err == nil {
		t.Fatal("historical observation before first success")
	}
	got, err := f.r.observeKernelLink(context.Background(), f.ops)
	if err != nil || got.TUN != f.d.value || got.Link != f.value || got.Namespace != (KernelNamespaceIdentity{7, 9}) {
		t.Fatalf("%+v %v", got, err)
	}
	if f.opens != 4 || f.inspects != 3 || f.links != 2 || f.closes[f.files[0]] != 0 || f.d.closeCalls != 0 {
		t.Fatal("incorrect retained ownership")
	}
	for _, token := range f.files[1:] {
		if f.closes[token] != 1 {
			t.Fatal("temporary namespace leaked")
		}
	}
	initial, _ := f.r.InitialKernelObservation()
	initial.Link.Index = 99
	// MTU/flags are observations, not immutable identity or applied-policy proof.
	f.value.MTU = 1400
	later, err := f.r.observeKernelLink(context.Background(), f.ops)
	if err != nil || later.Link.MTU != 1400 || f.opens != 7 {
		t.Fatal("later sequential observation failed", err)
	}
	historical, _ := f.r.InitialKernelObservation()
	if historical != got {
		t.Fatal("history overwritten or aliased")
	}
	if f.r.Close() != nil || f.r.Close() != nil || f.d.closeCalls != 1 || f.closes[f.files[0]] != 1 {
		t.Fatal("owner cleanup not exactly once")
	}
	if _, err = f.r.observeKernelLink(context.Background(), f.ops); err == nil || f.opens != 7 {
		t.Fatal("closed observer reopened")
	}
	if after, err := f.r.InitialKernelObservation(); err != nil || after != got {
		t.Fatal("close lost historical metadata")
	}
}
func TestTUNResourceKernelObservationInvalidation(t *testing.T) {
	boom := errors.New("injected")
	for _, mode := range []string{"open", "open-partial", "open-partial-cleanup", "retained-namespace", "fresh-namespace", "tun-name", "tun-mode", "tun-error", "first-link", "second-link", "link-drift", "link-name", "link-index", "later-index", "cancel", "temporary-close", "read-cleanup"} {
		t.Run(mode, func(t *testing.T) {
			f := newTUNKernelFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "later-index" {
				if _, err := f.r.observeKernelLink(ctx, f.ops); err != nil {
					t.Fatal(err)
				}
				f.value.Index++
			}
			switch mode {
			case "open":
				f.ops.openNamespace = func() (*os.File, KernelNamespaceIdentity, error) {
					f.opens++
					return nil, KernelNamespaceIdentity{}, boom
				}
			case "open-partial", "open-partial-cleanup":
				base := f.ops.openNamespace
				f.ops.openNamespace = func() (*os.File, KernelNamespaceIdentity, error) {
					p, id, _ := base()
					if mode == "open-partial-cleanup" {
						return p, id, errors.Join(ErrCleanup, boom)
					}
					return p, id, boom
				}
			case "retained-namespace":
				f.ops.inspectNamespace = func(*os.File) (KernelNamespaceIdentity, error) { return KernelNamespaceIdentity{7, 10}, nil }
			case "fresh-namespace":
				base := f.ops.openNamespace
				f.ops.openNamespace = func() (*os.File, KernelNamespaceIdentity, error) {
					p, id, e := base()
					if f.opens > 1 {
						id.Inode++
					}
					return p, id, e
				}
			case "tun-name":
				f.d.value.Name = "other"
			case "tun-mode":
				f.d.value.Flags = 0
			case "tun-error":
				f.d.observeErr = boom
			case "first-link", "second-link", "link-drift", "cancel", "read-cleanup":
				base := f.ops.link
				f.ops.link = func(ctx context.Context, id KernelNamespaceIdentity, name string) (KernelLinkObservation, error) {
					value, e := base(ctx, id, name)
					switch mode {
					case "first-link":
						e = boom
					case "second-link":
						if f.links == 2 {
							e = boom
						}
					case "link-drift":
						if f.links == 2 {
							value.MTU++
						}
					case "cancel":
						cancel()
					case "read-cleanup":
						e = errors.Join(ErrCleanup, boom)
					}
					return value, e
				}
			case "link-name":
				f.value.Name = "other"
			case "link-index":
				f.value.Index = 0
			case "temporary-close":
				base := f.ops.closeFile
				f.ops.closeFile = func(p *os.File) error {
					_ = base(p)
					if p != f.files[0] {
						return boom
					}
					return nil
				}
			}
			got, err := f.r.observeKernelLink(ctx, f.ops)
			if err == nil || got != (TUNKernelObservation{}) || f.r.closed || f.d.closeCalls != 0 {
				t.Fatal("failure lost owner or returned evidence", err)
			}
			calls := f.opens
			sticky, cleanup := f.r.kernel.invalid, f.r.kernel.cleanupErr
			for i := 0; i < 32; i++ {
				if _, err = f.r.observeKernelLink(context.Background(), f.ops); err != sticky || f.opens != calls || f.r.kernel.cleanupErr != cleanup {
					t.Fatal("invalid observer retried or grew retained errors")
				}
			}
			closeErr := f.r.Close()
			if f.d.closeCalls != 1 {
				t.Fatal("TUN cleanup lost")
			}
			for _, p := range f.files {
				if f.closes[p] != 1 {
					t.Fatal("namespace cleanup lost")
				}
			}
			if mode == "temporary-close" || mode == "read-cleanup" || mode == "open-partial-cleanup" {
				if !errors.Is(closeErr, ErrCleanup) {
					t.Fatal("cleanup uncertainty erased", closeErr)
				}
			}
		})
	}
}
func TestTUNResourceKernelRejectsWithoutAcquisition(t *testing.T) {
	f := newTUNKernelFixture(t)
	copied := reflect.New(reflect.TypeOf(f.r).Elem()).Interface().(*TUNResource)
	reflect.ValueOf(copied).Elem().Set(reflect.ValueOf(f.r).Elem())
	for _, r := range []*TUNResource{nil, {}, copied} {
		if _, err := r.observeKernelLink(context.Background(), f.ops); err == nil {
			t.Fatal("invalid owner accepted")
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled} {
		if _, err := f.r.observeKernelLink(ctx, f.ops); err == nil {
			t.Fatal("invalid context accepted")
		}
	}
	if _, err := f.r.ObserveKernelLink(context.Background()); err == nil {
		t.Fatal("public API accepted fake device")
	}
	if f.opens != 0 || f.r.kernel != nil || f.d.closeCalls != 0 {
		t.Fatal("preflight rejection acquired or destroyed owner")
	}
	if _, err := f.r.observeKernelLink(context.Background(), f.ops); err != nil {
		t.Fatal("preflight poisoned original owner", err)
	}
}
func TestTUNResourceKernelPinCloseFailureSticky(t *testing.T) {
	f := newTUNKernelFixture(t)
	boom := errors.New("namespace close failed")
	base := f.ops.closeFile
	f.ops.closeFile = func(p *os.File) error {
		_ = base(p)
		if p == f.files[0] {
			return boom
		}
		return nil
	}
	if _, err := f.r.observeKernelLink(context.Background(), f.ops); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := f.r.Close(); !errors.Is(err, ErrCleanup) || !errors.Is(err, boom) {
			t.Fatal("lost cleanup evidence", err)
		}
	}
	if f.closes[f.files[0]] != 1 || f.d.closeCalls != 1 {
		t.Fatal("close retried")
	}
}
func TestTUNResourceKernelObservationCloseJoins(t *testing.T) {
	f := newTUNKernelFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	base := f.ops.link
	f.ops.link = func(ctx context.Context, id KernelNamespaceIdentity, name string) (KernelLinkObservation, error) {
		if f.links == 0 {
			close(entered)
			<-release
		}
		return base(ctx, id, name)
	}
	observed := make(chan error, 1)
	go func() { _, err := f.r.observeKernelLink(context.Background(), f.ops); observed <- err }()
	<-entered
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = f.r.Close() }()
	close(release)
	if err := <-observed; err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if f.d.closeCalls != 1 || f.closes[f.files[0]] != 1 {
		t.Fatal("close did not retain/join original observer")
	}
}
func TestTUNRelayKernelBindingReadOnly(t *testing.T) {
	r, tun, d, _, _ := packetBindingRelay(t)
	binding := r.Binding()
	calls := 0
	observe := func(context.Context) (TUNKernelObservation, error) {
		calls++
		return TUNKernelObservation{TUN: d.value, Namespace: KernelNamespaceIdentity{7, 9}, Link: KernelLinkObservation{Index: 12, Name: "mrd0"}}, nil
	}
	if _, err := r.observeKernelBinding(context.Background(), binding, observe); err != nil || calls != 1 || r.attempted || tun.closed {
		t.Fatal("observation consumed lifecycle", err)
	}
	if _, err := r.ObserveKernelBinding(context.Background(), binding); err == nil {
		t.Fatal("public API accepted fake TUN")
	}
	if r.CheckBinding(binding) != nil || d.closeCalls != 0 {
		t.Fatal("failure changed ownership")
	}
	if err := r.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.observeKernelBinding(context.Background(), binding, observe); err == nil || calls != 1 {
		t.Fatal("stopped relay reached observer")
	}
}
func TestTUNRelayKernelBindingRejections(t *testing.T) {
	for _, mode := range []string{"foreign", "copied", "nil", "nil-context", "canceled", "closed-child", "close-during", "cancel-during", "tun-mismatch", "observe-error"} {
		t.Run(mode, func(t *testing.T) {
			r, _, d, _, child := packetBindingRelay(t)
			binding := r.Binding()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			observe := func(context.Context) (TUNKernelObservation, error) {
				calls++
				v := TUNKernelObservation{TUN: d.value}
				switch mode {
				case "close-during":
					_ = child.Close()
				case "cancel-during":
					cancel()
				case "tun-mismatch":
					v.TUN.Name = "other"
				case "observe-error":
					return v, errors.New("injected")
				}
				return v, nil
			}
			switch mode {
			case "foreign":
				binding = TUNRelayBinding{}
			case "copied":
				copyR := reflect.New(reflect.TypeOf(r).Elem()).Interface().(*TUNRelay)
				reflect.ValueOf(copyR).Elem().Set(reflect.ValueOf(r).Elem())
				r = copyR
			case "nil":
				r = nil
			case "nil-context":
				ctx = nil
			case "canceled":
				cancel()
			case "closed-child":
				_ = child.Close()
			}
			if got, err := r.observeKernelBinding(ctx, binding, observe); err == nil || got != (TUNKernelObservation{}) {
				t.Fatal("invalid binding accepted")
			}
			if d.closeCalls != 0 {
				t.Fatal("non-owning failure closed TUN")
			}
			if mode != "close-during" && mode != "cancel-during" && mode != "tun-mismatch" && mode != "observe-error" && calls != 0 {
				t.Fatal("invalid identity/context reached observer")
			}
		})
	}
}
