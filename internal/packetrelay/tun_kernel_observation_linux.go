//go:build linux

package packetrelay

import (
	"context"
	"errors"
	"os"
)

// TUNKernelObservation combines descriptor-derived namespace/name evidence with
// a kernel link lookup in that namespace. The link lookup is NOT made by TUN FD:
// names and ifindexes can be reused, and rename-away-and-back races remain.
// It is sequential consistency, not a device-generation identity, host namespace
// assertion, ownership lease, applied policy, readiness, or absence proof.
type TUNKernelObservation struct {
	TUN TUNObservation
	Namespace KernelNamespaceIdentity
	Link KernelLinkObservation
}

// The original resource owns this extra read-only namespace pin. The pin never
// owns/duplicates the TUN descriptor. Resource.Close closes it once, including
// after a failed observation. All fields are protected by TUNResource.mu.
type tunKernelPin struct {
	file *os.File
	identity KernelNamespaceIdentity
	initial *TUNKernelObservation
	invalid error
	cleanupErr error
	closed bool
	closeFile func(*os.File) error
}

func (p *tunKernelPin) close() error {
	if p == nil {
		return nil
	}
	if !p.closed {
		p.closed = true
		if p.file != nil {
			if err := p.closeFile(p.file); err != nil {
				p.cleanupErr = errors.Join(p.cleanupErr, ErrCleanup, err)
			}
		}
	}
	return p.cleanupErr
}

type tunKernelObservationOps struct {
	openNamespace func() (*os.File, KernelNamespaceIdentity, error)
	inspectNamespace func(*os.File) (KernelNamespaceIdentity, error)
	link func(context.Context, KernelNamespaceIdentity, string) (KernelLinkObservation, error)
	closeFile func(*os.File) error
}

// ObserveKernelLink only observes this resource's original concrete TUN. It
// retains a private network-namespace FD obtained from TUNGETDEVNETNS and reads
// that namespace's link metadata without setns or any networking mutation.
// TUNGETDEVNETNS needs CAP_NET_ADMIN in the device namespace's owning user ns;
// unsupported/denied reads fail, with no fallback to an ambient or named device.
//
// The first begun failure permanently invalidates this observer. Failed reads
// never close the TUN or discard its cleanup owner. Call Close (or the owning
// relay's Stop/Wait) to release the retained namespace pin even after failure.
// InitialKernelObservation remains historical metadata after invalidation/close.
// Link I/O is bounded, but context cannot interrupt a mutex or in-flight ioctl.
// No normal application path invokes this API.
func (r *TUNResource) ObserveKernelLink(ctx context.Context) (TUNKernelObservation, error) {
	if r == nil || r.self != r {
		return TUNKernelObservation{}, errTUNKernelObservation
	}
	d, ok := r.device.(*tunFileDevice)
	if !ok || d == nil || d.raw == nil {
		return TUNKernelObservation{}, errTUNKernelObservation
	}
	return r.observeKernelLink(ctx, tunKernelObservationOps{
		openNamespace: func() (*os.File, KernelNamespaceIdentity, error) { return openTUNNetworkNamespace(d.raw) },
		inspectNamespace: inspectNetworkNamespace,
		link: readTUNKernelLink,
		closeFile: func(f *os.File) error { return f.Close() },
	})
}

// Only package tests may substitute I/O. Public entry points require the
// concrete original tunFileDevice and the fixed read-only kernel operations.
func (r *TUNResource) observeKernelLink(ctx context.Context, ops tunKernelObservationOps) (TUNKernelObservation, error) {
	zero := TUNKernelObservation{}
	if r == nil || r.self != r || ctx == nil || ctx.Err() != nil || ops.openNamespace == nil || ops.inspectNamespace == nil || ops.link == nil || ops.closeFile == nil {
		return zero, errTUNKernelObservation
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return zero, errors.Join(errTUNKernelObservation, err)
	}
	if r.closed || r.device == nil || !r.observed {
		return zero, errors.Join(errTUNKernelObservation, r.closeErr)
	}
	if r.kernel == nil {
		// Retain the observer before acquiring any handle, including an error
		// return containing a partially validated namespace FD.
		r.kernel = &tunKernelPin{closeFile: ops.closeFile}
		r.kernel.file, r.kernel.identity, r.kernel.invalid = ops.openNamespace()
		if r.kernel.file == nil || r.kernel.identity.Inode == 0 {
			r.kernel.invalid = errors.Join(errTUNKernelObservation, r.kernel.invalid)
		}
	}
	p := r.kernel
	fail := func(err error) (TUNKernelObservation, error) {
		p.invalid = errors.Join(errTUNKernelObservation, p.invalid, err)
		if errors.Is(p.invalid, ErrCleanup) {
			p.cleanupErr = errors.Join(p.cleanupErr, p.invalid)
		}
		return zero, p.invalid
	}
	if p.invalid != nil {
		return zero, p.invalid
	}
	if p.closed {
		return fail(nil)
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		tun, err := r.device.observe()
		if err != nil || tun != r.initial {
			return errors.Join(errTUNKernelObservation, err)
		}
		retained, err := ops.inspectNamespace(p.file)
		if err != nil || retained != p.identity || ctx.Err() != nil {
			return errors.Join(errTUNKernelObservation, err, ctx.Err())
		}
		// Get a fresh descriptor-derived namespace, not a /proc/name lookup.
		// Each temporary FD closes once; an uncertain close is never retried.
		current, identity, err := ops.openNamespace()
		if current == nil || identity != p.identity {
			err = errors.Join(errTUNKernelObservation, err)
		}
		if current != nil {
			if closeErr := ops.closeFile(current); closeErr != nil {
				err = errors.Join(err, ErrCleanup, closeErr)
			}
		}
		return errors.Join(err, ctx.Err())
	}
	if err := check(); err != nil {
		return fail(err)
	}
	first, err := ops.link(ctx, p.identity, r.initial.Name)
	if err != nil {
		return fail(err)
	}
	if err := check(); err != nil {
		return fail(err)
	}
	second, err := ops.link(ctx, p.identity, r.initial.Name)
	if err != nil || first != second || second.Name != r.initial.Name || second.Index <= 0 {
		return fail(err)
	}
	if err := check(); err != nil {
		return fail(err)
	}
	// Preserve the first observed ifindex across later reads. Equality still
	// cannot rule out index/name ABA and must never confer generation authority.
	if p.initial != nil && p.initial.Link.Index != second.Index {
		return fail(nil)
	}
	result := TUNKernelObservation{TUN: r.initial, Namespace: p.identity, Link: second}
	if p.initial == nil {
		initial := result
		p.initial = &initial
	}
	return result, nil
}

// InitialKernelObservation returns only copied historical metadata. It performs
// no live I/O and does not revalidate the retained namespace, link or TUN.
func (r *TUNResource) InitialKernelObservation() (TUNKernelObservation, error) {
	if r == nil || r.self != r {
		return TUNKernelObservation{}, errTUNKernelObservation
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.kernel == nil || r.kernel.initial == nil {
		return TUNKernelObservation{}, errTUNKernelObservation
	}
	return *r.kernel.initial, nil
}

// ObserveKernelBinding adds kernel observations of the original TUN behind this
// exact retained relay identity. It does not start forwarding or consume Start.
// A mismatch never adopts/closes another relay. The existing owner retains all
// cleanup, including any namespace FD acquired by an observation that failed.
func (r *TUNRelay) ObserveKernelBinding(ctx context.Context, binding TUNRelayBinding) (TUNKernelObservation, error) {
	if r == nil || r.tun == nil {
		return TUNKernelObservation{}, errTUNKernelObservation
	}
	return r.observeKernelBinding(ctx, binding, r.tun.ObserveKernelLink)
}

func (r *TUNRelay) observeKernelBinding(ctx context.Context, binding TUNRelayBinding, observe func(context.Context) (TUNKernelObservation, error)) (TUNKernelObservation, error) {
	zero := TUNKernelObservation{}
	if r.CheckBinding(binding) != nil || ctx == nil || ctx.Err() != nil || observe == nil {
		return zero, errTUNKernelObservation
	}
	child, ok := r.child.(*DatagramPackets)
	if !ok || r.CheckPacketBinding(binding, child) != nil {
		return zero, errTUNKernelObservation
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case <-r.done:
		return zero, errors.Join(errTUNKernelObservation, r.cleanupErr)
	default:
	}
	if err := ctx.Err(); err != nil {
		return zero, errors.Join(errTUNKernelObservation, err)
	}
	if err := child.raw.Control(func(uintptr) {}); err != nil {
		return zero, errors.Join(errTUNKernelObservation, err)
	}
	value, err := observe(ctx)
	if err != nil || ctx.Err() != nil || value.TUN != r.tun.initial {
		return zero, errors.Join(errTUNKernelObservation, err, ctx.Err())
	}
	if err := child.raw.Control(func(uintptr) {}); err != nil {
		return zero, errors.Join(errTUNKernelObservation, err)
	}
	if err := ctx.Err(); err != nil {
		return zero, errors.Join(errTUNKernelObservation, err)
	}
	return value, nil
}
