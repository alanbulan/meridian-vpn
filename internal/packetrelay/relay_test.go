package packetrelay

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakePackets struct {
	reads              chan []byte
	writes             chan []byte
	closed             chan struct{}
	closes             atomic.Int32
	once               sync.Once
	short              bool
	writeErr, closeErr error
	blockWrite         bool
	writeStarted chan struct{}
}

func fake() *fakePackets {
	return &fakePackets{reads: make(chan []byte, 4), writes: make(chan []byte, 4), closed: make(chan struct{})}
}
func (f *fakePackets) ReadPacket(b []byte) (int, error) {
	select {
	case <-f.closed:
		return 0, io.ErrClosedPipe
	case p := <-f.reads:
		if p == nil {
			return 0, io.EOF
		}
		return copy(b, p), nil
	}
}
func (f *fakePackets) WritePacket(b []byte) (int, error) {
	if f.writeStarted != nil {
		select { case f.writeStarted <- struct{}{}: default: }
	}
	if f.blockWrite {
		<-f.closed
		return 0, io.ErrClosedPipe
	}
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if f.short {
		return len(b) - 1, nil
	}
	select {
	case <-f.closed:
		return 0, io.ErrClosedPipe
	case f.writes <- append([]byte(nil), b...):
		return len(b), nil
	}
}
func (f *fakePackets) Close() error {
	f.closes.Add(1)
	f.once.Do(func() { close(f.closed) })
	return f.closeErr
}

type outcome struct {
	c Counts
	e error
}

func finish(t *testing.T, ch <-chan outcome, h, c *fakePackets) outcome {
	t.Helper()
	select {
	case r := <-ch:
		if h.closes.Load() != 1 || c.closes.Load() != 1 {
			t.Fatalf("close counts %d %d", h.closes.Load(), c.closes.Load())
		}
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not stop")
		return outcome{}
	}
}
func launch(ctx context.Context, p *Policy, h, c *fakePackets) <-chan outcome {
	ch := make(chan outcome, 1)
	go func() { n, e := Run(ctx, p, h, c); ch <- outcome{n, e} }()
	return ch
}
func receive(t *testing.T, c <-chan []byte) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(time.Second):
		t.Fatal("no forwarded packet")
	}
}
func TestRelayBothDirectionsAndCancellation(t *testing.T) {
	h, c := fake(), fake()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := launch(ctx, policy(t), h, c)
	h.reads <- packet(17, "10.8.0.2", "10.20.0.10")
	c.reads <- packet(17, "10.20.0.10", "10.8.0.2")
	receive(t, c.writes)
	receive(t, h.writes)
	cancel()
	r := finish(t, done, h, c)
	if !errors.Is(r.e, context.Canceled) || r.c.Outbound != 1 || r.c.Inbound != 1 {
		t.Fatalf("%+v", r)
	}
}
func TestRelayFailureClosesBoth(t *testing.T) {
	for _, kind := range []string{"malformed", "oversize", "eof", "short", "write-error", "blocked-write"} {
		t.Run(kind, func(t *testing.T) {
			h, c := fake(), fake()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := ErrRejected
			switch kind {
			case "short":
				c.short = true
				want = io.ErrShortWrite
			case "write-error":
				c.writeErr = io.ErrUnexpectedEOF
				want = io.ErrUnexpectedEOF
			case "eof":
				want = io.EOF
			case "blocked-write":
				c.blockWrite = true
				want = context.Canceled
			}
			done := launch(ctx, policy(t), h, c)
			b := packet(17, "10.8.0.2", "10.20.0.10")
			switch kind {
			case "malformed":
				b[0] = 0
			case "oversize":
				b = make([]byte, 1600)
			case "eof":
				b = nil
			}
			h.reads <- b
			if kind == "blocked-write" {
				cancel()
			}
			r := finish(t, done, h, c)
			if !errors.Is(r.e, want) {
				t.Fatalf("want %v got %v", want, r.e)
			}
			if kind == "malformed" || kind == "oversize" {
				if len(c.writes) != 0 || r.c.Rejected != 1 {
					t.Fatal("rejected packet was forwarded")
				}
			}
		})
	}
}
func TestCleanupFailureAndNil(t *testing.T) {
	h, c := fake(), fake()
	sentinel := errors.New("cleanup uncertain")
	h.closeErr = sentinel
	h.reads <- nil
	r := finish(t, launch(context.Background(), policy(t), h, c), h, c)
	if !errors.Is(r.e, sentinel) || !errors.Is(r.e, ErrCleanup) || !errors.Is(r.e, io.EOF) {
		t.Fatalf("lost close error: %v", r.e)
	}
	var nilFake *fakePackets
	h = fake()
	if _, e := Run(context.Background(), policy(t), h, nilFake); e == nil || h.closes.Load() != 1 {
		t.Fatal("typed nil not handled")
	}
	h = fake()
	if _, e := Run(context.Background(), policy(t), h, h); e == nil || h.closes.Load() != 1 {
		t.Fatal("aliased endpoints not handled")
	}
}
func TestRejectNonPacketFile(t *testing.T) {
	f, e := os.CreateTemp(t.TempDir(), "not-a-device")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = NewFilePackets(f); e == nil {
		t.Fatal("regular file accepted")
	}
	if _, e = f.Stat(); e != nil {
		t.Fatal("constructor took ownership on error")
	}
	if _, e = NewFilePackets(nil); e == nil {
		t.Fatal("nil file accepted")
	}
}
