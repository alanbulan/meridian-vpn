package windowsvpn

import (
 "bytes"
 "context"
 "crypto/rand"
 "encoding/hex"
 "net"
 "reflect"
 "sync"
 "time"
)

// Identity is a cryptographically random, per-attempt ownership token. Drivers
// must exclusively create a private phonebook entry for it, never overwrite or
// adopt an existing entry, and bind all operations to that exact entry/handle.
type Identity string

type Observation struct {
 Identity Identity
 Connected bool
 InterfaceIndex uint32
 Address net.IP
}

// Driver is a trusted native boundary, not a command runner. Reserve must not
// mutate the OS. The returned lease must support cleanup even after partial
// Configure/Dial failure. The driver must honor context deadlines and must not
// retain secret slices, log them, store the password, or use argv/environment.
// Reserve is local-only and nonblocking; all OS operations belong to Lease.
// Configure may store the PSK only for this lease's entry. Caller has separately
// approved that persistence. No supplied production implementation exists yet.
type Driver interface { Reserve(Identity) (Lease, error) }

type Lease interface {
 // Configure borrows only the PSK for this call. It must clear every native
 // conversion buffer and stop all consumers before returning, even on error.
 // The sole persistence exception is the explicitly authorized owned RAS PSK.
 Configure(context.Context, Request, []byte) error
 // Dial borrows only the password for this call. It must never save it to a
 // phonebook/credential cache or retain a copy for reconnect. All asynchronous
 // native consumers must finish/cancel and all conversion buffers be erased
 // before return. The controller erases its borrowed slice immediately after.
 Dial(context.Context, []byte) error
 Inspect(context.Context) (Observation, error)
 // Cleanup must hang up and wait for RAS handle termination, then clear PSK
 // and delete only the owned entry. Success confirms all of these outcomes.
 // Repeated calls must be safe. A command returning success is insufficient.
 Cleanup(context.Context) error
}

// Controller serializes operations and retains a failed-cleanup lease so a
// later Stop can retry. It does not yet implement core.Adapter or auto-monitor.
type Controller struct {
 // opMu serializes lease access, including cleanup. mu separately protects
 // cancellation so Stop never waits for an OS call before requesting cancel.
 opMu sync.Mutex
 mu sync.Mutex
 operationCancel context.CancelFunc
 stopping int
 driver Driver
 lease Lease
 identity Identity
 ready bool
}

func New(driver Driver) *Controller { return &Controller{driver: driver} }

func (c *Controller) Start(ctx context.Context, r Request, secrets Secrets, consent Consent) error {
 if err := validate(r, secrets, consent); err != nil { return err }
 c.opMu.Lock()
 defer c.opMu.Unlock()
 op, finish, err := c.begin(ctx, 90*time.Second)
 if err != nil { return err }
 defer finish()
 if c.lease != nil { return ErrBusy }
 if nilValue(c.driver) { return ErrUnavailable }
 if err := op.Err(); err != nil { return err }
 var token [16]byte
 if _, err := rand.Read(token[:]); err != nil { return ErrOperation }
 id := Identity("Meridian-" + hex.EncodeToString(token[:]))
 lease, err := c.driver.Reserve(id)
 if err != nil || nilValue(lease) { return ErrOperation }
 c.lease, c.identity = lease, id
 copySecrets := Secrets{Password: bytes.Clone(secrets.Password), PSK: bytes.Clone(secrets.PSK)}
 erase := func() { clear(copySecrets.Password); clear(copySecrets.PSK) }
 defer erase()
 fail := func(cause error) error { erase(); return c.failed(cause) }
 if err := op.Err(); err != nil { return fail(err) }
 configureErr := lease.Configure(op, r, copySecrets.PSK)
 clear(copySecrets.PSK)
 if err := op.Err(); err != nil { return fail(err) }
 if configureErr != nil { return fail(ErrOperation) }
 dialErr := lease.Dial(op, copySecrets.Password)
 clear(copySecrets.Password)
 if err := op.Err(); err != nil { return fail(err) }
 if dialErr != nil { return fail(ErrOperation) }
 observation, err := lease.Inspect(op)
 if err != nil || !verified(observation, id) { return fail(ErrVerification) }
 if err := op.Err(); err != nil { return fail(err) }
 c.ready = true
 return nil
}

func verified(o Observation, id Identity) bool {
 return o.Identity == id && o.Connected && o.InterfaceIndex != 0 && o.Address != nil && !o.Address.IsUnspecified() && !o.Address.IsLoopback() && !o.Address.IsMulticast() && (o.Address.To4() != nil || o.Address.To16() != nil)
}

// Check verifies fresh state instead of treating a successful dial as readiness.
// It must be called by any future application's lifecycle monitor.
func (c *Controller) Check(ctx context.Context) error {
 c.opMu.Lock()
 defer c.opMu.Unlock()
 op, finish, err := c.begin(ctx, 10*time.Second)
 if err != nil { return err }
 defer finish()
 if c.lease == nil || !c.ready { return ErrVerification }
 o, err := c.lease.Inspect(op)
 if err != nil || op.Err() != nil || !verified(o, c.identity) { return c.failed(ErrVerification) }
 return nil
}

func (c *Controller) failed(cause error) error {
 if err := c.cleanup(); err != nil { return err }
 return cause
}

// begin is called with opMu held. Registration and Stop's cancellation request
// are atomic with respect to each other. No new operation can begin while a
// Stop is queued, including between another Stop's cleanup and return.
func (c *Controller) begin(ctx context.Context, timeout time.Duration) (context.Context, func(), error) {
 c.mu.Lock()
 defer c.mu.Unlock()
 if c.stopping != 0 { return nil, nil, ErrBusy }
 op, cancel := context.WithTimeout(ctx, timeout)
 c.operationCancel = cancel
 return op, func() {
  cancel()
  c.mu.Lock()
  c.operationCancel = nil
  c.mu.Unlock()
 }, nil
}

func (c *Controller) Stop() error {
 c.mu.Lock()
 c.stopping++
 if c.operationCancel != nil { c.operationCancel() }
 c.mu.Unlock()
 c.opMu.Lock()
 defer c.opMu.Unlock()
 defer func() {
  c.mu.Lock()
  c.stopping--
  c.mu.Unlock()
 }()
 return c.cleanup()
}

func (c *Controller) cleanup() error {
 c.ready = false
 if c.lease == nil { return nil }
 // Cleanup must outlive a canceled authentication/connection context.
 ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
 defer cancel()
 if err := c.lease.Cleanup(ctx); err != nil || ctx.Err() != nil { return ErrCleanup }
 c.lease, c.identity = nil, ""
 return nil
}

func nilValue(value any) bool {
 if value == nil { return true }
 v := reflect.ValueOf(value)
 switch v.Kind() {
 case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
  return v.IsNil()
 default:
  return false
 }
}
