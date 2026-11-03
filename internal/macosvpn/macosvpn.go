// Package macosvpn provides low-level control of an existing macOS L2TP service.
// It is deliberately not a core.Adapter: OS Connected does not verify interface,
// routing, DNS or intranet readiness. No profiles or credentials are written.
package macosvpn

import (
 "context"
 "errors"
 "strings"
 "sync"
 "time"
)

// CF text reads reserve one byte for the C string terminator.
const maxServiceIDBytes = 127

type Status int32
const (
 Invalid Status = -1
 Disconnected Status = 0
 Connecting Status = 1
 Connected Status = 2
 Disconnecting Status = 3
)
var (
 ErrAuthorization = errors.New("explicit authorization for this system VPN service is required")
 ErrBusy = errors.New("system VPN service is already active; refusing to adopt it")
 ErrCleanup = errors.New("system VPN disconnection is unconfirmed; another application may retain interest")
 ErrClosed = errors.New("system VPN reference is closed")
)

type connection interface {
 status() Status
 start() error // Must use NULL userOptions and linger=false.
 stop() error // Must use forceDisconnect=false.
 close()
}

// Session owns only this application's interest in the existing system service,
// not exclusive ownership of the service or its persistent configuration.
// Call Stop even after WaitConnected fails. Stop may be retried after a timeout.
type Session struct {
 mu sync.Mutex
 native connection
 stopping bool
 observedProgress bool
 poll time.Duration
}

// StartExistingL2TP starts precisely serviceID, using credentials already managed
// by macOS. authorized must describe approval to connect that existing service,
// including its network changes and use of its previously configured credentials.
// This function does not install services or obtain elevated privileges.
func StartExistingL2TP(ctx context.Context, serviceID string, authorized bool) (*Session, error) {
 return startExisting(ctx, serviceID, authorized, openNative)
}

func startExisting(ctx context.Context, id string, authorized bool, open func(string) (connection, error)) (*Session, error) {
 if !authorized { return nil, ErrAuthorization }
 if err := ctx.Err(); err != nil { return nil, err }
 // A system service identifier, never a display name, command or path.
 if len(id) == 0 || len(id) > maxServiceIDBytes || strings.ContainsAny(id, "\x00\r\n") { return nil, errors.New("invalid system service identifier") }
 for _, c := range id { if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') { return nil, errors.New("invalid system service identifier") } }
 n, err := open(id)
 if err != nil { return nil, err }
 if n.status() != Disconnected { n.close(); return nil, ErrBusy }
 if err := ctx.Err(); err != nil { n.close(); return nil, err }
 if err := n.start(); err != nil { n.close(); return nil, err }
 return &Session{native:n, poll:200*time.Millisecond}, nil
}

// Status returns only SystemConfiguration's high-level connection state.
func (s *Session) Status() (Status, error) {
 s.mu.Lock(); defer s.mu.Unlock()
 if s.native == nil { return Invalid, ErrClosed }
 v := s.native.status()
 if v == Connecting || v == Connected { s.observedProgress = true }
 if v < Disconnected || v > Disconnecting { return Invalid, errors.New("invalid system VPN status") }
 return v, nil
}

// WaitConnected waits for the OS connection state, NOT verified tunnel readiness.
// Start is asynchronous: initial Disconnected observations are not failures.
// Use a deadline/cancelable context to bound an accepted start that never advances.
// A timeout/cancellation does not discard the session: the caller must Stop it.
func (s *Session) WaitConnected(ctx context.Context) error {
 for {
  if err := ctx.Err(); err != nil { return err }
  s.mu.Lock()
  if s.stopping { s.mu.Unlock(); return errors.New("system VPN is stopping") }
  if s.native == nil { s.mu.Unlock(); return ErrClosed }
  state := s.native.status()
  if state == Connecting || state == Connected { s.observedProgress = true }
  progressed := s.observedProgress
  if state == Connected { s.mu.Unlock(); return nil }
  s.mu.Unlock()
  if state < Disconnected || state > Disconnecting { return errors.New("invalid system VPN status") }
  if state == Disconnecting || (state == Disconnected && progressed) { return errors.New("system VPN did not reach connected state") }
  if err := pause(ctx, s.poll); err != nil { return err }
 }
}

// Stop withdraws this application's interest, never forces other applications
// off the service, and retains the reference until disconnection is observed.
// Success does not independently verify restoration of routes or DNS.
func (s *Session) Stop(ctx context.Context) error {
 s.mu.Lock()
 if s.native == nil { s.mu.Unlock(); return nil }
 s.stopping = true
 if err := s.native.stop(); err != nil { s.mu.Unlock(); return errors.Join(ErrCleanup, err) }
 s.mu.Unlock()
 for {
  s.mu.Lock()
  if s.native == nil { s.mu.Unlock(); return nil }
  state := s.native.status()
  if state == Disconnected { s.native.close(); s.native=nil; s.mu.Unlock(); return nil }
  s.mu.Unlock()
  if state < Disconnected || state > Disconnecting { return ErrCleanup }
  if err := pause(ctx, s.poll); err != nil { return errors.Join(ErrCleanup, err) }
 }
}
func pause(ctx context.Context, d time.Duration) error {
 t:=time.NewTimer(d); defer t.Stop()
 select { case <-ctx.Done(): return ctx.Err(); case <-t.C: return nil }
}
