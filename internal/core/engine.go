package core

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync"
	"time"
)

const (
	Disconnected  = "Disconnected"
	Connecting    = "Connecting"
	Connected     = "Connected"
	Disconnecting = "Disconnecting"
	Failed        = "Failed"
	CleanupFailed = "CleanupFailed"
)

type Capability struct {
	Available  bool
	Message    string
	Executable string
}
type LogEntry struct {
	Time    time.Time
	Level   string
	Message string
}
type Snapshot struct {
	State                string
	Failure              FailureKind
	Message              string
	Logs                 []LogEntry
	VirtualIP            string
	Uploaded, Downloaded uint64
	MetricsAvailable     bool
	ConnectedAt          time.Time
}

// Session.Ready must originate from a trusted broker verifying active VPN state
// and its expected interface/address. It does not independently audit routes or
// DNS policy. Process creation or untrusted log output is never readiness.
// Done signals session termination, not a user-requested disconnect. Stop must
// confirm cleanup before returning nil, including after Done has fired.
// Ready and Done each publish at most one result; any terminal result must be
// published before Stop returns. Channels may remain open after that result.
type Session interface {
	Ready() <-chan error
	Done() <-chan error
	Stop() error
}
type Adapter interface {
	Capability() Capability
	Start(context.Context, Profile, []byte) (Session, error)
}

// Credentials are per-attempt secrets. They are never part of Profile or Config.
// Callers retain ownership; ConnectWithCredentials copies and clears its copy.
type Credentials struct {
	IPsecPSK    []byte `json:"-"`
	Password    []byte `json:"-"`
	KeyPassword []byte `json:"-"`
}
type CredentialAdapter interface {
	StartWithCredentials(context.Context, Profile, Credentials) (Session, error)
}

func validateCredentials(p Profile, c Credentials) error {
	if len(c.IPsecPSK) > 4096 || bytes.ContainsAny(c.IPsecPSK, "\r\n\x00") {
		return errors.New("invalid IPsec PSK")
	}
	if p.Protocol == "l2tp" {
		if len(c.IPsecPSK) == 0 || len(c.Password) == 0 {
			return errors.New("L2TP/IPsec requires password and PSK")
		}
	} else if len(c.IPsecPSK) > 0 {
		return errors.New("IPsec PSK requires L2TP protocol")
	}
	if len(c.Password) > 4096 || bytes.ContainsAny(c.Password, "\r\n\x00") {
		return errors.New("password contains unsupported characters or exceeds 4096 bytes")
	}
	if len(c.KeyPassword) > 4096 || bytes.ContainsAny(c.KeyPassword, "\r\n\x00") || (len(c.KeyPassword) > 0 && (c.KeyPassword[0] == ' ' || c.KeyPassword[0] == '\t')) {
		return errors.New("private-key passphrase must not begin with a space or tab, contain CR/LF/NUL, or exceed 4096 bytes")
	}
	if len(c.KeyPassword) > 0 && p.ClientCertificate == "" {
		return errors.New("private-key passphrase requires a client key")
	}
	return nil
}
func (c Credentials) clear() { clear(c.Password); clear(c.KeyPassword); clear(c.IPsecPSK) }

type Engine struct {
	mu             sync.Mutex
	adapter        Adapter
	state, message string
	failure        FailureKind
	logs           []LogEntry
	cancel         context.CancelFunc
	session        Session
	generation     uint64
	finished       chan struct{}
	shuttingDown   bool
	connectedAt    time.Time
}

func NewEngine(a Adapter) *Engine {
	e := &Engine{adapter: a, state: Disconnected, message: "No VPN tunnel is active"}
	e.add("info", "Application ready. No tunnel has been started.")
	return e
}
func (e *Engine) add(level, msg string) {
	e.logs = append(e.logs, LogEntry{time.Now(), level, msg})
	if len(e.logs) > 200 {
		e.logs = append([]LogEntry(nil), e.logs[len(e.logs)-200:]...)
	}
}
func (e *Engine) Snapshot() Snapshot {
	e.mu.Lock()
	snapshot := Snapshot{State: e.state, Failure: e.failure, Message: e.message, Logs: append([]LogEntry(nil), e.logs...), ConnectedAt: e.connectedAt}
	session := e.session
	e.mu.Unlock()
	if snapshot.State == Connected {
		if provider, ok := session.(interface{ Metrics() SessionMetrics }); ok {
			m := provider.Metrics()
			if m.Available {
				snapshot.VirtualIP = m.VirtualIP
				snapshot.Uploaded = m.Uploaded
				snapshot.Downloaded = m.Downloaded
				snapshot.MetricsAvailable = true
			}
		}
	}
	return snapshot
}
func (e *Engine) Connect(p Profile, password string, authorized bool) error {
	c := Credentials{Password: []byte(password)}
	defer c.clear()
	return e.ConnectWithCredentials(p, c, authorized)
}
func (e *Engine) ConnectWithCredentials(p Profile, credentials Credentials, authorized bool) error {
	if err := ValidateProfile(p); err != nil {
		return err
	}
	if err := validateCredentials(p, credentials); err != nil {
		return err
	}
	if !authorized {
		return errors.New("explicit authorization is required before changing network routes or DNS")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.shuttingDown {
		return errors.New("application shutdown is in progress")
	}
	if e.state == Connecting || e.state == Connected || e.state == Disconnecting || e.state == CleanupFailed {
		return errors.New("a connection operation is already active")
	}
	if nilInterface(e.adapter) {
		return errors.New("no backend adapter configured")
	}
	if _, ok := e.adapter.(CredentialAdapter); !ok && (p.Protocol == "l2tp" || p.InteractiveAuth || p.ClientCertificate != "" || len(credentials.KeyPassword) != 0) {
		return errors.New("backend does not support certificate or interactive authentication")
	}
	cap := e.adapter.Capability()
	if !cap.Available {
		e.failure = FailureBackendUnavailable
		e.message = NewConnectionError(FailureBackendUnavailable).Error()
		e.add("warning", "Connection blocked: required backend capability is unavailable.")
		return NewConnectionError(FailureBackendUnavailable)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.generation++
	generation := e.generation
	e.failure = FailureNone
	e.state = Connecting
	e.message = "Waiting for verified tunnel readiness"
	e.add("info", "Connection requested; credentials are not logged or persisted.")
	e.finished = make(chan struct{})
	credentials = Credentials{IPsecPSK: bytes.Clone(credentials.IPsecPSK), Password: bytes.Clone(credentials.Password), KeyPassword: bytes.Clone(credentials.KeyPassword)}
	p.AdditionalGateways = append([]string(nil), p.AdditionalGateways...)
	if p.L2TP != nil {
		options := *p.L2TP
		p.L2TP = &options
	}
	go e.run(ctx, generation, e.finished, p, credentials)
	return nil
}

// CleanupError means privileged cleanup was not confirmed. The UI must not
// report Disconnected or permit another connection in this state.
type CleanupError struct{}

func (*CleanupError) Error() string {
	return "VPN cleanup could not be confirmed; inspect the system VPN service before reconnecting or quitting"
}
func (e *Engine) run(ctx context.Context, generation uint64, finished chan struct{}, p Profile, credentials Credentials) {
	defer close(finished)
	var session Session
	var err error
	if adapter, ok := e.adapter.(CredentialAdapter); ok {
		session, err = adapter.StartWithCredentials(ctx, p, credentials)
	} else {
		session, err = e.adapter.Start(ctx, p, credentials.Password)
	}
	credentials.clear()
	if err != nil || nilInterface(session) {
		if !nilInterface(session) {
			e.beginCleanup()
			cleanupErr := session.Stop()
			pendingCleanup := pendingCleanupFailure(session)
			if cleanupErr != nil || pendingCleanup {
				e.complete(CleanupFailed, (&CleanupError{}).Error(), FailureCleanup)
				return
			}
		}
		if classifyFailure(err, FailureStart) == FailureCleanup {
			e.complete(CleanupFailed, (&CleanupError{}).Error(), FailureCleanup)
			return
		}
		e.mu.Lock()
		if ctx.Err() != nil {
			e.completeLocked(Disconnected, "No VPN tunnel is active", FailureNone)
		} else {
			failure := classifyFailure(err, FailureStart)
			e.completeLocked(Failed, failureMessage(failure, "Backend could not start. Check prerequisites, authentication and gateway configuration."), failure)
		}
		e.mu.Unlock()
		return
	}
	e.mu.Lock()
	e.session = session
	e.mu.Unlock()
	stop := func(message string, failure FailureKind) {
		e.beginCleanup()
		// Stop may complete while cancellation races with a queued terminal
		// notification. Observe both channels after cleanup so select ordering
		// cannot erase an already-reported cleanup uncertainty.
		stopErr := session.Stop()
		pendingCleanup := pendingCleanupFailure(session)
		if stopErr != nil || failure == FailureCleanup || pendingCleanup {
			e.complete(CleanupFailed, (&CleanupError{}).Error(), FailureCleanup)
		} else {
			// Serialize the cancellation check with Disconnect so a user request
			// racing with cleanup cannot be overwritten by a failure result.
			e.mu.Lock()
			if ctx.Err() == nil && message != "" {
				e.completeLocked(Failed, failureMessage(failure, message), failure)
			} else {
				e.completeLocked(Disconnected, "No VPN tunnel is active", FailureNone)
			}
			e.mu.Unlock()
		}
	}
	select {
	case <-ctx.Done():
		stop("", FailureNone)
		return
	case err, ok := <-session.Ready():
		if !ok || err != nil {
			stop("Tunnel ended without verified readiness", classifyFailure(err, FailureReadiness))
			return
		}
	case err := <-session.Done():
		if classifyFailure(err, FailureUnknown) == FailureCleanup {
			e.complete(CleanupFailed, (&CleanupError{}).Error(), FailureCleanup)
		} else {
			stop("Tunnel ended without verified readiness", classifyFailure(err, FailureReadiness))
		}
		return
	}
	// A readiness notification must not override an already-terminal session.
	select {
	case err := <-session.Done():
		if classifyFailure(err, FailureUnknown) == FailureCleanup {
			e.complete(CleanupFailed, (&CleanupError{}).Error(), FailureCleanup)
		} else {
			stop("Tunnel ended without verified readiness", classifyFailure(err, FailureReadiness))
		}
		return
	default:
	}
	e.mu.Lock()
	if ctx.Err() == nil {
		e.state = Connected
		e.connectedAt = time.Now()
		e.message = "Tunnel verified by the trusted broker and its interface"
		e.add("info", "Tunnel readiness verified.")
	}
	e.mu.Unlock()
	select {
	case <-ctx.Done():
		stop("", FailureNone)
	case err := <-session.Done():
		if classifyFailure(err, FailureUnknown) == FailureCleanup {
			e.complete(CleanupFailed, (&CleanupError{}).Error(), FailureCleanup)
		} else {
			stop("Tunnel connection was lost; cleanup completed. Sign in again to reconnect.", classifyFailure(err, FailureConnectionLost))
		}
	}
}

// beginCleanup stops advertising a usable tunnel while Stop verifies removal.
// It deliberately leaves cancellation to Disconnect so unexpected loss remains
// distinguishable from an explicit user cancellation.
func (e *Engine) beginCleanup() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state = Disconnecting
	e.connectedAt = time.Time{}
	e.message = "Waiting for verified tunnel cleanup"
}

func (e *Engine) complete(state, msg string, failure FailureKind) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.completeLocked(state, msg, failure)
}

// completeLocked requires e.mu.
func (e *Engine) completeLocked(state, msg string, failure FailureKind) {
	if e.cancel != nil {
		e.cancel()
	}
	e.cancel = nil
	e.session = nil
	e.state = state
	e.failure = failure
	e.connectedAt = time.Time{}
	e.message = msg
	level := "info"
	if state == Failed || state == CleanupFailed {
		level = "error"
	}
	e.add(level, msg)
}
func (e *Engine) Disconnect() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == CleanupFailed {
		return &CleanupError{}
	}
	if e.cancel == nil {
		return nil
	}
	e.state = Disconnecting
	e.message = "Waiting for verified tunnel cleanup"
	e.add("info", "Disconnect requested.")
	e.cancel()
	return nil
}

// Shutdown blocks until Start/Stop has finished, respecting the caller deadline.
// On any error the application should stay open and explain the cleanup state.
func (e *Engine) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	e.shuttingDown = true
	e.mu.Unlock()
	if err := e.Disconnect(); err != nil {
		return err
	}
	e.mu.Lock()
	done := e.finished
	e.mu.Unlock()
	if done != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == CleanupFailed {
		return &CleanupError{}
	}
	return nil
}
func (e *Engine) ClearLogs() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.logs = nil
	e.add("info", "Activity history cleared.")
}

// ReplaceAdapter refreshes prerequisites without dropping history or active work.
func (e *Engine) ReplaceAdapter(a Adapter) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.shuttingDown || (e.state != Disconnected && e.state != Failed) {
		return errors.New("backend cannot be replaced while connection or shutdown is active")
	}
	if nilInterface(a) {
		return errors.New("no backend adapter configured")
	}
	e.adapter = a
	e.add("info", "Backend prerequisites refreshed.")
	return nil
}
func nilInterface(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return r.IsNil()
	}
	return false
}
