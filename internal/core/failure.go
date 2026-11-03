package core

import "errors"

// FailureKind is a closed, secret-free classification, not a retry policy.
// Even transport failures require fresh authorization and credentials; cleanup
// uncertainty always blocks another attempt. Zero means no recorded failure.
type FailureKind uint8

const (
	FailureNone FailureKind = iota
	FailureUnknown
	FailureBackendUnavailable
	FailureStart
	FailureReadiness
	FailureConnectionLost
	FailureCleanup
	FailureAuthentication
	FailureTrust
	FailureConfiguration
	FailureTransport
)

// ConnectionError lets a trusted adapter supply a structured failure without
// retaining an underlying error, output, endpoint, credential or server label.
// Adapters must not infer these categories by matching untrusted output text.
// Use NewConnectionError rather than constructing a zero value.
type ConnectionError struct{ kind FailureKind }

func NewConnectionError(kind FailureKind) *ConnectionError {
	if kind < FailureUnknown || kind > FailureTransport {
		kind = FailureUnknown
	}
	return &ConnectionError{kind: kind}
}

func (e *ConnectionError) Kind() FailureKind {
	if e == nil || e.kind < FailureUnknown || e.kind > FailureTransport {
		return FailureUnknown
	}
	return e.kind
}

// Is preserves cleanup quarantine through wrapping and joined errors.
func (e *ConnectionError) Is(target error) bool {
	_, cleanup := target.(*CleanupError)
	return cleanup && e.Kind() == FailureCleanup
}

func (e *ConnectionError) Error() string {
	switch e.Kind() {
	case FailureBackendUnavailable:
		return "Required VPN backend capability is unavailable"
	case FailureStart:
		return "VPN backend could not start"
	case FailureReadiness:
		return "VPN tunnel readiness was not verified"
	case FailureConnectionLost:
		return "VPN tunnel connection was lost"
	case FailureCleanup:
		return (&CleanupError{}).Error()
	case FailureAuthentication:
		return "VPN authentication failed"
	case FailureTrust:
		return "VPN peer trust could not be verified"
	case FailureConfiguration:
		return "VPN configuration was rejected"
	case FailureTransport:
		return "VPN transport failed"
	default:
		return "VPN connection failed"
	}
}

// classifyFailure ignores raw strings and preserves cleanup as the highest
// priority even when errors.Join contains another typed classification.
func classifyFailure(err error, fallback FailureKind) FailureKind {
	var cleanup *CleanupError
	if errors.As(err, &cleanup) || errors.Is(err, &CleanupError{}) {
		return FailureCleanup
	}
	var failure *ConnectionError
	if errors.As(err, &failure) {
		return failure.Kind()
	}
	return NewConnectionError(fallback).Kind()
}

// pendingCleanupFailure is called only after Stop has returned, when the engine
// is no longer accepting readiness. Consume at most one notification per channel
// (the Session contract supplies one terminal result); never block on a backend.
func pendingCleanupFailure(session Session) bool {
	cleanup := false
	select {
	case err := <-session.Ready():
		cleanup = classifyFailure(err, FailureUnknown) == FailureCleanup
	default:
	}
	select {
	case err := <-session.Done():
		cleanup = classifyFailure(err, FailureUnknown) == FailureCleanup || cleanup
	default:
	}
	return cleanup
}
