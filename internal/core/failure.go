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

// Is preserves exact classifications through wrapping and joined errors.
func (e *ConnectionError) Is(target error) bool {
	if _, cleanup := target.(*CleanupError); cleanup {
		return e.Kind() == FailureCleanup
	}
	other, ok := target.(*ConnectionError)
	return ok && e.Kind() == other.Kind()
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

// classifyFailure ignores raw strings. A joined transport failure must not
// hide an authentication, trust or other non-transport failure just because
// it appears first. These are diagnostic categories, never retry permission.
func classifyFailure(err error, fallback FailureKind) FailureKind {
	var cleanup *CleanupError
	if errors.As(err, &cleanup) || errors.Is(err, &CleanupError{}) {
		return FailureCleanup
	}
	for _, kind := range []FailureKind{
		FailureTrust, FailureAuthentication, FailureConfiguration,
		FailureBackendUnavailable, FailureUnknown, FailureStart,
		FailureReadiness, FailureConnectionLost, FailureTransport,
	} {
		if errors.Is(err, NewConnectionError(kind)) {
			return kind
		}
	}
	var failure *ConnectionError
	if errors.As(err, &failure) {
		return failure.Kind()
	}
	return NewConnectionError(fallback).Kind()
}

// Non-transport failures should not invite another sign-in as a remedy. These
// fixed messages reveal neither the backend output nor the server's response.
func failureMessage(kind FailureKind, fallback string) string {
	switch kind {
	case FailureAuthentication, FailureTrust, FailureConfiguration, FailureBackendUnavailable, FailureUnknown, FailureStart, FailureReadiness:
		return NewConnectionError(kind).Error()
	default:
		return fallback
	}
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
