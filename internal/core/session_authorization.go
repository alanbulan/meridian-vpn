package core

import "context"

// SessionAuthorization is per-use intent, never persisted or reconstructed from
// a profile. Legacy Connect calls grant no Windows-specific permissions.
type SessionAuthorization struct {
	NetworkChanges               bool `json:"-"`
	WindowsCredentialPersistence bool `json:"-"`
	WindowsSharedReference       bool `json:"-"`
}
type AuthorizedAdapter interface {
	StartWithAuthorization(context.Context, Profile, Credentials, SessionAuthorization) (Session, error)
}

// CleanupRetrySession explicitly opts into safe fresh cleanup verification.
// Retrying must not repeat a consumed native release or detach live consumers.
// Nil confirms cleanup now, superseding prior terminal cleanup notifications.
// Implementations must honor context where feasible; Engine does not detach a
// blocking call or infer cleanup merely because a deadline passed.
type CleanupRetrySession interface{ RetryCleanup(context.Context) error }
