//go:build !linux

package credentialstore

// NewSystem fails closed on platforms with no reviewed provider.
func NewSystem() Store { return Store{} }
