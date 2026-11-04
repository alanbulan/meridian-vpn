//go:build windows

package windowsvpn

import "context"

// StartSystemBorrowed is explicitly invoked only after per-use consent. It may
// load RAS/start its service, read the exact existing profile, and dial it. No
// default application path invokes this unless limited mode is enabled.
func StartSystemBorrowed(ctx context.Context, request BorrowedRequest) (*BorrowedSession, error) {
	return startBorrowedSession(ctx, request, newSystemBorrowedSession, InspectSystemEntry)
}
