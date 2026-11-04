//go:build !windows

package windowsvpn

import "context"

func StartSystemBorrowed(context.Context, BorrowedRequest) (*BorrowedSession, error) {
	return nil, ErrUnavailable
}
