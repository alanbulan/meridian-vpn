//go:build !windows

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func commandSignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	// Register SIGPIPE explicitly: writes to a closed stdout/stderr pipe must
	// return EPIPE instead of terminating before foreground cleanup can run.
	// Terminal hangup also requests owned-session cleanup rather than exit.
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM, syscall.SIGPIPE, syscall.SIGHUP)
}
