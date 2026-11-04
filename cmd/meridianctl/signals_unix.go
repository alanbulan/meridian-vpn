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
	// Terminal hangup and job-control signals request cleanup rather than
	// leaving an owned VPN or a no-echo authentication prompt suspended.
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGPIPE, syscall.SIGHUP, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU)
}
