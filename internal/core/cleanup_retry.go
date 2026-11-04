package core

import (
	"context"
	"errors"
)

// RetryCleanup retains ownership on every failure. Only opt-in sessions may
// retry: legacy Stop is never repeated. Normal connect/replace/quit stays blocked
// while verification is in progress, including if the original shutdown failed.
func (e *Engine) RetryCleanup(ctx context.Context) error {
	if ctx == nil {
		e.mu.Lock()
		scope := e.attemptScope
		e.mu.Unlock()
		return &CleanupError{scope: scope}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	e.mu.Lock()
	scope := e.attemptScope
	if e.state != CleanupFailed || nilInterface(e.session) || e.cleanupRetrying {
		e.mu.Unlock()
		return &CleanupError{scope: scope}
	}
	if e.finished != nil {
		select {
		case <-e.finished:
		default:
			e.mu.Unlock()
			return errors.New("original cleanup is still finishing")
		}
	}
	retry, ok := e.session.(CleanupRetrySession)
	if !ok {
		e.mu.Unlock()
		return errors.New("backend does not support safe cleanup retry")
	}
	e.cleanupRetrying = true
	e.verifiedScope = ""
	e.message = "Retrying verification of pending VPN cleanup"
	e.mu.Unlock()
	err := func() (err error) {
		defer func() {
			if recover() != nil {
				err = &CleanupError{scope: scope}
			}
		}()
		return retry.RetryCleanup(ctx)
	}()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cleanupRetrying = false
	if err != nil {
		e.message = (&CleanupError{scope: scope}).Error()
		return &CleanupError{scope: scope}
	}
	e.completeLocked(Disconnected, disconnectedMessage(scope), FailureNone)
	return nil
}
