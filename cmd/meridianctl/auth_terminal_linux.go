//go:build linux && (amd64 || arm64)

package main

import (
	"context"
	"errors"
	"mygo-vpn/internal/core"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"
)

// Linux asm-generic termios ioctls used by amd64 and arm64. TCSETS is immediate;
// never use the drain variants, which can block indefinitely during cancellation.
const terminalFlushInput = 0x540b

type linuxAuthTerminal struct {
	mu            sync.Mutex
	fd            int
	saved         *syscall.Termios
	restoreFailed bool
}

func terminalIoctl(fd int, request uintptr, value unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, uintptr(value))
	if errno != 0 {
		return errno
	}
	return nil
}

func openAuthTerminal() (authTerminal, error) {
	fd, err := syscall.Open("/dev/tty", syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errTerminalAuth
	}
	t := &linuxAuthTerminal{fd: fd}
	var state syscall.Termios
	if !t.foreground() || terminalIoctl(fd, syscall.TCGETS, unsafe.Pointer(&state)) != nil {
		_ = syscall.Close(fd)
		return nil, errTerminalAuth
	}
	return t, nil
}

func (t *linuxAuthTerminal) foreground() bool {
	var group int32
	return terminalIoctl(t.fd, syscall.TIOCGPGRP, unsafe.Pointer(&group)) == nil && int(group) == syscall.Getpgrp()
}

// Job-control signals must not restart a tty syscall forever after the process
// loses its foreground group. Keep the process-wide NotifyContext handlers;
// only the OS thread doing terminal IO temporarily blocks SIGTTIN/SIGTTOU.
func blockTerminalJobControl() (func() error, error) {
	runtime.LockOSThread()
	mask := uint64(1) << (uint(syscall.SIGTTIN) - 1)
	mask |= uint64(1) << (uint(syscall.SIGTTOU) - 1)
	var previous uint64
	_, _, errno := syscall.RawSyscall6(syscall.SYS_RT_SIGPROCMASK, 0, uintptr(unsafe.Pointer(&mask)), uintptr(unsafe.Pointer(&previous)), 8, 0, 0)
	if errno != 0 {
		runtime.UnlockOSThread()
		return nil, errTerminalAuth
	}
	return func() error {
		_, _, errno := syscall.RawSyscall6(syscall.SYS_RT_SIGPROCMASK, 2, uintptr(unsafe.Pointer(&previous)), 0, 8, 0, 0)
		if errno != 0 {
			// Do not return a thread with an unexpected mask to the scheduler.
			// The failing foreground operation ends this goroutine/process; Go
			// retires a locked thread when its goroutine exits.
			return errTerminalAuth
		}
		runtime.UnlockOSThread()
		return nil
	}, nil
}

func (t *linuxAuthTerminal) restore() error {
	if t.saved == nil {
		return nil
	}
	// Discard unread secret bytes before returning the terminal to the shell.
	_, _, flushErr := syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.fd), terminalFlushInput, 0)
	err := terminalIoctl(t.fd, syscall.TCSETS, unsafe.Pointer(t.saved))
	if err == nil && flushErr == 0 {
		t.saved = nil
		return nil
	}
	t.restoreFailed = true
	return errTerminalAuth
}

func (t *linuxAuthTerminal) Close() (err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fd < 0 {
		if t.restoreFailed {
			return errTerminalAuth
		}
		return nil
	}
	restoreMask, err := blockTerminalJobControl()
	if err != nil {
		return errTerminalAuth
	}
	defer func() {
		if restoreMask() != nil {
			t.restoreFailed = true
			err = errTerminalAuth
		}
	}()
	err = t.restore()
	closeErr := syscall.Close(t.fd)
	t.fd = -1
	if err != nil || closeErr != nil || t.restoreFailed {
		return errTerminalAuth
	}
	return nil
}

func (t *linuxAuthTerminal) Prompt(ctx context.Context, ch core.AuthChallenge) (answer core.AuthAnswer, err error) {
	if !t.mu.TryLock() {
		return answer, errTerminalAuth
	}
	defer t.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if t.fd < 0 || t.restoreFailed || ctx.Err() != nil || !validTerminalChallenge(ch) || !t.foreground() {
		return answer, errTerminalAuth
	}
	restoreMask, err := blockTerminalJobControl()
	if err != nil {
		return answer, errTerminalAuth
	}
	defer func() {
		if restoreMask() != nil {
			t.restoreFailed = true
			for _, value := range answer.Values {
				clear(value)
			}
			answer = core.AuthAnswer{}
			err = errTerminalAuth
		}
	}()
	var state syscall.Termios
	if terminalIoctl(t.fd, syscall.TCGETS, unsafe.Pointer(&state)) != nil {
		return answer, errTerminalAuth
	}
	t.saved = &state
	defer func() {
		if t.restore() != nil {
			for _, v := range answer.Values {
				clear(v)
			}
			answer = core.AuthAnswer{}
			err = errTerminalAuth
		}
	}()
	hidden := state
	hidden.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.IEXTEN
	hidden.Lflag |= syscall.ISIG
	hidden.Iflag &^= syscall.IGNCR | syscall.INLCR | syscall.ISTRIP | syscall.IXON
	hidden.Iflag |= syscall.ICRNL
	hidden.Cc[syscall.VMIN] = 0
	hidden.Cc[syscall.VTIME] = 0
	if terminalIoctl(t.fd, syscall.TCSETS, unsafe.Pointer(&hidden)) != nil {
		return answer, errTerminalAuth
	}
	// Flush type-ahead so a pasted line cannot silently answer a fresh challenge.
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(t.fd), terminalFlushInput, 0)
	if errno != 0 {
		return answer, errTerminalAuth
	}
	return collectTerminalAnswer(ctx, ch, t.read, t.write)
}

func terminalPause(ctx context.Context) error {
	timer := time.NewTimer(10 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return errTerminalAuth
	case <-timer.C:
		return nil
	}
}

func (t *linuxAuthTerminal) write(ctx context.Context, message string) error {
	value := []byte(message) // Prompt text only, never an answer.
	for len(value) != 0 {
		if ctx.Err() != nil || !t.foreground() {
			return errTerminalAuth
		}
		n, err := syscall.Write(t.fd, value)
		if n > 0 {
			value = value[n:]
		}
		if err != nil && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) {
			return errTerminalAuth
		}
		if len(value) != 0 {
			if terminalPause(ctx) != nil {
				return errTerminalAuth
			}
		}
	}
	return nil
}

func (t *linuxAuthTerminal) read(ctx context.Context) (value []byte, err error) {
	// Fixed capacity avoids abandoned reallocations containing previous answers.
	value = make([]byte, 0, maxTerminalAnswer)
	defer func() {
		if err != nil {
			clear(value[:cap(value)])
			value = nil
		}
	}()
	var input [1]byte
	defer clear(input[:])
	for {
		if ctx.Err() != nil || !t.foreground() {
			return value, errTerminalAuth
		}
		n, readErr := syscall.Read(t.fd, input[:])
		if readErr != nil && !errors.Is(readErr, syscall.EAGAIN) && !errors.Is(readErr, syscall.EINTR) {
			return value, errTerminalAuth
		}
		if n == 0 || readErr != nil {
			if terminalPause(ctx) != nil {
				return value, errTerminalAuth
			}
			continue
		}
		switch input[0] {
		case '\n':
			return value, nil
		case 3, 4, 26:
			return value, errTerminalAuth // Ctrl+C/D/Z even if ISIG characters were remapped.
		case 8, 127:
			if len(value) > 0 {
				_, size := utf8.DecodeLastRune(value)
				clear(value[len(value)-size:])
				value = value[:len(value)-size]
			}
		case 21:
			clear(value)
			value = value[:0] // Ctrl+U
		default:
			if input[0] < 32 || len(value) == cap(value) {
				return value, errTerminalAuth
			}
			value = append(value, input[0])
		}
	}
}
