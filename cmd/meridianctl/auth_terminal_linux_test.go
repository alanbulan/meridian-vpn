//go:build linux && (amd64 || arm64)

package main

import (
	"bytes"
	"context"
	"fmt"
	"mygo-vpn/internal/core"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// A child is needed for a genuine controlling terminal. stdout/stderr remain
// redirected, so these tests also detect accidentally writing prompts there.
type terminalPTYSession struct {
	master     *os.File
	cmd        *exec.Cmd
	chunks     chan []byte
	done       chan error
	output     bytes.Buffer
	transcript string
	cursor     int
}

func startTerminalPTY(t *testing.T, test, scenario string) *terminalPTYSession {
	t.Helper()
	fd, err := syscall.Open("/dev/ptmx", syscall.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("PTY prerequisite unavailable:", err)
	}
	master := os.NewFile(uintptr(fd), "pty-master")
	var unlock int32
	if err = terminalIoctl(fd, 0x40045431, unsafe.Pointer(&unlock)); err != nil {
		master.Close()
		t.Fatal(err)
	}
	var number uint32
	if err = terminalIoctl(fd, 0x80045430, unsafe.Pointer(&number)); err != nil {
		master.Close()
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR, 0)
	if err != nil {
		master.Close()
		t.Fatal(err)
	}
	s := &terminalPTYSession{master: master, chunks: make(chan []byte, 256), done: make(chan error, 1)}
	s.cmd = exec.Command(os.Args[0], "-test.run=^"+test+"$", "-test.timeout=35s")
	s.cmd.Env = append(os.Environ(), "MERIDIAN_TERMINAL_TEST_CHILD="+scenario)
	s.cmd.Stdin, s.cmd.Stdout, s.cmd.Stderr = slave, &s.output, &s.output
	s.cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err = s.cmd.Start(); err != nil {
		master.Close()
		slave.Close()
		t.Fatal(err)
	}
	slave.Close()
	go func() {
		defer close(s.chunks)
		b := make([]byte, 4096)
		for {
			n, err := master.Read(b)
			if n > 0 {
				s.chunks <- append([]byte(nil), b[:n]...)
			}
			if err != nil {
				return
			}
		}
	}()
	go func() { s.done <- s.cmd.Wait() }()
	t.Cleanup(func() { _ = s.cmd.Process.Kill(); _ = master.Close() })
	return s
}

func (s *terminalPTYSession) await(t *testing.T, text string) {
	t.Helper()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for {
		if i := strings.Index(s.transcript[s.cursor:], text); i >= 0 {
			s.cursor += i + len(text)
			var state syscall.Termios
			if err := terminalIoctl(int(s.master.Fd()), syscall.TCGETS, unsafe.Pointer(&state)); err != nil {
				t.Fatal(err)
			}
			if state.Lflag&(syscall.ECHO|syscall.ECHONL|syscall.ICANON) != 0 {
				t.Fatal("terminal prompt is echoing or canonical")
			}
			return
		}
		select {
		case b, ok := <-s.chunks:
			if !ok {
				// Wait completes the stdout/stderr copy before reading the buffer.
				// Never inspect it while the child may still be writing diagnostics.
				select {
				case err := <-s.done:
					t.Fatalf("PTY closed before expected prompt; subprocess result: %v; %s", err, s.output.String())
				case <-timer.C:
					t.Fatal("PTY closed before expected prompt; subprocess did not finish")
				}
			}
			s.transcript += string(b)
		case <-timer.C:
			t.Fatal("timed out waiting for terminal prompt")
		}
	}
}
func (s *terminalPTYSession) write(t *testing.T, text string) {
	t.Helper()
	if _, err := s.master.Write([]byte(text)); err != nil {
		t.Fatal("PTY input failed:", err)
	}
}
func (s *terminalPTYSession) finish(t *testing.T, secrets ...string) {
	t.Helper()
	select {
	case err := <-s.done:
		if err != nil {
			t.Fatalf("terminal subprocess failed: %v; %s", err, s.output.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("terminal subprocess did not stop promptly")
	}
	drain := time.NewTimer(3 * time.Second)
	defer drain.Stop()
draining:
	for {
		select {
		case b, ok := <-s.chunks:
			if !ok {
				break draining
			}
			s.transcript += string(b)
		case <-drain.C:
			t.Fatal("PTY remained open after subprocess exit")
		}
	}
	for _, secret := range secrets {
		if strings.Contains(s.transcript, secret) || strings.Contains(s.output.String(), secret) {
			t.Fatal("secret appeared in terminal or redirected output")
		}
	}
	if strings.Contains(s.output.String(), "Hidden answer") || strings.Contains(s.output.String(), "Gateway field") {
		t.Fatal("prompt leaked to redirected output")
	}
	if strings.ContainsAny(s.transcript, "\x1b\x07\u202e") {
		t.Fatal("gateway control characters reached terminal")
	}
}

func terminalState(t *testing.T) syscall.Termios {
	t.Helper()
	var state syscall.Termios
	if err := terminalIoctl(0, syscall.TCGETS, unsafe.Pointer(&state)); err != nil {
		t.Fatal(err)
	}
	return state
}
func checkTerminalRestored(t *testing.T, before syscall.Termios) {
	t.Helper()
	if !reflect.DeepEqual(before, terminalState(t)) {
		t.Fatal("terminal attributes were not fully restored")
	}
}

func TestTerminalPTY(t *testing.T) {
	if scenario := os.Getenv("MERIDIAN_TERMINAL_TEST_CHILD"); scenario != "" {
		if scenario == "background_keeper" {
			time.Sleep(30 * time.Second)
			return
		}
		if scenario == "background" {
			testBackgroundTerminalChild(t)
			return
		}
		if scenario == "concurrent" || scenario == "closed_fd" || scenario == "two_rounds" {
			testAdvancedTerminalChild(t, scenario)
			return
		}
		if scenario == "no_terminal" {
			terminal, err := openAuthTerminal()
			if err == nil || terminal != nil {
				if terminal != nil {
					terminal.Close()
				}
				t.Fatal("authentication fell back without a controlling terminal")
			}
			return
		}
		before := terminalState(t)
		terminal, err := openAuthTerminal()
		if err != nil {
			t.Fatal(err)
		}
		ctx, stop := commandSignalContext(context.Background())
		defer stop()
		// Deadline is deliberately longer than prompt startup, shorter than the test.
		if scenario == "timeout" {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
		}
		ch := core.AuthChallenge{SessionID: strings.Repeat("a", 32), Round: 1, Title: "untrusted title", Message: "untrusted message", Fields: []core.AuthField{{ID: "otp", Kind: "password", Label: "Code\x1b[2J\x07\n\u202e"}}}
		answer, err := terminal.Prompt(ctx, ch)
		if scenario == "answer" {
			if err != nil || !bytes.Equal(answer.Values["otp"], []byte("pty-secret-123")) {
				t.Fatal("unexpected hidden answer result")
			}
			clear(answer.Values["otp"])
		} else if err == nil || len(answer.Values) != 0 {
			t.Fatal("canceled/invalid prompt returned an answer")
		}
		checkTerminalRestored(t, before)
		if terminal.Close() != nil || terminal.Close() != nil {
			t.Fatal("terminal close failed or was not idempotent")
		}
		checkTerminalRestored(t, before)
		return
	}
	for _, scenario := range []string{"concurrent", "closed_fd", "two_rounds", "background"} {
		t.Run(scenario, func(t *testing.T) {
			s := startTerminalPTY(t, "TestTerminalPTY", scenario)
			switch scenario {
			case "concurrent":
				s.await(t, "Concurrent prompt rejected")
				s.write(t, "\x03")
			case "two_rounds":
				s.await(t, "Hidden answer: ")
				s.write(t, "pty-secret-first\n")
				s.await(t, "Hidden answer: ")
				s.write(t, "pty-secret-second\n")
			}
			s.finish(t, "pty-secret-first", "pty-secret-second")
		})
	}
	t.Run("no_controlling_terminal", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTerminalPTY$", "-test.timeout=4s")
		cmd.Env = append(os.Environ(), "MERIDIAN_TERMINAL_TEST_CHILD=no_terminal")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("no-terminal subprocess failed: %v; %s", err, output)
		}
	})
	cases := []struct {
		name, input string
		signal      syscall.Signal
	}{
		{name: "answer", input: "pty-secret-123\n"},
		{name: "oversize", input: strings.Repeat("x", maxTerminalAnswer+1)},
		{name: "eof", input: "\x04"},
		{name: "ctrl_c", input: "\x03"},
		{name: "ctrl_backslash", input: "\x1c"},
		{name: "ctrl_z", input: "\x1a"},
		{name: "timeout"},
		{name: "sigterm", signal: syscall.SIGTERM},
		{name: "sighup", signal: syscall.SIGHUP},
		{name: "sigttin", signal: syscall.SIGTTIN},
		{name: "sigttou", signal: syscall.SIGTTOU},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := startTerminalPTY(t, "TestTerminalPTY", tc.name)
			s.await(t, "Hidden answer: ")
			if tc.input != "" {
				s.write(t, tc.input)
			}
			if tc.signal != 0 {
				if err := s.cmd.Process.Signal(tc.signal); err != nil {
					t.Fatal(err)
				}
			}
			s.finish(t, "pty-secret-123", strings.Repeat("x", 128))
			if strings.Contains(s.transcript, "untrusted title") || strings.Contains(s.transcript, "untrusted message") {
				t.Fatal("free-form gateway content was rendered")
			}
		})
	}
}

func waitTerminalHidden(t *testing.T) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		if terminalState(t).Lflag&syscall.ECHO == 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("prompt did not disable terminal echo")
		case <-time.After(time.Millisecond):
		}
	}
}

func testAdvancedTerminalChild(t *testing.T, scenario string) {
	t.Helper()
	before := terminalState(t)
	terminal, err := openAuthTerminal()
	if err != nil {
		t.Fatal(err)
	}
	linux := terminal.(*linuxAuthTerminal)
	defer terminal.Close()
	ctx, stop := commandSignalContext(context.Background())
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ch := core.AuthChallenge{SessionID: strings.Repeat("b", 32), Round: 1, Fields: []core.AuthField{{ID: "otp", Kind: "password", Label: "Code"}}}
	if scenario == "two_rounds" {
		for i, want := range []string{"pty-secret-first", "pty-secret-second"} {
			ch.Round = uint16(i + 1)
			answer, err := terminal.Prompt(ctx, ch)
			if err != nil || !bytes.Equal(answer.Values["otp"], []byte(want)) {
				t.Fatal("sequential terminal prompt failed")
			}
			clear(answer.Values["otp"])
			checkTerminalRestored(t, before)
		}
		if terminal.Close() != nil {
			t.Fatal("close after sequential prompts failed")
		}
		if answer, err := terminal.Prompt(ctx, ch); err == nil || len(answer.Values) != 0 {
			t.Fatal("closed terminal accepted a prompt")
		}
		return
	}
	type promptResult struct {
		answer core.AuthAnswer
		err    error
	}
	done := make(chan promptResult, 1)
	go func() { answer, err := terminal.Prompt(ctx, ch); done <- promptResult{answer, err} }()
	waitTerminalHidden(t)
	if scenario == "concurrent" {
		answer, err := terminal.Prompt(ctx, ch)
		if err == nil || len(answer.Values) != 0 {
			t.Fatal("concurrent prompt was accepted")
		}
		if _, err := syscall.Write(linux.fd, []byte("\nConcurrent prompt rejected\n")); err != nil {
			t.Fatal(err)
		}
	} else {
		// Close only this isolated child's /dev/tty descriptor. The still-open stdin
		// descriptor is used solely to restore the test terminal after the expected
		// failure. Do not mutate linux.fd while Prompt is reading it.
		if err := syscall.Close(linux.fd); err != nil {
			t.Fatal(err)
		}
	}
	var result promptResult
	select {
	case result = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("prompt did not terminate")
	}
	if result.err == nil || len(result.answer.Values) != 0 {
		t.Fatal("failed terminal submitted an answer")
	}
	if scenario == "closed_fd" {
		if !linux.restoreFailed || terminal.Close() == nil {
			t.Fatal("terminal restoration failure was not sticky")
		}
		if err := terminalIoctl(0, syscall.TCSETS, unsafe.Pointer(&before)); err != nil {
			t.Fatal("test terminal cleanup failed:", err)
		}
	} else if terminal.Close() != nil {
		t.Fatal("canceled prompt did not close cleanly")
	}
	checkTerminalRestored(t, before)
}

func testBackgroundTerminalChild(t *testing.T) {
	t.Helper()
	before := terminalState(t)
	keeper := exec.Command(os.Args[0], "-test.run=^TestTerminalPTY$", "-test.timeout=25s")
	keeper.Env = append(os.Environ(), "MERIDIAN_TERMINAL_TEST_CHILD=background_keeper")
	keeper.Stdin = os.Stdin
	keeper.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := keeper.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = keeper.Process.Kill(); _ = keeper.Wait() }()
	foreground := int32(syscall.Getpgrp())
	background := int32(keeper.Process.Pid)
	if err := terminalIoctl(0, syscall.TIOCSPGRP, unsafe.Pointer(&background)); err != nil {
		t.Fatal(err)
	}
	defer func() {
		// TIOCSPGRP from our now-background group otherwise raises SIGTTOU. This
		// disposition change is confined to the disposable setsid test child.
		signal.Ignore(syscall.SIGTTOU)
		if err := terminalIoctl(0, syscall.TIOCSPGRP, unsafe.Pointer(&foreground)); err != nil {
			t.Error("test foreground restoration failed:", err)
		}
		signal.Reset(syscall.SIGTTOU)
	}()
	terminal, err := openAuthTerminal()
	if err == nil || terminal != nil {
		if terminal != nil {
			terminal.Close()
		}
		t.Fatal("background process opened an authentication terminal")
	}
	checkTerminalRestored(t, before)
}
