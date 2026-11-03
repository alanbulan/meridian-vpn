//go:build !windows

package main

import (
	"bufio"
	"context"
	"io"
	"mygo-vpn/internal/core"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// This child only uses a fake session. It never invokes NetworkManager or
// authenticates. A real fd-1 pipe is needed to exercise Go's SIGPIPE behavior.
func TestForegroundBrokenStdoutChild(t *testing.T) {
	if os.Getenv("MERIDIAN_TEST_BROKEN_PIPE") != "1" { return }
	ctx, stop := commandSignalContext(context.Background())
	defer stop()
	s := &cliSession{ready: make(chan error, 1), done: make(chan error), stopped: make(chan struct{})}
	e := core.NewEngine(cliAdapter{s, make(chan struct{})})
	p := sampleProfile()
	p.InteractiveAuth = false
	if e.Connect(p, "", true) != nil { os.Exit(10) }
	writer := &gatedStdout{ready: s.ready}
	code := runForegroundSession(ctx, e, writer, io.Discard)
	if code != 1 || e.Snapshot().State != core.Disconnected { os.Exit(11) }
	select { case <-s.stopped: os.Exit(0); default: os.Exit(12) }
}

type gatedStdout struct {
	once sync.Once
	ready chan error
}

func (w *gatedStdout) Write(p []byte) (int, error) {
	n, err := os.Stdout.Write(p)
	w.once.Do(func() {
		// Parent closes the stdout reader before releasing this gate.
		var gate [1]byte
		_, _ = io.ReadFull(os.Stdin, gate[:])
		w.ready <- nil
	})
	return n, err
}

func TestForegroundBrokenStdoutStillCleansUp(t *testing.T) {
	executable, err := os.Executable()
	if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestForegroundBrokenStdoutChild$")
	cmd.Env = append(os.Environ(), "MERIDIAN_TEST_BROKEN_PIPE=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil { t.Fatal(err) }
	stdin, err := cmd.StdinPipe()
	if err != nil { t.Fatal(err) }
	if err := cmd.Start(); err != nil { t.Fatal(err) }
	defer func() { _ = stdout.Close(); _ = stdin.Close(); _ = cmd.Process.Kill() }()
	if _, err := bufio.NewReader(stdout).ReadString('\n'); err != nil { t.Fatal(err) }
	if err := stdout.Close(); err != nil { t.Fatal(err) }
	if _, err := stdin.Write([]byte{1}); err != nil { t.Fatal(err) }
	_ = stdin.Close()
	if err := cmd.Wait(); err != nil { t.Fatalf("broken stdout skipped safe cleanup: %v", err) }
}

func TestInheritedCredentialInputChild(t *testing.T) {
	if os.Getenv("MERIDIAN_TEST_INHERITED_STDIN") != "1" { return }
	ctx, stop := commandSignalContext(context.Background())
	defer stop()
	_, _ = os.Stdout.Write([]byte("ready\n"))
	credentials, err := readCredentialInput(ctx, os.Stdin)
	clearCredentials(credentials)
	if err == nil || ctx.Err() == nil { os.Exit(20) }
	os.Exit(0)
}

func TestInheritedCredentialInputCancelsWithoutEOF(t *testing.T) {
	executable, err := os.Executable()
	if err != nil { t.Fatal(err) }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestInheritedCredentialInputChild$")
	cmd.Env = append(os.Environ(), "MERIDIAN_TEST_INHERITED_STDIN=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil { t.Fatal(err) }
	stdin, err := cmd.StdinPipe()
	if err != nil { t.Fatal(err) }
	if err := cmd.Start(); err != nil { t.Fatal(err) }
	defer func() { _ = stdin.Close(); _ = stdout.Close(); _ = cmd.Process.Kill() }()
	if _, err := bufio.NewReader(stdout).ReadString('\n'); err != nil { t.Fatal(err) }
	// Keep stdin open without EOF, including after signalling the child.
	if _, err := stdin.Write([]byte(`{"password":"unfinished`)); err != nil { t.Fatal(err) }
	time.Sleep(50 * time.Millisecond)
	if err := cmd.Process.Signal(os.Interrupt); err != nil { t.Fatal(err) }
	if err := cmd.Wait(); err != nil { t.Fatalf("inherited stdin ignored cancellation: %v", err) }
}
