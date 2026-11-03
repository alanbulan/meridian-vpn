//go:build linux

package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

const fdTestKeySecret = "synthetic-fd-key'\"#=secret"
const fdTestLoginSecret = "synthetic-fd-login-secret"

type credentialSubprocessRunner struct{ wait bool }

func (r credentialSubprocessRunner) Run(ctx context.Context, path string, args []string, input []byte) ([]byte, error) {
	return execRunner{}.Run(ctx, path, args, input)
}
func (r credentialSubprocessRunner) RunWithFiles(ctx context.Context, _ string, args []string, input []byte, files []*os.File) ([]byte, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	helper := []string{"-test.run=^TestCredentialFDSubprocess$", "--"}
	if r.wait {
		helper = append(helper, "wait")
	}
	helper = append(helper, args...)
	return execRunner{}.RunWithFiles(ctx, executable, helper, input, files)
}
func TestCredentialFDSubprocess(t *testing.T) {
	if os.Getenv("MERIDIAN_FD_TEST_CHILD") != "1" {
		return
	}
	for _, v := range append(append([]string{}, os.Args...), os.Environ()...) {
		if strings.Contains(v, fdTestKeySecret) || strings.Contains(v, fdTestLoginSecret) {
			os.Exit(20)
		}
	}
	if strings.Contains(strings.Join(os.Args, " "), "-- wait ") {
		time.Sleep(time.Minute)
		os.Exit(21)
	}
	stdin, err := io.ReadAll(os.Stdin)
	if err != nil || string(stdin) != fdTestLoginSecret+"\n" {
		os.Exit(22)
	}
	config, err := os.ReadFile("/proc/self/fd/3")
	if err != nil || string(config) != "key-password="+fdTestKeySecret+"\n" {
		os.Exit(23)
	}
	cert, err := os.ReadFile("/proc/self/fd/4")
	if err != nil || !bytes.Contains(cert, []byte("BEGIN CERTIFICATE")) {
		os.Exit(24)
	}
	key, err := os.ReadFile("/proc/self/fd/5")
	if err != nil || !bytes.Contains(key, []byte("BEGIN EC PRIVATE KEY")) {
		os.Exit(25)
	}
	clear(stdin)
	clear(config)
	clear(key)
	fmt.Print(authFixture)
	os.Exit(0)
}
func TestCredentialSecretsReachOnlyPrivateSubprocessDescriptors(t *testing.T) {
	t.Setenv("MERIDIAN_FD_TEST_CHILD", "1")
	p, _, _ := clientIdentity(t, nil, time.Now().Add(time.Hour))
	out, err := authenticateOpenConnect(context.Background(), credentialSubprocessRunner{}, "ignored", p, Credentials{Password: []byte(fdTestLoginSecret), KeyPassword: []byte(fdTestKeySecret)})
	if err != nil {
		t.Fatal("subprocess private FD contract failed", err)
	}
	defer clear(out)
	if _, err = parseAuthentication(out); err != nil {
		t.Fatal(err)
	}
}
func TestCredentialSubprocessCancellation(t *testing.T) {
	t.Setenv("MERIDIAN_FD_TEST_CHILD", "1")
	p, _, _ := clientIdentity(t, nil, time.Now().Add(time.Hour))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := authenticateOpenConnect(ctx, credentialSubprocessRunner{wait: true}, "ignored", p, Credentials{KeyPassword: []byte(fdTestKeySecret)})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 3*time.Second {
		t.Fatal("cancelled credential subprocess did not terminate promptly", err)
	}
}
