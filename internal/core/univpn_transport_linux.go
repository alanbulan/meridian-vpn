//go:build linux

package core

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"time"

	"mygo-vpn/internal/fdtransport"
)

// UniVPNTransportProvider is a trusted deployment dependency, never IPC input.
// Acquire must honor ctx and transfer exclusive ownership of every returned file,
// INCLUDING on error. Distinct os.File wrappers must never share an FD number. It must retain no duplicate, goroutine or other socket owner.
// Unreturned resources must be cleaned before return; uncertain cleanup MUST return
// CleanupError. Neither caller nor provider may use originals after transfer.
// The endpoint is supplied by the exact gateway policy, never chosen by Acquire.
type UniVPNTransportProvider interface {
	Acquire(context.Context, string, fdtransport.Endpoint) (control, data *os.File, err error)
}

// UniVPNLaunchRollback must release even partially prepared containment resources.
// It is called after failed Prepare, command-integrity rejection, canceled launch,
// or failed Start. It must honor ctx, and prove no worker/resource remains.
// Prepare may configure SysProcAttr but MUST NOT start a worker, mutate the command
// transport/credential fields, change the launcher's reserved PidFD output slot,
// close its files, or retain command access after return.
type UniVPNLaunchRollback interface {
	RollbackLaunch(context.Context, *exec.Cmd) error
}

type uniVPNTransportBundle interface {
	Files() ([]*os.File, error)
	Close() error
}
type uniVPNTransportDuplicate func(*os.File, *os.File, fdtransport.Endpoint) (uniVPNTransportBundle, error)

func (l UniVPNExecLauncher) transportEndpoint(gateway string) (fdtransport.Endpoint, error) {
	e, ok := l.TransportGateways[gateway]
	u, err := url.Parse(gateway)
	if !ok || err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return e, errors.New("unapproved transport gateway")
	}
	if literal, err := netip.ParseAddr(u.Hostname()); err == nil && literal != e.Address {
		return e, errors.New("gateway literal differs from transport peer")
	}
	port := uint64(443)
	if u.Port() != "" {
		port, err = strconv.ParseUint(u.Port(), 10, 16)
	}
	if err != nil || uint16(port) != e.Port || e.Port == 0 || !e.Address.Is4() || e.Address.IsUnspecified() || e.Address.IsMulticast() {
		return e, errors.New("invalid gateway transport policy")
	}
	return e, nil
}

func acquireUniVPNTransport(ctx context.Context, provider UniVPNTransportProvider, gateway string, endpoint fdtransport.Endpoint, duplicate uniVPNTransportDuplicate) (uniVPNTransportBundle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, d, err := provider.Acquire(ctx, gateway, endpoint)
	var bundle uniVPNTransportBundle
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		if c == nil || d == nil || c == d {
			err = errors.New("distinct owned transport files required")
		} else {
			bundle, err = duplicate(c, d, endpoint)
		}
	}
	// os.File.Close invalidates the wrapper even on an error. Do not retry closes.
	var closeErr error
	if c != nil {
		closeErr = c.Close()
	}
	if d != nil && d != c {
		closeErr = errors.Join(closeErr, d.Close())
	}
	if closeErr != nil {
		err = errors.Join(err, &CleanupError{})
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		if !nilInterface(bundle) {
			if bundle.Close() != nil {
				err = errors.Join(err, &CleanupError{})
			}
		}
		return nil, err
	}
	if nilInterface(bundle) {
		return nil, errors.New("transport validation returned no descriptors")
	}
	return bundle, nil
}

// The only injectable launch seam is private and is used for non-executing tests.
// Production always supplies cmd.Start, after root ownership and pin verification.
func startUniVPNContained(ctx context.Context, cmd *exec.Cmd, isolation UniVPNProcessIsolation, start func() error) (err error) {
	rollback, ok := isolation.(UniVPNLaunchRollback)
	if !ok || nilInterface(rollback) {
		return errors.New("launch rollback unavailable")
	}
	path, dir := cmd.Path, cmd.Dir
	args, env := append([]string(nil), cmd.Args...), append([]string(nil), cmd.Env...)
	files := append([]*os.File(nil), cmd.ExtraFiles...)
	stdin, stdout, stderr := cmd.Stdin, cmd.Stdout, cmd.Stderr
	cancelPointer := reflect.ValueOf(cmd.Cancel).Pointer()
	waitDelay := cmd.WaitDelay
	var pidFD *int
	if cmd.SysProcAttr != nil {
		pidFD = cmd.SysProcAttr.PidFD
	}
	defer func() {
		if err == nil {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- rollback.RollbackLaunch(cleanupCtx, cmd) }()
		select {
		case e := <-done:
			if e != nil {
				err = errors.Join(err, &CleanupError{})
			}
		case <-cleanupCtx.Done():
			err = errors.Join(err, &CleanupError{})
		}
	}()
	if err = isolation.Prepare(cmd); err != nil {
		return err
	}
	if cmd.Path != path || cmd.Dir != dir || !reflect.DeepEqual(cmd.Args, args) || !reflect.DeepEqual(cmd.Env, env) || !reflect.DeepEqual(cmd.ExtraFiles, files) || !reflect.DeepEqual(cmd.Stdin, stdin) || !reflect.DeepEqual(cmd.Stdout, stdout) || !reflect.DeepEqual(cmd.Stderr, stderr) || reflect.ValueOf(cmd.Cancel).Pointer() != cancelPointer || cmd.WaitDelay != waitDelay || cmd.Err != nil || cmd.Process != nil || cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid || cmd.SysProcAttr.Pgid != 0 {
		return errors.New("isolation changed protected launch fields")
	}
	if cmd.SysProcAttr.PidFD != pidFD || (pidFD != nil && *pidFD != -1) {
		return errors.New("isolation changed reserved pidfd capture")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if starter, ok := isolation.(interface{ startContained(*exec.Cmd) error }); ok {
		return starter.startContained(cmd)
	}
	return start()
}

// wireUniVPNTransport is used by Launch after strict caller-argument validation.
// Child 3 is the private session pipe; TCP control/data are always child 4/5.
func wireUniVPNTransport(cmd *exec.Cmd, transport uniVPNTransportBundle) error {
	if len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0] == nil || len(cmd.Args) < 3 || cmd.Args[len(cmd.Args)-2] != "--" {
		return errors.New("native session descriptor required")
	}
	files, err := transport.Files()
	if err != nil {
		return err
	}
	if len(files) != 2 || files[0] == nil || files[1] == nil || files[0] == files[1] {
		return errors.New("invalid transport bundle")
	}
	n := len(cmd.Args) - 2
	args := append([]string(nil), cmd.Args[:n]...)
	args = append(args, "--meridian-control-fd=4", "--meridian-data-fd=5")
	cmd.Args = append(args, cmd.Args[n:]...)
	cmd.ExtraFiles = append(cmd.ExtraFiles, files...)
	return nil
}

// On successful Start keep the lifecycle reachable by the broker, force teardown,
// and let Wait report uncertainty. A nil process means no child was released.
func closeUniVPNLaunchTransport(transport uniVPNTransportBundle, p *uniVPNExecProcess, stop func() error, launchErr error) error {
	if err := transport.Close(); err != nil {
		if p != nil {
			p.launchCleanupErr = &CleanupError{}
			_ = stop()
		} else {
			launchErr = errors.Join(launchErr, &CleanupError{})
		}
	}
	return launchErr
}
