//go:build linux

package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mygo-vpn/internal/fdtransport"
	"mygo-vpn/internal/packetrelay"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// UniVPNExecLauncher runs only pinned root-owned files without a shell. Native
// session channel mode bypasses hooks entirely. Otherwise Hook must be a reviewed
// executable, NOT the distro's unconstrained vpnc-script. SHA256s are deployment pins.
// Supplying this launcher alone does not provide a NetworkController. The
// mandatory Isolation provider must contain every native/hook descendant in a
// session cgroup before Start and prove it empty after Wait. Native script hooks
// are direct execs in the native group; leader/PGID exit is insufficient.
type UniVPNProcessIsolation interface {
	Prepare(*exec.Cmd) error
	WaitEmpty(context.Context, *exec.Cmd) error
}
type UniVPNExecLauncher struct {
	Executable, ExecutableSHA256, Hook, HookSHA256 string
	Isolation                                      UniVPNProcessIsolation
	// NativeSessionChannel requires the pinned native session-channel patch. It
	// bypasses script hooks; default false preserves existing experimental callers.
	NativeSessionChannel bool
	// Transport is opt-in. Policy binds each exact backend-approved HTTPS gateway
	// to a pinned IPv4 peer; configuration must remain immutable during launch.
	Transport         UniVPNTransportProvider
	TransportGateways map[string]fdtransport.Endpoint
	AllowedCAFiles    map[string]bool
	// PacketProvider opts into native v2 offers and fixed packet child FD 6.
	PacketProvider UniVPNPacketProvider
}

func verifyUniVPNExecutable(path, digest string) error {
	if len(digest) != 64 {
		return errors.New("missing executable SHA256 pin")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("invalid executable path")
	}
	if err := trustedUniVPNPath(filepath.Dir(path), false); err != nil {
		return err
	}
	st, e := os.Lstat(path)
	if e != nil {
		return e
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != 0 || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Mode().Perm()&0111 == 0 {
		return errors.New("untrusted executable ownership or permissions")
	}
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return e
	}
	if hex.EncodeToString(h.Sum(nil)) != digest {
		return errors.New("executable pin mismatch")
	}
	return nil
}
func (l UniVPNExecLauncher) Launch(ctx context.Context, path string, args []string, password []byte) (result UniVPNNativeProcess, resultErr error) {
	if nilInterface(l.Isolation) {
		return nil, errors.New("trusted descendant containment unavailable")
	}
	// A concrete bootstrap adapter owns one cgroup even if argument/transport
	// validation fails before command construction. Rollback is idempotent.
	if worker, ok := l.Isolation.(interface {
		wrap(*exec.Cmd, string) error
		rollbackOwned(context.Context) error
	}); ok {
		defer func() {
			if result == nil && resultErr != nil {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if err := worker.rollbackOwned(cleanupCtx); err != nil {
					resultErr = errors.Join(resultErr, &CleanupError{})
				}
			}
		}()
		if !l.NativeSessionChannel || nilInterface(l.Transport) || nilInterface(l.PacketProvider) {
			return nil, errors.New("worker bootstrap requires session, transport and packet providers")
		}
	}
	if _, ok := l.Isolation.(UniVPNLaunchRollback); !ok {
		return nil, errors.New("launch rollback unavailable")
	}
	if err := validateUniVPNBrokerArgs(args, l.AllowedCAFiles); err != nil {
		return nil, err
	}
	if !nilInterface(l.PacketProvider) && (!l.NativeSessionChannel || nilInterface(l.Transport)) {
		return nil, errors.New("packet channel requires native session and preconnected TCP transport")
	}
	if !nilInterface(l.Transport) && !l.NativeSessionChannel {
		return nil, errors.New("transport requires native session channel")
	}
	if !l.NativeSessionChannel {
		for _, r := range l.Hook {
			if !(r == '/' || r == '-' || r == '_' || r == '.' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
				return nil, errors.New("hook path is not shell-safe")
			}
		}
	}
	if path != l.Executable {
		return nil, errors.New("unapproved native executable")
	}
	if err := verifyUniVPNExecutable(path, l.ExecutableSHA256); err != nil {
		return nil, err
	}
	if !l.NativeSessionChannel {
		if err := verifyUniVPNExecutable(l.Hook, l.HookSHA256); err != nil {
			return nil, err
		}
	}
	// The hook is fixed by trusted deployment, never provided by the IPC caller.
	if len(args) < 2 {
		return nil, errors.New("missing native arguments")
	}
	nativeArgs := append([]string(nil), args[:len(args)-2]...)
	var sessionRead, sessionWrite *os.File
	var sessionID string
	if l.NativeSessionChannel {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		sessionID = hex.EncodeToString(nonce[:])
		var err error
		sessionRead, sessionWrite, err = os.Pipe()
		if err != nil {
			return nil, err
		}
		defer sessionWrite.Close()
		// Ownership of the read end transfers to the channel reader only on success.
		defer func() {
			if sessionRead != nil {
				sessionRead.Close()
			}
		}()
		nativeArgs = append(nativeArgs, "--meridian-session-fd=3", "--meridian-session-id="+sessionID)
	} else {
		nativeArgs = append(nativeArgs, "--script="+l.Hook)
	}
	var transport uniVPNTransportBundle
	if !nilInterface(l.Transport) {
		endpoint, e := l.transportEndpoint(args[len(args)-1])
		if e != nil {
			return nil, e
		}
		transport, e = acquireUniVPNTransport(ctx, l.Transport, args[len(args)-1], endpoint, func(c, d *os.File, e fdtransport.Endpoint) (uniVPNTransportBundle, error) {
			return fdtransport.Prepare(c, d, e)
		})
		if e != nil {
			return nil, e
		}
		defer func() {
			p, _ := result.(*uniVPNExecProcess)
			var stop func() error
			if p != nil {
				stop = p.Stop
			}
			resultErr = closeUniVPNLaunchTransport(transport, p, stop, resultErr)
		}()
	}
	var packetNative uniVPNPacketNative
	var relay packetrelay.PacketIO
	if !nilInterface(l.PacketProvider) {
		var e error
		packetNative, relay, e = acquireUniVPNPacket(ctx, l.PacketProvider, sessionID, duplicateUniVPNPacket)
		if e != nil {
			return nil, e
		}
		defer func() {
			p, _ := result.(*uniVPNExecProcess)
			var stop func() error
			if p != nil {
				stop = p.Stop
			}
			resultErr = closeUniVPNPacketLaunch(packetNative, relay, p, stop, resultErr)
		}()
	}
	nativeArgs = append(nativeArgs, args[len(args)-2], args[len(args)-1])
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	input := append(append([]byte(nil), password...), '\n')
	defer clear(input)
	// <=4096 bytes fits the Linux pipe buffer and is written before Start. No Go
	// stdin-copy goroutine may outlive Launch and race with password clearing.
	if len(input) > 4096 {
		w.Close()
		return nil, errors.New("password too large")
	}
	if _, err = w.Write(input); err != nil {
		w.Close()
		return nil, err
	}
	w.Close()
	cmd := exec.CommandContext(ctx, path, nativeArgs...)
	cmd.Stdin = r
	if sessionWrite != nil {
		cmd.ExtraFiles = []*os.File{sessionWrite}
	}
	if transport != nil {
		if e := wireUniVPNTransport(cmd, transport); e != nil {
			return nil, e
		}
	}
	if packetNative.file != nil {
		if e := wireUniVPNPacket(cmd, packetNative.file); e != nil {
			return nil, e
		}
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "HOME=/"}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if worker, ok := l.Isolation.(interface{ wrap(*exec.Cmd, string) error }); ok {
		if err := worker.wrap(cmd, l.ExecutableSHA256); err != nil {
			return nil, err
		}
	}
	p := &uniVPNExecProcess{cmd: cmd, exited: make(chan struct{}), contained: make(chan struct{}), isolation: l.Isolation, packet: relay, sessionID: sessionID}
	if sessionRead != nil {
		if packetNative.file != nil {
			p.offer = newUniVPNOfferChannel()
		} else {
			p.session = newUniVPNNativeChannel()
		}
	}
	cmd.Cancel = func() error { return p.Stop() }
	cmd.WaitDelay = 3 * time.Second
	if err = startUniVPNContained(ctx, cmd, l.Isolation, cmd.Start); err != nil {
		return nil, err
	}
	// Retain the original process identity before any caller can begin Wait.
	// Failure only disables optional observations; it must not lose this child.
	p.observation = pinUniVPNOriginalProcess(p)
	if sessionRead != nil {
		reader := sessionRead
		p.sessionReader = reader
		sessionRead = nil
		sessionWrite.Close()
		go func() {
			defer reader.Close()
			if p.offer != nil {
				p.offer.read(reader, sessionID, func() { p.Stop() })
			} else {
				p.session.read(reader, sessionID, func() { p.Stop() })
			}
		}()
	}
	return p, nil
}

type uniVPNExecProcess struct {
	cmd              *exec.Cmd
	once             sync.Once
	exited           chan struct{}
	isolation        UniVPNProcessIsolation
	session          *uniVPNNativeChannel
	contained        chan struct{}
	containmentErr   error
	launchCleanupErr error
	sessionReader    *os.File
	offer            *uniVPNOfferChannel
	packet           packetrelay.PacketIO
	packetMu         sync.Mutex
	sessionID        string
	observation      *uniVPNProcessObservation
}

func (p *uniVPNExecProcess) Wait() error {
	err := errors.Join(p.cmd.Wait(), p.launchCleanupErr)
	close(p.exited)
	err = errors.Join(err, p.observation.close())
	p.packetMu.Lock()
	packet := p.packet
	p.packet = nil
	p.packetMu.Unlock()
	packetCloseErr := closeUniVPNPacket(packet)
	err = errors.Join(err, packetCloseErr)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.containmentErr = errors.Join(packetCloseErr, p.isolation.WaitEmpty(ctx, p.cmd))
	if p.session != nil {
		// Bound pipe drainage even if a failed isolation provider left writers alive.
		select {
		case <-p.session.done:
		case <-ctx.Done():
			p.containmentErr = errors.Join(p.containmentErr, &CleanupError{})
			if p.sessionReader != nil {
				p.sessionReader.Close()
			}
		}
	}
	if p.offer != nil {
		select {
		case <-p.offer.done:
		case <-ctx.Done():
			p.containmentErr = errors.Join(p.containmentErr, &CleanupError{})
			if p.sessionReader != nil {
				p.sessionReader.Close()
			}
		}
	}
	if p.contained != nil {
		close(p.contained)
	}
	if p.containmentErr != nil {
		return errors.Join(err, &CleanupError{})
	}
	return err
}
func (p *uniVPNExecProcess) Stop() error {
	var result error
	p.once.Do(func() {
		select {
		case <-p.exited:
			return
		default:
		}
		result = p.cmd.Process.Signal(syscall.SIGTERM)
		go func() {
			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()
			select {
			case <-p.exited:
			case <-timer.C:
				p.cmd.Process.Kill()
			}
		}()
	})
	if errors.Is(result, syscall.ESRCH) {
		return nil
	}
	return result
}
