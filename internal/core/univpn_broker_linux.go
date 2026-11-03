//go:build linux

package core

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

// UniVPNNativeProcess is the ORIGINAL authenticated native process, not a cookie
// exporter. Wait must be called exactly once; Stop must unblock Wait.
type UniVPNNativeProcess interface {
	Wait() error
	Stop() error
}

// Launch must not retain password, invoke a shell, or accept arbitrary scripts.
// A production implementation must pin/verify the executable and privileged hook.
type UniVPNNativeLauncher interface {
	Launch(context.Context, string, []string, []byte) (UniVPNNativeProcess, error)
}

// WaitReady must verify kernel interface/address and authenticated session state
// through a private trusted native hook, never stdout. Cleanup must be idempotent,
// restoring only the routes/DNS/interface owned by this session, including partial
// setup. Implementations must honor context cancellation.
type UniVPNNetworkController interface {
	WaitReady(context.Context, UniVPNNativeProcess) error
	Cleanup(context.Context, UniVPNNativeProcess) error
}

// UniVPNBrokerBackend keeps the native process alive from authentication through
// teardown. Its dependencies are mandatory: this does not install a root helper.
type UniVPNBrokerBackend struct {
	Executable     string
	AllowedCAFiles map[string]bool
	// Exact approved HTTPS gateway URLs, owned by the root service configuration.
	// Empty policy denies all launches. No caller can extend this list.
	AllowedGateways map[string]bool
	Launcher        UniVPNNativeLauncher
	Network         UniVPNNetworkController
	StartupTimeout  time.Duration
	mu              sync.Mutex
	active          bool
	quarantined     bool
}

func (b *UniVPNBrokerBackend) Available() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.quarantined && len(b.AllowedGateways) > 0 && filepath.IsAbs(b.Executable) && !nilInterface(b.Launcher) && !nilInterface(b.Network)
}
func (b *UniVPNBrokerBackend) Start(ctx context.Context, executable string, args []string, secret []byte) (Session, error) {
	if !b.Available() {
		return nil, errors.New("UniVPN trusted native launcher/network controller unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if executable != b.Executable {
		return nil, errors.New("unapproved UniVPN executable")
	}
	if err := validateUniVPNBrokerArgs(args, b.AllowedCAFiles); err != nil {
		return nil, err
	}
	if !b.AllowedGateways[args[len(args)-1]] {
		return nil, errors.New("unapproved UniVPN gateway")
	}
	if len(secret) == 0 || len(secret) > 4095 || strings.ContainsAny(string(secret), "\r\n\x00") {
		return nil, errors.New("invalid UniVPN password")
	}
	b.mu.Lock()
	if b.active {
		b.mu.Unlock()
		return nil, errors.New("UniVPN session already active")
	}
	b.active = true
	b.mu.Unlock()
	release := func() {
		b.mu.Lock()
		if !b.quarantined {
			b.active = false
		}
		b.mu.Unlock()
	}
	run, cancel := context.WithCancel(ctx)
	password := append([]byte(nil), secret...)
	p, err := b.Launcher.Launch(run, executable, append([]string(nil), args...), password)
	clear(password)
	if err != nil {
		cancel()
		var cleanup *CleanupError
		if errors.As(err, &cleanup) {
			b.mu.Lock()
			b.quarantined = true
			b.mu.Unlock()
		}
		release()
		if cleanup != nil {
			return nil, errors.Join(errors.New("UniVPN native launch failed"), cleanup)
		}
		return nil, errors.New("UniVPN native launch failed")
	}
	if nilInterface(p) {
		cancel()
		release()
		return nil, errors.New("UniVPN launcher returned no process")
	}
	s := &uniVPNBrokerSession{ready: make(chan error, 1), done: make(chan error, 1), cancel: cancel, finished: make(chan struct{})}
	timeout := b.StartupTimeout
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	go func() {
		defer close(s.finished)
		defer release()
		defer cancel()
		defer close(s.done)
		defer close(s.ready)
		exited := make(chan error, 1)
		go func() { exited <- p.Wait() }()
		verifyCtx, verifyCancel := context.WithTimeout(run, timeout)
		verified := make(chan error, 1)
		go func() { verified <- b.Network.WaitReady(verifyCtx, p) }()
		var result error
		var didExit bool
		var didVerify bool
		select {
		case err := <-verified:
			didVerify = true
			if err != nil {
				result = errors.New("UniVPN trusted readiness verification failed")
			} else if run.Err() != nil {
				result = run.Err()
			}
		case <-verifyCtx.Done():
			result = verifyCtx.Err()
		case exitErr := <-exited:
			var cleanup *CleanupError
			if errors.As(exitErr, &cleanup) {
				s.stopErr = cleanup
			}
			didExit = true
			result = errors.New("UniVPN native process exited before ready")
		}
		verifyCancel()
		if !didVerify {
			select {
			case <-verified:
				didVerify = true
			case <-time.After(2 * time.Second):
				s.stopErr = &CleanupError{}
			}
		} // serialize verifier termination before cleanup
		if result == nil {
			select {
			case exitErr := <-exited:
				var cleanup *CleanupError
				if errors.As(exitErr, &cleanup) {
					s.stopErr = cleanup
				}
				didExit = true
				result = errors.New("UniVPN native process exited before ready")
			default:
			}
		}
		if result == nil {
			s.ready <- nil
			select {
			case result = <-exited:
				var cleanup *CleanupError
				if errors.As(result, &cleanup) {
					s.stopErr = cleanup
				}
				didExit = true
			case <-run.Done():
				result = run.Err()
			}
		} else {
			s.ready <- result
		}
		cancel()
		if !didExit {
			stopErr := p.Stop()
			var waitErr error
			select {
			case waitErr = <-exited:
				didExit = true
			case <-time.After(3 * time.Second):
				s.stopErr = &CleanupError{}
			}
			result = errors.Join(result, stopErr, waitErr)
			var cleanup *CleanupError
			if errors.As(waitErr, &cleanup) {
				s.stopErr = cleanup
			}
			if stopErr != nil {
				s.stopErr = &CleanupError{}
			}
		}
		if didVerify && didExit && s.stopErr == nil {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
			cleanupDone := make(chan error, 1)
			go func() { cleanupDone <- b.Network.Cleanup(cleanupCtx, p) }()
			select {
			case err := <-cleanupDone:
				if err != nil {
					s.stopErr = &CleanupError{}
				}
			case <-cleanupCtx.Done():
				s.stopErr = &CleanupError{}
			}
			cleanupCancel()
		} else {
			s.stopErr = &CleanupError{}
		}
		if s.stopErr != nil {
			b.mu.Lock()
			b.quarantined = true
			b.mu.Unlock()
			result = errors.Join(result, s.stopErr)
		}

		s.done <- result
	}()
	return s, nil
}

type uniVPNBrokerSession struct {
	ready, done chan error
	cancel      context.CancelFunc
	once        sync.Once
	finished    chan struct{}
	stopErr     error
}

func (s *uniVPNBrokerSession) Ready() <-chan error { return s.ready }
func (s *uniVPNBrokerSession) Done() <-chan error  { return s.done }
func (s *uniVPNBrokerSession) Stop() error         { s.once.Do(s.cancel); <-s.finished; return s.stopErr }

func validateUniVPNBrokerArgs(args []string, allowedCA map[string]bool) error {
	prefix := []string{"--protocol=univpn", "--non-inter", "--passwd-on-stdin", "--no-proxy", "--no-dtls"}
	if len(args) < 7 || len(args) > 12 {
		return errors.New("invalid UniVPN options")
	}
	for i, p := range prefix {
		if args[i] != p {
			return errors.New("required UniVPN safety options missing")
		}
	}
	seen := map[string]bool{}
	for i := 5; i < len(args)-2; i++ {
		arg := args[i]
		if len(arg) > 4096 || strings.ContainsAny(arg, "\r\n\x00") {
			return errors.New("invalid UniVPN option value")
		}
		key, value, ok := strings.Cut(arg, "=")
		if !ok || value == "" || seen[key] {
			return errors.New("invalid or duplicate UniVPN option")
		}
		seen[key] = true
		switch key {
		case "--user", "--authgroup":
			if len(value) > 255 || !utf8.ValidString(value) || hasControl(value) {
				return errors.New("UniVPN identity too long")
			}
		case "--cafile":
			if !allowedCA[value] || trustedUniVPNCA(value) != nil {
				return errors.New("unapproved CA file")
			}
		case "--mtu":
			n, e := strconv.Atoi(value)
			if e != nil || n < 576 || n > 9000 {
				return errors.New("invalid MTU")
			}
		default:
			return errors.New("unapproved UniVPN option")
		}
	}
	if args[len(args)-2] != "--" {
		return errors.New("missing gateway separator")
	}
	raw := args[len(args)-1]
	if err := ValidateProfile(Profile{Name: "broker", Protocol: "univpn", Gateway: raw}); err != nil {
		return err
	}
	u, e := url.Parse(raw)
	if e != nil || len(raw) > 2048 || strings.ContainsAny(raw, "\r\n\x00") || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("invalid UniVPN gateway")
	}
	return nil
}

func trustedUniVPNCA(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("invalid CA path")
	}
	if err := trustedUniVPNPath(filepath.Dir(path), false); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != 0 || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 {
		return errors.New("untrusted CA file")
	}
	return nil
}

const uniVPNFrameLimit = 16384

type uniVPNRequest struct {
	Executable string
	Args       []string
	Password   []byte
}
type uniVPNResponse struct {
	Event         string
	Failed        bool
	CleanupFailed bool
}

func uniVPNWrite(w io.Writer, v any) error {
	p, e := json.Marshal(v)
	if e != nil {
		return e
	}
	defer clear(p)
	if len(p) > uniVPNFrameLimit {
		return errors.New("broker frame too large")
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(p)))
	if _, e = w.Write(h[:]); e != nil {
		return e
	}
	_, e = w.Write(p)
	return e
}
func uniVPNRead(r io.Reader, v any) error {
	var h [4]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return e
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > uniVPNFrameLimit {
		return errors.New("invalid broker frame size")
	}
	p := make([]byte, n)
	defer clear(p)
	if _, e := io.ReadFull(r, p); e != nil {
		return e
	}
	return json.Unmarshal(p, v)
}
func uniVPNPeer(conn *net.UnixConn) (uint32, error) {
	raw, e := conn.SyscallConn()
	if e != nil {
		return 0, e
	}
	var cred *syscall.Ucred
	var inner error
	e = raw.Control(func(fd uintptr) {
		cred, inner = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if e != nil {
		return 0, e
	}
	if inner != nil {
		return 0, inner
	}
	return cred.Uid, nil
}

// trustedUniVPNPath rejects symlinks and non-root/writable parent components.
// Provision the socket in a dedicated root-owned directory; never use /tmp.
func trustedUniVPNPath(path string, socket bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("broker path must be canonical and absolute")
	}
	for p := path; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil {
			return e
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || sys.Uid != 0 || st.Mode()&os.ModeSymlink != 0 || (p != path || !socket) && st.Mode().Perm()&0022 != 0 {
			return errors.New("untrusted broker path ownership or permissions")
		}
		if p == path && socket {
			if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm()&0007 != 0 {
				return errors.New("broker path is not a socket")
			}
		} else if !st.IsDir() {
			return errors.New("broker parent is not a directory")
		}
		if p == "/" {
			break
		}
	}
	return nil
}

// ServeUniVPNBroker serves a socket ALREADY provisioned by a service manager.
// The service manager must give the authorized desktop user connect permission
// via a dedicated group or ACL (e.g. socket mode 0660). Parent directories
// must remain root-owned and not group/other writable; peer UID is also checked.
// AllowedUIDs must be explicit and is copied before accepting clients.
// There is no listener creation, privilege escalation, or host mutation here.
func ServeUniVPNBroker(ctx context.Context, l *net.UnixListener, b *UniVPNBrokerBackend, allowedUIDs []uint32) (result error) {
	if os.Geteuid() != 0 {
		return errors.New("UniVPN broker must run as root")
	}
	if !b.Available() {
		return errors.New("UniVPN backend unavailable")
	}
	if err := trustedUniVPNPath(l.Addr().String(), true); err != nil {
		return err
	}
	allowed := map[uint32]bool{}
	for _, uid := range allowedUIDs {
		if uid != 0 {
			allowed[uid] = true
		}
	}
	if len(allowed) == 0 {
		return errors.New("no authorized desktop UID")
	}
	run, cancel := context.WithCancel(ctx)
	var handlers sync.WaitGroup
	defer func() {
		cancel()
		l.Close()
		result = errors.Join(result, waitUniVPNHandlers(&handlers, 20*time.Second))
		b.mu.Lock()
		dirty := b.quarantined
		b.mu.Unlock()
		if dirty {
			result = errors.Join(result, &CleanupError{})
		}
	}()
	go func() { <-run.Done(); l.Close() }()
	slots := make(chan struct{}, 8)
	for {
		c, e := l.AcceptUnix()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case slots <- struct{}{}:
			handlers.Add(1)
			go func() { defer handlers.Done(); defer func() { <-slots }(); serveUniVPNConn(run, c, b, allowed) }()
		default:
			c.Close()
		}
	}
}

// Join is bounded because injected launch/controller implementations can fail
// to honor cancellation. Timeout is uncertainty, never successful shutdown.
func waitUniVPNHandlers(handlers *sync.WaitGroup, timeout time.Duration) error {
	done := make(chan struct{})
	go func() { handlers.Wait(); close(done) }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return &CleanupError{}
	}
}

func serveUniVPNConn(ctx context.Context, c *net.UnixConn, b TunnelBroker, allowed map[uint32]bool) {
	defer c.Close()
	uid, err := uniVPNPeer(c)
	if err != nil || !allowed[uid] {
		return
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	var req uniVPNRequest
	defer func() { clear(req.Password) }()
	if err = uniVPNRead(c, &req); err != nil {
		return
	}
	session, err := b.Start(ctx, req.Executable, req.Args, req.Password)
	clear(req.Password)
	if err != nil {
		var cleanup *CleanupError
		uniVPNWrite(c, uniVPNResponse{Event: "start", Failed: true, CleanupFailed: errors.As(err, &cleanup)})
		return
	}
	defer session.Stop()
	c.SetDeadline(time.Time{})
	stopped := make(chan struct{})
	go func() { var b [1]byte; c.Read(b[:]); close(stopped) }()
	select {
	case err = <-session.Ready():
	case <-stopped:
		err = context.Canceled
	case <-ctx.Done():
		err = ctx.Err()
	}
	c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	writeErr := uniVPNWrite(c, uniVPNResponse{Event: "ready", Failed: err != nil})
	if err == nil && writeErr == nil {
		select {
		case err = <-session.Done():
		case <-stopped:
		case <-ctx.Done():
		}
	}
	cleanupErr := session.Stop() // never acknowledge disconnect before teardown
	c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	uniVPNWrite(c, uniVPNResponse{Event: "done", Failed: err != nil, CleanupFailed: cleanupErr != nil})

}

// UniVPNUnixBroker is the unprivileged GUI client. Root ownership and SO_PEERCRED
// are both checked; Available never launches anything or sends credentials.
type UniVPNUnixBroker struct{ SocketPath string }

func (b UniVPNUnixBroker) Available() bool { return trustedUniVPNPath(b.SocketPath, true) == nil }
func (b UniVPNUnixBroker) Start(ctx context.Context, executable string, args []string, password []byte) (Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !b.Available() {
		return nil, errors.New("trusted UniVPN socket unavailable")
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, e := d.DialContext(ctx, "unix", b.SocketPath)
	if e != nil {
		return nil, e
	}
	c := conn.(*net.UnixConn)
	uid, e := uniVPNPeer(c)
	if e != nil || uid != 0 {
		c.Close()
		return nil, errors.New("UniVPN broker peer is not root")
	}
	c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if e = uniVPNWrite(c, uniVPNRequest{executable, args, password}); e != nil {
		c.Close()
		return nil, errors.Join(e, &CleanupError{})
	}
	run, cancel := context.WithCancel(ctx)
	s := &uniVPNBrokerSession{ready: make(chan error, 1), done: make(chan error, 1), cancel: cancel, finished: make(chan struct{})}
	go func() {
		select {
		case <-run.Done():
			c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			c.Write([]byte{1})
			c.SetReadDeadline(time.Now().Add(20 * time.Second))
		case <-s.finished:
		}
	}()
	go func() {
		defer close(s.finished)
		defer cancel()
		defer c.Close()
		defer close(s.ready)
		defer close(s.done)
		var r uniVPNResponse
		e := uniVPNRead(c, &r)
		if e != nil || (r.Event != "ready" && r.Event != "start") {
			s.stopErr = &CleanupError{}
			s.ready <- s.stopErr
			s.done <- s.stopErr
			return
		}
		if r.Event == "start" {
			e = errors.New("UniVPN broker rejected start")
			if r.CleanupFailed {
				s.stopErr = &CleanupError{}
				e = errors.Join(e, s.stopErr)
			}
			s.ready <- e
			s.done <- e
			return
		}
		if r.Failed {
			e = errors.New("UniVPN broker failed before ready")
		}
		s.ready <- e
		if readErr := uniVPNRead(c, &r); readErr != nil || r.Event != "done" || r.CleanupFailed {
			s.stopErr = &CleanupError{}
			e = errors.Join(e, s.stopErr)
		} else if r.Failed {
			e = errors.Join(e, errors.New("UniVPN native session failed"))
		}
		s.done <- e
	}()
	return s, nil
}
