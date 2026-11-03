package core

// Linux transport: OpenConnect performs unprivileged authentication; NetworkManager
// and its distro-provided openconnect plugin own the privileged tunnel/routes/DNS.
// References: https://www.infradead.org/openconnect/nonroot.html
// https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nmcli.html
// GNOME NetworkManager-openconnect src/nm-openconnect-service.c (27aecc326d98).
import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type commandRunner interface {
	Run(context.Context, string, []string, []byte) ([]byte, error)
}
type execRunner struct{}
type boundedOutput struct {
	buffer   bytes.Buffer
	overflow context.CancelFunc
}

func (b *boundedOutput) Bytes() []byte { return b.buffer.Bytes() }
func (b *boundedOutput) Len() int      { return b.buffer.Len() }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 65536 {
		if b.overflow != nil {
			b.overflow()
		}
		return 0, errors.New("backend output exceeded limit")
	}
	return b.buffer.Write(p)
}
func (r execRunner) Run(ctx context.Context, path string, args []string, input []byte) ([]byte, error) {
	return r.RunWithFiles(ctx, path, args, input, nil)
}
func (execRunner) RunWithFiles(ctx context.Context, path string, args []string, input []byte, files []*os.File) ([]byte, error) {
	commandCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(commandCtx, path, args...)
	cmd.Env = isolatedCommandEnvironment(os.Environ())
	cmd.ExtraFiles = files
	cmd.Stdin = bytes.NewReader(input)
	b := boundedOutput{overflow: cancel}
	cmd.Stdout = &b
	cmd.Stderr = nil
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Run(); err != nil {
		for i := range b.Bytes() {
			b.Bytes()[i] = 0
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("backend command failed")
	}
	return b.Bytes(), nil
}

type NetworkManager struct {
	l2tpAvailable       bool
	mfa                 *MFAHelper
	authPrompt          AuthPrompt
	runner              commandRunner
	nm, oc              string
	cap                 Capability
	checkInterface      func(string) bool
	interfaceGone       func(string) bool
	interfaceHasAddress func(string, string) bool
	readMetrics         func(string) SessionMetrics
}

func NewNetworkManager() *NetworkManager {
	n := &NetworkManager{runner: execRunner{}, checkInterface: interfaceReady, interfaceGone: interfaceAbsent, readMetrics: readInterfaceMetrics, interfaceHasAddress: interfaceHasAddress}
	n.cap.Message = "Live VPN requires Linux with NetworkManager and its OpenConnect plugin."
	if runtime.GOOS != "linux" {
		return n
	}
	var e error
	n.nm, e = exec.LookPath("nmcli")
	if e != nil {
		n.cap.Message = "NetworkManager CLI is not installed; live connection unavailable."
		return n
	}
	n.oc, _ = exec.LookPath("openconnect")
	hasPlugin := func(name string) bool {
		for _, dir := range []string{"/usr/lib/NetworkManager/VPN/", "/usr/lib64/NetworkManager/VPN/", "/usr/share/NetworkManager/VPN/"} {
			b, err := os.ReadFile(dir + "nm-" + name + "-service.name")
			if err == nil && bytes.Contains(b, []byte("org.freedesktop.NetworkManager."+name)) {
				return true
			}
		}
		return false
	}
	if !hasPlugin("openconnect") {
		n.oc = ""
	}
	n.l2tpAvailable = hasPlugin("l2tp")
	if n.oc == "" && !n.l2tpAvailable {
		n.cap.Message = "Install NetworkManager OpenConnect or L2TP/IPsec plugin."
		return n
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, e := n.runner.Run(ctx, n.nm, []string{"-t", "-f", "RUNNING", "general"}, nil)
	if e != nil || strings.TrimSpace(string(out)) != "running" {
		n.cap.Message = "NetworkManager service is unavailable."
		return n
	}
	n.cap = Capability{true, "Linux VPN via installed NetworkManager plugins. Gateway compatibility must be validated; OS authorization may be required.", n.nm}
	return n
}

// SetAuthPrompt configures the UI prompt before the adapter is used by Engine.
// The adapter must not be reconfigured while authentication is in progress.
func (n *NetworkManager) SetAuthPrompt(prompt AuthPrompt) {
	n.authPrompt = prompt
	n.mfa = NewMFAHelper()
}
func (n *NetworkManager) Capability() Capability { return n.cap }
func (n *NetworkManager) SupportsProtocol(protocol string) bool {
	return n.cap.Available && ((protocol == "anyconnect" && n.oc != "") || (protocol == "l2tp" && n.l2tpAvailable))
}
func interfaceAbsent(name string) bool {
	all, e := net.Interfaces()
	if e != nil {
		return false
	}
	for _, i := range all {
		if i.Name == name {
			return false
		}
	}
	return true
}
func interfaceReady(name string) bool {
	i, e := net.InterfaceByName(name)
	if e != nil || i.Flags&net.FlagUp == 0 {
		return false
	}
	a, e := i.Addrs()
	return e == nil && len(a) > 0
}
func (n *NetworkManager) Start(ctx context.Context, p Profile, secret []byte) (Session, error) {
	return n.StartWithCredentials(ctx, p, Credentials{Password: secret})
}
func (n *NetworkManager) StartWithCredentials(ctx context.Context, p Profile, credentials Credentials) (Session, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if !n.cap.Available {
		return nil, errors.New(n.cap.Message)
	}
	if e := ValidateProfile(p); e != nil {
		return nil, e
	}
	if err := validateCredentials(p, credentials); err != nil {
		return nil, err
	}
	if p.Protocol == "l2tp" {
		return n.startL2TP(ctx, p, credentials)
	}
	if n.oc == "" {
		return nil, errors.New("OpenConnect plugin is unavailable")
	}
	if p.Protocol != "anyconnect" {
		return nil, errors.New("Linux broker currently supports AnyConnect only")
	}
	if err := validateCredentials(p, credentials); err != nil {
		return nil, err
	}
	if strings.ContainsAny(p.Gateway, ",\\") {
		return nil, errors.New("gateway contains unsupported delimiters")
	}
	authCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var fields map[string]string
	var e error
	if p.InteractiveAuth {
		if n.mfa == nil || n.authPrompt == nil {
			return nil, errors.New("interactive authentication requires the optional helper and an active authentication dialog")
		}
		fields, e = n.mfa.Authenticate(authCtx, p, credentials, n.authPrompt)
	} else {
		var out []byte
		out, e = authenticateOpenConnect(authCtx, n.runner, n.oc, p, credentials)
		if e == nil {
			fields, e = parseAuthentication(out)
		}
		clear(out)
	}
	if e != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("authentication failed; check gateway, credentials, client certificate and supported authentication method")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	id := NewID()
	uuid := id[:8] + "-" + id[8:12] + "-4" + id[13:16] + "-a" + id[17:20] + "-" + id[20:]
	iface := "md" + id[:10]
	vpnData := "gateway=" + p.Gateway + ",protocol=anyconnect,cookie-flags=2,gateway-flags=2,gwcert-flags=2,resolve-flags=2"
	if p.ProxyURL != "" {
		vpnData += ",proxy=" + p.ProxyURL
	}
	if p.DisableUDP {
		vpnData += ",disable-udp=yes"
	}
	if p.MTU != 0 {
		vpnData += ",mtu=" + strconv.Itoa(p.MTU)
	}
	add := []string{"--wait", "15", "connection", "add", "save", "no", "type", "vpn", "con-name", "Meridian-" + id[:8], "connection.uuid", uuid, "connection.interface-name", iface, "connection.autoconnect", "no", "vpn.service-type", "org.freedesktop.NetworkManager.openconnect", "vpn.data", vpnData}
	_, addErr := n.runner.Run(authCtx, n.nm, add, nil)
	s := &nmSession{n: n, uuid: uuid, iface: iface, ready: make(chan error, 1), done: make(chan error, 1)}
	s.ctx, s.cancel = context.WithCancel(ctx)
	fail := func(err error) (Session, error) {
		if stopErr := s.Stop(); stopErr != nil {
			return nil, errors.Join(err, stopErr)
		}
		return nil, err
	}
	if addErr != nil {
		return fail(errors.New("NetworkManager could not create a temporary profile; check OS permissions"))
	}
	var passwd bytes.Buffer
	for _, pair := range [][2]string{{"cookie", fields["COOKIE"]}, {"gateway", fields["CONNECT_URL"]}, {"gwcert", fields["FINGERPRINT"]}, {"resolve", fields["RESOLVE"]}} {
		if pair[1] != "" {
			fmt.Fprintf(&passwd, "vpn.secrets.%s:%s\n", pair[0], pair[1])
		}
	}
	_, e = n.runner.Run(authCtx, n.nm, []string{"--wait", "60", "connection", "up", "uuid", uuid, "passwd-file", "/proc/self/fd/0"}, passwd.Bytes())
	for i := range passwd.Bytes() {
		passwd.Bytes()[i] = 0
	}
	if e != nil {
		return fail(errors.New("NetworkManager activation failed"))
	}
	if !s.verified(authCtx) {
		return fail(errors.New("NetworkManager did not confirm the active tunnel and interface"))
	}
	if ctx.Err() != nil {
		return fail(ctx.Err())
	}
	s.updateMetrics()
	s.ready <- nil
	go s.monitor()
	return s, nil
}

// parseAuthentication accepts only OpenConnect's quoted assignments. No shell,
// expansion or eval is used. Quoting outside this strict subset fails closed.
func parseAuthentication(data []byte) (map[string]string, error) {
	if len(data) > 65536 {
		return nil, errors.New("authentication response exceeds size limit")
	}
	m := map[string]string{}
	allowed := map[string]bool{"COOKIE": true, "HOST": true, "CONNECT_URL": true, "FINGERPRINT": true, "RESOLVE": true}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || !allowed[k] {
			return nil, errors.New("unsupported authentication response")
		}
		if k == "RESOLVE" && v == "" { // OpenConnect 9.12 emits this exact empty assignment.
		} else {
			if len(v) < 2 || v[0] != '\'' || v[len(v)-1] != '\'' {
				return nil, errors.New("unsupported authentication response")
			}
			v = v[1 : len(v)-1]
		}
		_, duplicate := m[k]
		if strings.Contains(v, "'") || hasControl(v) || len(v) > 16384 || duplicate {
			return nil, errors.New("invalid authentication response")
		}
		m[k] = v
	}
	if m["COOKIE"] == "" || m["FINGERPRINT"] == "" || m["CONNECT_URL"] == "" {
		return nil, errors.New("authentication response lacks required modern OpenConnect fields")
	}
	p := Profile{Name: "auth", Protocol: "anyconnect", Gateway: m["CONNECT_URL"]}
	if ValidateProfile(p) != nil {
		return nil, errors.New("invalid authenticated gateway")
	}
	return m, nil
}

type nmSession struct {
	verifyAddress bool
	n             *NetworkManager
	uuid, iface   string
	ctx           context.Context
	cancel        context.CancelFunc
	ready, done   chan error
	once          sync.Once
	stopErr       error
	metricsMu     sync.RWMutex
	metrics       SessionMetrics
}

func (s *nmSession) Ready() <-chan error { return s.ready }
func (s *nmSession) Done() <-chan error  { return s.done }
func (s *nmSession) verified(ctx context.Context) bool {
	out, e := s.n.runner.Run(ctx, s.n.nm, []string{"-g", "GENERAL.STATE,VPN.VPN-STATE", "connection", "show", "uuid", s.uuid}, nil)
	if e != nil {
		return false
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if !(len(lines) == 2 && lines[0] == "activated" && strings.HasPrefix(lines[1], "5 ") && s.n.checkInterface(s.iface)) {
		return false
	}
	if s.verifyAddress {
		addresses, err := s.n.runner.Run(ctx, s.n.nm, []string{"-g", "IP4.ADDRESS", "connection", "show", "uuid", s.uuid}, nil)
		if err != nil || s.n.interfaceHasAddress == nil {
			return false
		}
		lines := strings.Split(strings.TrimSpace(string(addresses)), "\n")
		if len(lines) != 1 || !s.n.interfaceHasAddress(s.iface, lines[0]) {
			return false
		}
	}
	return true
}
func (s *nmSession) monitor() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
			ok := s.verified(ctx)
			cancel()
			if ok {
				s.updateMetrics()
			}
			if !ok {
				if s.ctx.Err() != nil {
					return
				}
				_ = s.stopWithCause(errors.New("tunnel verification was lost"))
				return
			}
		}
	}
}

// Stop waits for NetworkManager deletion, which deactivates this UUID and removes
// its routes/DNS. Only the fresh app-created UUID is ever deleted.
func (s *nmSession) Stop() error { return s.stopWithCause(nil) }
func (s *nmSession) stopWithCause(cause error) error {
	s.once.Do(func() {
		s.cancel()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, e := s.n.runner.Run(ctx, s.n.nm, []string{"--wait", "15", "connection", "delete", "uuid", s.uuid}, nil)
		if e != nil {
			// A cancelled add or repeated deletion may already have left no profile.
			// Only a successful fresh UUID inventory can establish absence.
			out, queryErr := s.n.runner.Run(ctx, s.n.nm, []string{"-g", "UUID", "connection", "show"}, nil)
			absent, valid := uuidAbsent(out, s.uuid)
			absent = absent && valid && queryErr == nil
			if !absent {
				s.stopErr = &CleanupError{}
			}
		}
		if s.stopErr == nil {
			for {
				out, err := s.n.runner.Run(ctx, s.n.nm, []string{"-g", "UUID", "connection", "show", "--active"}, nil)
				absent, valid := uuidAbsent(out, s.uuid)
				if !valid {
					s.stopErr = &CleanupError{}
					break
				}
				absent = absent && err == nil
				if absent && s.n.interfaceGone(s.iface) {
					break
				}
				select {
				case <-ctx.Done():
					s.stopErr = &CleanupError{}
				case <-time.After(100 * time.Millisecond):
					continue
				}
				break
			}
		}
		terminalErr := cause
		if s.stopErr != nil {
			terminalErr = s.stopErr
		}
		s.done <- terminalErr
		close(s.done)
	})
	return s.stopErr
}

// A malformed inventory is not evidence that the owned connection disappeared.
func uuidAbsent(data []byte, want string) (bool, bool) {
	absent := true
	text := strings.TrimSpace(string(data))
	if text == "" {
		return true, true
	}
	for _, id := range strings.Split(text, "\n") {
		if len(id) != 36 {
			return false, false
		}
		for i, c := range id {
			if i == 8 || i == 13 || i == 18 || i == 23 {
				if c != '-' {
					return false, false
				}
			} else if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false, false
			}
		}
		if strings.EqualFold(id, want) {
			absent = false
		}
	}
	return absent, true
}

func (s *nmSession) Metrics() SessionMetrics {
	if s.ctx.Err() != nil {
		return SessionMetrics{}
	}
	s.metricsMu.RLock()
	defer s.metricsMu.RUnlock()
	return s.metrics
}
func (s *nmSession) updateMetrics() {
	m := SessionMetrics{}
	if s.n.readMetrics != nil {
		m = s.n.readMetrics(s.iface)
	}
	s.metricsMu.Lock()
	s.metrics = m
	s.metricsMu.Unlock()
}

// Ambient proxy variables may contain credentials. Explicit profile proxy policy
// must not be silently replaced by the GUI process environment. This controls
// our children only, not the administrator-managed NetworkManager service.
func isolatedCommandEnvironment(env []string) []string {
	out := make([]string, 0, len(env)+2)
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		lower := strings.ToLower(key)
		if strings.HasSuffix(lower, "_proxy") || lower == "lc_all" || lower == "lang" {
			continue
		}
		out = append(out, entry)
	}
	return append(out, "LC_ALL=C", "LANG=C")
}
