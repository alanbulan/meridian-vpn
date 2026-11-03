//go:build linux

package nmvpn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"
)

// PluginPlan is trusted broker input. Its fresh nonce must be installed in the
// broker-owned activation profile before that single activation is requested.
// A profile UUID, user-provided active path or UUID-only scan is not a receipt.
// Only supports-multiple-connections=false registration is supported.
type PluginPlan struct{ UUID, Interface, Username, Nonce string }

func NewPluginPlan(uuid, iface, username string) (PluginPlan, error) {
	p := PluginPlan{UUID: uuid, Interface: iface, Username: username}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return PluginPlan{}, errPeer
	}
	p.Nonce = hex.EncodeToString(nonce[:])
	if !validPluginPlan(p) {
		return PluginPlan{}, errPeer
	}
	return p, nil
}
func validPluginPlan(p PluginPlan) bool {
	return uuidPattern.MatchString(p.UUID) && linkPattern.MatchString(p.Interface) && p.Interface != "lo" && sessionPattern.MatchString(p.Nonce) && len(p.Username) <= 255 && utf8.ValidString(p.Username) && !strings.ContainsAny(p.Username, "\r\n\x00")
}

// Plugin implements the deliberately non-interactive incoming NM ABI on the
// exact connection that emits Config. One bus owns one Plugin and one Connect.
// Connect acceptance is only a bounded handoff, not launch or network readiness.
type Plugin struct {
	mu           sync.Mutex
	bus          *PinnedBus
	plan         PluginPlan
	ctx          context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	requests     chan *Activation
	activation   atomic.Pointer[Activation]
	disconnected atomic.Bool
	disconnectCh chan struct{}
	published    atomic.Uint32
	state        uint32
	consumed     bool
}

// Activation is opaque authenticated Connect evidence. Secrets are separated
// from its immutable network profile. It does not itself prove host authority,
// active-path correlation, resource ownership, or deployment policy.
type Activation struct {
	mu           sync.Mutex
	plugin       *Plugin
	profile      map[string]map[string]dbus.Variant
	ctx          context.Context
	cancel       context.CancelFunc
	password     []byte
	secretExpiry *time.Timer
	used         bool
	usedOK       bool
	binding      *Binding
	offer        Offer
}

// ServePlugin exports before claiming the fixed name, never raw Conn or arbitrary
// methods. Closing its lifetime invalidates this bus; no activation can be reused.
func ServePlugin(ctx context.Context, b *PinnedBus, plan PluginPlan) (*Plugin, error) {
	if b == nil || ctx == nil || !validPluginPlan(plan) || ctx.Err() != nil {
		return nil, errPeer
	}
	run, cancel := context.WithCancel(ctx)
	p := &Plugin{bus: b, plan: plan, ctx: run, cancel: cancel, done: make(chan struct{}), requests: make(chan *Activation, 1), disconnectCh: make(chan struct{}), state: 1}
	if !b.plugin.CompareAndSwap(nil, p) {
		cancel()
		return nil, errPeer
	}
	err := b.run(ctx, func(ctx context.Context) error {
		if b.claimed || b.check(ctx, false) != nil {
			return errPeer
		}
		methods := map[string]any{"Connect": p.connect, "NeedSecrets": p.needSecrets, "ConnectInteractive": p.connectInteractive, "Disconnect": p.disconnect}
		if b.conn.ExportMethodTable(methods, PluginPath, PluginInterface) != nil {
			return errPeer
		}
		return b.conn.ExportMethodTable(map[string]any{"Get": p.get, "GetAll": p.getAll}, PluginPath, propertiesInterface)
	})
	if err == nil {
		err = b.ClaimPluginName(ctx)
	}
	if err != nil {
		cancel()
		_ = b.Close()
		close(p.done)
		return nil, errPeer
	}
	go func() {
		defer close(p.done)
		disconnect := p.disconnectCh
		for {
			select {
			case <-disconnect:
				if a := p.activation.Load(); a != nil {
					a.cancel()
					a.erasePassword()
				}
				disconnect = nil // stay available to report STOPPED after native cleanup
				continue
			case <-run.Done():
			case <-b.conn.Context().Done():
			case <-b.invalidated:
			}
			p.fence()
			cancel()
			if a := p.activation.Load(); a != nil {
				a.cancel()
				a.erasePassword()
			}
			_ = b.Close()
			return
		}
	}()
	return p, nil
}
func (p *Plugin) Close() error { p.cancel(); <-p.done; return nil }
func (p *Plugin) Receive(ctx context.Context) (*Activation, error) {
	select {
	case <-ctx.Done():
		return nil, errPeer
	case <-p.ctx.Done():
		return nil, errPeer
	case <-p.disconnectCh:
		return nil, errPeer
	case a := <-p.requests:
		if a.CheckLive(ctx) != nil {
			a.erasePassword()
			return nil, errPeer
		}
		return a, nil
	}
}

// The bus reader latches authenticated Disconnect in receive order, before
// godbus launches handlers in unordered goroutines. No callbacks/I/O/locks here.
func (p *Plugin) observe(m *dbus.Message) {
	if p.messageOK(m, "Disconnect") && len(m.Body) == 0 {
		p.fence()
	}
}
func (p *Plugin) fence() {
	if p.disconnected.CompareAndSwap(false, true) && p.disconnectCh != nil {
		close(p.disconnectCh)
	}
}
func (p *Plugin) messageOK(m *dbus.Message, member string) bool {
	if m.Type != dbus.TypeMethodCall || m.Flags&dbus.FlagNoReplyExpected != 0 || m.Headers[dbus.FieldSender].Value() != p.bus.pin.Owner || m.Headers[dbus.FieldPath].Value() != PluginPath || m.Headers[dbus.FieldMember].Value() != member {
		return false
	}
	iface := PluginInterface
	signature := ""
	switch member {
	case "Get":
		iface = propertiesInterface
		signature = "ss"
	case "GetAll":
		iface = propertiesInterface
		signature = "s"
	case "Connect", "NeedSecrets":
		signature = "a{sa{sv}}"
	case "ConnectInteractive":
		signature = "a{sa{sv}}a{sv}"
	case "Disconnect":
	default:
		return false
	}
	if m.Headers[dbus.FieldInterface].Value() != iface {
		return false
	}
	got, ok := m.Headers[dbus.FieldSignature].Value().(dbus.Signature)
	if signature != "" && (!ok || got.String() != signature) {
		return false
	}
	if signature == "" && ok && got.String() != "" {
		return false
	}
	dest := m.Headers[dbus.FieldDestination].Value()
	return dest == p.bus.unique || dest == PluginService
}
func pluginError(name string) *dbus.Error {
	return &dbus.Error{Name: name, Body: []any{"VPN request rejected"}}
}
func (p *Plugin) authenticate(m *dbus.Message, member string) error {
	if !p.messageOK(m, member) || p.ctx.Err() != nil || p.bus.invalid.Load() {
		return errPeer
	}
	return p.bus.run(p.ctx, func(ctx context.Context) error { return p.bus.check(ctx, true) })
}
func (p *Plugin) needSecrets(m dbus.Message, s map[string]map[string]dbus.Variant) (string, *dbus.Error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.authenticate(&m, "NeedSecrets") != nil || p.consumed || p.disconnected.Load() {
		return "", pluginError("org.freedesktop.NetworkManager.VPN.Error.WrongState")
	}
	_, password, err := incomingProfile(s, p.plan)
	if err != nil {
		return "", pluginError("org.freedesktop.NetworkManager.VPN.Error.BadArguments")
	}
	if len(password) == 0 {
		return "vpn", nil
	}
	return "", nil
}
func (p *Plugin) connectInteractive(m dbus.Message, s map[string]map[string]dbus.Variant, details map[string]dbus.Variant) *dbus.Error {
	// NM only falls back to Connect for this exact error, not UnknownMethod.
	if p.authenticate(&m, "ConnectInteractive") != nil {
		return pluginError("org.freedesktop.DBus.Error.AccessDenied")
	}
	return pluginError("org.freedesktop.NetworkManager.VPN.Error.InteractiveNotSupported")
}
func (p *Plugin) connect(m dbus.Message, s map[string]map[string]dbus.Variant) *dbus.Error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.authenticate(&m, "Connect") != nil {
		return pluginError("org.freedesktop.DBus.Error.AccessDenied")
	}
	if p.consumed || p.disconnected.Load() {
		return pluginError("org.freedesktop.NetworkManager.VPN.Error.WrongState")
	}
	profile, password, err := incomingProfile(s, p.plan)
	if err != nil || len(password) == 0 {
		return pluginError("org.freedesktop.NetworkManager.VPN.Error.BadArguments")
	}
	p.consumed = true
	ctx, cancel := context.WithCancel(p.ctx)
	a := &Activation{plugin: p, profile: profile, ctx: ctx, cancel: cancel, password: []byte(password)}
	a.secretExpiry = time.AfterFunc(30*time.Second, a.expireSecret)
	p.activation.Store(a)
	if p.disconnected.Load() || p.stateLocked(p.ctx, 3) != nil {
		p.fence()
		p.cancel()
		cancel()
		a.erasePassword()
		return pluginError("org.freedesktop.NetworkManager.VPN.Error.WrongState")
	}
	p.requests <- a // single bounded slot; consumed forbids a second writer
	return nil
}
func (p *Plugin) disconnect(m dbus.Message) *dbus.Error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.authenticate(&m, "Disconnect") != nil {
		return pluginError("org.freedesktop.DBus.Error.AccessDenied")
	}
	p.fence()
	a := p.activation.Load()
	if a != nil {
		a.cancel()
		a.erasePassword()
	}
	if p.state == 6 {
		return pluginError("org.freedesktop.NetworkManager.VPN.Error.AlreadyStopped")
	}
	if a == nil {
		if p.stateLocked(p.ctx, 6) != nil {
			return pluginError("org.freedesktop.NetworkManager.VPN.Error.WrongState")
		}
		return nil
	}
	if p.stateLocked(p.ctx, 5) != nil {
		return pluginError("org.freedesktop.NetworkManager.VPN.Error.WrongState")
	}
	return nil // native owner must join exact handles before MarkStopped
}
func (p *Plugin) get(m dbus.Message, iface, key string) (dbus.Variant, *dbus.Error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.authenticate(&m, "Get") != nil || iface != PluginInterface || key != "State" {
		return dbus.MakeVariant(uint32(0)), pluginError("org.freedesktop.DBus.Error.AccessDenied")
	}
	return dbus.MakeVariant(p.state), nil
}
func (p *Plugin) getAll(m dbus.Message, iface string) (map[string]dbus.Variant, *dbus.Error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.authenticate(&m, "GetAll") != nil || iface != PluginInterface {
		return nil, pluginError("org.freedesktop.DBus.Error.AccessDenied")
	}
	return map[string]dbus.Variant{"State": dbus.MakeVariant(p.state)}, nil
}
func (p *Plugin) stateLocked(ctx context.Context, state uint32) error {
	if ctx.Err() != nil {
		return errPeer
	}
	p.state = state
	return p.bus.run(ctx, func(ctx context.Context) error {
		if p.bus.check(ctx, true) != nil {
			return errPeer
		}
		if p.bus.conn.Emit(PluginPath, PluginInterface+".StateChanged", state) != nil {
			p.bus.markInvalid()
			return errPeer
		}
		return p.bus.check(ctx, true)
	})
}

func (a *Activation) Context() context.Context {
	if a == nil || a.ctx == nil {
		return canceledContext()
	}
	return a.ctx
}
func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
func (a *Activation) UUID() string {
	if a == nil || a.plugin == nil {
		return ""
	}
	return a.plugin.plan.UUID
}
func (a *Activation) Interface() string {
	if a == nil || a.plugin == nil {
		return ""
	}
	return a.plugin.plan.Interface
}
func (a *Activation) Username() string {
	if a == nil || a.plugin == nil {
		return ""
	}
	return a.plugin.plan.Username
}
func (a *Activation) Nonce() string {
	if a == nil || a.plugin == nil {
		return ""
	}
	return a.plugin.plan.Nonce
}
func (a *Activation) Profile() map[string]map[string]dbus.Variant {
	if a == nil {
		return nil
	}
	return cloneSafeProfile(a.profile)
}
func (a *Activation) CheckLive(ctx context.Context) error {
	if a == nil || a.plugin == nil || a.plugin.activation.Load() != a || ctx == nil || ctx.Err() != nil || a.ctx.Err() != nil || a.plugin.disconnected.Load() || a.plugin.bus.invalid.Load() {
		return errPeer
	}
	return nil
}
func (a *Activation) expireSecret() {
	a.mu.Lock()
	unused := !a.used
	if unused {
		clear(a.password)
		a.password = nil
	}
	a.mu.Unlock()
	if unused {
		a.plugin.fence()
		a.cancel()
		if a.plugin.cancel != nil {
			a.plugin.cancel()
		}
	}
}
func (a *Activation) erasePassword() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.secretExpiry != nil {
		a.secretExpiry.Stop()
	}
	clear(a.password)
	a.password = nil
}

// MarkStarted/MarkStopped perform bus I/O. Never call them inside Broker
// callbacks: DBusPeer holds its bus serialization lock during those callbacks.
// Call lifecycle reports after Controller/Peer operations have returned.

// Unconsumed credentials expire after 30 seconds, revoking the activation.
// UsePassword consumes exactly once, even on failure. It never retains callback
// errors, which could contain credentials. Callback must not retain the bytes.
// D-Bus decoding creates immutable Go strings: complete memory erasure is NOT
// promised. No secret reaches profile snapshots, journals, logs or reply text.
func (a *Activation) UsePassword(ctx context.Context, fn func([]byte) error) error {
	if a == nil || fn == nil {
		return errPeer
	}
	a.mu.Lock()
	if a.used || len(a.password) == 0 || a.CheckLive(ctx) != nil {
		clear(a.password)
		a.password = nil
		a.mu.Unlock()
		return errPeer
	}
	a.used = true
	if a.secretExpiry != nil {
		a.secretExpiry.Stop()
	}
	password := a.password
	a.password = nil
	a.mu.Unlock()
	defer clear(password)
	if err := fn(password); err != nil {
		return errPeer
	}
	if a.CheckLive(ctx) != nil {
		return errPeer
	}
	a.mu.Lock()
	a.usedOK = true
	a.mu.Unlock()
	return nil
}

// CheckReceipt rejects mismatched local pins before credentials are consumed.
// It is not proof of the external manager transaction; HostAuthority must supply
// that correlation, including Nonce. The native Session must still be empty.
func (a *Activation) CheckReceipt(ctx context.Context, b Binding) error {
	if a.CheckLive(ctx) != nil || b.Identity.Session != "" {
		return errPeer
	}
	candidate := b.Identity
	candidate.Session = strings.Repeat("0", 32)
	if validateRecord(Record{Version: 1, Identity: candidate, Phase: "intent"}) != nil || !settingsPathPattern.MatchString(string(b.ConnectionPath)) || len(b.ConnectionPath) > 128 || b.Identity.UUID != a.UUID() || b.Identity.Interface != a.Interface() || b.Identity.BusID != a.plugin.bus.pin.BusID || b.Identity.Owner != a.plugin.bus.pin.Owner || b.PluginOwner != a.plugin.bus.UniqueName() {
		return errPeer
	}
	return nil
}
func (a *Activation) Bind(ctx context.Context, b Binding, o Offer) error {
	if a == nil {
		return errPeer
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.CheckLive(ctx) != nil || !a.usedOK || a.binding != nil || validateRecord(Record{Version: 1, Identity: b.Identity, Phase: "intent"}) != nil || !settingsPathPattern.MatchString(string(b.ConnectionPath)) || len(b.ConnectionPath) > 128 || b.Identity.UUID != a.UUID() || b.Identity.Interface != a.Interface() || b.Identity.BusID != a.plugin.bus.pin.BusID || b.Identity.Owner != a.plugin.bus.pin.Owner || b.PluginOwner != a.plugin.bus.UniqueName() || o.Session != b.Identity.Session || o.Interface != b.Identity.Interface || ValidateProfile(a.profile, b.Identity) != nil {
		return errPeer
	}
	copy := b
	a.binding = &copy
	a.offer = copyOffer(o)
	return nil
}
func (a *Activation) VerifyBinding(b Binding, o Offer) error {
	if a == nil {
		return errPeer
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.plugin == nil || a.plugin.activation.Load() != a || a.binding == nil || *a.binding != b || !reflect.DeepEqual(a.offer, o) {
		return errPeer
	}
	return nil
}
func (a *Activation) MarkStarted(ctx context.Context) error {
	if a.CheckLive(ctx) != nil {
		return errPeer
	}
	p := a.plugin
	p.mu.Lock()
	defer p.mu.Unlock()
	if a.CheckLive(ctx) != nil || p.state != 3 || p.published.Load() != 2 {
		return errPeer
	}
	a.mu.Lock()
	bound := a.binding != nil
	a.mu.Unlock()
	if !bound {
		return errPeer
	}
	return p.stateLocked(ctx, 4)
}
func (a *Activation) MarkStopped(ctx context.Context) error {
	if a == nil || a.plugin == nil || ctx.Err() != nil {
		return errPeer
	}
	p := a.plugin
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.activation.Load() != a || (p.state != 3 && p.state != 4 && p.state != 5) {
		return errPeer
	}
	p.fence()
	a.cancel()
	a.erasePassword()
	return p.stateLocked(ctx, 6)
}

// Credential metadata is parsed separately from the closed network grammar.
// The only data are a fresh per-activation nonce and not-saved password flag.
// Native executable, gateway, CA and arguments never come from this envelope.
func incomingProfile(s map[string]map[string]dbus.Variant, p PluginPlan) (map[string]map[string]dbus.Variant, string, error) {
	network, username, nonce, password, err := splitProfileEnvelope(s)
	data, ok := s["vpn"]["data"].Value().(map[string]string)
	if !ok || data["password-flags"] != "2" {
		return nil, "", errPeer
	}
	if err != nil || username != p.Username || nonce != p.Nonce || ValidateProfile(network, Identity{UUID: p.UUID, Interface: p.Interface}) != nil {
		return nil, "", errPeer
	}
	return cloneSafeProfile(network), password, nil
}
func splitProfileEnvelope(s map[string]map[string]dbus.Variant) (map[string]map[string]dbus.Variant, string, string, string, error) {
	if len(s) < 4 || len(s) > 5 {
		return nil, "", "", "", errPeer
	}
	// Clone only outer maps first, bound before iterating. Accepted network values
	// are scalars or empty collections, so the final clone has no mutable children.
	n := make(map[string]map[string]dbus.Variant, len(s))
	for section, values := range s {
		if len(values) > 32 {
			return nil, "", "", "", errPeer
		}
		n[section] = make(map[string]dbus.Variant, len(values))
		for k, v := range values {
			n[section][k] = v
		}
	}
	vpn := n["vpn"]
	if vpn == nil {
		return nil, "", "", "", errPeer
	}
	username, nonce, password := "", "", ""
	if v, ok := vpn["user-name"]; ok {
		var valid bool
		username, valid = v.Value().(string)
		if !valid || v.Signature().String() != "s" || len(username) > 255 || !utf8.ValidString(username) || strings.ContainsAny(username, "\r\n\x00") {
			return nil, "", "", "", errPeer
		}
		delete(vpn, "user-name")
	}
	if v, ok := vpn["data"]; ok {
		data, valid := v.Value().(map[string]string)
		if !valid || v.Signature().String() != "a{ss}" || len(data) > 2 {
			return nil, "", "", "", errPeer
		}
		for k, value := range data {
			switch k {
			case "meridian-activation":
				if !sessionPattern.MatchString(value) {
					return nil, "", "", "", errPeer
				}
				nonce = value
			case "password-flags":
				if value != "2" {
					return nil, "", "", "", errPeer
				}
			default:
				return nil, "", "", "", errPeer
			}
		}
		delete(vpn, "data")
	}
	if v, ok := vpn["secrets"]; ok {
		secrets, valid := v.Value().(map[string]string)
		if !valid || v.Signature().String() != "a{ss}" || len(secrets) > 1 {
			return nil, "", "", "", errPeer
		}
		for k, value := range secrets {
			if k != "password" || len(value) > 4095 || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n\x00") {
				return nil, "", "", "", errPeer
			}
			password = value
		}
		delete(vpn, "secrets")
	}
	return n, username, nonce, password, nil
}
func cloneSafeProfile(s map[string]map[string]dbus.Variant) map[string]map[string]dbus.Variant {
	n := make(map[string]map[string]dbus.Variant, len(s))
	for k, values := range s {
		n[k] = make(map[string]dbus.Variant, len(values))
		for key, v := range values {
			r := reflect.ValueOf(v.Value())
			switch r.Kind() {
			case reflect.Map:
				r = reflect.MakeMap(r.Type())
			case reflect.Slice:
				r = reflect.MakeSlice(r.Type(), 0, 0)
			}
			n[k][key] = dbus.MakeVariantWithSignature(r.Interface(), v.Signature())
		}
	}
	return n
}

// Current settings may contain the narrow envelope, but are never substituted
// for authenticated captured Connect evidence or a broker activation receipt.
func validateCurrentProfile(s map[string]map[string]dbus.Variant, id Identity) error {
	n, _, _, password, err := splitProfileEnvelope(s)
	if err != nil || password != "" {
		return errPeer
	}
	return ValidateProfile(n, id)
}
