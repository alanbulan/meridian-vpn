package core

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func systemServiceProfile() Profile {
	return Profile{
		ID: "system-profile", Name: "Office system service", Protocol: ProtocolMacOSSystemL2TP,
		Gateway:       "vpn.example.com",
		SystemService: &SystemServiceOptions{ServiceID: "SERVICE-123", Targets: []string{"192.0.2.10", "2001:db8::10"}},
	}
}

func TestSystemServiceProfileValidation(t *testing.T) {
	for _, gateway := range []string{"vpn.example.com", "VPN.example.com.", "192.0.2.1", "2001:db8::1"} {
		p := systemServiceProfile()
		p.Gateway = gateway
		if err := ValidateProfile(p); err != nil {
			t.Fatalf("valid bare gateway %q: %v", gateway, err)
		}
	}
	for _, id := range []string{"", "service name", "service/name", "service_name", "service\x00", "service\n", "中文", strings.Repeat("a", 128)} {
		t.Run("service/"+id, func(t *testing.T) {
			p := systemServiceProfile()
			p.SystemService.ServiceID = id
			if ValidateProfile(p) == nil {
				t.Fatal("invalid system service ID accepted")
			}
		})
	}
	p := systemServiceProfile()
	p.SystemService.ServiceID = strings.Repeat("a", 127)
	if err := ValidateProfile(p); err != nil {
		t.Fatal(err)
	}
	for _, gateway := range []string{"", "https://vpn.example.com", "vpn.example.com:443", "alice@vpn.example.com", "vpn.example.com/path", "vpn.example.com?x=1", "bad host", "host\n", "-host.example", "host..example", "999.2.3.4", "0.0.0.0", "::", "::ffff:192.0.2.1", "fe80::1", "2001:db8::1%en0", "224.0.0.1", strings.Repeat("a", 128)} {
		t.Run("gateway/"+gateway, func(t *testing.T) {
			p := systemServiceProfile()
			p.Gateway = gateway
			if ValidateProfile(p) == nil {
				t.Fatal("invalid system-service gateway accepted")
			}
		})
	}
	for _, name := range []string{"", " ", "bad\nname", strings.Repeat("中", 81)} {
		p := systemServiceProfile()
		p.Name = name
		if ValidateProfile(p) == nil {
			t.Fatal("system service bypassed normal name validation")
		}
	}
}

func TestSystemServiceTargetsAreBoundedNumericAndDistinct(t *testing.T) {
	for _, targets := range [][]string{
		nil, {}, {"vpn.example.com"}, {"192.0.2.1:443"}, {"192.0.2.1/32"}, {"192.0.2.1 "},
		{"0.0.0.0"}, {"::"}, {"127.0.0.1"}, {"::1"}, {"::ffff:192.0.2.1"}, {"169.254.1.1"}, {"fe80::1"}, {"fe80::1%en0"},
		{"2001:db8::1%en0"}, {"224.0.0.1"}, {"ff02::1"}, {"192.0.2.1", "192.0.2.1"},
		{"2001:db8::1", "2001:0db8:0:0:0:0:0:1"},
	} {
		p := systemServiceProfile()
		p.SystemService.Targets = targets
		if ValidateProfile(p) == nil {
			t.Fatalf("invalid targets accepted: %q", targets)
		}
	}
	p := systemServiceProfile()
	p.SystemService.Targets = nil
	for i := 1; i <= 16; i++ {
		p.SystemService.Targets = append(p.SystemService.Targets, fmt.Sprintf("192.0.2.%d", i))
	}
	if err := ValidateProfile(p); err != nil {
		t.Fatalf("16 distinct numeric targets rejected: %v", err)
	}
	p.SystemService.Targets = append(p.SystemService.Targets, "192.0.2.17")
	if ValidateProfile(p) == nil {
		t.Fatal("17 targets accepted")
	}
}

func TestSystemServiceRejectsUnrelatedOptions(t *testing.T) {
	for name, change := range map[string]func(*Profile){
		"missing selection": func(p *Profile) { p.SystemService = nil },
		"username":          func(p *Profile) { p.Username = "alice" },
		"L2TP":              func(p *Profile) { p.L2TP = &L2TPOptions{} },
		"certificate":       func(p *Profile) { p.ClientCertificate, p.ClientKey = "/tmp/cert", "/tmp/key" },
		"format":            func(p *Profile) { p.CertificateFormat = "pem" },
		"CA":                func(p *Profile) { p.CAFile = "/tmp/ca" },
		"proxy":             func(p *Profile) { p.ProxyURL = "http://proxy.example.com" },
		"proxy auth":        func(p *Profile) { p.AllowProxySystemAuth = true },
		"UDP":               func(p *Profile) { p.DisableUDP = true },
		"interactive":       func(p *Profile) { p.InteractiveAuth = true },
		"group":             func(p *Profile) { p.AuthGroup = "group" },
		"MTU":               func(p *Profile) { p.MTU = 1400 },
		"extra gateway":     func(p *Profile) { p.AdditionalGateways = []string{"other.example.com"} },
	} {
		t.Run(name, func(t *testing.T) {
			p := systemServiceProfile()
			change(&p)
			if ValidateProfile(p) == nil {
				t.Fatal("unsupported option accepted")
			}
		})
	}
}

func TestSystemServiceDoesNotChangeOrdinaryProtocols(t *testing.T) {
	want := []string{"anyconnect", "nc", "pulse", "gp", "f5", "fortinet", "array", "l2tp", "univpn"}
	if !slices.Equal(Protocols, want) {
		t.Fatalf("ordinary profile editor choices changed: %v", Protocols)
	}
	for _, protocol := range want {
		p := profile()
		p.Protocol = protocol
		if protocol == "l2tp" {
			p.Gateway = "vpn.example.com"
		}
		if err := ValidateProfile(p); err != nil {
			t.Fatalf("ordinary protocol %s rejected: %v", protocol, err)
		}
		p.SystemService = systemServiceProfile().SystemService
		if ValidateProfile(p) == nil {
			t.Fatalf("ordinary protocol %s accepted system-service options", protocol)
		}
	}
	if _, err := OpenConnectArgs(systemServiceProfile()); err == nil {
		t.Fatal("limited system-service mode accepted by OpenConnect command builder")
	}
}

type systemScopeAdapter struct {
	scope string
	s     Session
	start func(Profile)
}

func (a systemScopeAdapter) VerificationScope() string { return a.scope }
func (a systemScopeAdapter) Capability() Capability    { return Capability{Available: true} }
func (a systemScopeAdapter) Start(_ context.Context, p Profile, secret []byte) (Session, error) {
	if len(secret) != 0 {
		return nil, errors.New("unexpected credentials")
	}
	if a.start != nil {
		a.start(p)
	}
	return a.s, nil
}

type systemScopeSession struct {
	*lifecycleSession
	scope string
}

func (s *systemScopeSession) VerificationScope() string { return s.scope }

func TestSystemServiceRejectsAllCredentialsAndRequiresAuthorization(t *testing.T) {
	started := false
	e := NewEngine(systemScopeAdapter{scope: SystemServiceTargetRoutes, start: func(Profile) { started = true }})
	for _, credentials := range []Credentials{
		{Password: []byte("password")}, {IPsecPSK: []byte("PSK")}, {KeyPassword: []byte("key")},
		{Password: []byte("password"), IPsecPSK: []byte("PSK"), KeyPassword: []byte("key")},
	} {
		if e.ConnectWithCredentials(systemServiceProfile(), credentials, true) == nil {
			t.Fatal("system-service mode accepted application-supplied credentials")
		}
	}
	if e.Connect(systemServiceProfile(), "", false) == nil {
		t.Fatal("system-service mode bypassed network authorization")
	}
	if started || e.Snapshot().AttemptID != 0 {
		t.Fatal("rejected attempt reached the backend")
	}
}

func TestSystemServiceRequiresMatchingAdapterScope(t *testing.T) {
	for name, adapter := range map[string]Adapter{
		"absent": sessionAdapter{newLifecycleSession()},
		"empty":  systemScopeAdapter{},
		"other":  systemScopeAdapter{scope: "whole-device"},
	} {
		t.Run(name, func(t *testing.T) {
			e := NewEngine(adapter)
			if err := e.Connect(systemServiceProfile(), "", true); !errors.Is(err, NewConnectionError(FailureBackendUnavailable)) {
				t.Fatalf("scope mismatch was not rejected: %v", err)
			}
			if snapshot := e.Snapshot(); snapshot.AttemptID != 0 || snapshot.VerificationScope != "" {
				t.Fatalf("rejected scope advertised an admitted attempt: %+v", snapshot)
			}
		})
	}
	e := NewEngine(systemScopeAdapter{scope: SystemServiceTargetRoutes})
	if e.Connect(profile(), "", true) == nil {
		t.Fatal("limited adapter substituted for an ordinary protocol")
	}
}

func TestSystemServiceRequiresMatchingSuccessfulSessionScope(t *testing.T) {
	for _, scope := range []string{"absent", "", "whole-device"} {
		t.Run(scope, func(t *testing.T) {
			s := newLifecycleSession()
			var session Session = &systemScopeSession{lifecycleSession: s, scope: scope}
			if scope == "absent" {
				session = s
			}
			e := NewEngine(systemScopeAdapter{scope: SystemServiceTargetRoutes, s: session})
			if err := e.Connect(systemServiceProfile(), "", true); err != nil {
				t.Fatal(err)
			}
			s.ready <- nil
			await(t, e, Failed)
			waitLifecycleSignal(t, s.stopping)
			if snapshot := e.Snapshot(); snapshot.Failure != FailureReadiness || snapshot.VerificationScope != "" {
				t.Fatalf("unscoped readiness was accepted: %+v", snapshot)
			}
		})
	}
	// A limited session also cannot silently weaken an ordinary adapter.
	s := &systemScopeSession{lifecycleSession: newLifecycleSession(), scope: SystemServiceTargetRoutes}
	e := NewEngine(sessionAdapter{s})
	if err := e.Connect(profile(), "", true); err != nil {
		t.Fatal(err)
	}
	s.ready <- nil
	await(t, e, Failed)
	if e.Snapshot().Failure != FailureReadiness {
		t.Fatal("ordinary mode accepted limited session verification")
	}
}

func TestSystemServiceScopeDoesNotReplaceReadinessOrTerminalChecks(t *testing.T) {
	for _, mode := range []string{"ready-error", "ready-closed", "already-terminal"} {
		t.Run(mode, func(t *testing.T) {
			s := &systemScopeSession{lifecycleSession: newLifecycleSession(), scope: SystemServiceTargetRoutes}
			switch mode {
			case "ready-error":
				s.ready <- NewConnectionError(FailureReadiness)
			case "ready-closed":
				close(s.ready)
			case "already-terminal":
				s.ready <- nil
				s.done <- NewConnectionError(FailureReadiness)
			}
			e := NewEngine(systemScopeAdapter{scope: SystemServiceTargetRoutes, s: s})
			if err := e.Connect(systemServiceProfile(), "", true); err != nil {
				t.Fatal(err)
			}
			await(t, e, Failed)
			if snapshot := e.Snapshot(); snapshot.VerificationScope != "" || snapshot.Failure != FailureReadiness {
				t.Fatalf("scope replaced verified readiness: %+v", snapshot)
			}
			for _, entry := range e.Snapshot().Logs {
				if strings.Contains(entry.Message, "系统服务和指定目标路由已验证") {
					t.Fatal("unready or terminated scoped session advertised Connected")
				}
			}
		})
	}
}

func TestSystemServiceScopeOnlyAppearsWhileConnected(t *testing.T) {
	s := &systemScopeSession{lifecycleSession: newLifecycleSession(), scope: SystemServiceTargetRoutes}
	s.release = make(chan struct{})
	defer func() {
		select {
		case <-s.release:
		default:
			close(s.release)
		}
	}()
	e := NewEngine(systemScopeAdapter{scope: SystemServiceTargetRoutes, s: s})
	if e.Snapshot().VerificationScope != "" {
		t.Fatal("unused engine advertised verification")
	}
	if err := e.Connect(systemServiceProfile(), "", true); err != nil {
		t.Fatal(err)
	}
	if snapshot := e.Snapshot(); snapshot.State != Connecting || snapshot.VerificationScope != "" {
		t.Fatalf("unready session advertised verification: %+v", snapshot)
	}
	s.ready <- nil
	await(t, e, Connected)
	if snapshot := e.Snapshot(); snapshot.VerificationScope != SystemServiceTargetRoutes || snapshot.Message != "系统服务和指定目标路由已验证；不提供全应用 DNS/IPv6 防泄漏保证" || snapshot.ConnectedAt.IsZero() {
		t.Fatalf("limited readiness was not clearly scoped: %+v", snapshot)
	}
	if err := e.Disconnect(); err != nil {
		t.Fatal(err)
	}
	if snapshot := e.Snapshot(); snapshot.State != Disconnecting || snapshot.VerificationScope != "" || !snapshot.ConnectedAt.IsZero() || !strings.Contains(snapshot.Message, "所选系统服务") {
		t.Fatalf("disconnecting advertised readiness or global cleanup: %+v", snapshot)
	}
	close(s.release)
	await(t, e, Disconnected)
	if snapshot := e.Snapshot(); snapshot.VerificationScope != "" || !strings.Contains(snapshot.Message, "未验证整机网络恢复") {
		t.Fatalf("disconnected scope or cleanup overstated: %+v", snapshot)
	}
	ordinary := newLifecycleSession()
	if err := e.ReplaceAdapter(sessionAdapter{ordinary}); err != nil {
		t.Fatal(err)
	}
	if err := e.Connect(profile(), "", true); err != nil {
		t.Fatal(err)
	}
	ordinary.ready <- nil
	await(t, e, Connected)
	if snapshot := e.Snapshot(); snapshot.VerificationScope != "" || snapshot.Message != "Tunnel verified by the trusted broker and its interface" {
		t.Fatalf("limited scope leaked into ordinary attempt: %+v", snapshot)
	}
	e.Disconnect()
	await(t, e, Disconnected)
}

func TestSystemServiceScopeClearsOnLossAndCleanupFailure(t *testing.T) {
	for _, cleanupFails := range []bool{false, true} {
		t.Run(fmt.Sprint(cleanupFails), func(t *testing.T) {
			s := &systemScopeSession{lifecycleSession: newLifecycleSession(), scope: SystemServiceTargetRoutes}
			if cleanupFails {
				s.stopErr = errors.New("synthetic cleanup failure")
			}
			e := NewEngine(systemScopeAdapter{scope: SystemServiceTargetRoutes, s: s})
			if err := e.Connect(systemServiceProfile(), "", true); err != nil {
				t.Fatal(err)
			}
			s.ready <- nil
			await(t, e, Connected)
			s.done <- errors.New("synthetic loss")
			want := Failed
			if cleanupFails {
				want = CleanupFailed
			}
			await(t, e, want)
			snapshot := e.Snapshot()
			if snapshot.VerificationScope != "" || !snapshot.ConnectedAt.IsZero() {
				t.Fatalf("terminated session advertised scoped readiness: %+v", snapshot)
			}
			if cleanupFails {
				if err := e.Disconnect(); err == nil || !strings.Contains(err.Error(), "所选系统服务") {
					t.Fatalf("cleanup uncertainty was not scoped: %v", err)
				}
			} else if !strings.Contains(snapshot.Message, "未验证整机网络恢复") {
				t.Fatalf("loss message overstated cleanup: %s", snapshot.Message)
			}
		})
	}
}

func TestSystemServiceOptionsAreCopiedForEngineAndStorage(t *testing.T) {
	p := systemServiceProfile()
	want := systemServiceProfile()
	gate := make(chan struct{})
	observed := make(chan Profile, 1)
	s := &systemScopeSession{lifecycleSession: newLifecycleSession(), scope: SystemServiceTargetRoutes}
	e := NewEngine(systemScopeAdapter{scope: SystemServiceTargetRoutes, s: s, start: func(p Profile) {
		<-gate
		observed <- p
	}})
	if err := e.Connect(p, "", true); err != nil {
		t.Fatal(err)
	}
	p.SystemService.ServiceID = "changed"
	p.SystemService.Targets[0] = "198.51.100.99"
	close(gate)
	if got := <-observed; !reflect.DeepEqual(got, want) {
		t.Fatalf("caller changed engine-owned profile: %+v", got.SystemService)
	}
	e.Disconnect()
	await(t, e, Disconnected)

	p = systemServiceProfile()
	config := Config{}
	if err := config.Upsert(p); err != nil {
		t.Fatal(err)
	}
	p.SystemService.ServiceID = "changed"
	p.SystemService.Targets[0] = "198.51.100.99"
	if !reflect.DeepEqual(config.Profiles[0], want) {
		t.Fatal("caller changed stored profile options")
	}
	store := Store{Path: filepath.Join(t.TempDir(), "profiles.json")}
	if err := store.Save(config); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil || len(loaded.Profiles) != 1 || !reflect.DeepEqual(loaded.Profiles[0], want) {
		t.Fatalf("system-service options did not round-trip: %+v %v", loaded, err)
	}
}
