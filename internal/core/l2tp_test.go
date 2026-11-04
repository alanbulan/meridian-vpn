package core

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func l2tpProfile() Profile {
	return Profile{Name: "L2TP test", Gateway: "vpn.example.com", Protocol: "l2tp", Username: "alice", L2TP: &L2TPOptions{}}
}

type l2tpRunner struct {
	mockRunner
	failAdd  bool
	mismatch bool
}

func (r *l2tpRunner) Run(ctx context.Context, p string, a []string, in []byte) ([]byte, error) {
	if len(a) > 1 && a[1] == "IP4.ADDRESS" {
		if r.mismatch {
			return []byte("192.0.2.99/32"), nil
		}
		return []byte("192.0.2.2/32"), nil
	}
	out, err := r.mockRunner.Run(ctx, p, a, in)
	if r.failAdd && strings.Contains(strings.Join(a, " "), "connection add") {
		return nil, errors.New("redacted")
	}
	return out, err
}
func l2tpNM(r *l2tpRunner) *NetworkManager {
	n := testNM(&r.mockRunner)
	n.runner = r
	n.l2tpAvailable = true
	n.checkInterface = func(s string) bool { return strings.HasPrefix(s, "ppp") }
	n.interfaceHasAddress = func(_ string, ip string) bool { return ip == "192.0.2.2/32" }
	return n
}
func TestL2TPLifecycleSecretsAndParameters(t *testing.T) {
	r := &l2tpRunner{}
	n := l2tpNM(r)
	p := l2tpProfile()
	p.L2TP = &L2TPOptions{PPPAuth: "pap", Domain: "corp", RemoteID: "@vpn.example.com", IKE: "aes256-sha256-modp2048", ESP: "aes256-sha256", ForceEncapsulation: true, MRU: 1400}
	p.MTU = 1400
	c := Credentials{Password: []byte("test-password"), IPsecPSK: []byte("test-ipsec-key")}
	s, err := n.StartWithCredentials(context.Background(), p, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	for _, call := range r.calls {
		args := strings.Join(call.args, " ")
		if strings.Contains(args, "test-password") || strings.Contains(args, "test-ipsec-key") || call.path == "oc" {
			t.Fatal("secret exposed or wrong backend")
		}
		if strings.Contains(args, "connection add") {
			for _, want := range []string{"save no", "connection.autoconnect no", "org.freedesktop.NetworkManager.l2tp", "ipsec-enabled=yes", "password-flags=2", "ipsec-psk-flags=2", "refuse-pap=no", "refuse-chap=yes", "refuse-mschapv2=yes", "domain=corp", "ipsec-remote-id=@vpn.example.com", "ipsec-ike=aes256-sha256-modp2048", "ipsec-esp=aes256-sha256", "ipsec-forceencaps=yes", "mru=1400", "mtu=1400"} {
				if !strings.Contains(args, want) {
					t.Errorf("missing %s", want)
				}
			}
			if strings.Contains(args, "connection.interface-name") {
				t.Fatal("must not bind physical interface")
			}
		}
		if strings.Contains(args, "connection up") && call.input != "vpn.secrets.password:test-password\nvpn.secrets.ipsec-psk:test-ipsec-key\n" {
			t.Fatal("invalid secret transport")
		}
	}
	b, _ := json.Marshal(c)
	if string(b) != "{}" {
		t.Fatal("credentials serialized")
	}
}
func TestL2TPFailuresCleanUp(t *testing.T) {
	for _, mode := range []string{"add", "up", "readiness", "address", "cleanup"} {
		t.Run(mode, func(t *testing.T) {
			r := &l2tpRunner{}
			switch mode {
			case "add":
				r.failAdd = true
			case "up":
				r.failUp = true
			case "readiness":
				r.notReady = true
			case "address":
				r.mismatch = true
			case "cleanup":
				r.failUp = true
				r.failDelete = true
			}
			_, err := l2tpNM(r).StartWithCredentials(context.Background(), l2tpProfile(), Credentials{Password: []byte("pw"), IPsecPSK: []byte("psk")})
			if err == nil {
				t.Fatal("accepted failure")
			}
			want := FailureStart
			if mode == "readiness" || mode == "address" {
				want = FailureReadiness
			} else if mode == "cleanup" {
				want = FailureCleanup
			}
			if classifyFailure(err, FailureUnknown) != want {
				t.Fatal("incorrect L2TP failure classification", err)
			}
			var ce *CleanupError
			if (mode == "cleanup") != errors.As(err, &ce) {
				t.Fatal("incorrect cleanup status", err)
			}
			deleted := false
			for _, c := range r.calls {
				deleted = deleted || strings.Contains(strings.Join(c.args, " "), "connection delete")
			}
			if !deleted {
				t.Fatal("no rollback")
			}
		})
	}
}
func TestL2TPValidation(t *testing.T) {
	for _, mutate := range []func(*Profile){func(p *Profile) { p.Gateway = "https://vpn.example.com" }, func(p *Profile) { p.Gateway = "vpn.example.com:1701" }, func(p *Profile) { p.Username = "alice,ipsec-enabled=no" }, func(p *Profile) { p.L2TP.PPPAuth = "eap" }, func(p *Profile) { p.L2TP.IKE = "aes256,ipsec-enabled=no" }, func(p *Profile) { p.L2TP.Domain = "x\ny" }, func(p *Profile) { p.L2TP.MRU = -1 }, func(p *Profile) { p.ProxyURL = "http://proxy.example.com" }, func(p *Profile) { p.InteractiveAuth = true }} {
		p := l2tpProfile()
		mutate(&p)
		if ValidateProfile(p) == nil {
			t.Fatalf("accepted %#v", p)
		}
	}
	for _, host := range []string{"vpn.example.com", "192.0.2.1", "2001:db8::1"} {
		p := l2tpProfile()
		p.Gateway = host
		if err := ValidateProfile(p); err != nil {
			t.Fatal(host, err)
		}
	}
	for _, c := range []Credentials{{Password: []byte("pw")}, {IPsecPSK: []byte("psk")}, {Password: []byte("pw"), IPsecPSK: []byte("x\ny")}} {
		if validateCredentials(l2tpProfile(), c) == nil {
			t.Fatal("accepted invalid credentials")
		}
	}
}
func TestL2TPUnavailableAndCancellationHaveNoSideEffects(t *testing.T) {
	r := &l2tpRunner{}
	n := l2tpNM(r)
	n.l2tpAvailable = false
	c := Credentials{Password: []byte("pw"), IPsecPSK: []byte("psk")}
	if _, err := n.StartWithCredentials(context.Background(), l2tpProfile(), c); err == nil {
		t.Fatal("accepted missing plugin")
	}
	n.l2tpAvailable = true
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := n.StartWithCredentials(ctx, l2tpProfile(), c); err == nil {
		t.Fatal("accepted cancellation")
	}
	if len(r.calls) != 0 {
		t.Fatal("unexpected mutation")
	}
}
