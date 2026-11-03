package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func caFixture(t *testing.T) string {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Isolated test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(t.TempDir(), "ca.pem")
	if e = os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	return p
}
func TestAdvancedProfilePersistenceAndArguments(t *testing.T) {
	p := profile()
	p.Description = "Corporate gateway\nOwned by IT"
	p.AuthGroup = "Staff Group"
	p.CAFile = caFixture(t)
	p.ProxyURL = "socks5://127.0.0.1:1080"
	p.AllowProxySystemAuth = true
	p.DisableUDP = true
	p.MTU = 1400
	s := Store{filepath.Join(t.TempDir(), "config.json")}
	if e := s.Save(Config{Profiles: []Profile{p}}); e != nil {
		t.Fatal(e)
	}
	c, e := s.Load()
	expected := p
	expected.AllowProxySystemAuth = false
	if e != nil || !reflect.DeepEqual(c.Profiles[0], expected) {
		t.Fatal("advanced fields did not round trip", e)
	}
	a, e := OpenConnectArgs(p)
	if runtime.GOOS == "windows" {
		if e == nil {
			t.Fatal("CA accepted without verified file permissions")
		}
		return
	}
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"--authgroup=Staff Group", "--cafile=" + p.CAFile, "--proxy=" + p.ProxyURL, "--proxy-auth=none"} {
		found := false
		for _, arg := range a {
			if arg == want {
				found = true
			}
		}
		if !found {
			t.Fatal("missing safe argument", want)
		}
	}
	r := &recordingFileRunner{mockRunner: &mockRunner{}}
	n := testNM(r.mockRunner)
	n.runner = r
	session, e := n.Start(context.Background(), p, []byte("secret"))
	if runtime.GOOS != "linux" {
		if e == nil || len(r.calls) != 0 {
			t.Fatal("unsupported private-FD authentication reached a command")
		}
		return
	}
	if e != nil {
		t.Fatal(e)
	}
	defer session.Stop()
	found := false
	for _, call := range r.calls {
		if strings.Contains(strings.Join(call.args, " "), "connection add") {
			for i, arg := range call.args {
				if arg == "vpn.data" {
					v := call.args[i+1]
					if !strings.Contains(v, "proxy="+p.ProxyURL) || !strings.Contains(v, "disable-udp=yes") || !strings.Contains(v, "mtu=1400") {
						t.Fatal(v)
					}
					if strings.Contains(v, p.CAFile) {
						t.Fatal("custom CA path sent to privileged backend")
					}
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("NM configuration absent")
	}
}
func TestAdvancedFieldsRejectInjectionAndUnsupportedValues(t *testing.T) {
	for _, proxy := range []string{"https://proxy.example:443", "http://user:pass@proxy.example", "http://proxy.example,x=y", "http://proxy.example\\x", "http://proxy.example?token=x", "http://proxy.example:0", "file:///tmp/proxy"} {
		p := profile()
		p.ProxyURL = proxy
		if ValidateProfile(p) == nil {
			t.Fatal("invalid proxy accepted", proxy)
		}
	}
	for _, mtu := range []int{-1, 575, 9001} {
		p := profile()
		p.MTU = mtu
		if ValidateProfile(p) == nil {
			t.Fatal("invalid MTU accepted")
		}
	}
	p := profile()
	p.AuthGroup = "x\n--insecure"
	if ValidateProfile(p) == nil {
		t.Fatal("auth group control accepted")
	}
	p = profile()
	p.CAFile = "relative.pem"
	if ValidateProfile(p) == nil {
		t.Fatal("relative CA accepted")
	}
}
func TestCertificateValidationFailBeforeAnyCommand(t *testing.T) {
	valid := caFixture(t)
	if runtime.GOOS == "windows" {
		p := profile()
		p.CAFile = valid
		r := &mockRunner{}
		if _, err := testNM(r).Start(context.Background(), p, nil); err == nil || len(r.calls) != 0 {
			t.Fatal("unverified CA permissions reached a command")
		}
		return
	}
	if e := ValidateCAFile(valid); e != nil {
		t.Fatal(e)
	}
	data, _ := os.ReadFile(valid)
	for _, content := range [][]byte{nil, []byte("not PEM"), append([]byte("junk before PEM\n"), data...), append(append([]byte{}, data...), []byte("-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n")...), bytes.Repeat([]byte("x"), (4<<20)+1)} {
		path := filepath.Join(t.TempDir(), "invalid.pem")
		os.WriteFile(path, content, 0600)
		p := profile()
		p.CAFile = path
		r := &mockRunner{}
		if _, e := testNM(r).Start(context.Background(), p, nil); e == nil {
			t.Fatal("invalid CA accepted")
		}
		if len(r.calls) != 0 {
			t.Fatal("backend started with invalid CA")
		}
	}
	p := profile()
	p.CAFile = filepath.Join(t.TempDir(), "missing.pem")
	r := &mockRunner{}
	if _, e := testNM(r).Start(context.Background(), p, nil); e == nil || len(r.calls) != 0 {
		t.Fatal("missing CA reached process")
	}
	if ValidateCAFile(t.TempDir()) == nil {
		t.Fatal("directory CA accepted")
	}
}
func TestMetricsCachedAvailableAndReset(t *testing.T) {
	r := &mockRunner{}
	n := testNM(r)
	reads := 0
	n.readMetrics = func(name string) SessionMetrics {
		reads++
		if !ownedInterfaceName(name) {
			t.Fatal("not own interface")
		}
		return SessionMetrics{"192.0.2.10", 123, 456, true}
	}
	raw, err := n.Start(context.Background(), profile(), nil)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(sessionAdapter{raw})
	e.Connect(profile(), "", true)
	await(t, e, Connected)
	for i := 0; i < 100; i++ {
		s := e.Snapshot()
		if !s.MetricsAvailable || s.VirtualIP != "192.0.2.10" || s.Uploaded != 123 || s.Downloaded != 456 || s.ConnectedAt.IsZero() {
			t.Fatal(s)
		}
	}
	if reads != 1 {
		t.Fatal("Snapshot performed repeated I/O")
	}
	if err = e.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := e.Snapshot()
	if s.MetricsAvailable || s.VirtualIP != "" || !s.ConnectedAt.IsZero() {
		t.Fatal("stale metrics after disconnect")
	}
}
func TestMetricsUnavailableAndCounterValidation(t *testing.T) {
	for _, name := range []string{"eth0", "lo", "../../etc/passwd", "mdzzzzzzzzzz", "md123"} {
		if m := readInterfaceMetrics(name); m.Available {
			t.Fatal("unowned interface metrics read")
		}
	}
	for _, value := range []string{"-1", "18446744073709551616", "123 garbage", strings.Repeat(" ", 65) + "1", ""} {
		p := filepath.Join(t.TempDir(), "counter")
		os.WriteFile(p, []byte(value), 0600)
		if _, e := readCounter(p); e == nil {
			t.Fatal("invalid counter accepted")
		}
	}
	p := filepath.Join(t.TempDir(), "counter")
	os.WriteFile(p, []byte("0\n"), 0600)
	if n, e := readCounter(p); e != nil || n != 0 {
		t.Fatal("real zero counter rejected")
	}
}
func TestProxyNeedsExplicitSystemAuthConsentBeforeAnyProcess(t *testing.T) {
	p := profile()
	p.ProxyURL = "http://127.0.0.1:3128"
	if _, e := OpenConnectArgs(p); e == nil {
		t.Fatal("proxy allowed without consent")
	}
	r := &mockRunner{}
	if _, e := testNM(r).Start(context.Background(), p, nil); e == nil || len(r.calls) != 0 {
		t.Fatal("proxy started before consent")
	}
	p.AllowProxySystemAuth = true
	p.ProxyURL = "http://user:password@proxy.example"
	if _, e := testNM(r).Start(context.Background(), p, nil); e == nil || len(r.calls) != 0 {
		t.Fatal("consent bypassed URL validation")
	}
}
func TestRealOpenConnectEmptyResolveAssignment(t *testing.T) {
	data := strings.Replace(authFixture, "RESOLVE='vpn.example.com:192.0.2.1'", "RESOLVE=", 1)
	m, e := parseAuthentication([]byte(data))
	if e != nil || m["RESOLVE"] != "" {
		t.Fatal("real empty RESOLVE rejected", e)
	}
	for _, bad := range []string{strings.Replace(data, "RESOLVE=", "RESOLVE=$(touch x)", 1), data + "RESOLVE=\n", strings.Replace(data, "COOKIE='test-cookie-opaque'", "COOKIE=unquoted", 1)} {
		if _, e := parseAuthentication([]byte(bad)); e == nil {
			t.Fatal("unsafe unquoted or duplicate assignment accepted")
		}
	}
}
func TestProxyConsentCannotPersistOrImport(t *testing.T) {
	p := profile()
	p.AllowProxySystemAuth = true
	s := Store{filepath.Join(t.TempDir(), "settings.json")}
	if e := s.Save(Config{Profiles: []Profile{p}}); e != nil {
		t.Fatal(e)
	}
	data, _ := os.ReadFile(s.Path)
	if bytes.Contains(data, []byte("allow_proxy")) {
		t.Fatal("runtime consent serialized")
	}
	cfg, e := s.Load()
	if e != nil || cfg.Profiles[0].AllowProxySystemAuth {
		t.Fatal("consent persisted")
	}
	injected := bytes.Replace(data, []byte(`"name": "Office"`), []byte(`"name": "Office", "allow_proxy_system_auth": true`), 1)
	if bytes.Equal(injected, data) {
		t.Fatal("fixture not injected")
	}
	os.WriteFile(s.Path, injected, 0600)
	if _, e := s.Load(); e == nil {
		t.Fatal("imported consent accepted")
	}
}
func TestDirectAuthenticationDisablesAmbientProxy(t *testing.T) {
	p := profile()
	args, err := OpenConnectArgs(p)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, arg := range args {
		if arg == "--no-proxy" {
			found = true
		}
	}
	if !found {
		t.Fatal("direct authentication can inherit https_proxy")
	}
}
func TestCommandEnvironmentDropsProxyCredentials(t *testing.T) {
	input := []string{"PATH=/usr/bin", "https_proxy=http://user:secret@proxy", "HTTPS_PROXY=http://user:secret@proxy", "ALL_PROXY=socks5://proxy", "BUNDLE_HTTPS_PROXY=http://proxy", "no_proxy=localhost", "LC_ALL=zh_CN.UTF-8", "LANG=zh_CN.UTF-8", "HOME=/home/test"}
	got := isolatedCommandEnvironment(input)
	joined := strings.Join(got, "\n")
	if strings.Contains(strings.ToLower(joined), "proxy=") || strings.Contains(joined, "secret") || strings.Contains(joined, "zh_CN") {
		t.Fatal("ambient proxy/locale leaked")
	}
	if !strings.Contains(joined, "PATH=/usr/bin") || !strings.Contains(joined, "LC_ALL=C") || !strings.Contains(joined, "LANG=C") {
		t.Fatal("safe env missing")
	}
	if len(input) != 9 {
		t.Fatal("input environment mutated")
	}
}
