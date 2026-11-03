package core

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
)

// UniVPN is a separate transport, not an AnyConnect alias. Its broker must keep
// the original native process (and authenticated control TLS connection) alive
// until Stop. A cookie-only NetworkManager handoff cannot implement this API.
// The caller supplies the reviewed executable and trusted broker explicitly;
// discovery never executes arbitrary PATH binaries or grants privileges.
type UniVPN struct {
	Executable string
	Broker     TunnelBroker
}

func (u UniVPN) Capability() Capability {
	if !filepath.IsAbs(u.Executable) {
		return Capability{Message: "Experimental UniVPN requires an explicitly configured native executable"}
	}
	info, err := os.Stat(u.Executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return Capability{Message: "Experimental UniVPN native executable is unavailable"}
	}
	if nilInterface(u.Broker) || !u.Broker.Available() {
		return Capability{Executable: u.Executable, Message: "UniVPN native engine requires a continuous-session trusted tunnel broker; NetworkManager cookie handoff is incompatible"}
	}
	return Capability{Available: true, Executable: u.Executable, Message: "Experimental UniVPN native engine and continuous-session broker configured"}
}
func (u UniVPN) SupportsProtocol(p string) bool { return p == "univpn" && u.Capability().Available }
func (u UniVPN) Start(ctx context.Context, p Profile, secret []byte) (Session, error) {
	return u.StartWithCredentials(ctx, p, Credentials{Password: secret})
}
func (u UniVPN) StartWithCredentials(ctx context.Context, p Profile, c Credentials) (Session, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err := validateCredentials(p, c); err != nil {
		return nil, err
	}
	if len(c.Password) > 4095 {
		return nil, errors.New("UniVPN password exceeds 4095 bytes")
	}
	if len(c.KeyPassword) != 0 {
		return nil, errors.New("UniVPN private-key authentication is not implemented")
	}
	args, err := UniVPNArgs(p)
	if err != nil {
		return nil, err
	}
	cap := u.Capability()
	if !cap.Available {
		return nil, errors.New(cap.Message)
	}
	return u.Broker.Start(ctx, cap.Executable, args, c.Password)
}

// UniVPNArgs intentionally rejects unsupported features rather than quietly
// sending an AnyConnect certificate/MFA/proxy configuration to this protocol.
func UniVPNArgs(p Profile) ([]string, error) {
	if err := ValidateProfile(p); err != nil {
		return nil, err
	}
	if len(p.Username) > 255 {
		return nil, errors.New("UniVPN username exceeds 255 bytes")
	}
	if p.Protocol != "univpn" {
		return nil, errors.New("UniVPN adapter requires univpn protocol")
	}
	if p.ProxyURL != "" || p.ClientCertificate != "" || p.ClientKey != "" || p.InteractiveAuth {
		return nil, errors.New("experimental UniVPN supports password authentication and direct TLS only; proxy, certificates and MFA are unsupported")
	}
	target, _ := url.Parse(p.Gateway)
	if target.Path != "" && target.Path != "/" {
		return nil, errors.New("UniVPN gateway cannot contain a URL path")
	}
	domain := p.AuthGroup
	if domain == "" {
		domain = target.Hostname()
	}
	if len(domain) > 255 {
		return nil, errors.New("UniVPN authentication domain exceeds 255 bytes")
	}
	args := []string{"--protocol=univpn", "--non-inter", "--passwd-on-stdin", "--no-proxy", "--no-dtls"}
	if p.Username != "" {
		args = append(args, "--user="+p.Username)
	}
	if p.AuthGroup != "" {
		args = append(args, "--authgroup="+p.AuthGroup)
	}
	if p.CAFile != "" {
		if err := ValidateCAFile(p.CAFile); err != nil {
			return nil, err
		}
		args = append(args, "--cafile="+p.CAFile)
	}
	if p.MTU != 0 {
		args = append(args, "--mtu="+strconv.Itoa(p.MTU))
	}
	return append(args, "--", p.Gateway), nil
}

// ProtocolRouter preserves independent broker lifecycles. It does not turn an
// unavailable experimental transport into an available one via the fallback.
type ProtocolRouter struct {
	Primary Adapter
	UniVPN  *UniVPN
}

func (r ProtocolRouter) Capability() Capability {
	if !nilInterface(r.Primary) && r.Primary.Capability().Available {
		return r.Primary.Capability()
	}
	if r.UniVPN != nil && r.UniVPN.Capability().Available {
		return r.UniVPN.Capability()
	}
	if !nilInterface(r.Primary) {
		return r.Primary.Capability()
	}
	return Capability{Message: "No tunnel broker is available"}
}
func (r ProtocolRouter) SupportsProtocol(p string) bool {
	if p == "univpn" {
		return r.UniVPN != nil && r.UniVPN.SupportsProtocol(p)
	}
	if s, ok := r.Primary.(interface{ SupportsProtocol(string) bool }); ok {
		return s.SupportsProtocol(p)
	}
	return p == "anyconnect" && !nilInterface(r.Primary) && r.Primary.Capability().Available
}
func (r ProtocolRouter) Start(ctx context.Context, p Profile, s []byte) (Session, error) {
	return r.StartWithCredentials(ctx, p, Credentials{Password: s})
}
func (r ProtocolRouter) StartWithCredentials(ctx context.Context, p Profile, c Credentials) (Session, error) {
	if p.Protocol == "univpn" {
		if r.UniVPN == nil {
			return nil, errors.New("UniVPN continuous-session broker is not configured")
		}
		return r.UniVPN.StartWithCredentials(ctx, p, c)
	}
	if nilInterface(r.Primary) {
		return nil, errors.New("No primary VPN adapter is configured")
	}
	if a, ok := r.Primary.(CredentialAdapter); ok {
		return a.StartWithCredentials(ctx, p, c)
	}
	if p.InteractiveAuth || p.ClientCertificate != "" || len(c.KeyPassword) != 0 {
		return nil, errors.New("primary adapter does not support certificate or interactive authentication")
	}
	return r.Primary.Start(ctx, p, c.Password)
}
func (r ProtocolRouter) SetAuthPrompt(p AuthPrompt) {
	if a, ok := r.Primary.(interface{ SetAuthPrompt(AuthPrompt) }); ok {
		a.SetAuthPrompt(p)
	}
}
