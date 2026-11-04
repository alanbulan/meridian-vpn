package core

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// OpenConnect detects the external binary. Broker is deliberately mandatory:
// this unprivileged GUI must never silently gain privileges, install routes,
// bypass server certificates, or infer success from arbitrary stdout.
type OpenConnect struct{ Broker TunnelBroker }
type TunnelBroker interface {
	Available() bool
	Start(context.Context, string, []string, []byte) (Session, error)
}

func (o OpenConnect) Capability() Capability {
	p, e := exec.LookPath("openconnect")
	if e != nil {
		return Capability{false, "OpenConnect is not installed. Install it through your operating system package manager.", ""}
	}
	if o.Broker == nil || !o.Broker.Available() {
		return Capability{false, "OpenConnect found; a verified privileged tunnel broker is not installed. Live connection is disabled.", p}
	}
	return Capability{true, "OpenConnect and trusted tunnel broker are available", p}
}
func (o OpenConnect) Start(ctx context.Context, p Profile, secret []byte) (Session, error) {
	if p.ClientCertificate != "" || p.InteractiveAuth {
		return nil, errors.New("certificate and interactive authentication require the Linux NetworkManager adapter")
	}
	cap := o.Capability()
	if !cap.Available {
		return nil, errors.New(cap.Message)
	}
	args, e := OpenConnectArgs(p)
	if e != nil {
		return nil, e
	}
	return o.Broker.Start(ctx, cap.Executable, args, secret)
}

// OpenConnectArgs builds noninteractive base options. Client identity descriptors
// and the passphrase channel are added only by authenticateOpenConnect.
func OpenConnectArgs(p Profile) ([]string, error) {
	if e := ValidateProfile(p); e != nil {
		return nil, e
	}
	if p.Protocol == ProtocolMacOSSystemL2TP || p.Protocol == WindowsBorrowedProtocol {
		return nil, errors.New("limited system VPN mode requires its scoped platform adapter")
	}
	args := []string{"--non-inter", "--passwd-on-stdin", "--protocol=" + p.Protocol}
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
	if p.ProxyURL != "" {
		if !p.AllowProxySystemAuth {
			return nil, errors.New("proxy use requires explicit per-connection consent for possible OS/backend integrated authentication")
		}
		args = append(args, "--proxy="+p.ProxyURL, "--proxy-auth=none")
	} else {
		args = append(args, "--no-proxy")
	}
	return append(args, "--", p.Gateway), nil
}

// ProbeVersion only executes the fixed --version command. It makes no network,
// route or DNS changes. Caller may cancel it; output is not written to activity logs.
func (o OpenConnect) ProbeVersion(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	p, e := exec.LookPath("openconnect")
	if e != nil {
		return "", e
	}
	cmd := exec.CommandContext(ctx, p, "--version")
	r, e := cmd.StdoutPipe()
	if e != nil {
		return "", e
	}
	if e = cmd.Start(); e != nil {
		return "", e
	}
	b, readErr := io.ReadAll(io.LimitReader(r, 8192))
	waitErr := cmd.Wait()
	if readErr != nil {
		return "", readErr
	}
	if waitErr != nil {
		return "", waitErr
	}
	line, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(line), nil
}
func Platform() string { return runtime.GOOS + " / " + runtime.GOARCH }
