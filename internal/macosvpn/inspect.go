package macosvpn

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
)

// ServiceConfiguration is an allowlisted diagnostic summary, NOT a complete
// configuration fingerprint or approval to activate a service. Unreported
// settings (including routing, DNS, scripts and credentials) remain unverified.
type ServiceConfiguration struct {
	ServiceID           string
	Gateway             string
	PPPAuthentication   []string
	IPSecAuthentication string
}

// GenerationEvidence correlates observations, not exclusive ownership. ConnectTime
// is an opaque positive integer from PPP extended status, not wall-clock time.
// A same-tick reconnect, stale data or an ABA change can escape these samples.
type GenerationEvidence struct {
	ConnectTime int64
	Interface   InterfaceEvidence
}

type ServiceInspection struct {
	Configuration ServiceConfiguration
	Status        Status
	Generation    *GenerationEvidence // Present only for an observed Connected service.
}

type inspectionConnection interface {
	status() Status
	close()
	readConfiguration() (ServiceConfiguration, error)
	readConnectTime() (int64, error)
	readSystemEvidence() (systemEvidence, error)
}

// InspectExistingService reads one explicitly selected existing L2TP service.
// It never starts, stops, adopts or edits a connection, including an active one.
// Output and read count are bounded; native calls are synchronous and NOT bounded
// by ctx. Cancellation is checked between calls, not by detaching native work.
// The result must not authorize a connection or satisfy core.Session.Ready.
func InspectExistingService(ctx context.Context, id string) (ServiceInspection, error) {
	return inspectExistingService(ctx, id, openInspectionNative, readInterface)
}

func validServiceID(id string) bool {
	if len(id) == 0 || len(id) > maxServiceIDBytes {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func validateDiagnosticConfig(c ServiceConfiguration, id string) error {
	fail := errors.New("system VPN diagnostic configuration is incomplete or unsupported")
	if c.ServiceID != id || !validServiceID(id) || len(c.Gateway) == 0 || len(c.Gateway) > 127 {
		return fail
	}
	// Display only a conservative ASCII host/IP token, never a URL, username,
	// command, zone ID or multiline/native dictionary value. Do not resolve it.
	if ip, err := netip.ParseAddr(c.Gateway); err == nil {
		if ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() || ip.Zone() != "" {
			return fail
		}
	} else {
		host := strings.TrimSuffix(c.Gateway, ".")
		if host == "" || strings.Trim(host, "0123456789.") == "" {
			return fail
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return fail
			}
			for _, b := range label {
				if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-') {
					return fail
				}
			}
		}
	}
	if len(c.PPPAuthentication) == 0 || len(c.PPPAuthentication) > 5 {
		return fail
	}
	seen := map[string]bool{}
	for _, v := range c.PPPAuthentication {
		switch v {
		case "PAP", "CHAP", "MSCHAP1", "MSCHAP2", "EAP":
		default:
			return fail
		}
		if seen[v] {
			return fail
		}
		seen[v] = true
	}
	switch c.IPSecAuthentication {
	case "SharedSecret", "Certificate", "Hybrid":
	default:
		return fail
	}
	return nil
}
func sameDiagnosticConfig(a, b ServiceConfiguration) bool {
	return a.ServiceID == b.ServiceID && a.Gateway == b.Gateway && a.IPSecAuthentication == b.IPSecAuthentication && slices.Equal(a.PPPAuthentication, b.PPPAuthentication)
}

func inspectExistingService(ctx context.Context, id string, open func(string) (inspectionConnection, error), lookup func(string) (observedInterface, error)) (ServiceInspection, error) {
	var zero ServiceInspection
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if !validServiceID(id) {
		return zero, errors.New("invalid system service identifier")
	}
	n, err := open(id)
	if err != nil {
		return zero, err
	}
	defer n.close()
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	before, err := n.readConfiguration()
	if err != nil {
		return zero, err
	}
	if err = validateDiagnosticConfig(before, id); err != nil {
		return zero, err
	}
	// Copy the slice so a mutable backend buffer cannot alter our first sample.
	before.PPPAuthentication = slices.Clone(before.PPPAuthentication)
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	state := n.status()
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	if state != Disconnected && state != Connected {
		return zero, errors.New("system VPN is transitioning or unavailable")
	}
	out := ServiceInspection{Configuration: before, Status: state}
	if state == Connected {
		start, err := n.readConnectTime()
		if err != nil || start <= 0 {
			return zero, errors.New("system VPN generation is unavailable")
		}
		if err = ctx.Err(); err != nil {
			return zero, err
		}
		raw, err := n.readSystemEvidence()
		if err != nil {
			return zero, err
		}
		if raw.requestedID != id {
			return zero, errors.New("system VPN service identity changed")
		}
		if err = ctx.Err(); err != nil {
			return zero, err
		}
		evidence, err := verifyEvidence(raw, lookup)
		if err != nil {
			return zero, err
		}
		if err = ctx.Err(); err != nil {
			return zero, err
		}
		out.Generation = &GenerationEvidence{ConnectTime: start, Interface: evidence}
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	after, err := n.readConfiguration()
	if err != nil {
		return zero, err
	}
	if err = validateDiagnosticConfig(after, id); err != nil {
		return zero, err
	}
	if !sameDiagnosticConfig(before, after) {
		return zero, errors.New("system VPN diagnostic configuration changed")
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	if out.Generation != nil {
		end, err := n.readConnectTime()
		if err != nil || end != out.Generation.ConnectTime {
			return zero, errors.New("system VPN generation changed")
		}
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	if n.status() != state {
		return zero, errors.New("system VPN state changed during inspection")
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	return out, nil
}
