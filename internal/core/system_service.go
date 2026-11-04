package core

import (
	"errors"
	"net/netip"
	"strings"
)

// ProtocolMacOSSystemL2TP selects an already configured macOS system service.
// It is deliberately separate from the password/PSK L2TP protocol and is not an
// entry in Protocols, the existing password-based profile editor's choices.
const ProtocolMacOSSystemL2TP = "macos-system-l2tp"

// SystemServiceTargetRoutes verifies only the selected system service and the
// finite numeric destinations in its profile. It is not a whole-device route,
// effective DNS, per-application, or IPv6 leak-prevention guarantee.
const SystemServiceTargetRoutes = "system-service-target-routes"

// ScopedVerification is an optional, immutable contract on both Adapter and
// Session. The system-service protocol requires this exact scope on the adapter
// and on a session whose Ready succeeds. Existing adapters and sessions omit it.
// A limited-scope adapter/session cannot satisfy an ordinary protocol's contract.
type ScopedVerification interface {
	VerificationScope() string
}

// SystemServiceOptions contains selection and verification expectations only.
// Credentials remain in macOS. Per-attempt permission to use saved credentials,
// change networking, operate a shared service, and accept limited verification
// belongs to the backend and must never be inferred from persisted options.
type SystemServiceOptions struct {
	ServiceID string   `json:"service_id"`
	Targets   []string `json:"targets"`
}

func validateSystemServiceProfile(p Profile) error {
	if p.SystemService == nil {
		return errors.New("macOS system-service mode requires an explicit service and numeric targets")
	}
	if p.Username != "" || p.L2TP != nil || p.ClientCertificate != "" || p.ClientKey != "" || p.CertificateFormat != "" || p.CAFile != "" || p.ProxyURL != "" || p.AllowProxySystemAuth || p.DisableUDP || p.InteractiveAuth || p.AuthGroup != "" || p.MTU != 0 || len(p.AdditionalGateways) != 0 {
		return errors.New("macOS system-service mode does not accept credentials, proxy, certificate, L2TP, authentication, MTU or additional-gateway options")
	}
	id := p.SystemService.ServiceID
	if len(id) == 0 || len(id) > 127 {
		return errors.New("invalid system service identifier")
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return errors.New("invalid system service identifier")
		}
	}
	// Match the conservative host/IP token exposed by system-service inspection;
	// never resolve a hostname or accept URL, credential, port or zone syntax.
	if len(p.Gateway) == 0 || len(p.Gateway) > 127 {
		return errors.New("system-service gateway must be a bare hostname or IP address")
	}
	if ip, err := netip.ParseAddr(p.Gateway); err == nil {
		if ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() || ip.Zone() != "" {
			return errors.New("invalid system-service gateway address")
		}
	} else {
		host := strings.TrimSuffix(p.Gateway, ".")
		if host == "" || strings.Trim(host, "0123456789.") == "" {
			return errors.New("invalid system-service gateway hostname")
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return errors.New("invalid system-service gateway hostname")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
					return errors.New("invalid system-service gateway hostname")
				}
			}
		}
	}
	if len(p.SystemService.Targets) < 1 || len(p.SystemService.Targets) > 16 {
		return errors.New("system-service mode requires 1–16 distinct numeric target addresses")
	}
	seen := make(map[netip.Addr]bool, len(p.SystemService.Targets))
	for _, target := range p.SystemService.Targets {
		ip, err := netip.ParseAddr(target)
		if err != nil || ip.Zone() != "" || ip.Is4In6() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || seen[ip] {
			return errors.New("system-service targets must be distinct numeric IPv4/IPv6 addresses without unspecified, loopback, mapped, link-local, multicast or zoned addresses")
		}
		seen[ip] = true
	}
	return nil
}

func cloneSystemServiceOptions(o *SystemServiceOptions) *SystemServiceOptions {
	if o == nil {
		return nil
	}
	copy := *o
	copy.Targets = append([]string(nil), o.Targets...)
	return &copy
}

func verificationScope(provider any) string {
	if scoped, ok := provider.(ScopedVerification); ok {
		return scoped.VerificationScope()
	}
	return ""
}

func profileVerificationScope(p Profile) string {
	if p.Protocol == WindowsBorrowedProtocol {
		return WindowsBorrowedObservedInterface
	}
	if p.Protocol == ProtocolMacOSSystemL2TP {
		return SystemServiceTargetRoutes
	}
	return ""
}

func disconnectedMessage(scope string) string {
	if scope == WindowsBorrowedObservedInterface {
		return "Meridian Windows attempt cleanup confirmed; whole-device network restoration is not verified"
	}
	if scope == SystemServiceTargetRoutes {
		return "所选系统服务已断开；未验证整机网络恢复"
	}
	return "No VPN tunnel is active"
}

func cleanupPendingMessage(scope string) string {
	if scope == WindowsBorrowedObservedInterface {
		return "Waiting for Windows reference termination and input cleanup verification"
	}
	if scope == SystemServiceTargetRoutes {
		return "正在等待所选系统服务及已观察的 PPP 接口和路由清理"
	}
	return "Waiting for verified tunnel cleanup"
}
