//go:build linux

package nmvpn

import (
	"reflect"

	"github.com/godbus/dbus/v5"
)

// equivalentProfiles compares only validated, secret-free network dictionaries.
// NM may add explicit defaults and bookkeeping to Connect and GetSettings. This
// is a deliberately closed equivalence relation, not general NM normalization.
// In particular it preserves interface binding, autoconnect, connection.id and
// the distinction between absent and present-empty dns-options.
func equivalentProfiles(expected, actual map[string]map[string]dbus.Variant, id Identity) bool {
	// Validate BOTH inputs before normalization so unsupported routes, DNS, data
	// or malformed values can never be mistaken for defaults.
	if ValidateProfile(expected, id) != nil || ValidateProfile(actual, id) != nil {
		return false
	}
	return reflect.DeepEqual(canonicalValidatedProfile(expected), canonicalValidatedProfile(actual))
}

// canonicalValidatedProfile must only receive a profile accepted by ValidateProfile.
// Keep this allowlist independent of that grammar: future accepted properties must
// remain exact unless their equivalence is separately justified.
func canonicalValidatedProfile(profile map[string]map[string]dbus.Variant) map[string]map[string]dbus.Variant {
	out := make(map[string]map[string]dbus.Variant, len(profile))
	for section, values := range profile {
		out[section] = make(map[string]dbus.Variant, len(values))
		for key, value := range values {
			if equivalentProfileDefault(section, key, value) {
				continue
			}
			// Only this retained collection has a nil/empty representation rule.
			// Its presence remains significant; all other retained values and
			// signatures are copied exactly, including future grammar extensions.
			if (section == "ipv4" || section == "ipv6") && key == "dns-options" && profileEmpty(value, "as") {
				value = dbus.MakeVariant([]string{})
			}
			out[section][key] = value
		}
	}
	// NM creates a proxy setting whose default method can be omitted on the wire.
	if proxy, ok := out["proxy"]; ok && (len(proxy) == 0 || (len(proxy) == 1 && profileEqual(proxy["method"], int32(0)))) {
		delete(out, "proxy")
	}
	return out
}

func equivalentProfileDefault(section, key string, value dbus.Variant) bool {
	switch section {
	case "connection":
		switch key {
		case "timestamp":
			_, ok := value.Value().(uint64)
			return ok && value.Signature().String() == "t"
		case "read-only":
			_, ok := value.Value().(bool)
			return ok && value.Signature().String() == "b"
		case "interface-name", "zone", "controller", "master", "port-type", "slave-type":
			return profileEqual(value, "")
		case "multi-connect", "autoconnect-priority":
			return profileEqual(value, int32(0))
		case "permissions", "secondaries":
			return profileEmpty(value, "as")
		}
	case "vpn":
		switch key {
		case "persistent":
			return profileEqual(value, false)
		case "timeout":
			return profileEqual(value, uint32(0))
		case "data", "secrets":
			return profileEmpty(value, "a{ss}")
		}
	case "ipv4", "ipv6":
		switch key {
		case "never-default", "ignore-auto-dns":
			return section == "ipv6" && profileEqual(value, false)
		case "ignore-auto-routes":
			return profileEqual(value, false)
		case "gateway":
			return profileEqual(value, "")
		case "route-table":
			return profileEqual(value, uint32(0))
		case "route-metric":
			return profileEqual(value, int64(-1))
		case "dns-priority":
			return profileEqual(value, int32(0))
		case "dns-data", "dns-search":
			return profileEmpty(value, "as")
		case "route-data", "address-data", "routing-rules":
			return profileEmpty(value, "aa{sv}")
		case "dns":
			if section == "ipv4" {
				return profileEmpty(value, "au")
			}
			return profileEmpty(value, "aay")
		case "addresses":
			if section == "ipv4" {
				return profileEmpty(value, "aau")
			}
			return profileEmpty(value, "a(ayuay)")
		case "routes":
			if section == "ipv4" {
				return profileEmpty(value, "aau")
			}
			return profileEmpty(value, "a(ayuayu)")
		}
	}
	return false
}
