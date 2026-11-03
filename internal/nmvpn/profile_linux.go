//go:build linux

package nmvpn

import (
	"errors"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"
)

// ValidateProfile accepts only the deliberately small, IPv4 split-route/no-DNS
// profile grammar supported by this protocol slice. It performs no I/O and does
// not retain or modify settings. The caller must own an immutable snapshot while
// this function runs; concurrent writes to Go maps are not supported.
//
// This is NOT proof of the active/applied profile, absence of dispatcher effects,
// global NM configuration, or atomicity between GetSettings and Connect. In
// particular route-table=0 can inherit global policy. Those remain adapter gates.
// Plugin-specific data, credentials and all unlisted properties are unsupported,
// even where another NM plugin or version might legitimately need them.
//
// Types follow the primary D-Bus property documentation:
// https://networkmanager.dev/docs/api/latest/settings-connection.html
// https://networkmanager.dev/docs/api/latest/settings-vpn.html
// https://networkmanager.dev/docs/api/latest/settings-ipv4.html
// https://networkmanager.dev/docs/api/latest/settings-ipv6.html
// https://networkmanager.dev/docs/api/latest/settings-proxy.html
func ValidateProfile(settings map[string]map[string]dbus.Variant, id Identity) error {
	bad := errors.New("unsupported or unapproved NM VPN profile")
	if len(settings) < 4 || len(settings) > 5 || len(id.UUID) != 36 || len(id.Interface) > 15 || !uuidPattern.MatchString(id.UUID) || !linkPattern.MatchString(id.Interface) || id.Interface == "lo" {
		return bad
	}
	for section, values := range settings {
		if len(values) > 32 {
			return bad
		}
		for key, v := range values {
			if len(key) > 64 || !profileProperty(section, key, v, id) {
				return bad
			}
		}
		switch section {
		case "connection", "vpn", "ipv4", "ipv6", "proxy":
		default:
			return bad
		}
	}
	for _, requirement := range []struct {
		section, key string
		value        interface{}
	}{
		{"connection", "uuid", id.UUID},
		{"connection", "type", "vpn"},
		{"vpn", "service-type", PluginService},
		{"ipv4", "method", "auto"},
		{"ipv4", "never-default", true},
		{"ipv4", "ignore-auto-dns", true},
		{"ipv6", "method", "disabled"},
	} {
		v, ok := settings[requirement.section][requirement.key]
		if !ok || !profileEqual(v, requirement.value) {
			return bad
		}
	}
	if proxy, ok := settings["proxy"]; ok {
		// NM's actual proxy.method wire type is int32, not uint32.
		if v, ok := proxy["method"]; !ok || !profileEqual(v, int32(0)) {
			return bad
		}
	}
	return nil
}

func profileEqual(v dbus.Variant, want interface{}) bool {
	return v.Signature() == dbus.SignatureOf(want) && reflect.DeepEqual(v.Value(), want)
}

func profileString(v dbus.Variant) bool {
	s, ok := v.Value().(string)
	return ok && v.Signature().String() == "s" && len(s) <= 256 && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

func profileEmpty(v dbus.Variant, signature string) bool {
	if v.Signature().String() != signature {
		return false
	}
	switch signature {
	case "a{ss}":
		x, ok := v.Value().(map[string]string)
		return ok && len(x) == 0
	case "as":
		x, ok := v.Value().([]string)
		return ok && len(x) == 0
	case "au":
		x, ok := v.Value().([]uint32)
		return ok && len(x) == 0
	case "aau":
		x, ok := v.Value().([][]uint32)
		return ok && len(x) == 0
	case "aay":
		x, ok := v.Value().([][]byte)
		return ok && len(x) == 0
	case "aa{sv}":
		x, ok := v.Value().([]map[string]dbus.Variant)
		return ok && len(x) == 0
	case "a(ayuay)", "a(ayuayu)":
		// godbus decodes D-Bus structs as []interface{}; locally constructed
		// variants may instead use Go structs. Only zero-length arrays pass.
		if x, ok := v.Value().([][]interface{}); ok {
			return len(x) == 0
		}
		x := reflect.ValueOf(v.Value())
		if !x.IsValid() || x.Kind() != reflect.Slice || x.Len() != 0 || x.Type().Elem().Kind() != reflect.Struct {
			return false
		}
		t := x.Type().Elem()
		fields := []reflect.Type{reflect.TypeOf([]byte{}), reflect.TypeOf(uint32(0)), reflect.TypeOf([]byte{})}
		if signature == "a(ayuayu)" {
			fields = append(fields, reflect.TypeOf(uint32(0)))
		}
		if t.NumField() != len(fields) {
			return false
		}
		for i, want := range fields {
			if t.Field(i).Type != want || t.Field(i).PkgPath != "" || t.Field(i).Tag.Get("dbus") != "" {
				return false
			}
		}
		return true
	}
	return false
}

func profileProperty(section, key string, v dbus.Variant, id Identity) bool {
	switch section {
	case "connection":
		switch key {
		case "uuid":
			return profileEqual(v, id.UUID)
		case "type":
			return profileEqual(v, "vpn")
		case "interface-name":
			return profileEqual(v, "") || profileEqual(v, id.Interface)
		case "id":
			return profileString(v)
		case "timestamp":
			_, ok := v.Value().(uint64)
			return ok && v.Signature().String() == "t"
		case "read-only", "autoconnect":
			// read-only is deprecated/no-op; autoconnect is not used by NM VPNs.
			_, ok := v.Value().(bool)
			return ok && v.Signature().String() == "b"
		case "permissions", "secondaries":
			return profileEmpty(v, "as")
		case "zone", "controller", "master", "port-type", "slave-type":
			return profileEqual(v, "")
		case "multi-connect", "autoconnect-priority":
			return profileEqual(v, int32(0))
		}
	case "vpn":
		switch key {
		case "service-type":
			return profileEqual(v, PluginService)
		case "persistent":
			return profileEqual(v, false)
		case "data", "secrets":
			return profileEmpty(v, "a{ss}")
		case "timeout":
			return profileEqual(v, uint32(0))
		}
	case "ipv4", "ipv6":
		switch key {
		case "method":
			if section == "ipv4" {
				return profileEqual(v, "auto")
			}
			return profileEqual(v, "disabled")
		case "never-default", "ignore-auto-dns":
			if section == "ipv4" {
				return profileEqual(v, true)
			}
			_, ok := v.Value().(bool)
			return ok && v.Signature().String() == "b"
		case "ignore-auto-routes":
			return profileEqual(v, false)
		case "gateway":
			return profileEqual(v, "")
		case "route-table":
			return profileEqual(v, uint32(0))
		case "route-metric":
			return profileEqual(v, int64(-1))
		case "dns-priority":
			return profileEqual(v, int32(0))
		case "dns-data", "dns-search", "dns-options":
			return profileEmpty(v, "as")
		case "route-data", "address-data", "routing-rules":
			return profileEmpty(v, "aa{sv}")
		case "dns":
			if section == "ipv4" {
				return profileEmpty(v, "au")
			}
			return profileEmpty(v, "aay")
		case "routes":
			if section == "ipv4" {
				return profileEmpty(v, "aau")
			}
			return profileEmpty(v, "a(ayuayu)")
		case "addresses":
			if section == "ipv4" {
				return profileEmpty(v, "aau")
			}
			return profileEmpty(v, "a(ayuay)")
		}
	case "proxy":
		return key == "method" && profileEqual(v, int32(0))
	}
	return false
}
