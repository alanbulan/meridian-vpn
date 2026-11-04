//go:build linux && nmvpnintegration

package nmvpn

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/godbus/dbus/v5"
)

type nmFixtureVariant struct {
	Signature string          `json:"signature"`
	Value     json.RawMessage `json:"value"`
}

type nmLibnmFixture struct {
	Version    int                                    `json:"version"`
	Library    string                                 `json:"libnmVersion"`
	Source     string                                 `json:"source"`
	Input      map[string]map[string]nmFixtureVariant `json:"input"`
	Normalized map[string]map[string]nmFixtureVariant `json:"normalized"`
}

func nmDecodeFixture(t *testing.T, raw map[string]map[string]nmFixtureVariant) map[string]map[string]dbus.Variant {
	t.Helper()
	result := make(map[string]map[string]dbus.Variant, len(raw))
	for section, values := range raw {
		result[section] = make(map[string]dbus.Variant, len(values))
		for key, item := range values {
			if bytes.Equal(bytes.TrimSpace(item.Value), []byte("null")) {
				t.Fatal("null is not a typed libnm value")
			}
			var target any
			switch item.Signature {
			case "s":
				target = new(string)
			case "b":
				target = new(bool)
			case "i":
				target = new(int32)
			case "u":
				target = new(uint32)
			case "x":
				target = new(int64)
			case "t":
				target = new(uint64)
			case "as":
				target = new([]string)
			case "a{ss}":
				target = new(map[string]string)
			case "au":
				target = new([]uint32)
			case "aau":
				target = new([][]uint32)
			case "aay":
				target = new([][]byte)
			case "aa{sv}":
				target = new([]map[string]dbus.Variant)
			default:
				t.Fatalf("unsupported libnm fixture signature %s for %s.%s", item.Signature, section, key)
			}
			if err := json.Unmarshal(item.Value, target); err != nil {
				t.Fatal("invalid typed libnm value", err)
			}
			variant := dbus.MakeVariant(reflect.ValueOf(target).Elem().Interface())
			if variant.Signature().String() != item.Signature {
				t.Fatal("fixture signature changed during decoding")
			}
			result[section][key] = variant
		}
	}
	return result
}

func nmLoadLibnmFixture(t *testing.T) (map[string]map[string]dbus.Variant, map[string]map[string]dbus.Variant) {
	t.Helper()
	if os.Getenv("MERIDIAN_NMVPN_WIRE_TESTS") != "1" {
		t.Fatal("explicit disposable-fixture opt-in required")
	}
	path := os.Getenv("MERIDIAN_NMVPN_PROFILE_FIXTURE")
	if !filepath.IsAbs(path) {
		t.Fatal("required real libnm normalization fixture was not generated")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 65536 {
		t.Fatal("normalization fixture unreadable or oversized", err)
	}
	var fixture nmLibnmFixture
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fixture); err != nil || fixture.Version != 1 || fixture.Library == "" || fixture.Source != "NM.SimpleConnection.new_from_dbus / to_dbus(ALL), no daemon" {
		t.Fatal("invalid normalization fixture provenance", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		t.Fatal("trailing normalization fixture data")
	}
	t.Log("Pure in-memory libnm version:", fixture.Library)
	input, normalized := nmDecodeFixture(t, fixture.Input), nmDecodeFixture(t, fixture.Normalized)
	id := Identity{UUID: wireUUID, Interface: "meridian0"}
	if ValidateProfile(input, id) != nil || ValidateProfile(normalized, id) != nil || !equivalentProfiles(input, normalized, id) {
		t.Fatal("real libnm normalization exceeded the approved equivalence grammar")
	}
	return input, normalized
}

// Copy the network output without erasing fields, then retain only the original
// authenticated envelope. Malicious test mutations are deliberately not sanitized.
func nmOverlayNetwork(original, network map[string]map[string]dbus.Variant) map[string]map[string]dbus.Variant {
	out := make(map[string]map[string]dbus.Variant, len(network))
	for section, values := range network {
		out[section] = make(map[string]dbus.Variant, len(values))
		for key, value := range values {
			out[section][key] = value
		}
	}
	for _, key := range []string{"user-name", "data", "secrets"} {
		if value, ok := original["vpn"][key]; ok {
			out["vpn"][key] = value
		}
	}
	return out
}

func TestNMVPNWireManagerLibnmNormalization(t *testing.T) {
	input, normalized := nmLoadLibnmFixture(t)
	for _, side := range []string{"connect", "settings", "both", "defaults-and-bookkeeping"} {
		t.Run(side, func(t *testing.T) {
			f, _, wire, manager := activationWireFixture(t)
			transform := func(original map[string]map[string]dbus.Variant) map[string]map[string]dbus.Variant {
				out := nmOverlayNetwork(original, normalized)
				if side == "defaults-and-bookkeeping" {
					out["connection"]["timestamp"] = dbus.MakeVariant(uint64(123))
					out["connection"]["read-only"] = dbus.MakeVariant(true)
					out["connection"]["permissions"] = dbus.MakeVariant([]string{})
					out["connection"]["multi-connect"] = dbus.MakeVariant(int32(0))
					out["vpn"]["timeout"] = dbus.MakeVariant(uint32(0))
					out["ipv4"]["route-table"] = dbus.MakeVariant(uint32(0))
					out["ipv6"]["never-default"] = dbus.MakeVariant(false)
				}
				return out
			}
			wire.mu.Lock()
			if side != "settings" {
				wire.connectTransform = transform
			}
			if side != "connect" {
				wire.settingsTransform = transform
			}
			wire.mu.Unlock()
			receipt, err := manager.Start(f.ctx, input)
			if err != nil {
				t.Fatal("normalized Connect rejected", err)
			}
			activation, err := f.plugin.Receive(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			binding, err := receipt.Correlate(f.ctx, activation)
			if err != nil || activation.CheckReceipt(f.ctx, binding) != nil {
				t.Fatal("normalized receipt rejected", err)
			}
		})
	}
}

func TestNMVPNWireManagerNormalizationTampering(t *testing.T) {
	input, normalized := nmLoadLibnmFixture(t)
	for _, side := range []string{"connect", "settings"} {
		for _, attack := range []string{"unknown", "wrong-type", "route-table", "dns-options", "interface", "autoconnect", "ports-zero", "ports-one", "port-alias-conflict", "ipv6-flag", "username", "nonce", "password-flags", "empty-section"} {
			t.Run(side+"/"+attack, func(t *testing.T) {
				f, journal, wire, manager := activationWireFixture(t)
				transform := func(original map[string]map[string]dbus.Variant) map[string]map[string]dbus.Variant {
					out := nmOverlayNetwork(original, normalized)
					switch attack {
					case "unknown":
						out["ipv4"]["unknown-default"] = dbus.MakeVariant(false)
					case "wrong-type":
						out["ipv4"]["route-table"] = dbus.MakeVariant(int32(0))
					case "route-table":
						out["ipv4"]["route-table"] = dbus.MakeVariant(uint32(254))
					case "dns-options":
						out["ipv4"]["dns-options"] = dbus.MakeVariant([]string{})
					case "interface":
						out["connection"]["interface-name"] = dbus.MakeVariant(f.plan.Interface)
					case "autoconnect":
						out["connection"]["autoconnect"] = dbus.MakeVariant(true)
					case "ports-zero":
						out["connection"]["autoconnect-ports"] = dbus.MakeVariant(int32(0))
					case "ports-one":
						out["connection"]["autoconnect-ports"] = dbus.MakeVariant(int32(1))
					case "port-alias-conflict":
						out["connection"]["autoconnect-ports"] = dbus.MakeVariant(int32(-1))
						out["connection"]["autoconnect-slaves"] = dbus.MakeVariant(int32(0))
					case "ipv6-flag":
						out["ipv6"]["never-default"] = dbus.MakeVariant(true)
					case "username":
						out["vpn"]["user-name"] = dbus.MakeVariant("another-user")
					case "nonce":
						out["vpn"]["data"] = dbus.MakeVariant(map[string]string{"meridian-activation": "00000000000000000000000000000000", "password-flags": "2"})
					case "password-flags":
						nonce := original["vpn"]["data"].Value().(map[string]string)["meridian-activation"]
						out["vpn"]["data"] = dbus.MakeVariant(map[string]string{"meridian-activation": nonce, "password-flags": "0"})
					case "empty-section":
						out["user"] = map[string]dbus.Variant{}
					}
					return out
				}
				wire.mu.Lock()
				if side == "connect" {
					wire.connectTransform = transform
				} else {
					wire.settingsTransform = transform
				}
				wire.mu.Unlock()
				receipt, err := manager.Start(f.ctx, input)
				if err == nil {
					activation, receiveErr := f.plugin.Receive(f.ctx)
					if receiveErr != nil {
						t.Fatal("accepted Connect missing", receiveErr)
					}
					if _, err := receipt.Correlate(f.ctx, activation); err == nil {
						t.Fatal("normalization concealed unauthorized profile change")
					}
				}
				record, err := journal.LoadActivation()
				if err != nil || record == nil || record.Phase != "quarantine" {
					t.Fatal("tampering did not retain quarantine")
				}
			})
		}
	}
}
