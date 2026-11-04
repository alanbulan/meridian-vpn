//go:build linux

package nmvpn

import (
	"encoding/xml"
	"io"
	"strings"

	"github.com/godbus/dbus/v5"
)

const (
	resolvedXMLMaxBytes      = 65536
	resolvedXMLMaxDepth      = 8
	resolvedXMLMaxElements   = 2048
	resolvedXMLMaxAttributes = 4096
	// Exact inert preamble emitted by upstream sd-bus v258. It is recognized
	// literally and removed, never interpreted, fetched or entity-expanded.
	// https://github.com/systemd/systemd/blob/v258/src/libsystemd/sd-bus/bus-introspect.c
	resolvedIntrospectionPreamble = "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n\"https://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
)

func resolvedPropertyNames(manager bool) []string {
	fields := resolvedLinkFields
	if manager {
		fields = resolvedManagerFields
	}
	out := append([]string{}, fields...)
	out = append(out, "CurrentDNSServer", "CurrentDNSServerEx")
	if manager {
		out = append(out, "LLMNRHostname", "TransactionStatistics", "CacheStatistics", "DNSSECStatistics")
	}
	return out
}

func resolvedPropertySchema(manager bool) map[string]string {
	schema := map[string]string{
		"LLMNR": "s", "MulticastDNS": "s", "DNSOverTLS": "s", "DNSSEC": "s",
		"DNSSECSupported": "b", "DNSSECNegativeTrustAnchors": "as",
		"DNS": "a(iay)", "DNSEx": "a(iayqs)", "Domains": "a(sb)",
		"CurrentDNSServer": "(iay)", "CurrentDNSServerEx": "(iayqs)",
	}
	if manager {
		schema["DNS"], schema["DNSEx"], schema["Domains"] = "a(iiay)", "a(iiayqs)", "a(isb)"
		schema["CurrentDNSServer"], schema["CurrentDNSServerEx"] = "(iiay)", "(iiayqs)"
		schema["FallbackDNS"], schema["FallbackDNSEx"] = "a(iiay)", "a(iiayqs)"
		schema["DNSStubListener"], schema["ResolvConfMode"], schema["LLMNRHostname"] = "s", "s", "s"
		schema["TransactionStatistics"], schema["CacheStatistics"], schema["DNSSECStatistics"] = "(tt)", "(ttt)", "(tttt)"
	} else {
		schema["DefaultRoute"], schema["ScopesMask"] = "b", "t"
	}
	return schema
}

type resolvedXMLFrame struct {
	kind        string
	annotations map[string]bool
}

// Validate token-by-token so duplicate declarations cannot disappear into maps
// during XML unmarshalling. Only the target interface's exact reviewed property
// schema is accepted; the three standard property-free D-Bus interfaces may
// coexist. Methods/signals are metadata, never an authority to invoke them.
func validateResolvedIntrospection(document string, path dbus.ObjectPath, target string) error {
	if len(document) == 0 || len(document) > resolvedXMLMaxBytes || (target != resolvedManagerInterface && target != resolvedLinkInterface) || (target == resolvedManagerInterface && path != resolvedPath) || (target == resolvedLinkInterface && !resolvedValidLinkPath(path)) {
		return errResolvedObservation
	}
	if strings.HasPrefix(document, resolvedIntrospectionPreamble) {
		document = document[len(resolvedIntrospectionPreamble):]
	}
	decoder := xml.NewDecoder(strings.NewReader(document))
	decoder.Strict = true
	// No CharsetReader, Entity table or external resolver is installed.
	schema := resolvedPropertySchema(target == resolvedManagerInterface)
	properties, interfaces, members, nodes := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	var stack []resolvedXMLFrame
	currentInterface := ""
	rootSeen, rootClosed := false, false
	elements, attributes, tokens := 0, 0, 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errResolvedObservation
		}
		tokens++
		if tokens > resolvedXMLMaxElements*8 {
			return errResolvedObservation
		}
		switch t := token.(type) {
		case xml.StartElement:
			elements++
			attributes += len(t.Attr)
			if rootClosed || elements > resolvedXMLMaxElements || attributes > resolvedXMLMaxAttributes || len(stack) >= resolvedXMLMaxDepth || t.Name.Space != "" {
				return errResolvedObservation
			}
			attrs, ok := resolvedXMLAttrs(t.Attr)
			if !ok {
				return errResolvedObservation
			}
			parent := ""
			if len(stack) > 0 {
				parent = stack[len(stack)-1].kind
			}
			switch t.Name.Local {
			case "node":
				if len(stack) == 0 {
					if rootSeen || len(attrs) > 1 || (len(attrs) == 1 && attrs["name"] != string(path)) {
						return errResolvedObservation
					}
					rootSeen = true
				} else {
					name := attrs["name"]
					if len(stack) != 1 || parent != "node" || len(attrs) != 1 || name == "" || len(name) > 128 || strings.HasPrefix(name, "/") || !dbus.ObjectPath("/"+name).IsValid() || nodes[name] {
						return errResolvedObservation
					}
					nodes[name] = true
				}
			case "interface":
				name := attrs["name"]
				if len(stack) != 1 || parent != "node" || len(attrs) != 1 || interfaces[name] || (name != target && name != resolvedBusName+".Peer" && name != resolvedIntrospectInterface && name != propertiesInterface) {
					return errResolvedObservation
				}
				interfaces[name], currentInterface = true, name
			case "property":
				name := attrs["name"]
				typeSignature, known := schema[name]
				if len(stack) != 2 || parent != "interface" || currentInterface != target || len(attrs) != 3 || !known || properties[name] || attrs["type"] != typeSignature || attrs["access"] != "read" {
					return errResolvedObservation
				}
				properties[name] = true
			case "method", "signal":
				name := attrs["name"]
				key := currentInterface + "/" + t.Name.Local + "/" + name
				if len(stack) != 2 || parent != "interface" || len(attrs) != 1 || !resolvedXMLMember(name) || members[key] {
					return errResolvedObservation
				}
				members[key] = true
			case "arg":
				if parent != "method" && parent != "signal" {
					return errResolvedObservation
				}
				if !resolvedXMLOnly(attrs, "name", "type", "direction") || attrs["type"] == "" || len(attrs["type"]) > 255 {
					return errResolvedObservation
				}
				if _, err := dbus.ParseSignature(attrs["type"]); err != nil {
					return errResolvedObservation
				}
				if name, ok := attrs["name"]; ok && !resolvedXMLMember(name) {
					return errResolvedObservation
				}
				if direction, ok := attrs["direction"]; ok && (direction != "in" && direction != "out") {
					return errResolvedObservation
				}
			case "annotation":
				if parent != "interface" && parent != "property" && parent != "method" && parent != "signal" && parent != "arg" {
					return errResolvedObservation
				}
				name := attrs["name"]
				if len(attrs) != 2 || !resolvedXMLDotted(name) {
					return errResolvedObservation
				}
				if _, ok := attrs["value"]; !ok {
					return errResolvedObservation
				}
				frame := &stack[len(stack)-1]
				if frame.annotations == nil {
					frame.annotations = map[string]bool{}
				}
				if frame.annotations[name] {
					return errResolvedObservation
				}
				frame.annotations[name] = true
			default:
				return errResolvedObservation
			}
			stack = append(stack, resolvedXMLFrame{kind: t.Name.Local})
		case xml.EndElement:
			if len(stack) == 0 || t.Name.Space != "" || stack[len(stack)-1].kind != t.Name.Local {
				return errResolvedObservation
			}
			stack = stack[:len(stack)-1]
			if t.Name.Local == "interface" {
				currentInterface = ""
			}
			if len(stack) == 0 {
				rootClosed = true
			}
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return errResolvedObservation
			}
		case xml.Comment:
			// Inert bounded comments are permitted; they declare no properties.
		case xml.Directive, xml.ProcInst:
			// Includes every other DOCTYPE, entity/internal subset and PI.
			return errResolvedObservation
		default:
			return errResolvedObservation
		}
	}
	if !rootSeen || !rootClosed || len(stack) != 0 || !interfaces[target] || len(properties) != len(schema) {
		return errResolvedObservation
	}
	return nil
}

func resolvedXMLAttrs(attrs []xml.Attr) (map[string]string, bool) {
	if len(attrs) > 8 {
		return nil, false
	}
	out := make(map[string]string, len(attrs))
	for _, attr := range attrs {
		if attr.Name.Space != "" || len(attr.Name.Local) > 64 || len(attr.Value) > 512 {
			return nil, false
		}
		if _, exists := out[attr.Name.Local]; exists {
			return nil, false
		}
		out[attr.Name.Local] = attr.Value
	}
	return out, true
}

func resolvedXMLOnly(attrs map[string]string, allowed ...string) bool {
	for name := range attrs {
		if !resolvedPropertyListed(name, allowed) {
			return false
		}
	}
	return true
}

func resolvedXMLMember(name string) bool {
	if len(name) == 0 || len(name) > 255 {
		return false
	}
	for i, c := range []byte(name) {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func resolvedXMLDotted(name string) bool {
	if len(name) > 255 || !strings.Contains(name, ".") {
		return false
	}
	for _, part := range strings.Split(name, ".") {
		if !resolvedXMLMember(part) {
			return false
		}
	}
	return true
}
