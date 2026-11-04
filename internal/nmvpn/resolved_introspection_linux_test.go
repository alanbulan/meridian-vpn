//go:build linux

package nmvpn

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

func resolvedIntrospectionFixture(manager bool) string {
	iface := resolvedLinkInterface
	if manager {
		iface = resolvedManagerInterface
	}
	var out strings.Builder
	out.WriteString(resolvedIntrospectionPreamble + "<node>\n")
	out.WriteString(`<interface name="org.freedesktop.DBus.Peer"><method name="Ping"/></interface>`)
	out.WriteString(`<interface name="org.freedesktop.DBus.Introspectable"><method name="Introspect"><arg name="xml_data" type="s" direction="out"/></method></interface>`)
	out.WriteString(`<interface name="org.freedesktop.DBus.Properties"><method name="Get"><arg name="interface_name" type="s" direction="in"/><arg name="property_name" type="s" direction="in"/><arg name="value" type="v" direction="out"/></method></interface>`)
	out.WriteString(`<interface name="` + iface + `">`)
	if manager {
		out.WriteString(`<method name="GetLink"><arg type="i" name="ifindex" direction="in"/><arg type="o" name="path" direction="out"/></method><method name="ListDelegates"><arg type="a(so)" name="delegates" direction="out"/></method>`)
	}
	for _, name := range resolvedPropertyNames(manager) {
		out.WriteString(`<property name="` + name + `" type="` + resolvedPropertySchema(manager)[name] + `" access="read"><annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="false"/></property>`)
	}
	out.WriteString(`</interface><node name="children"/></node>`)
	return out.String()
}

func TestResolvedIntrospectionAcceptsSourceShapedInventory(t *testing.T) {
	for _, manager := range []bool{false, true} {
		path, iface := resolvedLinkPath(2), resolvedLinkInterface
		if manager {
			path, iface = resolvedPath, resolvedManagerInterface
		}
		fixture := resolvedIntrospectionFixture(manager)
		for _, document := range []string{fixture, strings.TrimPrefix(fixture, resolvedIntrospectionPreamble), strings.Replace(fixture, "<node>", `<node name="`+string(path)+`">`, 1)} {
			if err := validateResolvedIntrospection(document, path, iface); err != nil {
				t.Fatal(err)
			}
		}
		schema := resolvedPropertySchema(manager)
		if len(schema) != len(resolvedPropertyNames(manager)) {
			t.Fatal("inventory/read-list mismatch")
		}
		for _, name := range resolvedPropertyNames(manager) {
			if _, ok := schema[name]; !ok {
				t.Fatal("missing field type", name)
			}
		}
	}
}

func TestResolvedIntrospectionRejectsAmbiguousDeclarations(t *testing.T) {
	base := resolvedIntrospectionFixture(true)
	property := `<property name="LLMNR" type="s" access="read"/>`
	for _, test := range []struct {
		name     string
		document string
	}{
		{"duplicate-property", strings.Replace(base, "</interface><node", property+"</interface><node", 1)},
		{"conflicting-duplicate", strings.Replace(base, "</interface><node", `<property name="LLMNR" type="b" access="read"/></interface><node`, 1)},
		{"duplicate-telemetry", strings.Replace(base, "</interface><node", `<property name="CacheStatistics" type="(ttt)" access="read"/></interface><node`, 1)},
		{"unknown-property", strings.Replace(base, "</interface><node", `<property name="FuturePolicy" type="s" access="read"/></interface><node`, 1)},
		{"missing-property", strings.Replace(base, `name="LLMNR"`, `name="Unknown"`, 1)},
		{"missing-telemetry", strings.Replace(base, `name="CacheStatistics"`, `name="Unknown"`, 1)},
		{"wrong-type", strings.Replace(base, `name="LLMNR" type="s"`, `name="LLMNR" type="b"`, 1)},
		{"writable", strings.Replace(base, `access="read"`, `access="readwrite"`, 1)},
		{"duplicate-attribute", strings.Replace(base, `name="LLMNR"`, `name="LLMNR" name="DNS"`, 1)},
		{"duplicate-type", strings.Replace(base, `name="LLMNR" type="s"`, `name="LLMNR" type="b" type="s"`, 1)},
		{"unknown-attribute", strings.Replace(base, `name="LLMNR"`, `name="LLMNR" extra="hidden"`, 1)},
		{"duplicate-target", strings.Replace(base, "</node>", `<interface name="org.freedesktop.resolve1.Manager"/></node>`, 1)},
		{"wrong-target", strings.Replace(base, resolvedManagerInterface, resolvedLinkInterface, 1)},
		{"unknown-interface", strings.Replace(base, resolvedBusName+".Peer", "org.example.Unknown", 1)},
		{"property-under-standard-interface", strings.Replace(base, `<method name="Ping"/>`, property, 1)},
		{"nested-target", strings.Replace(base, `<node name="children"/>`, `<node name="children"><interface name="org.freedesktop.resolve1.Manager"/></node>`, 1)},
		{"namespace", strings.Replace(base, `<property name="LLMNR"`, `<property xmlns="urn:hidden" name="LLMNR"`, 1)},
		{"prefix-namespace", strings.Replace(base, `<property name="LLMNR"`, `<x:property xmlns:x="urn:hidden" name="LLMNR"`, 1)},
		{"duplicate-node", strings.Replace(base, `<node name="children"/>`, `<node name="children"/><node name="children"/>`, 1)},
		{"second-root", base + "<node/>"},
		{"truncated", base[:len(base)-7]},
		{"text", strings.Replace(base, "</node>", "undeclared-text</node>", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateResolvedIntrospection(test.document, resolvedPath, resolvedManagerInterface); err == nil {
				t.Fatal("ambiguous XML accepted")
			}
		})
	}
}

func TestResolvedIntrospectionRejectsEntitiesDirectivesAndBounds(t *testing.T) {
	base := strings.TrimPrefix(resolvedIntrospectionFixture(true), resolvedIntrospectionPreamble)
	for _, prefix := range []string{
		`<!DOCTYPE node [<!ENTITY hidden "future">]>`,
		`<!DOCTYPE node SYSTEM "file:///etc/passwd">`,
		`<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN" "https://attacker.invalid/introspect.dtd">`,
		strings.TrimSuffix(resolvedIntrospectionPreamble, ">\n") + ` [<!ENTITY hidden "future">]>`,
		resolvedIntrospectionPreamble + resolvedIntrospectionPreamble,
		" " + resolvedIntrospectionPreamble,
		`<?xml version="1.0"?>`, `<?unexpected data?>`,
	} {
		if err := validateResolvedIntrospection(prefix+base, resolvedPath, resolvedManagerInterface); err == nil {
			t.Fatal("unreviewed directive/entity accepted")
		}
	}
	if err := validateResolvedIntrospection(strings.Replace(base, `name="LLMNR"`, `name="&hidden;"`, 1), resolvedPath, resolvedManagerInterface); err == nil {
		t.Fatal("custom entity accepted")
	}
	for _, doc := range []string{
		strings.Repeat(" ", resolvedXMLMaxBytes) + base,
		strings.Replace(base, "</node>", strings.Repeat("<node>", resolvedXMLMaxDepth)+strings.Repeat("</node>", resolvedXMLMaxDepth)+"</node>", 1),
		strings.Replace(base, `<method name="Ping"/>`, `<method name="`+strings.Repeat("x", 513)+`"/>`, 1),
	} {
		if err := validateResolvedIntrospection(doc, resolvedPath, resolvedManagerInterface); err == nil {
			t.Fatal("unbounded XML accepted")
		}
	}
	var nodes strings.Builder
	for i := 0; i < resolvedXMLMaxElements; i++ {
		fmt.Fprintf(&nodes, `<node name="n%d"/>`, i)
	}
	doc := strings.Replace(base, "</node>", nodes.String()+"</node>", 1)
	if len(doc) > resolvedXMLMaxBytes {
		t.Fatal("element-bound fixture exceeds byte bound")
	}
	if err := validateResolvedIntrospection(doc, resolvedPath, resolvedManagerInterface); err == nil {
		t.Fatal("element count bound ignored")
	}
}

func TestResolvedIndividualGetsBracketInventory(t *testing.T) {
	for _, manager := range []bool{false, true} {
		path, iface := resolvedLinkPath(2), resolvedLinkInterface
		if manager {
			path, iface = resolvedPath, resolvedManagerInterface
		}
		values := resolvedFullFixture(manager)
		var calls []string
		out, err := readResolvedPropertiesWith(context.Background(), path, iface, func(method string, args []any, signature string, outputs ...any) error {
			calls = append(calls, method)
			if method == resolvedIntrospectInterface+".Introspect" {
				if len(args) != 0 || signature != "s" {
					t.Fatal("wrong inventory envelope")
				}
				*outputs[0].(*string) = resolvedIntrospectionFixture(manager)
				return nil
			}
			if method != propertiesInterface+".Get" || len(args) != 2 || args[0] != iface || signature != "v" {
				t.Fatal("dictionary or unapproved read requested", method)
			}
			*outputs[0].(*dbus.Variant) = values[args[1].(string)]
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		want, err := resolvedPolicyProperties(values, manager)
		if err != nil || !reflect.DeepEqual(out, want) || len(calls) != len(values)+2 || calls[0] != resolvedIntrospectInterface+".Introspect" || calls[len(calls)-1] != calls[0] {
			t.Fatal("property reads not bracketed")
		}
	}
}

func TestResolvedIndividualGetsRejectChangedInventoryAndDictionaries(t *testing.T) {
	for _, mode := range []string{"bad-first-inventory", "bad-last-inventory", "dictionary-value", "missing-value", "read-error", "wrong-signature"} {
		t.Run(mode, func(t *testing.T) {
			introspects, gets := 0, 0
			_, err := readResolvedPropertiesWith(context.Background(), resolvedPath, resolvedManagerInterface, func(method string, args []any, signature string, out ...any) error {
				if method == resolvedIntrospectInterface+".Introspect" {
					introspects++
					document := resolvedIntrospectionFixture(true)
					if mode == "bad-first-inventory" || mode == "bad-last-inventory" && introspects == 2 {
						document = strings.Replace(document, `name="LLMNR"`, `name="Unknown"`, 1)
					}
					*out[0].(*string) = document
					return nil
				}
				gets++
				value := resolvedFullFixture(true)[args[1].(string)]
				if mode == "read-error" {
					return errors.New("injected")
				}
				if mode == "dictionary-value" {
					value = dbus.MakeVariant(map[string]dbus.Variant{"LLMNR": dbus.MakeVariant("no")})
				}
				if mode == "missing-value" {
					value = dbus.Variant{}
				}
				if mode == "wrong-signature" {
					value = dbus.MakeVariant(uint32(0))
				}
				*out[0].(*dbus.Variant) = value
				return nil
			})
			if err == nil || mode == "bad-first-inventory" && gets != 0 {
				t.Fatal("ambiguous property read accepted")
			}
		})
	}
}

// Regression evidence: the upstream decoder really collapses duplicate a{sv}
// keys. The production path must not request or accept that dictionary at all.
// This makes no claim about duplicate message headers beyond the trusted bus.
func TestResolvedGetAllDuplicateDictionaryPathIsForbidden(t *testing.T) {
	type row struct {
		Key   string
		Value dbus.Variant
	}
	rows := []row{{"LLMNR", dbus.MakeVariant("unsupported")}, {"LLMNR", dbus.MakeVariant("no")}}
	m := &dbus.Message{Type: dbus.TypeSignal, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldPath: dbus.MakeVariant(dbus.ObjectPath("/fixture")), dbus.FieldInterface: dbus.MakeVariant("test.Fixture"), dbus.FieldMember: dbus.MakeVariant("Value"), dbus.FieldSignature: dbus.MakeVariant(dbus.SignatureOf(rows)),
	}, Body: []any{rows}}
	var encoded bytes.Buffer
	if err := m.EncodeTo(&encoded, binary.LittleEndian); err != nil {
		t.Fatal(err)
	}
	decoded, err := dbus.DecodeMessage(bytes.NewReader(bytes.Replace(encoded.Bytes(), []byte("a(sv)"), []byte("a{sv}"), 1)))
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded.Body[0].(map[string]dbus.Variant); len(got) != 1 || got["LLMNR"].Value() != "no" {
		t.Fatal("upstream decoder behavior changed; reassess regression")
	}
	b := resolvedTestObserver()
	request := resolvedTestMessage(dbus.TypeMethodCall, "", resolvedPath, propertiesInterface, "GetAll", resolvedManagerInterface)
	request.Headers[dbus.FieldDestination] = dbus.MakeVariant(b.pin.Owner)
	request.Flags = dbus.FlagNoAutoStart
	if b.permittedCall(request) {
		t.Fatal("duplicate-collapsing dictionary path admitted")
	}
}
