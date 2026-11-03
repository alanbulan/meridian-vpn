//go:build linux

package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// Reject duplicate keys at every nesting level. encoding/json otherwise silently
// accepts the last duplicate, which is unsuitable for kernel absence evidence.
func uniVPNCheckJSONValue(d *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("kernel JSON nesting limit")
	}
	tok, e := d.Token()
	if e != nil {
		return e
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			key, ok := k.(string)
			if !ok || seen[key] || key != strings.ToLower(key) || !uniVPNASCIIKey(key) {
				return errors.New("duplicate or invalid kernel JSON key")
			}
			seen[key] = true
			if e = uniVPNCheckJSONValue(d, depth+1); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return errors.New("invalid kernel JSON object")
		}
	case '[':
		for d.More() {
			if e = uniVPNCheckJSONValue(d, depth+1); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return errors.New("invalid kernel JSON array")
		}
	default:
		return errors.New("invalid kernel JSON delimiter")
	}
	return nil
}
func uniVPNKernelObjects(b []byte) ([]json.RawMessage, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || b[0] != '[' {
		return nil, errors.New("kernel output must be an array")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e := uniVPNCheckJSONValue(d, 0); e != nil {
		return nil, e
	}
	if _, e := d.Token(); e != io.EOF {
		return nil, errors.New("trailing kernel JSON")
	}
	var objects []json.RawMessage
	if e := json.Unmarshal(b, &objects); e != nil {
		return nil, e
	}
	if objects == nil || len(objects) > 65536 {
		return nil, errors.New("invalid kernel object array")
	}
	for _, raw := range objects {
		r := bytes.TrimSpace(raw)
		if len(r) == 0 || r[0] != '{' {
			return nil, errors.New("kernel array contains nonobject")
		}
	}
	return objects, nil
}
func uniVPNKernelScalar(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s != ""
	}
	var n json.Number
	if json.Unmarshal(raw, &n) != nil {
		return false
	}
	_, e := strconv.ParseUint(string(n), 10, 32)
	return e == nil
}
func uniVPNDecodeRoutes(b []byte) ([]uniVPNIPRoute, error) {
	objects, e := uniVPNKernelObjects(b)
	if e != nil {
		return nil, e
	}
	routes := make([]uniVPNIPRoute, 0, len(objects))
	for _, raw := range objects {
		var fields map[string]json.RawMessage
		if e = json.Unmarshal(raw, &fields); e != nil {
			return nil, e
		}
		for _, key := range []string{"nexthops", "multipath", "nhid", "encap", "via"} {
			if _, present := fields[key]; present {
				return nil, errors.New("unsupported nested kernel route structure")
			}
		}
		for _, key := range []string{"dst", "gateway", "dev", "protocol", "metric", "type", "table"} {
			if v, ok := fields[key]; ok && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
				return nil, errors.New("null kernel route field")
			}
		}
		var r uniVPNIPRoute
		if e = json.Unmarshal(raw, &r); e != nil {
			return nil, e
		}
		if r.Dst == "" || r.Metric < 0 || uint64(r.Metric) > uint64(^uint32(0)) || !uniVPNKernelScalar(r.Table) || !uniVPNKernelScalar(r.Protocol) {
			return nil, errors.New("invalid kernel route record")
		}
		if r.Dst != "default" {
			if _, e := netip.ParsePrefix(r.Dst); e != nil {
				if _, e = netip.ParseAddr(r.Dst); e != nil {
					return nil, errors.New("invalid kernel route destination")
				}
			}
		}
		if r.Gateway != "" {
			if _, e := netip.ParseAddr(r.Gateway); e != nil {
				return nil, errors.New("invalid kernel route gateway")
			}
		}
		switch r.Type {
		case "", "unicast", "local", "broadcast", "multicast", "anycast":
			if r.Dev == "" {
				return nil, errors.New("kernel route device missing or unsupported multipath")
			}
		case "blackhole", "unreachable", "prohibit", "throw":
		default:
			return nil, errors.New("unsupported kernel route type")
		}
		routes = append(routes, r)
	}
	return routes, nil
}
func uniVPNDecodeLinks(b []byte) ([]uniVPNIPLink, error) {
	objects, e := uniVPNKernelObjects(b)
	if e != nil {
		return nil, e
	}
	links := make([]uniVPNIPLink, 0, len(objects))
	indexes := map[int]bool{}
	names := map[string]bool{}
	for _, raw := range objects {
		var l uniVPNIPLink
		if e = json.Unmarshal(raw, &l); e != nil {
			return nil, e
		}
		if l.Index <= 0 || l.Name == "" || indexes[l.Index] || names[l.Name] {
			return nil, errors.New("invalid or duplicate kernel link record")
		}
		indexes[l.Index] = true
		names[l.Name] = true
		var fields map[string]json.RawMessage
		if e = json.Unmarshal(raw, &fields); e != nil {
			return nil, e
		}
		for _, key := range []string{"ifindex", "ifname", "ifalias", "flags", "addr_info", "linkinfo"} {
			if v, ok := fields[key]; ok && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
				return nil, errors.New("null kernel link field")
			}
		}
		if v, ok := fields["addr_info"]; ok {
			entries, e := uniVPNKernelObjects(v)
			if e != nil {
				return nil, e
			}
			for _, entry := range entries {
				var address map[string]json.RawMessage
				if e = json.Unmarshal(entry, &address); e != nil {
					return nil, e
				}
				local, exists := address["local"]
				prefix, present := address["prefixlen"]
				if !exists || !present || bytes.Equal(prefix, []byte("null")) {
					return nil, errors.New("incomplete kernel address")
				}
				var a string
				var bits int
				if json.Unmarshal(local, &a) != nil || json.Unmarshal(prefix, &bits) != nil {
					return nil, errors.New("invalid kernel address")
				}
				ip, e := netip.ParseAddr(a)
				if e != nil || bits < 0 || bits > ip.BitLen() {
					return nil, errors.New("invalid kernel address prefix")
				}
			}
		}
		links = append(links, l)
	}
	return links, nil
}

func uniVPNASCIIKey(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
}
