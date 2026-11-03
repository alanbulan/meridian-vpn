//go:build linux

package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const nativeTestID = "00112233445566778899aabbccddeeff"

func nativeTestRecord() uniVPNNativeRecord {
	return uniVPNNativeRecord{Version: 1, Event: "config", Session: nativeTestID, Interface: "tun7", Index: 7, Alias: "meridian-" + nativeTestID, Addresses: []netip.Prefix{netip.MustParsePrefix("10.1.2.3/24")}, Routes: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/16")}, Endpoint: netip.MustParseAddr("192.0.2.8")}
}
func nativeTestJSON(r uniVPNNativeRecord) string { b, _ := json.Marshal(r); return string(b) + "\n" }
func TestNativeChannelRejectsInvalidRecords(t *testing.T) {
	good := nativeTestJSON(nativeTestRecord())
	cases := map[string]string{
		"empty": "", "partial": strings.TrimSuffix(good, "\n"), "oversize": strings.Repeat("x", uniVPNNativeRecordLimit) + "\n",
		"unknown":              strings.Replace(good, `"version":1`, `"unexpected":1,"version":1`, 1),
		"case_alias":           strings.Replace(good, `"version":1`, `"Version":2,"version":1`, 1),
		"duplicate_key":        strings.Replace(good, `"version":1`, `"version":2,"version":1`, 1),
		"trailing":             strings.TrimSuffix(good, "\n") + "{}\n",
		"duplicate_config":     good + good,
		"wrong_session":        strings.Replace(good, nativeTestID, strings.Repeat("a", 32), 1),
		"wrong_alias":          strings.Replace(good, "meridian-", "foreign-", 1),
		"wrong_index":          strings.Replace(good, `"index":7`, `"index":0`, 1),
		"wrong_event":          strings.Replace(good, `"config"`, `"ready"`, 1),
		"invalid_endpoint":     strings.Replace(good, "192.0.2.8", "127.0.0.1", 1),
		"closed_before_config": `{"version":1,"event":"closed","session":"` + nativeTestID + `"}` + "\n",
		"data_after_closed":    good + `{"version":1,"event":"closed","session":"` + nativeTestID + `"}` + "\n" + good,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			c := newUniVPNNativeChannel()
			stops := 0
			c.read(strings.NewReader(data), nativeTestID, func() { stops++ })
			if c.err == nil || stops != 1 {
				t.Fatalf("accepted invalid record, stops=%d err=%v", stops, c.err)
			}
			select {
			case <-c.ready:
			default:
				t.Fatal("readiness not unblocked")
			}
			select {
			case <-c.done:
			default:
				t.Fatal("reader not joined")
			}
		})
	}
}
func TestNativeChannelConfigIsNotCleanupProof(t *testing.T) {
	c := newUniVPNNativeChannel()
	c.read(strings.NewReader(nativeTestJSON(nativeTestRecord())), nativeTestID, func() { t.Fatal("valid config rejected") })
	ops := &networkTestOps{}
	source, err := NewUniVPNNativeSessionSource(ops)
	if err != nil {
		t.Fatal(err)
	}
	p := &uniVPNExecProcess{session: c, contained: make(chan struct{})}
	got, err := source.WaitNetworkConfig(context.Background(), p)
	if err != nil || got.Index != 7 {
		t.Fatalf("config %v %v", got, err)
	}
	got.Addresses[0] = netip.MustParsePrefix("10.3.4.5/24")
	again, _ := source.WaitNetworkConfig(context.Background(), p)
	if again.Addresses[0] == got.Addresses[0] {
		t.Fatal("configuration aliasing")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if source.ProveNetworkGone(ctx, p) == nil {
		t.Fatal("accepted live process cleanup")
	}
	close(p.contained)
	if source.ProveNetworkGone(context.Background(), p) != nil {
		t.Fatal("rejected contained process plus positive absence")
	}
	ops.proofErr = errors.New("kernel state remains")
	if source.ProveNetworkGone(context.Background(), p) == nil {
		t.Fatal("accepted absent proof failure")
	}
	p.containmentErr = errors.New("descendants remain")
	if source.ProveNetworkGone(context.Background(), p) == nil {
		t.Fatal("accepted containment failure")
	}
	if _, err = source.WaitNetworkConfig(context.Background(), &networkTestProcess{}); err == nil {
		t.Fatal("accepted unrelated process")
	}
}
func TestNativeChannelCancellationAndLateFailure(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	channel := newUniVPNNativeChannel()
	var stopped atomic.Bool
	go channel.read(reader, nativeTestID, func() { stopped.Store(true) })
	source, _ := NewUniVPNNativeSessionSource(&networkTestOps{})
	p := &uniVPNExecProcess{session: channel}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.WaitNetworkConfig(ctx, p); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	if _, err := io.WriteString(writer, nativeTestJSON(nativeTestRecord())); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := source.WaitNetworkConfig(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, "malformed\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-channel.done:
	case <-ctx.Done():
		t.Fatal("late failure blocked")
	}
	if !stopped.Load() {
		t.Fatal("late protocol error did not stop native process")
	}
	if _, err := source.WaitNetworkConfig(ctx, p); err == nil {
		t.Fatal("returned config after channel corruption")
	}
}
func TestNativeChannelClosedCannotOverrideMissingProof(t *testing.T) {
	c := newUniVPNNativeChannel()
	data := nativeTestJSON(nativeTestRecord()) + `{"version":1,"event":"closed","session":"` + nativeTestID + `"}` + "\n"
	c.read(strings.NewReader(data), nativeTestID, func() { t.Fatal("valid close rejected") })
	source, _ := NewUniVPNNativeSessionSource(&networkTestOps{proofErr: errors.New("route remains")})
	p := &uniVPNExecProcess{session: c, contained: make(chan struct{})}
	close(p.contained)
	if source.ProveNetworkGone(context.Background(), p) == nil {
		t.Fatal("native closed event replaced kernel proof")
	}
}

type nativeUncreatedOps struct {
	networkTestOps
	uncreatedErr error
	aliases      []string
}

func (o *nativeUncreatedOps) ProveUncreatedSession(_ context.Context, alias string) error {
	o.aliases = append(o.aliases, alias)
	return o.uncreatedErr
}
func TestNativeNoNetworkRequiresIndependentAbsence(t *testing.T) {
	makeChannel := func(data string) *uniVPNNativeChannel {
		c := newUniVPNNativeChannel()
		c.read(strings.NewReader(data), nativeTestID, func() {})
		return c
	}
	data := `{"version":1,"event":"no-network","session":"` + nativeTestID + `"}` + "\n"
	ops := &nativeUncreatedOps{}
	source, _ := NewUniVPNNativeSessionSource(ops)
	p := &uniVPNExecProcess{session: makeChannel(data), contained: make(chan struct{})}
	close(p.contained)
	if _, err := source.WaitNetworkConfig(context.Background(), p); err == nil {
		t.Fatal("no-network reported readiness")
	}
	if err := source.ProveNetworkGone(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if len(ops.aliases) != 1 || ops.aliases[0] != "meridian-"+nativeTestID {
		t.Fatal("missing independent alias proof")
	}
	ops.uncreatedErr = errors.New("unexpected link")
	if source.ProveNetworkGone(context.Background(), p) == nil {
		t.Fatal("accepted remaining alias")
	}
	source, _ = NewUniVPNNativeSessionSource(&networkTestOps{})
	if source.ProveNetworkGone(context.Background(), p) == nil {
		t.Fatal("accepted missing uncreated proof provider")
	}
	for _, bad := range []string{nativeTestJSON(nativeTestRecord()) + data, data + nativeTestJSON(nativeTestRecord()), data + data, strings.Replace(data, `"event"`, `"index":7,"event"`, 1)} {
		p.session = makeChannel(bad)
		if source.ProveNetworkGone(context.Background(), p) == nil {
			t.Fatal("accepted invalid no-network sequence")
		}
	}
}
func TestNativeNoNetworkMustReachEOF(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	channel := newUniVPNNativeChannel()
	go channel.read(reader, nativeTestID, func() {})
	source, _ := NewUniVPNNativeSessionSource(&nativeUncreatedOps{})
	p := &uniVPNExecProcess{session: channel, contained: make(chan struct{})}
	close(p.contained)
	io.WriteString(writer, `{"version":1,"event":"no-network","session":"`+nativeTestID+`"}`+"\n")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if source.ProveNetworkGone(ctx, p) == nil {
		t.Fatal("accepted terminal attestation before EOF")
	}
	writer.Close()
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := source.ProveNetworkGone(ctx, p); err != nil {
		t.Fatal(err)
	}
}

func TestNativeUncreatedKernelReadback(t *testing.T) {
	for _, mode := range []string{"absent", "present", "malformed", "error", "null", "empty_link"} {
		t.Run(mode, func(t *testing.T) {
			runner := &networkCommandMock{response: func(path string, args []string) ([]byte, error) {
				if path != "/trusted/ip" || strings.Join(args, " ") != "-json -details address show" {
					t.Fatal("unexpected command", path, args)
				}
				switch mode {
				case "null":
					return []byte(`null`), nil
				case "empty_link":
					return []byte(`[{}]`), nil
				case "present":
					return []byte(`[{"ifindex":7,"ifname":"tun7","ifalias":"meridian-` + nativeTestID + `"}]`), nil
				case "malformed":
					return []byte(`{"bad":"shape"}`), nil
				case "error":
					return nil, errors.New("failed read")
				}
				return []byte(`[]`), nil
			}}
			ops := commandOpsFixture(t, runner)
			err := ops.ProveUncreatedSession(context.Background(), "meridian-"+nativeTestID)
			if (err == nil) != (mode == "absent") {
				t.Fatalf("mode=%s err=%v", mode, err)
			}
			before := len(runner.calls)
			if ops.ProveUncreatedSession(context.Background(), "foreign-marker") == nil || len(runner.calls) != before {
				t.Fatal("invalid marker issued kernel read")
			}
		})
	}
}

// These fixtures are generated by the actual native C emitter, not hand-written
// JSON. Native syscall wrappers prevent TUN/netlink operations during generation.
func TestNativeEmitterWireCompatibility(t *testing.T) {
	const nonce = "0123456789abcdef0123456789abcdef"
	for _, kind := range []string{"config", "no-network"} {
		data, err := os.ReadFile("../../integration/univpn-native/tests/testdata/native-" + kind + ".jsonl")
		if err != nil {
			t.Fatal(err)
		}
		record, err := decodeUniVPNNativeRecord(data)
		if err != nil || record.Event != kind || record.Session != nonce || record.Version != 1 {
			t.Fatalf("native wire mismatch %s: %+v %v", kind, record, err)
		}
		c := newUniVPNNativeChannel()
		c.read(bytes.NewReader(data), nonce, func() {})
		if kind == "config" {
			// The native isolated fixture connects to loopback, forbidden by production
			// source policy. Decode compatibility must not weaken that restriction.
			if c.err == nil || record.Index != 17 || record.Alias != "meridian-"+nonce {
				t.Fatal("native fixture identity or endpoint policy mismatch")
			}
		} else if c.err != nil || !c.noNetwork {
			t.Fatal("native no-network fixture rejected")
		}
	}
}
