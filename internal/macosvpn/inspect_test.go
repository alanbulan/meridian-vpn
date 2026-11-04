package macosvpn

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type inspectionFake struct {
	config     func() (ServiceConfiguration, error)
	state      func() Status
	generation func() (int64, error)
	evidence   func() (systemEvidence, error)
	closes     int
}

func (f *inspectionFake) close()                                           { f.closes++ }
func (f *inspectionFake) status() Status                                   { return f.state() }
func (f *inspectionFake) readConfiguration() (ServiceConfiguration, error) { return f.config() }
func (f *inspectionFake) readConnectTime() (int64, error)                  { return f.generation() }
func (f *inspectionFake) readSystemEvidence() (systemEvidence, error)      { return f.evidence() }
func diagnosticConfig() ServiceConfiguration {
	return ServiceConfiguration{ServiceID: "service-id", Gateway: "vpn.example.com", PPPAuthentication: []string{"MSCHAP2"}, IPSecAuthentication: "SharedSecret"}
}
func diagnosticFake(state Status) *inspectionFake {
	return &inspectionFake{
		config:     func() (ServiceConfiguration, error) { return diagnosticConfig(), nil },
		state:      func() Status { return state },
		generation: func() (int64, error) { return 123, nil },
		evidence: func() (systemEvidence, error) {
			return systemEvidence{requestedID: "service-id", actualID: "service-id", interfaceName: "ppp7", extendedAddresses: []string{"10.8.0.2"}, serviceAddresses: []string{"10.8.0.2"}}, nil
		},
	}
}
func runDiagnostic(f *inspectionFake) (ServiceInspection, error) {
	return inspectExistingService(context.Background(), "service-id", func(string) (inspectionConnection, error) { return f, nil }, validInterface)
}
func TestInspectExistingServiceReadOnlyStates(t *testing.T) {
	for _, state := range []Status{Disconnected, Connected} {
		t.Run(map[Status]string{Disconnected: "disconnected", Connected: "connected"}[state], func(t *testing.T) {
			f := diagnosticFake(state)
			if state == Disconnected {
				f.generation = func() (int64, error) { t.Fatal("queried inactive generation"); return 0, nil }
				f.evidence = func() (systemEvidence, error) { t.Fatal("queried inactive interface"); return systemEvidence{}, nil }
			}
			out, err := runDiagnostic(f)
			if err != nil {
				t.Fatal(err)
			}
			if out.Status != state || !reflect.DeepEqual(out.Configuration, diagnosticConfig()) || f.closes != 1 {
				t.Fatalf("bad diagnostic: %+v; closes %d", out, f.closes)
			}
			if (out.Generation != nil) != (state == Connected) {
				t.Fatal("generation presence")
			}
			if out.Generation != nil && (out.Generation.ConnectTime != 123 || out.Generation.Interface.ServiceID != "service-id") {
				t.Fatal("wrong generation")
			}
		})
	}
}
func TestInspectRejectsInvalidIDsBeforeNativeOpen(t *testing.T) {
	for _, id := range []string{"", strings.Repeat("a", 128), "name with spaces", "x/y", "x\x00y", "x\ny", "é"} {
		_, err := inspectExistingService(context.Background(), id, func(string) (inspectionConnection, error) { t.Fatal("opened invalid ID"); return nil, nil }, validInterface)
		if err == nil {
			t.Fatalf("accepted %q", id)
		}
	}
}
func TestInspectServiceIDBoundaryAndOpenFailure(t *testing.T) {
	id := strings.Repeat("a", 127)
	opened := false
	sentinel := errors.New("open failure")
	_, err := inspectExistingService(context.Background(), id, func(got string) (inspectionConnection, error) {
		opened = true
		if got != id {
			t.Fatal("ID altered")
		}
		return nil, sentinel
	}, validInterface)
	if !opened || !errors.Is(err, sentinel) {
		t.Fatal("boundary/open failure")
	}
}
func TestInspectRejectsDriftAndIncompleteEvidence(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*inspectionFake)
	}{
		{"connecting", func(f *inspectionFake) { f.state = func() Status { return Connecting } }},
		{"disconnecting", func(f *inspectionFake) { f.state = func() Status { return Disconnecting } }},
		{"invalid", func(f *inspectionFake) { f.state = func() Status { return Invalid } }},
		{"config read", func(f *inspectionFake) {
			f.config = func() (ServiceConfiguration, error) { return ServiceConfiguration{}, errors.New("read") }
		}},
		{"config invalid", func(f *inspectionFake) {
			f.config = func() (ServiceConfiguration, error) {
				c := diagnosticConfig()
				c.Gateway = "https://vpn.example.com"
				return c, nil
			}
		}},
		{"config changes", func(f *inspectionFake) {
			calls := 0
			f.config = func() (ServiceConfiguration, error) {
				calls++
				c := diagnosticConfig()
				if calls > 1 {
					c.Gateway = "other.example.com"
				}
				return c, nil
			}
		}},
		{"config slice alias", func(f *inspectionFake) {
			c := diagnosticConfig()
			calls := 0
			f.config = func() (ServiceConfiguration, error) {
				calls++
				if calls > 1 {
					c.PPPAuthentication[0] = "PAP"
				}
				return c, nil
			}
		}},
		{"generation missing", func(f *inspectionFake) { f.generation = func() (int64, error) { return 0, nil } }},
		{"generation negative", func(f *inspectionFake) { f.generation = func() (int64, error) { return -1, nil } }},
		{"generation error", func(f *inspectionFake) { f.generation = func() (int64, error) { return 0, errors.New("missing") } }},
		{"generation changed", func(f *inspectionFake) {
			calls := int64(0)
			f.generation = func() (int64, error) { calls++; return calls, nil }
		}},
		{"generation changed while rereading configuration", func(f *inspectionFake) {
			generation := int64(1)
			calls := 0
			f.config = func() (ServiceConfiguration, error) {
				calls++
				if calls > 1 {
					generation++
				}
				return diagnosticConfig(), nil
			}
			f.generation = func() (int64, error) { return generation, nil }
		}},
		{"evidence error", func(f *inspectionFake) {
			f.evidence = func() (systemEvidence, error) { return systemEvidence{}, errors.New("unavailable") }
		}},
		{"wrong requested service", func(f *inspectionFake) {
			old := f.evidence
			f.evidence = func() (systemEvidence, error) { v, _ := old(); v.requestedID = "other"; return v, nil }
		}},
		{"wrong actual service", func(f *inspectionFake) {
			old := f.evidence
			f.evidence = func() (systemEvidence, error) { v, _ := old(); v.actualID = "other"; return v, nil }
		}},
		{"state drift", func(f *inspectionFake) {
			calls := 0
			f.state = func() Status {
				calls++
				if calls > 1 {
					return Disconnected
				}
				return Connected
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := diagnosticFake(Connected)
			tc.setup(f)
			out, err := runDiagnostic(f)
			if err == nil || !reflect.DeepEqual(out, ServiceInspection{}) || f.closes != 1 {
				t.Fatalf("unsafe partial result: %+v, %v; closes %d", out, err, f.closes)
			}
		})
	}
}
func TestInspectCancellationReleasesReadOnlyReference(t *testing.T) {
	for _, stage := range []string{"before open", "after open", "after config", "after generation", "after evidence", "after second config", "after final status"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := diagnosticFake(Connected)
			opened := false
			if stage == "before open" {
				cancel()
			}
			oldConfig := f.config
			calls := 0
			f.config = func() (ServiceConfiguration, error) {
				calls++
				if stage == "after config" || stage == "after second config" && calls == 2 {
					cancel()
				}
				return oldConfig()
			}
			oldGen := f.generation
			f.generation = func() (int64, error) {
				if stage == "after generation" {
					cancel()
				}
				return oldGen()
			}
			oldEvidence := f.evidence
			f.evidence = func() (systemEvidence, error) {
				if stage == "after evidence" {
					cancel()
				}
				return oldEvidence()
			}
			states := 0
			f.state = func() Status {
				states++
				if states == 2 && stage == "after final status" {
					cancel()
				}
				return Connected
			}
			out, err := inspectExistingService(ctx, "service-id", func(string) (inspectionConnection, error) {
				opened = true
				if stage == "after open" {
					cancel()
				}
				return f, nil
			}, validInterface)
			wantCloses := 1
			if !opened {
				wantCloses = 0
			}
			if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(out, ServiceInspection{}) || f.closes != wantCloses {
				t.Fatalf("cancel: %+v %v closes %d", out, err, f.closes)
			}
		})
	}
}
func TestDiagnosticConfigIsBoundedAndNotActivationPolicy(t *testing.T) {
	for _, gateway := range []string{"vpn.example.com", "vpn.example.com.", "10.0.0.1", "2001:db8::1"} {
		c := diagnosticConfig()
		c.Gateway = gateway
		if err := validateDiagnosticConfig(c, c.ServiceID); err != nil {
			t.Fatalf("valid %s: %v", gateway, err)
		}
	}
	for _, gateway := range []string{"", "https://vpn.example.com", "user@host", "host:443", "host\nsecret", "127.1", "2130706433", "::ffff:10.0.0.1", "fe80::1%en0", "127.0.0.1", "-host", "host..test", strings.Repeat("a", 128)} {
		c := diagnosticConfig()
		c.Gateway = gateway
		if err := validateDiagnosticConfig(c, c.ServiceID); err == nil {
			t.Fatalf("accepted %q", gateway)
		}
	}
	for _, auth := range [][]string{nil, {}, {"MSCHAP2", "MSCHAP2"}, {"unknown"}, {"PAP", "CHAP", "MSCHAP1", "MSCHAP2", "EAP", "PAP"}} {
		c := diagnosticConfig()
		c.PPPAuthentication = auth
		if err := validateDiagnosticConfig(c, c.ServiceID); err == nil {
			t.Fatalf("accepted protocols %v", auth)
		}
	}
	c := diagnosticConfig()
	c.IPSecAuthentication = "unknown"
	if validateDiagnosticConfig(c, c.ServiceID) == nil {
		t.Fatal("unknown IPsec method")
	}
}

func TestInspectCancellationSkipsLaterBackendOperations(t *testing.T) {
	stages := []string{"open", "config1", "status1", "generation1", "evidence", "lookup", "config2", "generation2", "status2"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// Any operation reached after a previous operation canceled is a failure.
			visit := func(name string) {
				if ctx.Err() != nil {
					t.Fatalf("called %s after cancellation at %s", name, stage)
				}
				if name == stage {
					cancel()
				}
			}
			f := diagnosticFake(Connected)
			configs, states, generations := 0, 0, 0
			f.config = func() (ServiceConfiguration, error) {
				configs++
				name := "config1"
				if configs == 2 {
					name = "config2"
				}
				visit(name)
				return diagnosticConfig(), nil
			}
			f.state = func() Status {
				states++
				name := "status1"
				if states == 2 {
					name = "status2"
				}
				visit(name)
				return Connected
			}
			f.generation = func() (int64, error) {
				generations++
				name := "generation1"
				if generations == 2 {
					name = "generation2"
				}
				visit(name)
				return 123, nil
			}
			old := f.evidence
			f.evidence = func() (systemEvidence, error) { visit("evidence"); return old() }
			lookup := func(name string) (observedInterface, error) { visit("lookup"); return validInterface(name) }
			out, err := inspectExistingService(ctx, "service-id", func(string) (inspectionConnection, error) { visit("open"); return f, nil }, lookup)
			if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(out, ServiceInspection{}) || f.closes != 1 {
				t.Fatalf("cancel result: %+v %v; closes %d", out, err, f.closes)
			}
		})
	}
}
