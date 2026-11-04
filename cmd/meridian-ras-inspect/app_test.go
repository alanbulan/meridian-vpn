package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"mygo-vpn/internal/windowsvpn"
	"strings"
	"testing"
)

var probeArgs = []string{"--phonebook", `C:\private-org\private-phonebook.pbk`, "--entry", "private-entry", "--gateway", "private.example.test", "--acknowledge-service-start"}

func fakeProbe(t *testing.T) probe {
	t.Helper()
	return probe{
		supported: func() bool { return true },
		inspect: func(windowsvpn.PhonebookEntry, string) (windowsvpn.EntryEvidence, error) {
			t.Fatal("unexpected native inspection boundary")
			return windowsvpn.EntryEvidence{}, nil
		},
		observe: func(windowsvpn.EntryEvidence) (windowsvpn.ConnectionSnapshot, error) {
			t.Fatal("unexpected native observation boundary")
			return windowsvpn.ConnectionSnapshot{}, nil
		},
	}
}

func runProbe(p probe, args []string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := p.run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func assertProbeRedacted(t *testing.T, output string) {
	t.Helper()
	for _, marker := range []string{"private-org", "private-phonebook", "private-entry", "private.example.test", "private-api-error"} {
		if strings.Contains(output, marker) {
			t.Fatal("private input or native error disclosed")
		}
	}
}

func decodeProbeReport(t *testing.T, out string) probeReport {
	t.Helper()
	var report probeReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal("invalid JSON report")
	}
	if report.SchemaVersion != 1 || !report.ReadOnly || report.DialingAllowed || report.LiveTunnelVerified || report.NativeQuiescenceVerified {
		t.Fatal("probe implied unsafe or unverified capabilities")
	}
	return report
}

func TestProbeHelpNeverTouchesHost(t *testing.T) {
	p := fakeProbe(t)
	p.supported = func() bool { t.Fatal("help checked host"); return false }
	for _, args := range [][]string{nil, {"--help"}, {"-h"}} {
		code, out, errOut := runProbe(p, args)
		if code != 0 || out != probeUsage || errOut != "" {
			t.Fatal("help failed")
		}
	}
}

func TestProbeRequiresExplicitInputsAndAcknowledgement(t *testing.T) {
	for _, args := range [][]string{
		probeArgs[:len(probeArgs)-1],
		{"--acknowledge-service-start"},
		{"--phonebook", "private-phonebook", "--entry", "private-entry", "--acknowledge-service-start"},
		{"--gateway", "private.example.test", "--entry", "private-entry", "--acknowledge-service-start"},
		{"--unknown-private-api-error"},
		append(append([]string{}, probeArgs...), "private-api-error"),
		append(append([]string{}, probeArgs...), "--acknowledge-service-start=false"),
		append(append([]string{}, probeArgs...), "--acknowledge-service-start=private-api-error"),
	} {
		p := fakeProbe(t)
		p.supported = func() bool { t.Fatal("invalid args checked host"); return false }
		code, out, errOut := runProbe(p, args)
		if code != 2 || out != "" || errOut == "" {
			t.Fatal("invalid or unacknowledged probe accepted")
		}
		assertProbeRedacted(t, out+errOut)
	}
}

func TestProbeUnsupportedPlatformNeverCallsNativeBoundary(t *testing.T) {
	p := fakeProbe(t)
	p.supported = func() bool { return false }
	code, out, errOut := runProbe(p, probeArgs)
	report := decodeProbeReport(t, out)
	if code != 1 || report.ErrorCode != "windows_required" || report.ProfileMetadataVerified || report.ObservedConnections != nil || errOut != "" {
		t.Fatal("unsupported platform report incorrect")
	}
	assertProbeRedacted(t, out)
}

func TestProbeRedactsNativeErrorsAndRetainsPartialEvidence(t *testing.T) {
	for _, failInspect := range []bool{true, false} {
		p := fakeProbe(t)
		p.inspect = func(windowsvpn.PhonebookEntry, string) (windowsvpn.EntryEvidence, error) {
			if failInspect {
				return windowsvpn.EntryEvidence{}, errors.New("private-api-error")
			}
			return windowsvpn.EntryEvidence{}, nil
		}
		p.observe = func(windowsvpn.EntryEvidence) (windowsvpn.ConnectionSnapshot, error) {
			if failInspect {
				t.Fatal("observed after failed profile inspection")
			}
			return windowsvpn.ConnectionSnapshot{}, errors.New("private-api-error")
		}
		code, out, errOut := runProbe(p, probeArgs)
		report := decodeProbeReport(t, out)
		if code != 1 || report.ErrorCode == "" || report.ProfileMetadataVerified == failInspect || report.ConnectionObservationVerified || report.ObservedConnections != nil {
			t.Fatal("failure represented as success")
		}
		assertProbeRedacted(t, out+errOut)
	}
}

func TestProbePassesExactSelectionAndNeverAllowsDialing(t *testing.T) {
	p := fakeProbe(t)
	inspections, observations := 0, 0
	p.inspect = func(entry windowsvpn.PhonebookEntry, gateway string) (windowsvpn.EntryEvidence, error) {
		inspections++
		if entry.PhonebookPath != probeArgs[1] || entry.Name != probeArgs[3] || gateway != probeArgs[5] {
			t.Fatal("selection or independent gateway changed")
		}
		return windowsvpn.EntryEvidence{}, nil
	}
	p.observe = func(windowsvpn.EntryEvidence) (windowsvpn.ConnectionSnapshot, error) {
		observations++
		return windowsvpn.ConnectionSnapshot{}, nil
	}
	code, out, errOut := runProbe(p, probeArgs)
	report := decodeProbeReport(t, out)
	if code != 0 || errOut != "" || inspections != 1 || observations != 1 || !report.ProfileMetadataVerified || !report.ConnectionObservationVerified || report.ObservedConnections == nil || *report.ObservedConnections != 0 || report.ErrorCode != "" {
		t.Fatal("observation report failed")
	}
	assertProbeRedacted(t, out)
}

type brokenProbeWriter struct{}

func (brokenProbeWriter) Write([]byte) (int, error) { return 0, errors.New("private-api-error") }

func TestProbeOutputFailuresAreRedacted(t *testing.T) {
	for _, args := range [][]string{nil, probeArgs} {
		p := fakeProbe(t)
		p.supported = func() bool { return false }
		var errOut bytes.Buffer
		if p.run(args, brokenProbeWriter{}, &errOut) != 1 {
			t.Fatal("output failure reported success")
		}
		assertProbeRedacted(t, errOut.String())
	}
	if fakeProbe(t).run([]string{"--unknown-private-api-error"}, &bytes.Buffer{}, brokenProbeWriter{}) != 1 {
		t.Fatal("usage output failure reported usage success")
	}
}

func TestProbeMissingBoundariesFailClosed(t *testing.T) {
	for _, missingInspect := range []bool{true, false} {
		p := fakeProbe(t)
		if missingInspect {
			p.inspect = nil
		} else {
			p.observe = nil
		}
		code, out, errOut := runProbe(p, probeArgs)
		report := decodeProbeReport(t, out)
		if code != 1 || report.ErrorCode != "probe_unavailable" || report.ProfileMetadataVerified || errOut != "" {
			t.Fatal("missing native boundary accepted")
		}
	}
}
