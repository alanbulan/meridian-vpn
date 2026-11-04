package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mygo-vpn/internal/windowsvpn"
	"runtime"
)

const probeUsage = `Read-only Windows RAS acceptance probe. This is not a VPN dialer.

Usage: meridian-ras-inspect --phonebook FILE --entry NAME --gateway HOST --acknowledge-service-start

Select one existing local fixed-drive .pbk and its exact entry name. Supply the
intended gateway independently, not by copying an untrusted entry's destination.
Loading RAS may start its Windows service, even for these read-only queries.
--acknowledge-service-start is required before any native inspection.

The JSON report omits names, paths, gateway values, handles and credentials.
Arguments can still appear in shell history and local process listings.
A successful probe only establishes the reported metadata observations. It does
not verify a usable tunnel, IPsec, routes/DNS, ownership, exclusivity or cleanup.
Dialing remains blocked regardless of the observed connection count.

No entries are enumerated automatically. No credentials are read or stored,
no VPN is dialed or disconnected, and no profiles or system settings are changed.
Native queries are synchronous and have no proven cancellation/time bound.
Exit codes: 0 observations completed, 1 unavailable/unverified/output failure,
2 parsing/missing-input errors or missing service-start acknowledgement.
Nonempty selections rejected by metadata validation return exit 1.
`

type probe struct {
	supported func() bool
	inspect   func(windowsvpn.PhonebookEntry, string) (windowsvpn.EntryEvidence, error)
	observe   func(windowsvpn.EntryEvidence) (windowsvpn.ConnectionSnapshot, error)
}

func newProbe() probe {
	return probe{
		supported: func() bool { return runtime.GOOS == "windows" },
		inspect:   windowsvpn.InspectSystemEntry,
		observe:   windowsvpn.ObserveSystemConnections,
	}
}

type probeReport struct {
	SchemaVersion                 int    `json:"schema_version"`
	ReadOnly                      bool   `json:"read_only"`
	ProfileMetadataVerified       bool   `json:"profile_metadata_verified"`
	ConnectionObservationVerified bool   `json:"connection_observation_verified"`
	ObservedConnections           *int   `json:"observed_connections,omitempty"`
	DialingAllowed                bool   `json:"dialing_allowed"`
	LiveTunnelVerified            bool   `json:"live_tunnel_verified"`
	NativeQuiescenceVerified      bool   `json:"native_quiescence_verified"`
	ErrorCode                     string `json:"error_code,omitempty"`
}

func (p probe) run(args []string, out, errOut io.Writer) int {
	f := flag.NewFlagSet("meridian-ras-inspect", flag.ContinueOnError)
	f.SetOutput(io.Discard) // Parser errors can include private arguments.
	phonebook := f.String("phonebook", "", "Exact local phonebook")
	entry := f.String("entry", "", "Exact entry name")
	gateway := f.String("gateway", "", "Independently supplied intended gateway")
	acknowledge := f.Bool("acknowledge-service-start", false, "Acknowledge RAS service startup")
	if len(args) == 0 {
		return probeWriteText(out, errOut, probeUsage)
	}
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return probeWriteText(out, errOut, probeUsage)
		}
		return probeUsageError(errOut)
	}
	if f.NArg() != 0 || *phonebook == "" || *entry == "" || *gateway == "" || !*acknowledge {
		return probeUsageError(errOut)
	}
	report := probeReport{SchemaVersion: 1, ReadOnly: true}
	if p.supported == nil || !p.supported() {
		report.ErrorCode = "windows_required"
		return probeWriteReport(out, errOut, report, 1)
	}
	if p.inspect == nil || p.observe == nil {
		report.ErrorCode = "probe_unavailable"
		return probeWriteReport(out, errOut, report, 1)
	}
	evidence, err := p.inspect(windowsvpn.PhonebookEntry{Name: *entry, PhonebookPath: *phonebook}, *gateway)
	if err != nil {
		report.ErrorCode = "profile_unverified"
		return probeWriteReport(out, errOut, report, 1)
	}
	report.ProfileMetadataVerified = true
	snapshot, err := p.observe(evidence)
	if err != nil {
		report.ErrorCode = "connection_observation_unverified"
		return probeWriteReport(out, errOut, report, 1)
	}
	// Even a zero-value or empty snapshot cannot grant dial permission. Do not
	// derive readiness from success, count, owner-match flags or a callback.
	if snapshot.DialBlocker() == nil {
		report.ErrorCode = "unexpected_dial_permission"
		return probeWriteReport(out, errOut, report, 1)
	}
	count := snapshot.ObservedConnections()
	report.ObservedConnections = &count
	report.ConnectionObservationVerified = true
	return probeWriteReport(out, errOut, report, 0)
}

func probeUsageError(errOut io.Writer) int {
	if _, err := fmt.Fprintln(errOut, "Exact phonebook, entry, intended gateway and service-start acknowledgement are required. Run with --help."); err != nil {
		return 1
	}
	return 2
}

func probeWriteText(out, errOut io.Writer, text string) int {
	if _, err := io.WriteString(out, text); err != nil {
		_, _ = fmt.Fprintln(errOut, "Could not write probe output.")
		return 1
	}
	return 0
}

func probeWriteReport(out, errOut io.Writer, report probeReport, code int) int {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		_, _ = fmt.Fprintln(errOut, "Could not write probe output.")
		return 1
	}
	return code
}
