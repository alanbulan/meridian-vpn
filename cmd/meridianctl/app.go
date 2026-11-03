package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mygo-vpn/internal/core"
	"mygo-vpn/internal/diagnostics"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

const usage = `Meridian CLI: configuration, readiness checks and Linux foreground VPN.

Usage: meridianctl [--config FILE] COMMAND

Commands:
  connect --profile INDEX --authorize-network --credentials-stdin
      Linux foreground VPN. Read credentials from a private non-terminal stdin
      JSON stream. Ctrl+C/SIGTERM disconnects only this process-owned session.
      Requires explicit permission for gateway authentication and routes/DNS.
  profiles list [--json] [--show-private]
      List profile indexes and configured feature flags. Names, IDs, gateways,
      accounts and local paths are hidden unless --show-private is requested.
  validate [--json] [--check-files]
      Validate the existing Meridian config. --check-files also checks local
      CA/client certificate/key files, without sending data to a gateway.
  diagnostics [--json]
      Read-only platform/dependency/service and optional MFA-helper report.
      Never contacts a gateway; missing optional MFA does not block basic VPN.
  profiles import --file FILE [--output NEW_FILE] [--json]
      Preview a deduplicated merge. --output saves a NEW merged config, leaving
      the active config unchanged. Review it, then open the GUI with --config.
  profiles preview-ini --file FILE [--json]
      Inspect INI structure only, hiding all names and values; does not import
      or infer vendor schema/protocol compatibility.
  profiles export --output NEW_FILE [--profile INDEX]
      Export all profiles or one 1-based index as private Meridian JSON.
      Export contains gateways/accounts/local paths, but no passwords or keys.
  version
  help

Files must be Meridian versioned JSON, not UniVPN proprietary configuration.
Output files are created with mode 0600 and existing files are never replaced.
Only connect authenticates and changes routes/DNS after explicit authorization.
Other commands remain offline/read-only. No command installs software.
Diagnostics checks prerequisites only, not enterprise compatibility.
Exit codes: 0 success/ready, 1 invalid/unavailable/failure, 2 usage error.
`

type application struct {
	version     string
	configDir   func() (string, error)
	diagnostics func(context.Context, string) diagnostics.Report
	vpnSupported func() bool
	vpnAdapter func() core.Adapter
	credentials func(context.Context) (core.Credentials, error)
}

func newApplication() application {
	return application{
		version: version, configDir: os.UserConfigDir, diagnostics: diagnostics.Collect,
		vpnSupported: foregroundVPNSupported,
		vpnAdapter: func() core.Adapter { return core.NewNetworkManager() },
		credentials: func(ctx context.Context) (core.Credentials, error) { return readCredentialInput(ctx, os.Stdin) },
	}
}

func (a application) run(ctx context.Context, args []string, out, errOut io.Writer) int {
	f := flag.NewFlagSet("meridianctl", flag.ContinueOnError)
	f.SetOutput(io.Discard) // Flag errors can quote sensitive arguments.
	configPath := f.String("config", "", "Meridian configuration file")
	showVersion := f.Bool("version", false, "Print application version")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(out, usage)
			return 0
		}
		return usageError(errOut)
	}
	if *showVersion {
		if len(f.Args()) != 0 {
			return usageError(errOut)
		}
		_, err := fmt.Fprintf(out, "Meridian CLI %s\n", a.version)
		return outputResult(err, errOut)
	}
	args = f.Args()
	if len(args) == 0 || args[0] == "help" {
		if len(args) > 1 {
			return usageError(errOut)
		}
		_, err := io.WriteString(out, usage)
		return outputResult(err, errOut)
	}
	if args[0] == "version" {
		if len(args) != 1 {
			return usageError(errOut)
		}
		_, err := fmt.Fprintf(out, "Meridian CLI %s\n", a.version)
		return outputResult(err, errOut)
	}
	if len(args) >= 2 && args[0] == "profiles" && args[1] == "preview-ini" {
		return a.previewINI(args[2:], out, errOut)
	}
	if args[0] == "diagnostics" {
		return a.diagnose(ctx, args[1:], out, errOut)
	}
	if args[0] != "profiles" && args[0] != "validate" && args[0] != "connect" {
		return usageError(errOut)
	}
	if *configPath == "" {
		base, err := a.configDir()
		if err != nil {
			return failure(errOut, "Cannot locate the configuration directory; pass --config FILE.")
		}
		*configPath = filepath.Join(base, "meridian", "profiles.json")
	}
	if args[0] == "connect" {
		return a.connect(ctx, *configPath, args[1:], out, errOut)
	}
	if args[0] == "validate" {
		return a.validate(*configPath, args[1:], out, errOut)
	}
	if len(args) < 2 {
		return usageError(errOut)
	}
	switch args[1] {
	case "list":
		return a.list(*configPath, args[2:], out, errOut)
	case "import":
		return a.importProfiles(*configPath, args[2:], out, errOut)
	case "export":
		return a.exportProfiles(*configPath, args[2:], out, errOut)
	default:
		return usageError(errOut)
	}
}

func newFlags(name string) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	return f
}

func parseFlags(f *flag.FlagSet, args []string) bool { return f.Parse(args) == nil && f.NArg() == 0 }
func usageError(out io.Writer) int {
	_, _ = fmt.Fprintln(out, "Invalid arguments. Run meridianctl help for usage.")
	return 2
}
func failure(out io.Writer, message string) int { _, _ = fmt.Fprintln(out, message); return 1 }
func outputResult(err error, errOut io.Writer) int {
	if err != nil {
		return failure(errOut, "Could not write the command output.")
	}
	return 0
}
func writeJSON(out io.Writer, value any) error {
	e := json.NewEncoder(out)
	e.SetIndent("", "  ")
	return e.Encode(value)
}

func loadConfig(path string) (core.Config, bool, error) {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return core.Config{Version: 1, Profiles: []core.Profile{}}, false, nil
	}
	if err != nil || !st.Mode().IsRegular() {
		return core.Config{}, false, errors.New("configuration is unreadable or not a regular file")
	}
	cfg, err := (core.Store{Path: path}).Load()
	if err != nil {
		return core.Config{}, true, errors.New("configuration is invalid; check the Meridian JSON schema and supported field values")
	}
	return cfg, true, nil
}

type listedProfile struct {
	Index                       int           `json:"index"`
	Selected                    bool          `json:"selected"`
	Protocol                    string        `json:"protocol"`
	GatewayConfigured           bool          `json:"gateway_configured"`
	UsernameConfigured          bool          `json:"username_configured"`
	AuthGroupConfigured         bool          `json:"auth_group_configured"`
	CustomCAConfigured          bool          `json:"custom_ca_configured"`
	ProxyConfigured             bool          `json:"proxy_configured"`
	ClientCertificateConfigured bool          `json:"client_certificate_configured"`
	ClientKeyConfigured         bool          `json:"client_key_configured"`
	AdditionalGatewayCount      int           `json:"additional_gateway_count"`
	InteractiveAuth             bool          `json:"interactive_auth"`
	TCPOnly                     bool          `json:"tcp_only"`
	MTU                         int           `json:"mtu"`
	Private                     *core.Profile `json:"private,omitempty"`
}

func (a application) list(path string, args []string, out, errOut io.Writer) int {
	f := newFlags("profiles list")
	jsonOutput := f.Bool("json", false, "JSON output")
	showPrivate := f.Bool("show-private", false, "Include private profile fields")
	if !parseFlags(f, args) {
		return usageError(errOut)
	}
	cfg, exists, err := loadConfig(path)
	if err != nil {
		return failure(errOut, err.Error())
	}
	profiles := make([]listedProfile, 0, len(cfg.Profiles))
	for i, p := range cfg.Profiles {
		summary := listedProfile{Index: i + 1, Selected: p.ID == cfg.SelectedID, Protocol: p.Protocol,
			GatewayConfigured: p.Gateway != "", UsernameConfigured: p.Username != "", AuthGroupConfigured: p.AuthGroup != "",
			CustomCAConfigured: p.CAFile != "", ProxyConfigured: p.ProxyURL != "", ClientCertificateConfigured: p.ClientCertificate != "",
			ClientKeyConfigured: p.ClientKey != "", AdditionalGatewayCount: len(p.AdditionalGateways), InteractiveAuth: p.InteractiveAuth, TCPOnly: p.DisableUDP, MTU: p.MTU}
		if *showPrivate {
			p.AllowProxySystemAuth = false
			summary.Private = &p
		}
		profiles = append(profiles, summary)
	}
	if *jsonOutput {
		return outputResult(writeJSON(out, struct {
			SchemaVersion int             `json:"schema_version"`
			ConfigExists  bool            `json:"config_exists"`
			Redacted      bool            `json:"redacted"`
			Profiles      []listedProfile `json:"profiles"`
		}{1, exists, !*showPrivate, profiles}), errOut)
	}
	var b strings.Builder
	if !exists {
		b.WriteString("No configuration file exists; no profiles are configured.\n")
	} else if len(profiles) == 0 {
		b.WriteString("No profiles are configured.\n")
	}
	for _, p := range profiles {
		fmt.Fprintf(&b, "%d  protocol=%s selected=%t username=%t client_certificate=%t interactive_auth=%t proxy=%t additional_gateways=%d tcp_only=%t mtu=%d\n", p.Index, p.Protocol, p.Selected, p.UsernameConfigured, p.ClientCertificateConfigured, p.InteractiveAuth, p.ProxyConfigured, p.AdditionalGatewayCount, p.TCPOnly, p.MTU)
		if p.Private != nil {
			data, err := json.Marshal(p.Private)
			if err != nil {
				return failure(errOut, "Could not format private profile fields.")
			}
			fmt.Fprintf(&b, "   private=%s\n", data)
		}
	}
	if !*showPrivate {
		b.WriteString("Private fields are hidden. Use --show-private only when needed locally.\n")
	}
	_, err = io.WriteString(out, b.String())
	return outputResult(err, errOut)
}

type validationIssue struct {
	ProfileIndex int    `json:"profile_index,omitempty"`
	Code         string `json:"code"`
	Message      string `json:"message"`
}

type validationReport struct {
	SchemaVersion           int               `json:"schema_version"`
	Valid                   bool              `json:"valid"`
	ProfileCount            int               `json:"profile_count"`
	CertificateFilesChecked bool              `json:"certificate_files_checked"`
	Issues                  []validationIssue `json:"issues"`
}

func (a application) validate(path string, args []string, out, errOut io.Writer) int {
	f := newFlags("validate")
	jsonOutput := f.Bool("json", false, "JSON output")
	checkFiles := f.Bool("check-files", false, "Check local certificate files")
	if !parseFlags(f, args) {
		return usageError(errOut)
	}
	r := validationReport{SchemaVersion: 1, Issues: []validationIssue{}}
	cfg, exists, err := loadConfig(path)
	switch {
	case err != nil:
		r.Issues = append(r.Issues, validationIssue{Code: "invalid_config", Message: "Configuration is unreadable or invalid; check the Meridian schema and supported field values."})
	case !exists:
		r.Issues = append(r.Issues, validationIssue{Code: "missing_config", Message: "No configuration file exists."})
	default:
		r.ProfileCount = len(cfg.Profiles)
		r.CertificateFilesChecked = *checkFiles
		if *checkFiles {
			for i, p := range cfg.Profiles {
				if core.ValidateCAFile(p.CAFile) != nil {
					r.Issues = append(r.Issues, validationIssue{i + 1, "invalid_ca_file", "CA certificate file did not pass local validation."})
				}
				if core.ValidateClientCertificate(p) != nil {
					r.Issues = append(r.Issues, validationIssue{i + 1, "invalid_client_certificate", "Client certificate/key files did not pass local validation."})
				}
			}
		}
	}
	r.Valid = len(r.Issues) == 0
	if *jsonOutput {
		err = writeJSON(out, r)
	} else {
		var b strings.Builder
		if r.Valid {
			fmt.Fprintf(&b, "Configuration is valid: %d profile(s).\n", r.ProfileCount)
		}
		for _, issue := range r.Issues {
			if issue.ProfileIndex != 0 {
				fmt.Fprintf(&b, "Profile %d: ", issue.ProfileIndex)
			}
			fmt.Fprintln(&b, issue.Message)
		}
		if r.Valid {
			b.WriteString("This checks local configuration only, not gateway compatibility or connection success.\n")
		}
		_, err = io.WriteString(out, b.String())
	}
	if outputResult(err, errOut) != 0 || !r.Valid {
		return 1
	}
	return 0
}

func (a application) diagnose(ctx context.Context, args []string, out, errOut io.Writer) int {
	f := newFlags("diagnostics")
	jsonOutput := f.Bool("json", false, "JSON output")
	if !parseFlags(f, args) {
		return usageError(errOut)
	}
	r := a.diagnostics(ctx, a.version)
	var err error
	if *jsonOutput {
		err = writeJSON(out, r)
	} else {
		var b strings.Builder
		fmt.Fprintf(&b, "Meridian %s · %s/%s\n", r.Application.Version, r.Platform.OS, r.Platform.Architecture)
		for _, check := range r.Checks {
			fmt.Fprintf(&b, "%s: %s. %s\n", check.ID, check.Status, check.Message)
		}
		b.WriteString("Read-only report. No gateway authentication, tunnel, route or DNS changes were attempted.\n")
		_, err = io.WriteString(out, b.String())
	}
	if outputResult(err, errOut) != 0 || !r.Backend.PrerequisitesAvailable {
		return 1
	}
	return 0
}

func (a application) importProfiles(path string, args []string, out, errOut io.Writer) int {
	f := newFlags("profiles import")
	input := f.String("file", "", "Input Meridian JSON")
	output := f.String("output", "", "Write a new merged config")
	jsonOutput := f.Bool("json", false, "JSON output")
	if !parseFlags(f, args) || *input == "" {
		return usageError(errOut)
	}
	cfg, _, err := loadConfig(path)
	if err != nil {
		return failure(errOut, err.Error())
	}
	imported, exists, err := loadConfig(*input)
	if err != nil || !exists {
		return failure(errOut, "Import file is missing, unreadable or invalid Meridian JSON.")
	}
	added, duplicates := 0, 0
	for _, p := range imported.Profiles {
		duplicate := false
		for _, existing := range cfg.Profiles {
			x, y := p, existing
			x.ID, y.ID = "", ""
			x.AllowProxySystemAuth, y.AllowProxySystemAuth = false, false
			if reflect.DeepEqual(x, y) {
				duplicate = true
				break
			}
		}
		if duplicate {
			duplicates++
			continue
		}
		p.ID, p.AllowProxySystemAuth = core.NewID(), false
		if cfg.Upsert(p) != nil {
			return failure(errOut, "Import would exceed the profile limit or contains an unsupported profile.")
		}
		added++
	}
	if *output != "" {
		if samePath(*output, path) || samePath(*output, *input) {
			return failure(errOut, "Merged output must be a new file, not the active config or import source.")
		}
		if saveNewConfig(*output, cfg) != nil {
			return failure(errOut, "Could not create the merged config. Output must be new and its parent directory must already exist.")
		}
	}
	if *jsonOutput {
		return outputResult(writeJSON(out, struct {
			SchemaVersion       int  `json:"schema_version"`
			Added               int  `json:"added"`
			Duplicates          int  `json:"duplicates"`
			Total               int  `json:"total"`
			Saved               bool `json:"saved"`
			ActiveConfigChanged bool `json:"active_config_changed"`
		}{1, added, duplicates, len(cfg.Profiles), *output != "", false}), errOut)
	}
	_, err = fmt.Fprintf(out, "Import preview: %d new, %d duplicate, %d total profile(s). Active config is unchanged.\n", added, duplicates, len(cfg.Profiles))
	if err == nil && *output != "" {
		_, err = fmt.Fprintln(out, "Merged config saved as a new private file. Review before opening the GUI with --config FILE.")
	}
	if err == nil && *output == "" {
		_, err = fmt.Fprintln(out, "Nothing was written. Pass --output NEW_FILE to save the merged config.")
	}
	return outputResult(err, errOut)
}

func (a application) exportProfiles(path string, args []string, out, errOut io.Writer) int {
	f := newFlags("profiles export")
	output := f.String("output", "", "New output file")
	index := f.Int("profile", 0, "One-based profile index; omitted means all")
	if !parseFlags(f, args) || *output == "" || *index < 0 {
		return usageError(errOut)
	}
	cfg, exists, err := loadConfig(path)
	if err != nil || !exists {
		return failure(errOut, "Cannot export a missing, unreadable or invalid config.")
	}
	if samePath(path, *output) {
		return failure(errOut, "Export cannot replace the active configuration.")
	}
	if *index > len(cfg.Profiles) {
		return failure(errOut, "Profile index does not exist. Use profiles list to see current indexes.")
	}
	if *index != 0 {
		cfg.Profiles = []core.Profile{cfg.Profiles[*index-1]}
		cfg.SelectedID = cfg.Profiles[0].ID
	}
	cfg.Settings = core.Settings{}
	for i := range cfg.Profiles {
		cfg.Profiles[i].AllowProxySystemAuth = false
	}
	if saveNewConfig(*output, cfg) != nil {
		return failure(errOut, "Could not create the export. Output must be new and its parent directory must already exist.")
	}
	_, err = fmt.Fprintf(out, "Exported %d profile(s) to a new private file. It contains gateways, accounts and local certificate paths; share carefully.\n", len(cfg.Profiles))
	return outputResult(err, errOut)
}
