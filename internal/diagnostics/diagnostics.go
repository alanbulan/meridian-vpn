// Package diagnostics produces a bounded, support-safe, read-only readiness
// report. It never authenticates, enumerates connections, or changes networking.
package diagnostics

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mygo-vpn/internal/core"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	Available      = "available"
	Missing        = "missing"
	Unavailable    = "unavailable"
	NotChecked     = "not_checked"
	Unsupported    = "unsupported"
	MaxProbeOutput = 4096
	MaxPluginBytes = 64 << 10
	ProbeTimeout   = 3 * time.Second
)

// Check messages are fixed strings, never raw errors or subprocess output.
type Check struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Message  string `json:"message"`
	Optional bool   `json:"optional,omitempty"`
}

type Platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

type Application struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Backend struct {
	Name                         string   `json:"name"`
	Protocol                     string   `json:"protocol"`
	PrerequisitesAvailable       bool     `json:"prerequisites_available"`
	ConnectionTested             bool     `json:"connection_tested"`
	RequiresNetworkAuthorization bool     `json:"requires_network_authorization"`
	Blockers                     []string `json:"blockers"`
}

// Report deliberately has no profile, filesystem path, username, IP, hostname,
// environment, or raw command-output fields. Safe to inspect before connecting.
type Report struct {
	SchemaVersion int         `json:"schema_version"`
	ReadOnly      bool        `json:"read_only"`
	Application   Application `json:"application"`
	Platform      Platform    `json:"platform"`
	Backend       Backend     `json:"backend"`
	Checks        []Check     `json:"checks"`
}

// Collector dependencies are injectable so tests cannot alter host networking.
// Run is invoked only for nmcli's read-only RUNNING status. ReadFile is invoked
// only for the three standard NetworkManager plugin descriptors below. The MFA
// check reuses core's bounded protocol probe and sibling/PATH discovery rules.
type Collector struct {
	OS            string
	Architecture  string
	Version       string
	LookPath      func(string) (string, error)
	ReadFile      func(string, int64) ([]byte, error)
	Run           func(context.Context, string, []string) ([]byte, error)
	MFACapability func() core.Capability
}

// Collect performs no network request and needs neither root nor a GUI session.
func Collect(ctx context.Context, version string) Report {
	return Collector{OS: runtime.GOOS, Architecture: runtime.GOARCH, Version: version,
		LookPath: exec.LookPath, ReadFile: readBoundedFile, Run: runBounded}.Collect(ctx)
}

func (c Collector) Collect(ctx context.Context) Report {
	r := Report{SchemaVersion: 1, ReadOnly: true,
		Application: Application{Name: "Meridian", Version: safeToken(c.Version)},
		Platform:    Platform{OS: safeToken(c.OS), Architecture: safeToken(c.Architecture)},
		Backend:     Backend{Name: "networkmanager-openconnect", Protocol: "anyconnect", RequiresNetworkAuthorization: true, Blockers: []string{}},
		Checks:      []Check{},
	}
	add := func(id, status, message string, blocker bool) {
		r.Checks = append(r.Checks, Check{ID: id, Status: status, Message: message})
		if blocker {
			r.Backend.Blockers = append(r.Backend.Blockers, id)
		}
	}
	if c.OS != "linux" {
		add("platform", Unsupported, "Live VPN currently requires Linux; this platform supports configuration workflows only.", true)
		r.Checks = append(r.Checks, Check{ID: "interactive_auth_helper", Status: Unsupported, Optional: true, Message: "The optional interactive authentication helper currently requires Linux."})
		return r
	}
	add("platform", Available, "Linux is supported by the NetworkManager AnyConnect backend.", false)
	lookPath := c.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	paths := map[string]string{}
	for _, name := range []string{"nmcli", "openconnect"} {
		path, err := lookPath(name)
		if err != nil || !filepath.IsAbs(path) {
			add(name, Missing, "Required executable was not found at an absolute path.", true)
		} else {
			paths[name] = path
			add(name, Available, "Required executable was found; its version and gateway compatibility have not been tested.", false)
		}
	}
	readFile := c.ReadFile
	if readFile == nil {
		readFile = readBoundedFile
	}
	plugin := false
	for _, path := range []string{
		"/usr/lib/NetworkManager/VPN/nm-openconnect-service.name",
		"/usr/lib64/NetworkManager/VPN/nm-openconnect-service.name",
		"/usr/share/NetworkManager/VPN/nm-openconnect-service.name",
	} {
		data, err := readFile(path, MaxPluginBytes)
		if err == nil && len(data) <= MaxPluginBytes && bytes.Contains(data, []byte("org.freedesktop.NetworkManager.openconnect")) {
			plugin = true
			break
		}
	}
	if plugin {
		add("networkmanager_openconnect_plugin", Available, "NetworkManager OpenConnect plugin descriptor was found.", false)
	} else {
		add("networkmanager_openconnect_plugin", Missing, "A supported NetworkManager OpenConnect plugin descriptor was not found.", true)
	}
	if paths["nmcli"] == "" {
		add("networkmanager_service", NotChecked, "Service status cannot be checked without nmcli.", true)
	} else {
		run := c.Run
		if run == nil {
			run = runBounded
		}
		probeCtx, cancel := context.WithTimeout(ctx, ProbeTimeout)
		out, err := run(probeCtx, paths["nmcli"], []string{"-t", "-f", "RUNNING", "general"})
		cancel()
		if err == nil && len(out) <= MaxProbeOutput && strings.TrimSpace(string(out)) == "running" {
			add("networkmanager_service", Available, "NetworkManager reports that its service is running.", false)
		} else {
			add("networkmanager_service", Unavailable, "NetworkManager did not confirm its service is running within the bounded read-only check.", true)
		}
	}
	r.Backend.PrerequisitesAvailable = len(r.Backend.Blockers) == 0
	optional := Check{ID: "interactive_auth_helper", Status: NotChecked, Optional: true, Message: "Optional interactive authentication helper check was canceled; basic backend readiness is unaffected."}
	if ctx.Err() == nil {
		capability := c.MFACapability
		if capability == nil {
			capability = func() core.Capability { return core.NewMFAHelper().Capability() }
		}
		// Only the boolean is retained: core's executable path and any future
		// capability message must never enter this support-safe report.
		if capability().Available {
			optional.Status = Available
			optional.Message = "Optional interactive authentication helper passed its protocol probe; gateway MFA compatibility has not been tested."
		} else {
			optional.Status = Unavailable
			optional.Message = "Optional interactive authentication helper is unavailable or incompatible. Profiles with interactive_auth enabled require it; basic backend readiness is unaffected."
		}
	}
	r.Checks = append(r.Checks, optional)
	add("gateway_authentication", NotChecked, "No gateway contact or authentication was attempted.", false)
	add("tunnel_routes_dns", NotChecked, "No tunnel, route, DNS, authorization policy, or leak test was attempted.", false)
	return r
}

func safeToken(value string) string {
	if value == "" || len(value) > 64 {
		return "unknown"
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._+-", r)) {
			return "unknown"
		}
	}
	return value
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > limit {
		return nil, errors.New("plugin descriptor unavailable")
	}
	f, err := openDescriptor(path)
	if err != nil {
		return nil, errors.New("plugin descriptor unavailable")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(st, opened) || opened.Size() > limit {
		return nil, errors.New("plugin descriptor unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("plugin descriptor unavailable")
	}
	return data, nil
}

type boundedOutput struct {
	buffer bytes.Buffer
	cancel context.CancelFunc
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.buffer.Len()+len(p) > MaxProbeOutput {
		b.cancel()
		return 0, errors.New("diagnostic output exceeded limit")
	}
	return b.buffer.Write(p)
}

func runBounded(ctx context.Context, path string, args []string) ([]byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	// Never pass inherited secrets or mutable locale/bus overrides to probes.
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	out := &boundedOutput{cancel: cancel}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 250 * time.Millisecond
	if err := cmd.Run(); err != nil {
		return nil, errors.New("read-only diagnostic probe failed")
	}
	return out.buffer.Bytes(), nil
}
