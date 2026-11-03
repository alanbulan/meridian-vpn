package diagnostics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mygo-vpn/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func readyCollector() Collector {
	return Collector{OS: "linux", Architecture: "amd64", Version: "0.2.0-test",
		LookPath: func(name string) (string, error) { return filepath.Join(os.TempDir(), "meridian-test-bin", name), nil },
		ReadFile: func(string, int64) ([]byte, error) {
			return []byte("service=org.freedesktop.NetworkManager.openconnect\n"), nil
		},
		Run:           func(context.Context, string, []string) ([]byte, error) { return []byte("running\n"), nil },
		MFACapability: func() core.Capability { return core.Capability{} },
	}
}

func checkByID(t *testing.T, r Report, id string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("missing check %q", id)
	return Check{}
}

func TestReadinessUsesOnlyBoundedReadOnlyProbe(t *testing.T) {
	c := readyCollector()
	calls := 0
	c.Run = func(ctx context.Context, path string, args []string) ([]byte, error) {
		calls++
		if path != filepath.Join(os.TempDir(), "meridian-test-bin", "nmcli") || !reflect.DeepEqual(args, []string{"-t", "-f", "RUNNING", "general"}) {
			t.Fatalf("unexpected probe: %q %q", path, args)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > ProbeTimeout {
			t.Fatal("probe does not have a bounded deadline")
		}
		return []byte("running\n"), nil
	}
	c.ReadFile = func(path string, limit int64) ([]byte, error) {
		if path != "/usr/lib/NetworkManager/VPN/nm-openconnect-service.name" || limit != MaxPluginBytes {
			t.Fatal("unexpected file probe")
		}
		return []byte("service=org.freedesktop.NetworkManager.openconnect"), nil
	}
	r := c.Collect(context.Background())
	if !r.ReadOnly || !r.Backend.PrerequisitesAvailable || r.Backend.ConnectionTested || !r.Backend.RequiresNetworkAuthorization || len(r.Backend.Blockers) != 0 || calls != 1 {
		t.Fatalf("incorrect readiness: %+v", r)
	}
	if checkByID(t, r, "gateway_authentication").Status != NotChecked || checkByID(t, r, "tunnel_routes_dns").Status != NotChecked {
		t.Fatal("unperformed operations claimed")
	}
}

func TestUnsupportedPlatformDoesNotProbe(t *testing.T) {
	for _, goos := range []string{"darwin", "windows", "unknown"} {
		c := readyCollector()
		c.OS = goos
		c.MFACapability = func() core.Capability {
			t.Fatal("unsupported platform must not probe an MFA helper")
			return core.Capability{}
		}
		c.LookPath = func(string) (string, error) { t.Fatal("unsupported platform must not run probes"); return "", nil }
		c.ReadFile = func(string, int64) ([]byte, error) {
			t.Fatal("unsupported platform must not read plugin descriptors")
			return nil, nil
		}
		c.Run = func(context.Context, string, []string) ([]byte, error) {
			t.Fatal("unsupported platform must not run subprocesses")
			return nil, nil
		}
		r := c.Collect(context.Background())
		if r.Backend.PrerequisitesAvailable || !reflect.DeepEqual(r.Backend.Blockers, []string{"platform"}) {
			t.Fatalf("unsupported platform marked ready: %+v", r)
		}
	}
}

func TestOptionalMFAReadinessNeverBlocksBasicBackendOrLeaksDetails(t *testing.T) {
	for _, available := range []bool{false, true} {
		c := readyCollector()
		calls := 0
		c.MFACapability = func() core.Capability {
			calls++
			return core.Capability{Available: available, Message: "private-account secret private.example", Executable: "/home/alice/private-helper"}
		}
		r := c.Collect(context.Background())
		check := checkByID(t, r, "interactive_auth_helper")
		if !r.Backend.PrerequisitesAvailable || len(r.Backend.Blockers) != 0 || !check.Optional || calls != 1 {
			t.Fatal("optional MFA probe blocked basic readiness or was not run")
		}
		if (check.Status == Available) != available {
			t.Fatal("incorrect optional MFA status")
		}
		assertNoPrivateData(t, r)
	}
}

func TestCancelledReportSkipsOptionalMFAProbe(t *testing.T) {
	c := readyCollector()
	c.MFACapability = func() core.Capability { t.Fatal("canceled report probed helper"); return core.Capability{} }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := c.Collect(ctx)
	if checkByID(t, r, "interactive_auth_helper").Status != NotChecked {
		t.Fatal("canceled optional check not reported")
	}
}

func TestMissingDependenciesAndPluginAreExplicit(t *testing.T) {
	c := readyCollector()
	c.LookPath = func(string) (string, error) { return "", errors.New("secret user /home/private host 10.0.0.1") }
	c.ReadFile = func(string, int64) ([]byte, error) { return nil, errors.New("private content") }
	c.Run = func(context.Context, string, []string) ([]byte, error) {
		t.Fatal("missing nmcli must not run")
		return nil, nil
	}
	r := c.Collect(context.Background())
	for _, id := range []string{"nmcli", "openconnect", "networkmanager_openconnect_plugin"} {
		if checkByID(t, r, id).Status != Missing {
			t.Fatalf("%s not marked missing", id)
		}
	}
	if checkByID(t, r, "networkmanager_service").Status != NotChecked || r.Backend.PrerequisitesAvailable {
		t.Fatal("incorrect service status")
	}
	assertNoPrivateData(t, r)
}

func TestServiceProbeFailsClosedAndNeverLeaksOutput(t *testing.T) {
	cases := []struct {
		name   string
		output []byte
		err    error
	}{
		{"error", []byte("username=alice password=secret gateway=https://private.example 10.0.0.1"), errors.New("secret error")},
		{"malformed", []byte("running\nCOOKIE=secret private.example"), nil},
		{"stopped", []byte("not running"), nil},
		{"oversized", bytes.Repeat([]byte("running "), MaxProbeOutput), nil},
		{"cancelled", nil, context.Canceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := readyCollector()
			c.Run = func(context.Context, string, []string) ([]byte, error) { return tc.output, tc.err }
			r := c.Collect(context.Background())
			if r.Backend.PrerequisitesAvailable || checkByID(t, r, "networkmanager_service").Status != Unavailable {
				t.Fatal("unsafe output accepted")
			}
			assertNoPrivateData(t, r)
		})
	}
}

func assertNoPrivateData(t *testing.T, r Report) {
	t.Helper()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"alice", "secret", "private.example", "10.0.0.1", "/home/", "/usr/bin/", "meridian-test-bin", "COOKIE", "username="} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("report disclosed %q", secret)
		}
	}
}

func TestRelativeExecutablePathsAreRejected(t *testing.T) {
	c := readyCollector()
	c.LookPath = func(string) (string, error) { return "./nmcli", nil }
	c.Run = func(context.Context, string, []string) ([]byte, error) {
		t.Fatal("relative executable ran")
		return nil, nil
	}
	if c.Collect(context.Background()).Backend.PrerequisitesAvailable {
		t.Fatal("relative executables accepted")
	}
}

func TestOversizedPluginMetadataFailsClosed(t *testing.T) {
	c := readyCollector()
	c.ReadFile = func(string, int64) ([]byte, error) {
		return append(bytes.Repeat([]byte{'x'}, MaxPluginBytes), []byte("org.freedesktop.NetworkManager.openconnect")...), nil
	}
	r := c.Collect(context.Background())
	if checkByID(t, r, "networkmanager_openconnect_plugin").Status != Missing || r.Backend.PrerequisitesAvailable {
		t.Fatal("oversized plugin accepted")
	}
}

func TestMetadataTokensAreBounded(t *testing.T) {
	c := readyCollector()
	c.OS = "linux\nHOST=private.example"
	c.Architecture = "/home/alice"
	c.Version = strings.Repeat("x", 65)
	r := c.Collect(context.Background())
	if r.Application.Version != "unknown" || r.Platform.OS != "unknown" || r.Platform.Architecture != "unknown" {
		t.Fatal("invalid metadata was not discarded")
	}
	assertNoPrivateData(t, r)
}

func TestReadBoundedFileRejectsOversizeDirectoryAndSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plugin")
	if err := os.WriteFile(path, []byte("abcd"), 0600); err != nil {
		t.Fatal(err)
	}
	if b, err := readBoundedFile(path, 4); err != nil || string(b) != "abcd" {
		t.Fatal("valid bounded file rejected")
	}
	if _, err := readBoundedFile(path, 3); err == nil {
		t.Fatal("oversize accepted")
	}
	if _, err := readBoundedFile(dir, 100); err == nil {
		t.Fatal("directory accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err == nil {
		if _, err := readBoundedFile(link, 100); err == nil {
			t.Fatal("symlink accepted")
		}
	}
}

func TestBoundedOutputCancelsBeforeOverflow(t *testing.T) {
	cancelled := false
	b := &boundedOutput{cancel: func() { cancelled = true }}
	if _, err := b.Write(bytes.Repeat([]byte{'a'}, MaxProbeOutput)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte{'b'}); err == nil || !cancelled || b.buffer.Len() != MaxProbeOutput {
		t.Fatal("output limit not enforced")
	}
}

func TestSubprocessProbeBoundsAndIsolatesEnvironment(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MERIDIAN_DIAG_PRIVATE", "secret")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	data, err := runBounded(ctx, exe, []string{"-test.run=^TestProbeHelper$", "--", "ready"})
	if err != nil || string(data) != "running\n" {
		t.Fatalf("probe failed: %v %q", err, data)
	}
	data, err = runBounded(ctx, exe, []string{"-test.run=^TestProbeHelper$", "--", "overflow"})
	if err == nil || len(data) != 0 {
		t.Fatal("oversized subprocess output escaped")
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := runBounded(cancelled, exe, []string{"-test.run=^TestProbeHelper$", "--", "ready"}); err == nil {
		t.Fatal("cancelled probe succeeded")
	}
}

// TestProbeHelper is a child of TestSubprocessProbeBoundsAndIsolatesEnvironment,
// never a real host service. It receives no inherited environment variables.
func TestProbeHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--" {
		return
	}
	if os.Getenv("MERIDIAN_DIAG_PRIVATE") != "" {
		os.Exit(41)
	}
	switch os.Args[len(os.Args)-1] {
	case "ready":
		fmt.Fprintln(os.Stderr, "private stderr")
		fmt.Fprintln(os.Stdout, "running")
		os.Exit(0)
	case "overflow":
		fmt.Fprint(os.Stdout, strings.Repeat("x", MaxProbeOutput+1))
		os.Exit(0)
	}
}
