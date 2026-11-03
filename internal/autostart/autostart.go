// Package autostart manages Meridian's opt-in, per-user desktop startup entry.
// Constructing a Manager and inspecting its state are read-only. Callers must
// obtain explicit user confirmation before Enable or Disable.
package autostart

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

const FileName = "meridian-vpn.desktop"
const ownerMarker = "X-Meridian-Owner=meridian.vpn.autostart.v1"
const executableKey = "X-Meridian-Executable="

var (
	ErrBusy                = errors.New("autostart is busy in another process; try again")
	ErrUnsupported         = errors.New("desktop autostart is supported only on Linux")
	ErrUnsafePath          = errors.New("autostart path is not safe")
	ErrForeignEntry        = errors.New("autostart entry is not an unmodified Meridian-owned file")
	ErrDifferentExecutable = errors.New("autostart already points to another executable; disable it before enabling the new location")
)

// Options allows an explicitly selected config directory and executable. Empty
// values use os.UserConfigDir and os.Executable. No arguments are ever saved.
// Tests must inject temporary paths rather than use a real home directory.
type Options struct {
	ConfigDir  string
	Executable string
}

type Status struct {
	Supported bool
	Enabled   bool
	Path      string
	// Executable is the resolved executable this Manager would register.
	Executable string
	// RegisteredExecutable is populated only for a validated owned entry.
	RegisteredExecutable string
}

type Manager struct {
	mu         sync.Mutex
	configDir  string
	executable string
}

// New resolves the exact executable and target without creating anything.
func New(opts Options) (*Manager, error) {
	m := &Manager{}
	if runtime.GOOS != "linux" {
		return m, nil
	}
	config := opts.ConfigDir
	var err error
	if config == "" {
		config, err = os.UserConfigDir()
		if err != nil {
			return nil, fmt.Errorf("resolve user config directory: %w", err)
		}
	}
	if !filepath.IsAbs(config) || !validText(config) {
		return nil, fmt.Errorf("%w: config directory must be an absolute path without control characters", ErrUnsafePath)
	}
	m.configDir = filepath.Clean(config)
	exe := opts.Executable
	if exe == "" {
		exe, err = os.Executable()
		if err != nil {
			return nil, fmt.Errorf("resolve executable: %w", err)
		}
	}
	if !filepath.IsAbs(exe) {
		return nil, fmt.Errorf("%w: executable path must be absolute", ErrUnsafePath)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return nil, fmt.Errorf("resolve executable: %w", err)
	}
	m.executable = filepath.Clean(exe)
	if _, err := desktopEntry(m.executable); err != nil {
		return nil, err
	}
	if err := checkExecutable(m.executable); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) state() Status {
	s := Status{Supported: runtime.GOOS == "linux", Executable: m.executable}
	if s.Supported {
		s.Path = filepath.Join(m.configDir, "autostart", FileName)
	}
	return s
}

// Status reads only this application's entry. It never creates directories or
// files. A conflict is returned as an error, not reported as a disabled entry.
func (m *Manager) Status() (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.state()
	if !s.Supported {
		return s, nil
	}
	registered, err := m.readRegistration()
	if err != nil {
		return s, err
	}
	s.Enabled = registered != ""
	s.RegisteredExecutable = registered
	return s, nil
}

// Preview returns the exact prospective file bytes without changing anything.
// The UI should also show Status.Path and explain that startup never connects.
func (m *Manager) Preview() ([]byte, error) {
	if runtime.GOOS != "linux" {
		return nil, ErrUnsupported
	}
	return desktopEntry(m.executable)
}

// Enable must be called only after explicit user confirmation of the resolved
// target and executable. It starts only the GUI on a future desktop login; it
// does not execute anything, connect to a VPN or save the current arguments.
func (m *Manager) Enable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if runtime.GOOS != "linux" {
		return ErrUnsupported
	}
	if err := checkExecutable(m.executable); err != nil {
		return err
	}
	content, err := desktopEntry(m.executable)
	if err != nil {
		return err
	}
	return m.enable(content)
}

// Disable must be called only after explicit user confirmation. It removes only
// an unmodified, owned Meridian entry, not directories or other startup files.
func (m *Manager) Disable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if runtime.GOOS != "linux" {
		return ErrUnsupported
	}
	return m.disable()
}

func validText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func desktopEntry(executable string) ([]byte, error) {
	if !filepath.IsAbs(executable) || filepath.Clean(executable) != executable || !validText(executable) || strings.Contains(executable, "=") {
		return nil, fmt.Errorf("%w: executable must be a clean absolute path without control characters or '='", ErrUnsafePath)
	}
	// Desktop Entry has two escaping layers: command-line quoting, then the
	// general string escape layer. This is not shell quoting. Percent signs
	// must be doubled so an executable name cannot inject field codes.
	var quoted strings.Builder
	quoted.WriteByte('"')
	for _, r := range executable {
		switch r {
		case '\\':
			quoted.WriteString(`\\\\`)
		case '"', '`', '$':
			quoted.WriteString(`\\`)
			quoted.WriteRune(r)
		case '%':
			quoted.WriteString("%%")
		default:
			quoted.WriteRune(r)
		}
	}
	quoted.WriteByte('"')
	return []byte("[Desktop Entry]\nType=Application\nVersion=1.0\nName=Meridian\nComment=Open Meridian without connecting to a VPN\nExec=" + quoted.String() + "\nTerminal=false\n" + ownerMarker + "\n" + executableKey + base64.RawStdEncoding.EncodeToString([]byte(executable)) + "\n"), nil
}

// An owner marker alone is not enough: accept only our exact canonical format,
// including a single argument-free Exec. Any user edits are preserved as a
// conflict, including Hidden=true, extra keys, additional args or a new shell.
func ownedExecutable(content []byte) (string, error) {
	lines := strings.Split(string(content), "\n")
	var executable string
	for _, line := range lines {
		if strings.HasPrefix(line, executableKey) {
			decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(line, executableKey))
			if err != nil {
				return "", ErrForeignEntry
			}
			executable = string(decoded)
		}
	}
	canonical, err := desktopEntry(executable)
	if err != nil || !bytes.Equal(canonical, content) {
		return "", ErrForeignEntry
	}
	return executable, nil
}
