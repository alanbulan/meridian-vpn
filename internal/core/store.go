// Package core contains the platform-independent VPN domain and private local storage.
package core

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxConfigBytes = 1 << 20

const MaxProfiles = 128

var Protocols = []string{"anyconnect", "nc", "pulse", "gp", "f5", "fortinet", "array", "l2tp", "univpn"}

type Profile struct {
	WindowsBorrowed      *WindowsBorrowedOptions `json:"windows_borrowed,omitempty"`
	SystemService        *SystemServiceOptions   `json:"system_service,omitempty"`
	L2TP                 *L2TPOptions            `json:"l2tp,omitempty"`
	CertificateFormat    string                  `json:"certificate_format,omitempty"`
	InteractiveAuth      bool                    `json:"interactive_auth,omitempty"`
	ClientCertificate    string                  `json:"client_certificate,omitempty"`
	ClientKey            string                  `json:"client_key,omitempty"`
	AdditionalGateways   []string                `json:"additional_gateways,omitempty"`
	AllowProxySystemAuth bool                    `json:"-"`
	Description          string                  `json:"description,omitempty"`
	AuthGroup            string                  `json:"auth_group,omitempty"`
	CAFile               string                  `json:"ca_file,omitempty"`
	ProxyURL             string                  `json:"proxy_url,omitempty"`
	DisableUDP           bool                    `json:"disable_udp,omitempty"`
	MTU                  int                     `json:"mtu,omitempty"`
	ID                   string                  `json:"id"`
	Name                 string                  `json:"name"`
	Gateway              string                  `json:"gateway"`
	Protocol             string                  `json:"protocol"`
	Username             string                  `json:"username,omitempty"`
}
type Settings struct {
	ReauthOnLoss   bool   `json:"reauth_on_loss,omitempty"`
	Language       string `json:"language,omitempty"`
	MinimizeToTray bool   `json:"minimize_to_tray"`
	DarkMode       bool   `json:"dark_mode"`
}

// SavedMacServiceSelection stores expectations only, never authority or credentials.
type SavedMacServiceSelection struct {
	ServiceID string   `json:"service_id"`
	Gateway   string   `json:"gateway"`
	Targets   []string `json:"targets"`
}

type Config struct {
	MacServiceSelection *SavedMacServiceSelection `json:"mac_service_selection,omitempty"`
	Version             int                       `json:"version"`
	Profiles            []Profile                 `json:"profiles"`
	Settings            Settings                  `json:"settings"`
	SelectedID          string                    `json:"selected_id,omitempty"`
}
type Store struct{ Path string }

func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func ValidateProfile(p Profile) error {
	if p.SystemService != nil && p.Protocol != ProtocolMacOSSystemL2TP {
		return errors.New("system-service options require the macOS system-service protocol")
	}
	if err := validateCertificateReferences(p); err != nil {
		return err
	}
	if len(p.AdditionalGateways) > 15 {
		return errors.New("at most 15 additional gateways are supported")
	}
	seenGateways := map[string]bool{p.Gateway: true}
	for _, gateway := range p.AdditionalGateways {
		if seenGateways[gateway] {
			return errors.New("gateway addresses must be distinct")
		}
		seenGateways[gateway] = true
		if err := ValidateProfile(Profile{Name: "gateway", Protocol: p.Protocol, Gateway: gateway}); err != nil {
			return errors.New("invalid additional gateway: " + err.Error())
		}
	}

	if len(p.Description) > 4096 || !utf8.ValidString(p.Description) || strings.ContainsFunc(p.Description, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }) {
		return errors.New("description is invalid or exceeds 4096 bytes")
	}
	if len(p.AuthGroup) > 256 || hasControl(p.AuthGroup) || !utf8.ValidString(p.AuthGroup) {
		return errors.New("invalid authentication group")
	}
	if p.CAFile != "" && (!filepath.IsAbs(p.CAFile) || len(p.CAFile) > 4096 || hasControl(p.CAFile)) {
		return errors.New("CA file must use an absolute path without control characters")
	}
	if p.MTU != 0 && (p.MTU < 576 || p.MTU > 9000) {
		return errors.New("MTU must be 0 (automatic) or 576–9000")
	}
	if err := validateProxy(p.ProxyURL); err != nil {
		return err
	}

	if len(p.ID) > 128 || hasControl(p.ID) || !utf8.ValidString(p.ID) {
		return errors.New("invalid profile ID")
	}
	if strings.TrimSpace(p.Name) == "" || utf8.RuneCountInString(p.Name) > 80 || !utf8.ValidString(p.Name) || hasControl(p.Name) {
		return errors.New("profile name must be 1–80 characters")
	}
	if p.Protocol == WindowsBorrowedProtocol {
		return validateWindowsBorrowedProfile(p)
	}
	if p.WindowsBorrowed != nil {
		return errors.New("Windows VPN selection requires Windows borrowed mode")
	}
	if !supportedProtocol(p.Protocol) {
		return errors.New("unsupported protocol; select an OpenConnect protocol")
	}
	if p.Protocol == ProtocolMacOSSystemL2TP {
		return validateSystemServiceProfile(p)
	}
	if p.Protocol == "l2tp" {
		return validateL2TPProfile(p)
	}
	if p.L2TP != nil {
		return errors.New("L2TP options require L2TP protocol")
	}
	u, e := url.Parse(p.Gateway)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(p.Gateway, "#") || u.Opaque != "" {
		return errors.New("gateway must be an HTTPS URL without credentials, query or fragment")
	}
	if len(p.Gateway) > 2048 {
		return errors.New("gateway exceeds 2048 bytes")
	}
	if strings.HasSuffix(u.Host, ":") {
		return errors.New("gateway port must not be empty")
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return errors.New("gateway port must be 1–65535")
		}
	}
	if strings.ContainsAny(p.Gateway, "\r\n\t ") || hasControl(p.Username) || !utf8.ValidString(p.Username) || len(p.Username) > 256 {
		return errors.New("invalid gateway or username")
	}
	return nil
}
func (s Store) Load() (Config, error) {
	cfg := Config{Version: 1, Profiles: []Profile{}}
	info, e := os.Lstat(s.Path)
	if errors.Is(e, os.ErrNotExist) {
		return cfg, nil
	}
	if e != nil {
		return cfg, e
	}
	if !info.Mode().IsRegular() {
		return cfg, errors.New("settings path must be a regular file")
	}
	if info.Size() > maxConfigBytes {
		return cfg, errors.New("settings file exceeds size limit")
	}
	f, e := os.Open(s.Path)
	if errors.Is(e, os.ErrNotExist) {
		return cfg, nil
	}
	if e != nil {
		return cfg, e
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if e != nil {
		return Config{}, e
	}
	if len(data) > maxConfigBytes {
		return Config{}, errors.New("settings file exceeds size limit")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e = d.Decode(&cfg); e != nil {
		return Config{}, fmt.Errorf("invalid settings file: %w", e)
	}
	var extra any
	if e = d.Decode(&extra); e != io.EOF {
		return Config{}, errors.New("settings file contains trailing data")
	}
	if cfg.Version != 1 {
		return Config{}, errors.New("unsupported settings version")
	}
	if e = validateConfig(cfg); e != nil {
		return Config{}, e
	}
	return cfg, nil
}
func validateConfig(c Config) error {
	if s := c.MacServiceSelection; s != nil {
		if err := ValidateProfile(Profile{ID: s.ServiceID, Name: "macOS service", Protocol: ProtocolMacOSSystemL2TP, Gateway: s.Gateway, SystemService: &SystemServiceOptions{ServiceID: s.ServiceID, Targets: s.Targets}}); err != nil {
			return err
		}
	}
	if c.Settings.Language != "" && c.Settings.Language != "zh" && c.Settings.Language != "en" && c.Settings.Language != "system" {
		return errors.New("unsupported language")
	}
	seen := map[string]bool{}
	if len(c.Profiles) > MaxProfiles {
		return errors.New("profile limit is 128")
	}
	for _, p := range c.Profiles {
		if p.ID == "" || len(p.ID) > 128 || hasControl(p.ID) || !utf8.ValidString(p.ID) || seen[p.ID] {
			return errors.New("profile ID is empty or duplicated")
		}
		seen[p.ID] = true
		if e := ValidateProfile(p); e != nil {
			return e
		}
	}
	if c.SelectedID != "" && !seen[c.SelectedID] {
		return errors.New("selected profile does not exist")
	}
	return nil
}
func (s Store) Save(c Config) error {
	c.Version = 1
	if e := validateConfig(c); e != nil {
		return e
	}
	data, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	if len(data) > maxConfigBytes {
		return errors.New("settings exceed size limit")
	}
	dir := filepath.Dir(s.Path)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".profiles-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(f.Name(), s.Path)
}
func (c *Config) Upsert(p Profile) error {
	p.SystemService = cloneSystemServiceOptions(p.SystemService)
	if p.WindowsBorrowed != nil {
		options := *p.WindowsBorrowed
		p.WindowsBorrowed = &options
	}
	if p.L2TP != nil {
		options := *p.L2TP
		p.L2TP = &options
	}
	if e := ValidateProfile(p); e != nil {
		return e
	}
	if p.ID == "" {
		p.ID = NewID()
	}
	for i := range c.Profiles {
		if c.Profiles[i].ID == p.ID {
			c.Profiles[i] = p
			return nil
		}
	}
	if len(c.Profiles) >= MaxProfiles {
		return errors.New("profile limit is 128")
	}
	c.Profiles = append(c.Profiles, p)
	if c.SelectedID == "" {
		c.SelectedID = p.ID
	}
	return nil
}
func (c *Config) Delete(id string) {
	c.Profiles = slices.DeleteFunc(c.Profiles, func(p Profile) bool { return p.ID == id })
	if c.SelectedID == id {
		c.SelectedID = ""
		if len(c.Profiles) > 0 {
			c.SelectedID = c.Profiles[0].ID
		}
	}
}

func hasControl(s string) bool { return strings.ContainsFunc(s, unicode.IsControl) }
func supportedProtocol(s string) bool {
	switch s {
	case "anyconnect", "nc", "pulse", "gp", "f5", "fortinet", "array", "l2tp", "univpn", ProtocolMacOSSystemL2TP:
		return true
	}
	return false
}

func validateProxy(raw string) error {
	if raw == "" {
		return nil
	}
	u, e := url.Parse(raw)
	if e != nil || len(raw) > 2048 || hasControl(raw) || strings.ContainsAny(raw, ",\\ ") || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return errors.New("proxy must be an HTTP or SOCKS5 URL without embedded credentials or extra fields")
	}
	switch u.Scheme {
	case "http", "socks5":
	default:
		return errors.New("unsupported proxy scheme")
	}
	if strings.HasSuffix(u.Host, ":") {
		return errors.New("empty proxy port")
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return errors.New("invalid proxy port")
		}
	}
	return nil
}
