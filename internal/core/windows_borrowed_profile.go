package core

import (
	"errors"
	"mygo-vpn/internal/windowsvpn"
)

// Deliberately absent from default Protocols; only explicit Windows limited mode
// exposes a separate editor choice and authorization-aware backend.
const WindowsBorrowedProtocol = "windows-ras-borrowed"

// WindowsBorrowedOptions references an existing profile without owning it.
// No password, PSK or consent is persisted with these selection fields.
type WindowsBorrowedOptions struct {
	PhonebookPath string `json:"phonebook_path"`
	EntryName     string `json:"entry_name"`
	Domain        string `json:"domain,omitempty"`
}

func validateWindowsBorrowedProfile(p Profile) error {
	if p.WindowsBorrowed == nil {
		return errors.New("existing Windows VPN selection is required")
	}
	if p.SystemService != nil || p.L2TP != nil || p.ClientCertificate != "" || p.ClientKey != "" || p.CertificateFormat != "" || p.CAFile != "" || p.ProxyURL != "" || p.DisableUDP || p.InteractiveAuth || p.AuthGroup != "" || p.MTU != 0 || len(p.AdditionalGateways) != 0 || p.AllowProxySystemAuth {
		return errors.New("existing Windows VPN mode does not accept transport or authentication overrides")
	}
	o := p.WindowsBorrowed
	if windowsvpn.ValidateBorrowedSelection(windowsvpn.PhonebookEntry{PhonebookPath: o.PhonebookPath, Name: o.EntryName}, p.Gateway, p.Username, o.Domain) != nil {
		return errors.New("invalid existing Windows VPN selection, gateway or account")
	}
	return nil
}
