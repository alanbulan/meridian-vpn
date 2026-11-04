//go:build !windows

package windowsvpn

// EnumerateSystemEntries has no command or emulation fallback outside Windows.
func EnumerateSystemEntries() ([]PhonebookEntry,error) { return nil,ErrUnavailable }
