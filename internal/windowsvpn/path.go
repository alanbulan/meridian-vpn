package windowsvpn

import "strings"

// validPhonebookComponent rejects Win32 names which can resolve to a device
// rather than the selected file. The restriction applies to ancestors too.
// See https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file.
// This lexical check is not proof of file identity or protection against races.
func validPhonebookComponent(part string) bool {
	if part == "" || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
		return false
	}
	for _, c := range part {
		if c < 32 {
			return false
		}
	}
	// Extensions do not make reserved device names into ordinary files. Be
	// conservative about spaces before the extension as well, rather than
	// relying on differences in Win32 path normalization between APIs.
	base, _, _ := strings.Cut(part, ".")
	base = strings.ToUpper(strings.TrimRight(base, " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return false
	}
	for _, prefix := range []string{"COM", "LPT"} {
		if strings.HasPrefix(base, prefix) {
			suffix := strings.TrimPrefix(base, prefix)
			switch suffix {
			case "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
				return false
			}
		}
	}
	return true
}
