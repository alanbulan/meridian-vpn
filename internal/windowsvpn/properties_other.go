//go:build !windows

package windowsvpn

func InspectSystemEntry(PhonebookEntry, string) (EntryEvidence, error) {
	return EntryEvidence{}, ErrUnavailable
}

func RevalidateSystemEntry(EntryEvidence) error { return ErrUnavailable }
