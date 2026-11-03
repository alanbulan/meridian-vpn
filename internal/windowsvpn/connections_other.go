//go:build !windows

package windowsvpn

func ObserveSystemConnections(EntryEvidence) (ConnectionSnapshot, error) {
	return ConnectionSnapshot{}, ErrUnavailable
}
