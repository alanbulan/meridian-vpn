package core

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// SessionMetrics is unavailable when either interface identity or either counter
// cannot be read. Zero values alone never represent a successfully measured link.
type SessionMetrics struct {
	VirtualIP            string
	Uploaded, Downloaded uint64
	Available            bool
}

func readInterfaceMetrics(name string) SessionMetrics {
	if runtime.GOOS != "linux" || !ownedInterfaceName(name) {
		return SessionMetrics{}
	}
	i, e := net.InterfaceByName(name)
	if e != nil || i.Flags&net.FlagUp == 0 {
		return SessionMetrics{}
	}
	addresses, e := i.Addrs()
	if e != nil {
		return SessionMetrics{}
	}
	ip := ""
	for _, a := range addresses {
		candidate, _, e := net.ParseCIDR(a.String())
		if e != nil || candidate.IsLoopback() || candidate.IsUnspecified() {
			continue
		}
		if ip == "" || candidate.To4() != nil {
			ip = candidate.String()
		}
		if candidate.To4() != nil {
			break
		}
	}
	if ip == "" {
		return SessionMetrics{}
	}
	root := filepath.Join("/sys/class/net", name, "statistics")
	rx, e := readCounter(filepath.Join(root, "rx_bytes"))
	if e != nil {
		return SessionMetrics{}
	}
	tx, e := readCounter(filepath.Join(root, "tx_bytes"))
	if e != nil {
		return SessionMetrics{}
	}
	return SessionMetrics{ip, tx, rx, true}
}
func ownedInterfaceName(n string) bool {
	if len(n) != 12 || !strings.HasPrefix(n, "md") {
		return false
	}
	for _, c := range n[2:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func readCounter(path string) (uint64, error) {
	f, e := os.Open(path)
	if e != nil {
		return 0, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 65))
	if e != nil {
		return 0, e
	}
	if len(b) > 64 {
		return 0, errors.New("invalid byte counter")
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}
