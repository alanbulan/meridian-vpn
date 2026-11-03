//go:build linux

package core

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This opt-in integration test requires AF_UNIX permission. It was blocked by
// sandbox EPERM in the recovery environment; it is NOT a verified passing test.
func TestUniVPNBrokerPeerCredentialsAndDeniedUID(t *testing.T) {
	if os.Getenv("UNIVPN_TEST_SOCKET") != "1" {
		t.Skip("AF_UNIX integration not verified: recovery sandbox denied socket creation (EPERM); opt in only in an authorized environment with UNIVPN_TEST_SOCKET=1")
	}
	path := filepath.Join(t.TempDir(), "broker.sock")
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		c, e := l.AcceptUnix()
		if e != nil {
			return
		}
		uid, e := uniVPNPeer(c)
		if e != nil || uid != uint32(os.Getuid()) {
			t.Errorf("wrong peer credentials %d %v", uid, e)
		}
		serveUniVPNConn(context.Background(), c, nil, map[uint32]bool{})
	}()
	c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	var x [1]byte
	if _, e = c.Read(x[:]); e == nil {
		t.Fatal("denied peer retained")
	}
	<-ended
	if (UniVPNUnixBroker{SocketPath: path}).Available() {
		t.Fatal("unsafe writable parent accepted")
	}
}
