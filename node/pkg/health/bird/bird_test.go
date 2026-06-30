package bird

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type mockConn struct {
	r io.Reader
}

func (m *mockConn) Read(b []byte) (int, error)         { return m.r.Read(b) }
func (m *mockConn) Write(b []byte) (int, error)        { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestScanBIRDPeers_MixedFamilies(t *testing.T) {
	// Single BIRD3 socket returns both v4 and v6 peers.
	output := `0001 BIRD 3.3.0 ready.
2002-name     proto    table    state  since       info
1002-Mesh_172_17_8_102 BGP      master   up     2016-11-21  Established
 Mesh_fd80_24e2_f998_72d7__2 BGP      master   up     2016-11-21  Established
 Node_10_0_0_5 BGP      master   start  2016-11-21  Active
0000
`
	// v4 request -> only v4 peers
	v4, err := scanBIRDPeers("4", &mockConn{r: strings.NewReader(output)})
	if err != nil {
		t.Fatalf("v4 scan error: %v", err)
	}
	if len(v4) != 2 {
		t.Fatalf("expected 2 v4 peers, got %d: %+v", len(v4), v4)
	}
	for _, p := range v4 {
		if strings.Contains(p.PeerIP, ":") {
			t.Errorf("v4 filter returned v6 peer: %s", p.PeerIP)
		}
	}
	if v4[0].PeerIP != "172.17.8.102" {
		t.Errorf("expected 172.17.8.102, got %s", v4[0].PeerIP)
	}

	// v6 request -> only v6 peers
	v6, err := scanBIRDPeers("6", &mockConn{r: strings.NewReader(output)})
	if err != nil {
		t.Fatalf("v6 scan error: %v", err)
	}
	if len(v6) != 1 {
		t.Fatalf("expected 1 v6 peer, got %d: %+v", len(v6), v6)
	}
	if v6[0].PeerIP != "fd80:24e2:f998:72d7::2" {
		t.Errorf("expected fd80:24e2:f998:72d7::2, got %s", v6[0].PeerIP)
	}
}
