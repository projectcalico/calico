//go:build !windows

// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package intdataplane

import (
	"net"
	"testing"

	bpfconntrack "github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

// newConnLimitTestMgr returns a minimal bpfEndpointManager wired up just enough
// for the connlimit incremental-maintenance helpers. We deliberately skip
// NewBPFEndpointManager: it pulls in a full BPF map fixture, runit health
// checks, etc., which aren't needed to exercise the maps + RWMutex contract
// these tests target.
func newConnLimitTestMgr() *bpfEndpointManager {
	return &bpfEndpointManager{
		connLimitPodInfo: map[string]bpfconntrack.ConnLimitPodInfo{},
		connLimitWLToIPs: map[types.WorkloadEndpointID][]string{},
	}
}

// connLimitWEP returns a proto.WorkloadEndpoint shaped how the dataplane
// receives it: IPs as CIDR strings, QosControls populated if hasIngress or
// hasEgress are true.
func connLimitWEP(name string, ipv4Nets []string, ingressMax, egressMax int64) *proto.WorkloadEndpoint {
	wep := &proto.WorkloadEndpoint{
		Name:     name,
		Ipv4Nets: ipv4Nets,
	}
	if ingressMax > 0 || egressMax > 0 {
		wep.QosControls = &proto.QoSControls{
			IngressMaxConnections: ingressMax,
			EgressMaxConnections:  egressMax,
		}
	}
	return wep
}

// assertConnLimitInfo asserts the (Ipv4) info entry in the manager's map. ipv4
// is the dotted-quad string; want is what we expect to be there. If want is
// the zero value of ConnLimitPodInfo, we assert the key is absent.
func assertConnLimitInfo(t *testing.T, m *bpfEndpointManager, ipv4 string, want bpfconntrack.ConnLimitPodInfo) {
	t.Helper()
	key := string(net.ParseIP(ipv4).To4())
	got, ok := m.GetConnLimitedPodInfo()[key]
	if want == (bpfconntrack.ConnLimitPodInfo{}) {
		if ok {
			t.Errorf("ip=%s: expected absent, got %+v", ipv4, got)
		}
		return
	}
	if !ok {
		t.Errorf("ip=%s: expected %+v, got absent", ipv4, want)
		return
	}
	if got != want {
		t.Errorf("ip=%s: got %+v, want %+v", ipv4, got, want)
	}
}

func wlID(name string) types.WorkloadEndpointID {
	return types.WorkloadEndpointID{
		OrchestratorId: "k8s",
		WorkloadId:     name,
		EndpointId:     "eth0",
	}
}

// TestConnLimitPodInfoIncremental exercises the five correctness paths the
// event-driven map maintenance introduces.
func TestConnLimitPodInfoIncremental(t *testing.T) {
	t.Run("WEP-before-iface ordering: ifIndex=0 defers, later iface event resolves", func(t *testing.T) {
		m := newConnLimitTestMgr()
		id := wlID("w1")
		wep := connLimitWEP("cali123", []string{"10.0.0.1/32"}, 5, 0)

		// WEP arrives first with ifIndex=0 — deferred, map stays empty.
		m.updateConnLimitForWEP(id, wep, 0)
		assertConnLimitInfo(t, m, "10.0.0.1", bpfconntrack.ConnLimitPodInfo{})

		// Iface event delivers ifIndex=42 — entry now present.
		m.updateConnLimitForWEP(id, wep, 42)
		assertConnLimitInfo(t, m, "10.0.0.1", bpfconntrack.ConnLimitPodInfo{
			IfIndex:         42,
			HasIngressLimit: true,
			HasEgressLimit:  false,
		})
	})

	t.Run("WEP IP change: old IP dropped, new IP added", func(t *testing.T) {
		m := newConnLimitTestMgr()
		id := wlID("w1")

		m.updateConnLimitForWEP(id, connLimitWEP("cali123", []string{"10.0.0.1/32"}, 5, 0), 42)
		assertConnLimitInfo(t, m, "10.0.0.1", bpfconntrack.ConnLimitPodInfo{
			IfIndex: 42, HasIngressLimit: true,
		})

		// Same wlID, different IP — old should go, new should appear.
		m.updateConnLimitForWEP(id, connLimitWEP("cali123", []string{"10.0.0.2/32"}, 5, 0), 42)
		assertConnLimitInfo(t, m, "10.0.0.1", bpfconntrack.ConnLimitPodInfo{})
		assertConnLimitInfo(t, m, "10.0.0.2", bpfconntrack.ConnLimitPodInfo{
			IfIndex: 42, HasIngressLimit: true,
		})
	})

	t.Run("WEP limit removed: entries cleared", func(t *testing.T) {
		m := newConnLimitTestMgr()
		id := wlID("w1")

		m.updateConnLimitForWEP(id, connLimitWEP("cali123", []string{"10.0.0.1/32"}, 5, 0), 42)
		assertConnLimitInfo(t, m, "10.0.0.1", bpfconntrack.ConnLimitPodInfo{
			IfIndex: 42, HasIngressLimit: true,
		})

		// WEP now has no QoS limits — entries should drop out.
		m.updateConnLimitForWEP(id, connLimitWEP("cali123", []string{"10.0.0.1/32"}, 0, 0), 42)
		assertConnLimitInfo(t, m, "10.0.0.1", bpfconntrack.ConnLimitPodInfo{})
	})

	t.Run("WEP remove: entries cleared and secondary index pruned", func(t *testing.T) {
		m := newConnLimitTestMgr()
		id := wlID("w1")

		m.updateConnLimitForWEP(id, connLimitWEP("cali123", []string{"10.0.0.1/32"}, 5, 0), 42)
		assertConnLimitInfo(t, m, "10.0.0.1", bpfconntrack.ConnLimitPodInfo{
			IfIndex: 42, HasIngressLimit: true,
		})

		m.clearConnLimitForWEP(id)
		assertConnLimitInfo(t, m, "10.0.0.1", bpfconntrack.ConnLimitPodInfo{})

		// Secondary index must also be pruned so a later add doesn't
		// double-track.
		if _, ok := m.connLimitWLToIPs[id]; ok {
			t.Errorf("connLimitWLToIPs[%v] should be empty after clear, got entry", id)
		}
	})

	t.Run("iface flap: ifIndex 42 → 0 clears, ifIndex 0 → 99 re-adds with new value", func(t *testing.T) {
		m := newConnLimitTestMgr()
		id := wlID("w1")
		wep := connLimitWEP("cali123", []string{"10.0.0.1/32"}, 0, 3) // egress limit

		// Up at 42.
		m.updateConnLimitForWEP(id, wep, 42)
		assertConnLimitInfo(t, m, "10.0.0.1", bpfconntrack.ConnLimitPodInfo{
			IfIndex: 42, HasEgressLimit: true,
		})

		// Iface goes down (ifIndex=0).
		m.updateConnLimitForWEP(id, wep, 0)
		assertConnLimitInfo(t, m, "10.0.0.1", bpfconntrack.ConnLimitPodInfo{})

		// Iface comes back at a *different* ifIndex.
		m.updateConnLimitForWEP(id, wep, 99)
		assertConnLimitInfo(t, m, "10.0.0.1", bpfconntrack.ConnLimitPodInfo{
			IfIndex: 99, HasEgressLimit: true,
		})
	})

	t.Run("WEP with multiple IPs: all tracked together, all cleared together", func(t *testing.T) {
		m := newConnLimitTestMgr()
		id := wlID("w1")
		wep := connLimitWEP("cali123", []string{"10.0.0.1/32", "10.0.0.2/32"}, 5, 5)

		m.updateConnLimitForWEP(id, wep, 42)
		assertConnLimitInfo(t, m, "10.0.0.1", bpfconntrack.ConnLimitPodInfo{
			IfIndex: 42, HasIngressLimit: true, HasEgressLimit: true,
		})
		assertConnLimitInfo(t, m, "10.0.0.2", bpfconntrack.ConnLimitPodInfo{
			IfIndex: 42, HasIngressLimit: true, HasEgressLimit: true,
		})

		m.clearConnLimitForWEP(id)
		assertConnLimitInfo(t, m, "10.0.0.1", bpfconntrack.ConnLimitPodInfo{})
		assertConnLimitInfo(t, m, "10.0.0.2", bpfconntrack.ConnLimitPodInfo{})
	})
}
