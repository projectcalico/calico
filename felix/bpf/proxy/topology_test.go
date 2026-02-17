// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.
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

package proxy_test

import (
	"testing"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/sets"
	k8sp "k8s.io/kubernetes/pkg/proxy"

	"github.com/projectcalico/calico/felix/bpf/proxy"
)

type fakeEndpoint struct {
	ip          string
	ready       bool
	terminating bool
	zoneHints   sets.Set[string]
	nodeHints   sets.Set[string]
}

// Implement k8sp.Endpoint interface for testing.
type testEndpoint struct {
	fakeEndpoint
}

func (e testEndpoint) IP() string                  { return e.ip }
func (e testEndpoint) IsReady() bool               { return e.ready }
func (e testEndpoint) IsTerminating() bool         { return e.terminating }
func (e testEndpoint) ZoneHints() sets.Set[string] { return e.zoneHints }
func (e testEndpoint) NodeHints() sets.Set[string] { return e.nodeHints }
func (e testEndpoint) IsLocal() bool               { panic("unimplemented") }
func (e testEndpoint) IsServing() bool             { panic("unimplemented") }
func (e testEndpoint) Port() int                   { panic("unimplemented") }
func (e testEndpoint) String() string              { panic("unimplemented") }

func TestFilterEpsByTopologyAwareRouting(t *testing.T) {
	tests := []struct {
		name         string
		topologyMode string
		nodeZone     string
		endpoints    []testEndpoint
		wantIPs      []string
		wantFiltered bool
	}{
		{
			name:         "topologyMode not auto: returns all endpoints, not applied",
			topologyMode: "disabled",
			nodeZone:     "zone-a",
			endpoints: []testEndpoint{
				{fakeEndpoint{"10.0.0.1", true, false, sets.New[string]("zone-a"), sets.New[string]()}},
				{fakeEndpoint{"10.0.0.2", true, false, sets.New[string]("zone-b"), sets.New[string]()}},
			},
			wantIPs:      []string{"10.0.0.1", "10.0.0.2"},
			wantFiltered: false,
		},
		{
			name:         "endpoint not ready or terminating is skipped",
			topologyMode: "auto",
			nodeZone:     "zone-a",
			endpoints: []testEndpoint{
				{fakeEndpoint{"10.0.0.1", false, false, sets.New[string]("zone-a"), sets.New[string]()}},
				{fakeEndpoint{"10.0.0.2", true, false, sets.New[string]("zone-a"), sets.New[string]()}},
			},
			wantIPs:      []string{"10.0.0.2"},
			wantFiltered: true,
		},
		{
			name:         "endpoint with no zone hints disables filtering",
			topologyMode: "auto",
			nodeZone:     "zone-a",
			endpoints: []testEndpoint{
				{fakeEndpoint{"10.0.0.1", true, false, sets.New[string](), sets.New[string]()}},
				{fakeEndpoint{"10.0.0.2", true, false, sets.New[string]("zone-a"), sets.New[string]()}},
			},
			wantIPs:      []string{"10.0.0.1", "10.0.0.2"},
			wantFiltered: true,
		},
		{
			name:         "only endpoints matching nodeZone are returned",
			topologyMode: "auto",
			nodeZone:     "zone-a",
			endpoints: []testEndpoint{
				{fakeEndpoint{"10.0.0.1", true, false, sets.New[string]("zone-a"), sets.New[string]()}},
				{fakeEndpoint{"10.0.0.2", true, false, sets.New[string]("zone-b"), sets.New[string]()}},
			},
			wantIPs:      []string{"10.0.0.1"},
			wantFiltered: true,
		},
		{
			name:         "no endpoints match nodeZone, fallback to all endpoints",
			topologyMode: "auto",
			nodeZone:     "zone-c",
			endpoints: []testEndpoint{
				{fakeEndpoint{"10.0.0.1", true, false, sets.New[string]("zone-a"), sets.New[string]()}},
				{fakeEndpoint{"10.0.0.2", true, false, sets.New[string]("zone-b"), sets.New[string]()}},
			},
			wantIPs:      []string{"10.0.0.1", "10.0.0.2"},
			wantFiltered: true,
		},
		{
			name:         "all endpoints not ready or terminating, returns all endpoints",
			topologyMode: "auto",
			nodeZone:     "zone-a",
			endpoints: []testEndpoint{
				{fakeEndpoint{"10.0.0.1", false, false, sets.New[string]("zone-a"), sets.New[string]()}},
				{fakeEndpoint{"10.0.0.2", false, false, sets.New[string]("zone-a"), sets.New[string]()}},
			},
			wantIPs:      []string{"10.0.0.1", "10.0.0.2"},
			wantFiltered: true,
		},
		{
			name:         "endpoint terminating is included",
			topologyMode: "auto",
			nodeZone:     "zone-a",
			endpoints: []testEndpoint{
				{fakeEndpoint{"10.0.0.1", false, true, sets.New[string]("zone-a"), sets.New[string]()}},
				{fakeEndpoint{"10.0.0.2", true, false, sets.New[string]("zone-a"), sets.New[string]()}},
			},
			wantIPs:      []string{"10.0.0.1", "10.0.0.2"},
			wantFiltered: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			// Convert []testEndpoint to []k8sp.Endpoint
			var eps []k8sp.Endpoint
			for _, ep := range tt.endpoints {
				eps = append(eps, ep)
			}
			got, filtered := proxy.FilterEpsByTopologyAwareRouting(eps, tt.topologyMode, tt.nodeZone)
			var gotIPs []string
			for _, ep := range got {
				gotIPs = append(gotIPs, ep.IP())
			}
			g.Expect(gotIPs).To(ConsistOf(tt.wantIPs))
			g.Expect(filtered).To(Equal(tt.wantFiltered))
		})
	}
}

func TestFilterEpsByTrafficDistribution(t *testing.T) {
	tests := []struct {
		name      string
		nodeName  string
		nodeZone  string
		endpoints []testEndpoint
		wantIPs   []string
	}{
		{
			name:     "prefer endpoints with node hint, only matching node",
			nodeName: "node-1",
			nodeZone: "zone-a",
			endpoints: []testEndpoint{
				{fakeEndpoint{"10.0.0.1", true, false, sets.New[string]("zone-a"), sets.New[string]("node-1")}},
				{fakeEndpoint{"10.0.0.2", true, false, sets.New[string]("zone-a"), sets.New[string]("node-2")}},
			},
			wantIPs: []string{"10.0.0.1"},
		},
		{
			name:     "prefer endpoints with zone hint if no node hint matches",
			nodeName: "node-3",
			nodeZone: "zone-b",
			endpoints: []testEndpoint{
				{fakeEndpoint{"10.0.0.1", true, false, sets.New[string]("zone-b"), sets.New[string]("node-1")}},
				{fakeEndpoint{"10.0.0.2", true, false, sets.New[string]("zone-a"), sets.New[string]("node-2")}},
			},
			wantIPs: []string{"10.0.0.1"},
		},
		{
			name:     "one endpoint with zone hint, one with none, only zone-hinted returned",
			nodeName: "node-x",
			nodeZone: "zone-a",
			endpoints: []testEndpoint{
				{fakeEndpoint{"10.0.0.1", true, false, sets.New[string]("zone-a"), sets.New[string]()}},
				{fakeEndpoint{"10.0.0.2", true, false, sets.New[string](), sets.New[string]()}},
			},
			wantIPs: []string{"10.0.0.1"},
		},
		{
			name:     "prefer endpoints with zone hint if node hint missing",
			nodeName: "node-1",
			nodeZone: "zone-a",
			endpoints: []testEndpoint{
				{fakeEndpoint{"10.0.0.1", true, false, sets.New[string]("zone-a"), sets.New[string]()}}, // no node hint
				{fakeEndpoint{"10.0.0.2", true, false, sets.New[string]("zone-a"), sets.New[string]()}}, // no node hint
			},
			wantIPs: []string{"10.0.0.1", "10.0.0.2"}, // fallback to zone
		},
		{
			name:     "fallback to all endpoints if no node or zone hint matches",
			nodeName: "node-x",
			nodeZone: "zone-x",
			endpoints: []testEndpoint{
				{fakeEndpoint{"10.0.0.1", true, false, sets.New[string]("zone-a"), sets.New[string]("node-1")}},
				{fakeEndpoint{"10.0.0.2", true, false, sets.New[string]("zone-b"), sets.New[string]("node-2")}},
			},
			wantIPs: []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			name:     "one endpoint with node hint, one with none, only node-hinted returned",
			nodeName: "node-1",
			nodeZone: "zone-a",
			endpoints: []testEndpoint{
				{fakeEndpoint{"10.0.0.1", true, false, sets.New[string]("zone-a"), sets.New[string]("node-1")}},
				{fakeEndpoint{"10.0.0.2", true, false, sets.New[string]("zone-a"), sets.New[string]()}},
			},
			wantIPs: []string{"10.0.0.1"},
		},
		{
			name:     "endpoint with no node or zone hints is ignored for node/zone, fallback to all",
			nodeName: "node-x",
			nodeZone: "zone-x",
			endpoints: []testEndpoint{
				{fakeEndpoint{"10.0.0.1", true, false, sets.New[string](), sets.New[string]()}},
				{fakeEndpoint{"10.0.0.2", true, false, sets.New[string](), sets.New[string]()}},
			},
			wantIPs: []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			name:     "endpoint not ready or terminating is skipped for node and zone hint",
			nodeName: "node-1",
			nodeZone: "zone-a",
			endpoints: []testEndpoint{
				{fakeEndpoint{"10.0.0.1", false, false, sets.New[string]("zone-a"), sets.New[string]("node-1")}},
				{fakeEndpoint{"10.0.0.2", true, false, sets.New[string]("zone-a"), sets.New[string]("node-1")}},
			},
			wantIPs: []string{"10.0.0.2"},
		},
		{
			name:     "endpoint terminating is included",
			nodeName: "node-1",
			nodeZone: "zone-a",
			endpoints: []testEndpoint{
				{fakeEndpoint{"10.0.0.1", false, true, sets.New[string]("zone-a"), sets.New[string]("node-1")}},
				{fakeEndpoint{"10.0.0.2", true, false, sets.New[string]("zone-a"), sets.New[string]("node-1")}},
			},
			wantIPs: []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			name:     "all endpoints not ready or terminating, fallback to all endpoints",
			nodeName: "node-1",
			nodeZone: "zone-a",
			endpoints: []testEndpoint{
				{fakeEndpoint{"10.0.0.1", false, false, sets.New[string]("zone-a"), sets.New[string]("node-1")}},
				{fakeEndpoint{"10.0.0.2", false, false, sets.New[string]("zone-a"), sets.New[string]("node-1")}},
			},
			wantIPs: []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			name:     "one endpoint with node hint but not ready, one with zone hint and ready",
			nodeName: "node-1",
			nodeZone: "zone-a",
			endpoints: []testEndpoint{
				{fakeEndpoint{"10.0.0.1", false, false, sets.New[string]("zone-a"), sets.New[string]("node-1")}}, // not ready
				{fakeEndpoint{"10.0.0.2", true, false, sets.New[string]("zone-a"), sets.New[string]()}},          // ready, zone hint
			},
			wantIPs: []string{"10.0.0.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			var eps []k8sp.Endpoint
			for _, ep := range tt.endpoints {
				eps = append(eps, ep)
			}
			got := proxy.FilterEpsByTrafficDistribution(eps, tt.nodeName, tt.nodeZone)
			var gotIPs []string
			for _, ep := range got {
				gotIPs = append(gotIPs, ep.IP())
			}
			g.Expect(gotIPs).To(ConsistOf(tt.wantIPs))
		})
	}
}
