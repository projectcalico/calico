// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tests

import "testing"

func TestIgnoredInterfacesTemplates(t *testing.T) {
	for _, be := range activeBackends {
		t.Run(be.name, func(t *testing.T) {
			runConfdTest(t, be, "ignored_interfaces/input.yaml", "ignored_interfaces")
		})
	}
}

func TestReachableByTemplates(t *testing.T) {
	tests := []struct {
		name      string
		inputYAML string
		goldenDir string
	}{
		{"global_peers", "reachable_by/global_peers/input.yaml", "reachable_by/global_peers"},
		{"route_reflectors", "reachable_by/route_reflectors/input.yaml", "reachable_by/route_reflectors"},
	}

	for _, be := range activeBackends {
		t.Run(be.name, func(t *testing.T) {
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					runConfdTest(t, be, tc.inputYAML, tc.goldenDir)
				})
			}
		})
	}
}

func TestFelixClusterRoutingTemplates(t *testing.T) {
	for _, be := range activeBackends {
		t.Run(be.name, func(t *testing.T) {
			runConfdTest(t, be, "felix_cluster_routing/input.yaml", "felix_cluster_routing")
		})
	}
}

func TestNextHopModeTemplates(t *testing.T) {
	tests := []struct {
		name      string
		inputYAML string
		goldenDir string
	}{
		{"global_peers", "next_hop_mode/global_peers/input.yaml", "next_hop_mode/global_peers"},
		{"route_reflectors", "next_hop_mode/route_reflectors/input.yaml", "next_hop_mode/route_reflectors"},
	}

	for _, be := range activeBackends {
		t.Run(be.name, func(t *testing.T) {
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					runConfdTest(t, be, tc.inputYAML, tc.goldenDir)
				})
			}
		})
	}
}

func TestReversePeeringTemplates(t *testing.T) {
	tests := []struct {
		name      string
		inputYAML string
		goldenDir string
	}{
		{"manual", "reverse_peering/manual/input.yaml", "reverse_peering/manual"},
		{"auto", "reverse_peering/auto/input.yaml", "reverse_peering/auto"},
	}

	for _, be := range activeBackends {
		t.Run(be.name, func(t *testing.T) {
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					runConfdTest(t, be, tc.inputYAML, tc.goldenDir)
				})
			}
		})
	}
}
