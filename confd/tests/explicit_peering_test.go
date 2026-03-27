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

func TestExplicitPeeringTemplates(t *testing.T) {
	tests := []struct {
		name      string
		inputYAML string
		goldenDir string
	}{
		{"global", "explicit_peering/global/input.yaml", "explicit_peering/global"},
		{"global-external", "explicit_peering/global-external/input.yaml", "explicit_peering/global-external"},
		{"global-ipv6", "explicit_peering/global-ipv6/input.yaml", "explicit_peering/global-ipv6"},
		{"specific_node", "explicit_peering/specific_node/input.yaml", "explicit_peering/specific_node"},
		{"selectors", "explicit_peering/selectors/input.yaml", "explicit_peering/selectors"},
		{"route_reflector", "explicit_peering/route_reflector/input.yaml", "explicit_peering/route_reflector"},
		{"route_reflector_v6_by_ip", "explicit_peering/route_reflector_v6_by_ip/input.yaml", "explicit_peering/route_reflector_v6_by_ip"},
		{"keepnexthop", "explicit_peering/keepnexthop/input.yaml", "explicit_peering/keepnexthop"},
		{"keepnexthop-global", "explicit_peering/keepnexthop-global/input.yaml", "explicit_peering/keepnexthop-global"},
		{"local-as", "explicit_peering/local-as/input.yaml", "explicit_peering/local-as"},
		{"local-as-global", "explicit_peering/local-as-global/input.yaml", "explicit_peering/local-as-global"},
		{"local-as-ipv6", "explicit_peering/local-as-ipv6/input.yaml", "explicit_peering/local-as-ipv6"},
		{"local-as-global-ipv6", "explicit_peering/local-as-global-ipv6/input.yaml", "explicit_peering/local-as-global-ipv6"},
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
