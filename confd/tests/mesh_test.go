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

func TestMeshTemplates(t *testing.T) {
	tests := []struct {
		name      string
		inputYAML string
		goldenDir string
		envVars   map[string]string
	}{
		{"bgp-export", "mesh/bgp-export/input.yaml", "mesh/bgp-export", nil},
		{"ipip-always", "mesh/ipip-always/input.yaml", "mesh/ipip-always", nil},
		{"ipip-cross-subnet", "mesh/ipip-cross-subnet/input.yaml", "mesh/ipip-cross-subnet", nil},
		{"ipip-off", "mesh/ipip-off/input.yaml", "mesh/ipip-off", nil},
		{"vxlan-always", "mesh/vxlan-always/input.yaml", "mesh/vxlan-always", nil},
		{"hash", "mesh/hash/input.yaml", "mesh/hash", map[string]string{"CALICO_ROUTER_ID": "hash"}},
		{"communities", "mesh/communities/input.yaml", "mesh/communities", nil},
		{"restart-time", "mesh/restart-time/input.yaml", "mesh/restart-time", nil},
		{"route-reflector-mesh-enabled", "mesh/route-reflector-mesh-enabled/input.yaml", "mesh/route-reflector-mesh-enabled", nil},
		{"static-routes", "mesh/static-routes/input.yaml", "mesh/static-routes", nil},
		{"static-routes-exclude-node", "mesh/static-routes-exclude-node/input.yaml", "mesh/static-routes-exclude-node", nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.envVars {
				t.Setenv(k, v)
			}
			runConfdTest(t, tc.inputYAML, tc.goldenDir)
		})
	}
}
