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
	runOneshotTests(t, []oneshotTestCase{
		{name: "bgp-export", goldenDir: "mesh/bgp-export"},
		{name: "ipip-always", goldenDir: "mesh/ipip-always"},
		{name: "ipip-cross-subnet", goldenDir: "mesh/ipip-cross-subnet"},
		{name: "ipip-off", goldenDir: "mesh/ipip-off"},
		{name: "vxlan-always", goldenDir: "mesh/vxlan-always"},
		{name: "hash", goldenDir: "mesh/hash", envVars: map[string]string{"CALICO_ROUTER_ID": "hash"}},
		{name: "communities", goldenDir: "mesh/communities"},
		{name: "restart-time", goldenDir: "mesh/restart-time"},
		{name: "route-reflector-mesh-enabled", goldenDir: "mesh/route-reflector-mesh-enabled"},
		{name: "static-routes", goldenDir: "mesh/static-routes", kddOnly: true},
		{name: "static-routes-exclude-node", goldenDir: "mesh/static-routes-exclude-node", kddOnly: true},
		{name: "static-routes-no-ipv4-address", goldenDir: "mesh/static-routes-no-ipv4-address", envVars: map[string]string{"CALICO_ROUTER_ID": "10.10.10.10"}, kddOnly: true},
	})
}
