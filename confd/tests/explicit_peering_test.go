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
	runOneshotTests(t, []oneshotTestCase{
		{name: "global", goldenDir: "explicit_peering/global"},
		{name: "global-external", goldenDir: "explicit_peering/global-external"},
		{name: "global-ipv6", goldenDir: "explicit_peering/global-ipv6"},
		{name: "specific_node", goldenDir: "explicit_peering/specific_node"},
		{name: "selectors", goldenDir: "explicit_peering/selectors"},
		{name: "route_reflector", goldenDir: "explicit_peering/route_reflector"},
		{name: "route_reflector_v6_by_ip", goldenDir: "explicit_peering/route_reflector_v6_by_ip"},
		{name: "keepnexthop", goldenDir: "explicit_peering/keepnexthop"},
		{name: "keepnexthop-global", goldenDir: "explicit_peering/keepnexthop-global"},
		{name: "local-as", goldenDir: "explicit_peering/local-as"},
		{name: "local-as-global", goldenDir: "explicit_peering/local-as-global"},
		{name: "local-as-ipv6", goldenDir: "explicit_peering/local-as-ipv6"},
		{name: "local-as-global-ipv6", goldenDir: "explicit_peering/local-as-global-ipv6"},
	})
}
