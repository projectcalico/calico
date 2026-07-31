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
	runOneshotTests(t, []oneshotTestCase{
		{name: "ignored_interfaces", goldenDir: "ignored_interfaces"},
	})
}

func TestReachableByTemplates(t *testing.T) {
	runOneshotTests(t, []oneshotTestCase{
		{name: "global_peers", goldenDir: "reachable_by/global_peers"},
		{name: "route_reflectors", goldenDir: "reachable_by/route_reflectors"},
	})
}

func TestFelixClusterRoutingTemplates(t *testing.T) {
	runOneshotTests(t, []oneshotTestCase{
		{name: "felix_cluster_routing", goldenDir: "felix_cluster_routing"},
	})
}

func TestNextHopModeTemplates(t *testing.T) {
	runOneshotTests(t, []oneshotTestCase{
		{name: "global_peers", goldenDir: "next_hop_mode/global_peers"},
		{name: "route_reflectors", goldenDir: "next_hop_mode/route_reflectors"},
	})
}

func TestReversePeeringTemplates(t *testing.T) {
	runOneshotTests(t, []oneshotTestCase{
		{name: "manual", goldenDir: "reverse_peering/manual"},
		{name: "auto", goldenDir: "reverse_peering/auto"},
	})
}
