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

func TestBGPFilterTemplates(t *testing.T) {
	runOneshotTests(t, []oneshotTestCase{
		{name: "single_filter/global_peer", goldenDir: "bgpfilter/single_filter/global_peer"},
		{name: "single_filter/explicit_peer", goldenDir: "bgpfilter/single_filter/explicit_peer"},
		{name: "multi_filter/global_peer", goldenDir: "bgpfilter/multi_filter/global_peer"},
		{name: "multi_filter/explicit_peer", goldenDir: "bgpfilter/multi_filter/explicit_peer"},
		{name: "node_mesh", goldenDir: "bgpfilter/node_mesh"},
		{name: "match_operators", goldenDir: "bgpfilter/match_operators"},
		{name: "match_source", goldenDir: "bgpfilter/match_source"},
		{name: "match_interface", goldenDir: "bgpfilter/match_interface"},
		{name: "filter_names", goldenDir: "bgpfilter/filter_names"},
		{name: "import_only/explicit_peer", goldenDir: "bgpfilter/import_only/explicit_peer"},
		{name: "import_only/global_peer", goldenDir: "bgpfilter/import_only/global_peer"},
		{name: "v6_only/global_peer", goldenDir: "bgpfilter/v6_only/global_peer"},
		{name: "export_only/explicit_peer", goldenDir: "bgpfilter/export_only/explicit_peer"},
		{name: "export_only/global_peer", goldenDir: "bgpfilter/export_only/global_peer"},
		{name: "v4_only/explicit_peer", goldenDir: "bgpfilter/v4_only/explicit_peer"},
		{name: "v4_only/global_peer", goldenDir: "bgpfilter/v4_only/global_peer"},
		{name: "v6_only/explicit_peer", goldenDir: "bgpfilter/v6_only/explicit_peer"},
		{name: "communities_and_operations", goldenDir: "bgpfilter/communities_and_operations"},
		{name: "peer_type", goldenDir: "bgpfilter/peer_type"},
		{name: "as_path_and_priority", goldenDir: "bgpfilter/as_path_and_priority"},
		{name: "large_community", goldenDir: "bgpfilter/large_community"},
		{name: "kubevirt_live_migration", goldenDir: "bgpfilter/kubevirt_live_migration"},
	})
}
