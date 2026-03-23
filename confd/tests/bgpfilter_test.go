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
	tests := []struct {
		name      string
		inputYAML string
		goldenDir string
	}{
		{"single_filter/global_peer", "bgpfilter/single_filter/global_peer/input.yaml", "bgpfilter/single_filter/global_peer"},
		{"single_filter/explicit_peer", "bgpfilter/single_filter/explicit_peer/input.yaml", "bgpfilter/single_filter/explicit_peer"},
		{"multi_filter/global_peer", "bgpfilter/multi_filter/global_peer/input.yaml", "bgpfilter/multi_filter/global_peer"},
		{"multi_filter/explicit_peer", "bgpfilter/multi_filter/explicit_peer/input.yaml", "bgpfilter/multi_filter/explicit_peer"},
		{"node_mesh", "bgpfilter/node_mesh/input.yaml", "bgpfilter/node_mesh"},
		{"match_operators", "bgpfilter/match_operators/input.yaml", "bgpfilter/match_operators"},
		{"match_source", "bgpfilter/match_source/input.yaml", "bgpfilter/match_source"},
		{"match_interface", "bgpfilter/match_interface/input.yaml", "bgpfilter/match_interface"},
		{"filter_names", "bgpfilter/filter_names/input.yaml", "bgpfilter/filter_names"},
		{"import_only/explicit_peer", "bgpfilter/import_only/explicit_peer/input.yaml", "bgpfilter/import_only/explicit_peer"},
		{"import_only/global_peer", "bgpfilter/import_only/global_peer/input.yaml", "bgpfilter/import_only/global_peer"},
		{"v6_only/global_peer", "bgpfilter/v6_only/global_peer/input.yaml", "bgpfilter/v6_only/global_peer"},
		{"export_only/explicit_peer", "bgpfilter/export_only/explicit_peer/input.yaml", "bgpfilter/export_only/explicit_peer"},
		{"export_only/global_peer", "bgpfilter/export_only/global_peer/input.yaml", "bgpfilter/export_only/global_peer"},
		{"v4_only/explicit_peer", "bgpfilter/v4_only/explicit_peer/input.yaml", "bgpfilter/v4_only/explicit_peer"},
		{"v4_only/global_peer", "bgpfilter/v4_only/global_peer/input.yaml", "bgpfilter/v4_only/global_peer"},
		{"v6_only/explicit_peer", "bgpfilter/v6_only/explicit_peer/input.yaml", "bgpfilter/v6_only/explicit_peer"},
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
