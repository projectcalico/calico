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

package jump

import (
	"strings"
	"testing"
)

// TestPolicyJumpMapName pins the direction/mode -> map-name mapping so a future
// inversion (the bug this test was added with) cannot regress silently.
func TestPolicyJumpMapName(t *testing.T) {
	cases := []struct {
		name            string
		netkit          bool
		ingressOrEgress string
		wantDir         string // substring that must appear (direction marker)
		wantNetkit      bool   // whether the netkit marker must appear
	}{
		{"tc ingress", false, "ingress", "_ing", false},
		{"tc egress", false, "egress", "_egr", false},
		{"netkit ingress", true, "ingress", "_ing", true},
		{"netkit egress", true, "egress", "_egr", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PolicyJumpMapName(tc.netkit, tc.ingressOrEgress)
			if !strings.Contains(got, tc.wantDir) {
				t.Errorf("PolicyJumpMapName(%v, %q) = %q, want substring %q",
					tc.netkit, tc.ingressOrEgress, got, tc.wantDir)
			}
			hasNetkit := strings.Contains(got, "_nk_")
			if hasNetkit != tc.wantNetkit {
				t.Errorf("PolicyJumpMapName(%v, %q) = %q, want netkit=%v",
					tc.netkit, tc.ingressOrEgress, got, tc.wantNetkit)
			}
			// Direction substrings must be mutually exclusive in the name.
			otherDir := "_egr"
			if tc.wantDir == "_egr" {
				otherDir = "_ing"
			}
			if strings.Contains(got, otherDir) {
				t.Errorf("PolicyJumpMapName(%v, %q) = %q, contains opposite-direction marker %q",
					tc.netkit, tc.ingressOrEgress, got, otherDir)
			}
		})
	}
}
