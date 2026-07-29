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

package describe

import "testing"

func TestMentionsUnnegated(t *testing.T) {
	const label = "RequiresAuthzWebhook"

	for _, tc := range []struct {
		expr string
		want bool
	}{
		{"", false},
		{"RequiresAuthzWebhook", true},
		{"RequiresAuthzWebhook && !Disruptive", true},
		{"!Disruptive && RequiresAuthzWebhook", true},
		{"(RequiresAuthzWebhook || Serial)", true},
		{"!RequiresAuthzWebhook", false},
		{"! RequiresAuthzWebhook", false},
		{"Serial && !RequiresAuthzWebhook", false},
		{"!(RequiresAuthzWebhook)", false},
		{"RequiresReadPathTierRBAC", false},
		// A double mention where one side is negated still counts as selecting it: the run
		// named the label affirmatively somewhere, so failing beats silently skipping.
		{"!RequiresAuthzWebhook || RequiresAuthzWebhook", true},
	} {
		if got := mentionsUnnegated(tc.expr, label); got != tc.want {
			t.Errorf("mentionsUnnegated(%q, %q) = %v, want %v", tc.expr, label, got, tc.want)
		}
	}
}
