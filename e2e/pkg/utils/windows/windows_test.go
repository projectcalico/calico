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

package windows

import "testing"

func TestSelectsWindows(t *testing.T) {
	windowsSpec := []string{"sig-calico", "Covers:NetworkPolicy", "Covers:Windows"}
	linuxSpec := []string{"sig-calico", "Covers:NetworkPolicy"}

	tests := []struct {
		name        string
		focus       []string
		labelFilter string
		specLabels  []string
		want        bool
	}{
		{name: "focus on Covers:Windows", focus: []string{"Covers:Windows"}, specLabels: windowsSpec, want: true},
		{name: "no selection", specLabels: windowsSpec, want: false},
		{name: "windows lane label filter", labelFilter: "(sig-calico && Covers:Windows) && !Requires:KubeVirt", specLabels: windowsSpec, want: true},
		{name: "linux lane runs a windows-capable spec", labelFilter: "sig-calico && !Requires:KubeVirt", specLabels: windowsSpec, want: false},
		{name: "negated windows label", labelFilter: "sig-calico && !Covers:Windows", specLabels: linuxSpec, want: false},
		{name: "windows label is one alternative", labelFilter: "Covers:Windows || Covers:NetworkPolicy", specLabels: windowsSpec, want: false},
		{name: "outside a spec", labelFilter: "sig-calico && Covers:Windows", want: false},
		{name: "unparseable filter", labelFilter: "sig-calico &&", specLabels: windowsSpec, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := selectsWindows(tc.focus, tc.labelFilter, tc.specLabels); got != tc.want {
				t.Errorf("selectsWindows(%q, %q, %q) = %v, want %v", tc.focus, tc.labelFilter, tc.specLabels, got, tc.want)
			}
		})
	}
}
