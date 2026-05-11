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

package defaults

import "testing"

func TestMKLookup(t *testing.T) {
	t.Cleanup(resetValues)
	setValues(map[string]string{
		KeyOrganization: "myorg",
		KeyGitRepo:      "",
	})
	cases := []struct {
		key     string
		wantVal string
		wantOK  bool
	}{
		{KeyOrganization, "myorg", true},
		{KeyGitRepo, "", false},    // empty value falls through
		{"UNKNOWN_KEY", "", false}, // missing key falls through
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			v, ok := MK(tc.key).Lookup()
			if v != tc.wantVal || ok != tc.wantOK {
				t.Errorf("MK(%q).Lookup() = (%q, %v), want (%q, %v)", tc.key, v, ok, tc.wantVal, tc.wantOK)
			}
		})
	}
}
