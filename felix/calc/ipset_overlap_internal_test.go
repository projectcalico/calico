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

package calc

import "testing"

// nftables hash:net IP sets are programmed with the interval flag, which rejects
// overlapping intervals (e.g. 192.168.0.0/16 and 192.168.82.2/32). Whenever the
// dataplane *might* end up nftables, the calc graph must suppress overlaps so
// that the dataplane never receives a /32 contained in a previously-emitted
// supernet. NFTablesMode=Auto resolves to nftables when kube-proxy is in
// nftables mode, so it must opt in to suppression too.
func TestShouldSuppressIPSetOverlaps(t *testing.T) {
	cases := []struct {
		mode string
		want bool
	}{
		{"Enabled", true},
		{"Auto", true},
		{"Disabled", false},
	}
	for _, tc := range cases {
		if got := shouldSuppressIPSetOverlaps(tc.mode); got != tc.want {
			t.Errorf("shouldSuppressIPSetOverlaps(%q) = %v, want %v", tc.mode, got, tc.want)
		}
	}
}
