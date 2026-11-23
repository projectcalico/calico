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

package policyscale

import (
	"testing"

	googleproto "google.golang.org/protobuf/proto"
)

// The composite holds each measured preset's policies exactly as the preset builds them alone, so
// tests and benchmarks of the composite stand in for both.
func TestCompositeHoldsEachPresetUnchanged(t *testing.T) {
	composite := compositeFixture()
	for _, c := range []struct {
		dir   Direction
		alone *Fixture
	}{
		{Ingress, baselineFixture()},
		{Egress, egressFixture()},
	} {
		got, want := composite.tiers[0].policies[c.dir], c.alone.tiers[0].policies[c.dir]
		if len(got) == 0 || len(got) != len(want) {
			t.Fatalf("%s: %d policies in the composite, %d alone", c.dir, len(got), len(want))
		}
		for i := range want {
			if got[i].name != want[i].name || !googleproto.Equal(got[i].policy, want[i].policy) {
				t.Fatalf("%s: policy %d differs: %s against %s", c.dir, i, got[i].name, want[i].name)
			}
		}
	}
}
