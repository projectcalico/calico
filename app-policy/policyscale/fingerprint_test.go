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

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

func TestFingerprintFollowsTheFixture(t *testing.T) {
	a, err := Preset("composite", DefaultSeed)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Preset("composite", DefaultSeed)
	if Fingerprint(a) != Fingerprint(b) {
		t.Errorf("the same preset and seed gave fingerprints %s and %s", Fingerprint(a), Fingerprint(b))
	}
	for _, other := range []struct {
		name string
		seed int64
	}{{"composite", DefaultSeed + 1}, {"egress", DefaultSeed}, {"shapes", DefaultSeed}} {
		o, err := Preset(other.name, other.seed)
		if err != nil {
			t.Fatal(err)
		}
		if Fingerprint(o) == Fingerprint(a) {
			t.Errorf("%s with seed %d has the composite's fingerprint %s", other.name, other.seed, Fingerprint(a))
		}
	}
	if _, err := Preset("nope", DefaultSeed); err == nil {
		t.Error("an unknown preset gave no error")
	}
}

// The fingerprint is on the applied tiers, so a tool can read what a cluster has.
func TestRenderedTiersCarryTheFingerprint(t *testing.T) {
	spec, err := Preset("shapes", DefaultSeed)
	if err != nil {
		t.Fatal(err)
	}
	fx := Build(spec)
	tiers := 0
	for _, o := range fx.Resources(ResourceOptions{}) {
		tier, ok := o.(*v3.Tier)
		if !ok {
			continue
		}
		tiers++
		if got := tier.Annotations[FingerprintAnnotation]; got != Fingerprint(fx.Spec) {
			t.Errorf("tier %s: annotation %q, want %s", tier.Name, got, Fingerprint(fx.Spec))
		}
	}
	if tiers == 0 {
		t.Fatal("no tiers rendered")
	}
}
