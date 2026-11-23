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
	"net/netip"
	"strconv"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestFingerprintFollowsTheFixture(t *testing.T) {
	egress := func(seed int64) *Fixture {
		spec, err := Preset("egress", seed)
		if err != nil {
			t.Fatal(err)
		}
		return Build(spec)
	}
	a := egress(DefaultSeed)
	if b := egress(DefaultSeed); a.Fingerprint() != b.Fingerprint() {
		t.Errorf("one preset and seed gave fingerprints %s and %s", a.Fingerprint(), b.Fingerprint())
	}
	if b := egress(DefaultSeed + 1); a.Fingerprint() == b.Fingerprint() {
		t.Errorf("another seed kept fingerprint %s", a.Fingerprint())
	}
	if a.Fingerprint() == compositeFixture().Fingerprint() {
		t.Errorf("egress and composite share fingerprint %s", a.Fingerprint())
	}
	// The shapes preset draws nothing at random, so its seed doesn't change the set.
	s1, _ := Preset("shapes", 1)
	s2, _ := Preset("shapes", 2)
	if Build(s1).Fingerprint() != Build(s2).Fingerprint() {
		t.Error("the shapes preset's fingerprint depends on a seed it doesn't use")
	}
	if _, err := Preset("nope", DefaultSeed); err == nil {
		t.Error("an unknown preset gave no error")
	}
}

// The fingerprint comes from what was built, so a generator that builds something else from the
// same Spec gets another fingerprint, including for a set the store leaves out.
func TestFingerprintSeesTheBuiltFixture(t *testing.T) {
	build := func() *Fixture {
		spec := Baseline()
		spec.Baseline.MissingIPSets = 2
		return Build(spec)
	}
	want := build().Fingerprint()
	for _, change := range []struct {
		name string
		mod  func(*Fixture)
	}{
		{"a set member", func(fx *Fixture) {
			for _, id := range fx.setOrder {
				if s := fx.sets[id]; !s.missing && len(s.members) > 0 {
					s.members[0] = "10.127.255.254/32"
					return
				}
			}
		}},
		{"a member of a set the store leaves out", func(fx *Fixture) {
			for _, id := range fx.setOrder {
				if s := fx.sets[id]; s.missing && len(s.members) > 0 {
					s.members[0] = "10.127.255.254/32"
					return
				}
			}
			t.Fatal("the baseline preset has no missing set with members")
		}},
		{"a tier's default action", func(fx *Fixture) { fx.tiers[0].defaultAction = "Pass" }},
		{"a rule's action", func(fx *Fixture) {
			p := fx.tiers[0].policies[Ingress][0]
			p.policy.InboundRules[0].Action = "allow"
		}},
	} {
		fx := build()
		change.mod(fx)
		if fx.Fingerprint() == want {
			t.Errorf("changing %s kept the fingerprint", change.name)
		}
	}
}

// Every applied object says which fixture it came from, so objects left over from another set can
// be found, and the tiers say how many there should be, so a partly applied set shows.
func TestRenderedObjectsCarryTheFingerprint(t *testing.T) {
	spec, err := Preset("shapes", DefaultSeed)
	if err != nil {
		t.Fatal(err)
	}
	fx := Build(spec)
	objects := fx.Resources(ResourceOptions{})
	tiers := 0
	for _, o := range objects {
		m := o.(metav1.Object)
		if got := m.GetLabels()[FixtureLabel]; got != fx.Fingerprint() {
			t.Errorf("%T %s: label %q, want %s", o, m.GetName(), got, fx.Fingerprint())
		}
		if _, ok := o.(*v3.Tier); ok {
			tiers++
			if got := m.GetAnnotations()[ObjectsAnnotation]; got != strconv.Itoa(len(objects)) {
				t.Errorf("tier %s: %s=%q, want %d", m.GetName(), ObjectsAnnotation, got, len(objects))
			}
		}
		if set, ok := o.(*v3.GlobalNetworkSet); ok && set.Labels[defaultSetLabelKey] == "" {
			t.Errorf("network set %s lost the label rules select it by", set.Name)
		}
	}
	if tiers == 0 {
		t.Fatal("no tiers rendered")
	}
}

// Prefixes covers every address a fixture's sets, rules and flows use, so a sink routed for them
// answers every flow.
func TestPrefixesCoverTheFixture(t *testing.T) {
	shapes, err := Preset("shapes", DefaultSeed)
	if err != nil {
		t.Fatal(err)
	}
	for name, fx := range map[string]*Fixture{"composite": compositeFixture(), "shapes": Build(shapes)} {
		prefixes := fx.Prefixes()
		covered := func(a netip.Addr) bool {
			for _, p := range prefixes {
				if p.Contains(a.Unmap()) {
					return true
				}
			}
			return false
		}
		check := func(what string, a netip.Addr) {
			if !covered(a) {
				t.Fatalf("%s: %s %s is outside %v", name, what, a, prefixes)
			}
		}
		for _, id := range fx.setOrder {
			for _, m := range fx.sets[id].members {
				if pfx, err := netip.ParsePrefix(m); err == nil {
					check("set member", pfx.Addr())
				}
			}
		}
		for _, t := range fx.tiers {
			for _, policies := range t.policies {
				for _, p := range policies {
					for _, r := range p.rules {
						for _, n := range append(append(append(append([]netip.Prefix{r.dstNet}, r.srcNets...), r.notSrcNets...), r.dstNets...), r.notDstNets...) {
							if n.IsValid() {
								check("rule CIDR", n.Addr())
							}
						}
					}
				}
			}
		}
		for _, dir := range []Direction{Ingress, Egress} {
			var flows []*Flow
			if fx.Spec.Shapes != nil {
				for _, sf := range fx.ShapeFlows(dir) {
					flows = append(flows, sf.Flow)
				}
			} else {
				s := fx.NewSampler(1, FlowModel{Direction: dir, MissFraction: 0.2})
				for range 2000 {
					flows = append(flows, s.Next())
				}
			}
			for _, f := range flows {
				src, _ := netip.AddrFromSlice(f.SrcIP)
				dst, _ := netip.AddrFromSlice(f.DstIP)
				check("flow source", src)
				check("flow destination", dst)
			}
		}
	}
}
