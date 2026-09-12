// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

// Direction of the rules a policy carries, and of an evaluation.
type Direction int

const (
	Ingress Direction = iota
	Egress
)

func (d Direction) String() string {
	if d == Egress {
		return "egress"
	}
	return "ingress"
}

// Spec describes a synthetic policy set applied to one endpoint. A nil preset is left out.
type Spec struct {
	// Seed drives every random choice. Two Specs that are equal build identical fixtures.
	Seed     int64
	Baseline *BaselineParams
	Egress   *EgressParams
}

// DefaultSeed is the seed the presets use; it is the one the original benchmarks were written
// with, so their numbers stay comparable.
const DefaultSeed = 20200

// SizeBucket is one bucket of an IP set size histogram: Sets sets of between MinSize and MaxSize
// members each.
type SizeBucket struct {
	Sets, MinSize, MaxSize int
}

// BaselineParams describes a policy store dominated by "baseline" policies: every policy applies
// to the endpoint, and almost every rule is a Pass. The rules are ingress rules.
type BaselineParams struct {
	Tier           string
	Policies       int
	RulesPerPolicy int
	// DenyRules and AllowRules are spread at random over the rule slots; every other rule is a Pass.
	DenyRules  int
	AllowRules int
	// IPSetRefFraction is the fraction of rules that reference an IP set. A referencing rule pairs
	// the reference with a negated reference to the sentinel set (which holds the denied flow's
	// addresses) so that it reaches the set lookup whatever order the engine evaluates criteria in
	// and still misses when the referenced set is absent. Rules with no reference are guarded by a
	// destination port no generated flow uses (BaselineGuardPort).
	IPSetRefFraction float64
	// MissingIPSets is how many referenced sets to leave out of the store, reproducing the
	// "IPSet not found" warning storm seen when the store is out of sync.
	MissingIPSets int
	// SizeHistogram is the IP set size distribution. Members are unique /32s from 10.0.0.0/9.
	SizeHistogram []SizeBucket
}

// PortWeight is the fraction of egress rules whose destination ports include Port.
type PortWeight struct {
	Port     int32
	Fraction float64
}

// PortCount is the fraction of egress rules that carry Count destination ports.
type PortCount struct {
	Count    int
	Fraction float64
}

// EgressParams describes a single-tier destination allow-list: every policy applies to the
// endpoint, every rule is a Pass matching a destination address plus a handful of destination
// ports, and a flow that matches nothing meets the tier default deny.
type EgressParams struct {
	Tier           string
	Policies       int
	RulesPerPolicy int
	// IPSetRuleFraction is the fraction of rules whose destination is an IP set (a selector, once
	// it reaches the engine); the rest carry a CIDR. CIDRs are handed out sequentially from
	// 10.0.0.0/9 so that no two rules share one.
	IPSetRuleFraction float64
	// IPSets and MembersPerSet size the destination sets. Members are unique /32s from
	// 10.128.0.0/9, disjoint from the rule CIDRs.
	IPSets        int
	MembersPerSet int
	// PortWeights is the head of the destination port distribution; PortsPerRule the spread of
	// port counts per rule. Rules top up from a long tail of otherwise-unique ports.
	PortWeights  []PortWeight
	PortsPerRule []PortCount
	// TargetDepth, when positive, turns the rule at this fraction of the walk into an Allow with a
	// CIDR and a port of its own, so that a flow aimed at it matches nothing earlier. The
	// benchmarks use it to measure a match at a known depth; see Fixture.EgressTarget.
	TargetDepth float64
}

// DefaultBaseline returns the anonymised per-node scale measured in a large production
// deployment: 294 policies of 68 rules, ~24% referencing one of 3,708 IP sets, dominated by tiny
// sets with a long tail of large ones. The measured sets held ~256k members in total; drawn
// uniformly within each bucket the histogram gives about 1M, which the tests pin.
func DefaultBaseline() BaselineParams {
	return BaselineParams{
		Tier:             "perimeter",
		Policies:         294,
		RulesPerPolicy:   68,
		DenyRules:        10,
		AllowRules:       1,
		IPSetRefFraction: 0.242, // ~4,838 IP set references across 294*68 rules.
		SizeHistogram: []SizeBucket{
			{4, 0, 0},
			{3035, 1, 9},
			{446, 10, 99},
			{64, 100, 999},
			{158, 1000, 9999},
			{1, 54566, 54566},
		},
	}
}

// DefaultEgress returns the second rule-set shape measured in production: 301 policies of 62
// egress rules (18,662 in all), 4,644 of 18,675 measured rules with a selector destination, and
// the measured port distribution (443 on 18% of rules, 11001 and 27054 on 12% each, 80 on 8%;
// median 2 ports per rule, mean ~5). The target sits at 65% of the walk.
func DefaultEgress() EgressParams {
	return EgressParams{
		Tier:              "perimeter",
		Policies:          301,
		RulesPerPolicy:    62,
		IPSetRuleFraction: 0.25,
		IPSets:            3862,
		MembersPerSet:     3,
		PortWeights: []PortWeight{
			{443, 0.182},
			{11001, 0.123},
			{27054, 0.122},
			{80, 0.081},
		},
		PortsPerRule: []PortCount{
			{1, 0.25},
			{2, 0.45},
			{3, 0.15},
			{8, 0.10},
			{20, 0.05},
		},
		TargetDepth: 0.65,
	}
}

// Baseline is the baseline preset on its own.
func Baseline() Spec {
	p := DefaultBaseline()
	return Spec{Seed: DefaultSeed, Baseline: &p}
}

// EgressAllowList is the egress allow-list preset on its own.
func EgressAllowList() Spec {
	p := DefaultEgress()
	return Spec{Seed: DefaultSeed, Egress: &p}
}

// Composite applies both presets to one endpoint: the baseline set governs its ingress
// evaluations and the allow-list its egress evaluations. This is the reference set the
// PMREQ-954 targets are quoted against.
func Composite() Spec {
	b, e := DefaultBaseline(), DefaultEgress()
	return Spec{Seed: DefaultSeed, Baseline: &b, Egress: &e}
}
