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

package labelindex_test

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/labelindex"
)

const dedupTestSet = "test-set"

// TestOverlapSuppressorRemoveCoveredByAncestor reproduces CORE-13009: removing a CIDR that a broader
// ancestor still covers must emit nothing, because the removed CIDR was never programmed as its own
// interval element and the ancestor keeps masking its descendants.
func TestOverlapSuppressorRemoveCoveredByAncestor(t *testing.T) {
	RegisterTestingT(t)

	s := labelindex.NewMemberOverlapSuppressor()
	broad := ip.MustParseCIDROrIP("10.0.0.0/16")
	nested := ip.MustParseCIDROrIP("10.0.1.0/24")

	add, removes := s.Add(dedupTestSet, broad)
	Expect(add).To(Equal(broad), "broad CIDR should be programmed")
	Expect(removes).To(BeEmpty())

	add, removes = s.Add(dedupTestSet, nested)
	Expect(add).To(BeNil(), "nested CIDR is covered by the ancestor, so must be suppressed")
	Expect(removes).To(BeEmpty())

	rem, adds := s.Remove(dedupTestSet, nested)
	Expect(rem).To(BeNil(), "nested CIDR was never programmed, so its removal must not be emitted")
	Expect(adds).To(BeEmpty(), "ancestor still covers the range, so nothing is re-exposed")
}

// TestOverlapSuppressorRemoveAncestorReExposesDescendants proves the teardown direction: removing the
// ancestor re-exposes the descendants it had been masking.
func TestOverlapSuppressorRemoveAncestorReExposesDescendants(t *testing.T) {
	RegisterTestingT(t)

	s := labelindex.NewMemberOverlapSuppressor()
	broad := ip.MustParseCIDROrIP("10.0.0.0/16")
	nested := ip.MustParseCIDROrIP("10.0.1.0/24")

	s.Add(dedupTestSet, broad)
	s.Add(dedupTestSet, nested)

	rem, adds := s.Remove(dedupTestSet, broad)
	Expect(rem).To(Equal(broad), "ancestor was programmed, so its removal must be emitted")
	Expect(adds).To(ConsistOf(nested), "previously masked descendant must be re-exposed")
}

// TestOverlapSuppressorRemoveWithoutAncestorEmits is the negative-direction case: with no ancestor
// coverage the removal IS emitted, and any masked descendant is re-exposed.
func TestOverlapSuppressorRemoveWithoutAncestorEmits(t *testing.T) {
	RegisterTestingT(t)

	s := labelindex.NewMemberOverlapSuppressor()
	parent := ip.MustParseCIDROrIP("10.0.1.0/24")
	child := ip.MustParseCIDROrIP("10.0.1.5/32")

	add, _ := s.Add(dedupTestSet, parent)
	Expect(add).To(Equal(parent))

	add, _ = s.Add(dedupTestSet, child)
	Expect(add).To(BeNil(), "child is covered by the parent, so must be suppressed")

	rem, adds := s.Remove(dedupTestSet, parent)
	Expect(rem).To(Equal(parent), "no ancestor covers the parent, so its removal must be emitted")
	Expect(adds).To(ConsistOf(child), "child is no longer masked and must be re-exposed")
}

// TestOverlapSuppressorRemoveMiddleCoveredByAncestor covers a three-level trie: with a broad ancestor
// present, removing a middle CIDR must emit nothing and must not re-expose the still-covered leaf.
func TestOverlapSuppressorRemoveMiddleCoveredByAncestor(t *testing.T) {
	RegisterTestingT(t)

	s := labelindex.NewMemberOverlapSuppressor()
	broad := ip.MustParseCIDROrIP("10.0.0.0/16")
	middle := ip.MustParseCIDROrIP("10.0.1.0/24")
	leaf := ip.MustParseCIDROrIP("10.0.1.5/32")

	s.Add(dedupTestSet, broad)
	s.Add(dedupTestSet, middle)
	s.Add(dedupTestSet, leaf)

	rem, adds := s.Remove(dedupTestSet, middle)
	Expect(rem).To(BeNil(), "middle CIDR was suppressed by the ancestor, so its removal must not be emitted")
	Expect(adds).To(BeEmpty(), "the ancestor still covers the leaf, so nothing is re-exposed")
}

// programmedSet tracks the net set of emitted (dataplane-programmed) CIDRs as Add/Remove results are
// applied, so a test can assert what the dataplane would hold after a sequence of operations. Add
// returns (cidrToProgram, cidrsToWithdraw); Remove returns (cidrToWithdraw, cidrsToReadvertise).
type programmedSet map[string]bool

func (p programmedSet) applyAdd(add ip.CIDR, withdraw []ip.CIDR) {
	if add != nil {
		p[add.String()] = true
	}
	for _, w := range withdraw {
		delete(p, w.String())
	}
}

func (p programmedSet) applyRemove(withdraw ip.CIDR, readvertise []ip.CIDR) {
	if withdraw != nil {
		delete(p, withdraw.String())
	}
	for _, r := range readvertise {
		p[r.String()] = true
	}
}

// TestOverlapSuppressorRemoveAncestorFirstLeavesNoStale exercises (a): when the ancestor is removed
// before the descendants it masks, Remove re-advertises those descendants (ClosestDescendants) even
// though they are themselves about to be removed. The transient re-advertise must be cleaned up so
// that removing every CIDR leaves no stale member behind.
func TestOverlapSuppressorRemoveAncestorFirstLeavesNoStale(t *testing.T) {
	RegisterTestingT(t)

	type step struct {
		op   string // "add" or "remove"
		cidr string
	}
	tests := []struct {
		name  string
		steps []step
	}{
		{
			name: "two levels, ancestor removed before descendant",
			steps: []step{
				{"add", "10.0.0.0/16"},
				{"add", "10.0.1.0/24"},    // suppressed by the ancestor
				{"remove", "10.0.0.0/16"}, // re-advertises 10.0.1.0/24
				{"remove", "10.0.1.0/24"}, // the transient re-advertise must be removed
			},
		},
		{
			name: "three levels, removed top-down",
			steps: []step{
				{"add", "10.0.0.0/16"},
				{"add", "10.0.1.0/24"},
				{"add", "10.0.1.5/32"},
				{"remove", "10.0.0.0/16"},
				{"remove", "10.0.1.0/24"},
				{"remove", "10.0.1.5/32"},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			RegisterTestingT(t)

			s := labelindex.NewMemberOverlapSuppressor()
			prog := programmedSet{}
			readvertised := false
			for _, st := range tc.steps {
				cidr := ip.MustParseCIDROrIP(st.cidr)
				switch st.op {
				case "add":
					add, withdraw := s.Add(dedupTestSet, cidr)
					prog.applyAdd(add, withdraw)
				case "remove":
					withdraw, readd := s.Remove(dedupTestSet, cidr)
					if len(readd) > 0 {
						readvertised = true
					}
					prog.applyRemove(withdraw, readd)
				}
			}
			Expect(readvertised).To(BeTrue(),
				"removing an ancestor before its descendants must transiently re-advertise the masked descendant")
			Expect(prog).To(BeEmpty(),
				"after removing every CIDR, the transient re-advertise must leave no stale member")
		})
	}
}

// TestOverlapSuppressorIPv6 exercises (d): the suppressor discriminates address family by a string
// check for ":" in the CIDR, keeping v4 and v6 in separate tries. IPv6 CIDRs must nest and suppress
// exactly like IPv4, and a v4 entry must never mask a v6 entry (or vice versa) in the same set.
func TestOverlapSuppressorIPv6(t *testing.T) {
	RegisterTestingT(t)

	t.Run("IPv6 nesting is suppressed and re-exposed like IPv4", func(t *testing.T) {
		RegisterTestingT(t)

		s := labelindex.NewMemberOverlapSuppressor()
		broad := ip.MustParseCIDROrIP("fd00::/16")
		nested := ip.MustParseCIDROrIP("fd00:1::/32")

		add, withdraw := s.Add(dedupTestSet, broad)
		Expect(add).To(Equal(broad), "broad IPv6 CIDR should be programmed")
		Expect(withdraw).To(BeEmpty())

		add, withdraw = s.Add(dedupTestSet, nested)
		Expect(add).To(BeNil(), "nested IPv6 CIDR is covered by the ancestor, so must be suppressed")
		Expect(withdraw).To(BeEmpty())

		rem, readd := s.Remove(dedupTestSet, broad)
		Expect(rem).To(Equal(broad), "IPv6 ancestor was programmed, so its removal must be emitted")
		Expect(readd).To(ConsistOf(nested), "removing the IPv6 ancestor must re-expose its descendant")
	})

	t.Run("v4 and v6 entries in one set do not mask each other", func(t *testing.T) {
		RegisterTestingT(t)

		s := labelindex.NewMemberOverlapSuppressor()
		v4 := ip.MustParseCIDROrIP("0.0.0.0/0")
		v6 := ip.MustParseCIDROrIP("::/0")

		add, _ := s.Add(dedupTestSet, v4)
		Expect(add).To(Equal(v4), "IPv4 default route must be programmed")

		add, withdraw := s.Add(dedupTestSet, v6)
		Expect(add).To(Equal(v6),
			"IPv6 default route lives in a separate trie (':' discriminates family), so it must not be suppressed by the IPv4 entry")
		Expect(withdraw).To(BeEmpty(), "adding the IPv6 entry must not withdraw the IPv4 entry")
	})
}
