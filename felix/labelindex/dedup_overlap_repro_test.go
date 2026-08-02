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
