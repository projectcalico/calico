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

package model_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/randfill"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// fullyPopulated returns a block with every field set to a non-zero value. The
// seed makes it deterministic, so it doubles as a snapshot of the pre-mutation
// state in the aliasing test below. NilChance(0) guarantees no field is left at
// its zero value, so a Clone that drops a field is caught by the round-trip.
func fullyPopulated() model.AllocationBlock {
	var b model.AllocationBlock
	randfill.NewWithSeed(2026).NilChance(0).NumElements(2, 4).Funcs(
		func(t *metav1.Time, c randfill.Continue) {
			*t = metav1.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		},
	).Fill(&b)
	return b
}

var _ = Describe("AllocationBlock Clone", func() {
	It("copies every field", func() {
		orig := fullyPopulated()
		Expect(*orig.Clone()).To(Equal(orig))
	})

	It("does not alias mutable fields with the original", func() {
		orig := fullyPopulated()
		clone := orig.Clone()

		// Mutate every reference-typed field on the original through the value it
		// points at, not by reassigning the field. A shallow copy would let the
		// clone observe these changes.
		orig.CIDR.IP[0]++
		*orig.Allocations[0]++
		*orig.Affinity += "-mutated"
		*orig.HostAffinity += "-mutated"
		*orig.AffinityClaimTime = metav1.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
		orig.Unallocated[0]++
		for k := range orig.SequenceNumberForAllocation {
			orig.SequenceNumberForAllocation[k]++
		}
		orig.Attributes[0].ActiveOwnerAttrs["mutated"] = "true"
		*orig.Attributes[0].HandleID += "-mutated"
		*orig.Attributes[0].ReleasedAt = metav1.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

		Expect(*clone).To(Equal(fullyPopulated()))
	})
})
