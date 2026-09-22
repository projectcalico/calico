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

package common

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

var _ = Describe("MergeOwnerReferences", func() {
	ref := func(name, uid string) metav1.OwnerReference {
		return metav1.OwnerReference{
			APIVersion: "operator.tigera.io/v1",
			Kind:       "EgressGateway",
			Name:       name,
			UID:        types.UID(uid),
		}
	}
	refA := ref("egw-a", "aaaa-1111")
	refB := ref("egw-b", "bbbb-2222")

	It("is convergent regardless of which owner writes last", func() {
		// Each controller passes only its own reference as desired. Whichever
		// writes second must reproduce the object it found, or the two rewrite
		// the object in turn on every reconcile.
		byA := MergeOwnerReferences([]metav1.OwnerReference{refA}, []metav1.OwnerReference{refB, refA})
		byB := MergeOwnerReferences([]metav1.OwnerReference{refB}, []metav1.OwnerReference{refA, refB})
		Expect(byA).To(Equal(byB))

		// Merging a reference already present changes nothing.
		Expect(MergeOwnerReferences([]metav1.OwnerReference{refA}, byA)).To(Equal(byA))
	})

	It("orders the result by UID", func() {
		merged := MergeOwnerReferences([]metav1.OwnerReference{refB}, []metav1.OwnerReference{refA})
		Expect(merged).To(Equal([]metav1.OwnerReference{refA, refB}))
	})

	It("keeps desired's version of a reference that is already on the object", func() {
		// A re-rendered reference with corrected fields (e.g. a bumped APIVersion)
		// must replace the stored one.
		updated := refA
		updated.APIVersion = "operator.tigera.io/v2"
		merged := MergeOwnerReferences([]metav1.OwnerReference{updated}, []metav1.OwnerReference{refA, refB})
		Expect(merged).To(ConsistOf(updated, refB))
	})

	It("deduplicates by UID even when pointer fields differ", func() {
		// The pointer fields make whole-struct comparison identity-based: a
		// reference with Controller set and one without are the same owner.
		controller := refA
		controller.Controller = ptr.To(true)
		merged := MergeOwnerReferences([]metav1.OwnerReference{controller}, []metav1.OwnerReference{refA, refB})
		Expect(merged).To(HaveLen(2))
		Expect(merged).To(ContainElement(controller))
	})

	It("does not mutate the caller's slices", func() {
		desired := make([]metav1.OwnerReference, 1, 3)
		desired[0] = refA
		current := []metav1.OwnerReference{refB}
		MergeOwnerReferences(desired, current)
		Expect(desired).To(Equal([]metav1.OwnerReference{refA}))
		Expect(current).To(Equal([]metav1.OwnerReference{refB}))
	})
})
