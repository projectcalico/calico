// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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
	. "github.com/projectcalico/calico/felix/labelindex"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
)

type update struct {
	op      string
	labelId interface{}
	selId   interface{}
}

var _ = Describe("Keys", func() {
	It("should work as a map key", func() {
		key1 := model.KeyFromDefaultPath("/calico/v1/policy/tier/tier1/policy/policy1")
		key2 := model.KeyFromDefaultPath("calico/v1/policy/tier/tier1/policy/policy1")
		key3 := model.KeyFromDefaultPath("/calico/v1/policy/tier/tier1/policy/policy2")
		m := make(map[interface{}]bool)
		m[key1] = true
		Expect(m[key2]).To(BeTrue())
		Expect(m[key3]).To(BeFalse())
	})
})

var _ = Describe("Index", func() {
	var (
		updates []update
		idx     *InheritIndex
		a_eq_a1 selector.Selector
		a_eq_b  selector.Selector
		c_eq_d  selector.Selector
		err     error
	)

	onMatchStart := func(selId, labelId interface{}) {
		updates = append(updates,
			update{op: "start",
				labelId: labelId,
				selId:   selId})
	}
	onMatchStop := func(selId, labelId interface{}) {
		updates = append(updates,
			update{op: "stop",
				labelId: labelId,
				selId:   selId})
	}

	BeforeEach(func() {
		updates = make([]update, 0)
		idx = NewInheritIndex(onMatchStart, onMatchStop)

		a_eq_a1, err = selector.Parse(`a=="a1"`)
		Expect(err).To(BeNil())
		a_eq_b, err = selector.Parse(`a=="b"`)
		Expect(err).To(BeNil())
		c_eq_d, err = selector.Parse(`c=="d"`)
		Expect(err).To(BeNil())
	})

	Context("with empty index", func() {
		It("should do nothing when adding labels", func() {
			idx.UpdateLabels("foo", map[string]string{"a": "b"}, nil)
			idx.UpdateLabels("bar", map[string]string{}, nil)
			Expect(updates).To(BeEmpty())
		})
		It("should do nothing when adding selectors", func() {
			idx.UpdateSelector("foo", a_eq_a1)
			idx.UpdateSelector("bar", a_eq_a1)
			Expect(updates).To(BeEmpty())
		})
	})

	Context("with one set of labels added", func() {
		BeforeEach(func() {
			idx.UpdateLabels("l1", map[string]string{"a": "b", "c": "d"}, nil)
		})

		It("should ignore non-matching selectors", func() {
			By("ignoring selector add")
			idx.UpdateSelector("e1", a_eq_a1)
			By("ignoring selector delete")
			idx.DeleteSelector("e1")
			Expect(updates).To(BeEmpty())
		})

		It("should fire correct events for matching selector", func() {
			By("firing start event on addition")
			idx.UpdateSelector("e1", a_eq_b)
			Expect(updates).To(Equal([]update{{
				"start", "l1", "e1",
			}}))
			updates = updates[:0]
			By("ignoring idempotent update")
			idx.UpdateSelector("e1", a_eq_b)
			Expect(updates).To(BeEmpty())
			By("ignoring update to also-matching selector")
			idx.UpdateSelector("e1", c_eq_d)
			Expect(updates).To(BeEmpty())
			By("firing stop event on deletion")
			idx.DeleteSelector("e1")
			Expect(updates).To(Equal([]update{{
				"stop", "l1", "e1",
			}}))
		})

		It("should handle multiple matches", func() {
			By("firing events for both")
			idx.UpdateSelector("e1", a_eq_b)
			idx.UpdateSelector("e2", c_eq_d)
			Expect(updates).To(Equal([]update{
				{"start", "l1", "e1"},
				{"start", "l1", "e2"},
			}))
			updates = updates[:0]

			By("firing stop for update to non-matching selector")
			idx.UpdateSelector("e2", a_eq_a1)
			Expect(updates).To(Equal([]update{
				{"stop", "l1", "e2"},
			}))
			updates = updates[:0]

			By("firing stop when selector deleted")
			idx.DeleteSelector("e1")
			Expect(updates).To(Equal([]update{
				{"stop", "l1", "e1"},
			}))
		})
	})

	Context("with one selector added", func() {
		BeforeEach(func() {
			idx.UpdateSelector("e1", a_eq_a1)
		})

		It("should ignore non-matching labels", func() {
			idx.UpdateLabels("l1", map[string]string{"a": "b"}, nil)
			Expect(updates).To(BeEmpty())
		})
		It("should fire correct events for match", func() {
			By("firing for add")
			idx.UpdateLabels("l1", map[string]string{"a": "a1"}, nil)
			Expect(updates).To(Equal([]update{{
				"start", "l1", "e1",
			}}))
			updates = updates[:0]
			By("ignoring idempotent add")
			idx.UpdateLabels("l1", map[string]string{"a": "a1"}, nil)
			Expect(updates).To(BeEmpty())
			By("ignoring update to also-matching labels")
			idx.UpdateLabels("l1",
				map[string]string{"a": "a1", "b": "c"}, nil)
			Expect(updates).To(BeEmpty())
			By("firing stop on delete")
			idx.DeleteLabels("l1")
			Expect(updates).To(Equal([]update{{
				"stop", "l1", "e1",
			}}))
		})
		It("should handle multiple matches", func() {
			By("firing events for both")
			idx.UpdateLabels("l1", map[string]string{"a": "a1"}, nil)
			idx.UpdateLabels("l2",
				map[string]string{"a": "a1", "b": "b1"}, nil)
			Expect(updates).To(Equal([]update{
				{"start", "l1", "e1"},
				{"start", "l2", "e1"},
			}))
			updates = updates[:0]

			By("handling updates to non-matching labels")
			idx.UpdateLabels("l1", map[string]string{"a": "a2"}, nil)
			Expect(updates).To(Equal([]update{
				{"stop", "l1", "e1"},
			}))
			updates = updates[:0]

			By("handling removal of selector")
			idx.DeleteSelector("e1")
			Expect(updates).To(Equal([]update{
				{"stop", "l2", "e1"},
			}))
		})
	})
})
