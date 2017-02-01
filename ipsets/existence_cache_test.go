// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

package ipsets_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/set"
)

var _ = Describe("ExistenceCache", func() {
	var dataplane *mockDataplane
	var cache *ExistenceCache

	Describe("with empty dataplane", func() {
		BeforeEach(func() {
			dataplane = newMockDataplane()
			cache = NewExistenceCache(dataplane.newCmd)
		})
		It("should load no IP sets", func() {
			cache.Iter(func(setName string) {
				Fail("Unexpected IP set")
			})
		})
		It("should return false for unknown sets", func() {
			Expect(cache.IPSetExists("unknown")).To(BeFalse())
		})

		Describe("after dataplane update that adds a set", func() {
			BeforeEach(func() {
				dataplane.IPSetMembers["cali6ts:qMt7iLlGDhvLnCjM0l9nzxb"] = set.New()
			})
			It("should still report no IP sets due to caching", func() {
				cache.Iter(func(setName string) {
					Fail("Unexpected IP set")
				})
			})
			It("and Reload()ing, it should report the IP set", func() {
				cache.Reload()
				setNames := set.New()
				cache.Iter(func(setName string) {
					// Should only report each set once.
					Expect(setNames.Contains(setName)).To(BeFalse())
					setNames.Add(setName)
				})
				expectedNames := set.New()
				expectedNames.Add("cali6ts:qMt7iLlGDhvLnCjM0l9nzxb")
				Expect(setNames).To(Equal(expectedNames))
			})
			It("should return false for unknown sets", func() {
				Expect(cache.IPSetExists("unknown")).To(BeFalse())
			})
		})

		Describe("after explicitly marking a set as added", func() {
			BeforeEach(func() {
				cache.SetIPSetExists("cali6ts:qMt7iLlGDhvLnCjM0l9nzxb", true)
			})
			It("should report the IP set as present", func() {
				Expect(cache.IPSetExists("cali6ts:qMt7iLlGDhvLnCjM0l9nzxb")).To(BeTrue())
			})
			It("should return false for unknown sets", func() {
				Expect(cache.IPSetExists("unknown")).To(BeFalse())
			})

			Describe("and then Reload()ing", func() {
				BeforeEach(func() {
					cache.Reload()
				})
				It("should report the IP set as gone", func() {
					Expect(cache.IPSetExists("cali6ts:qMt7iLlGDhvLnCjM0l9nzxb")).To(BeFalse())
				})
			})
			Describe("and then removing it again", func() {
				BeforeEach(func() {
					cache.SetIPSetExists("cali6ts:qMt7iLlGDhvLnCjM0l9nzxb", false)
				})
				It("should report the IP set as gone", func() {
					Expect(cache.IPSetExists("cali6ts:qMt7iLlGDhvLnCjM0l9nzxb")).To(BeFalse())
				})
			})
		})
	})

	Describe("with some sets in dataplane at start of day", func() {
		BeforeEach(func() {
			dataplane = newMockDataplane()
			dataplane.IPSetMembers["foobar"] = set.New()
			dataplane.IPSetMembers["cali6ts:qMt7iLlGDhvLnCjM0l9nzxb"] = set.New()
			cache = NewExistenceCache(dataplane.newCmd)
		})

		It("should load them", func() {
			Expect(cache.IPSetExists("foobar")).To(BeTrue())
			Expect(cache.IPSetExists("cali6ts:qMt7iLlGDhvLnCjM0l9nzxb")).To(BeTrue())
		})
		It("should return false for unknown sets", func() {
			Expect(cache.IPSetExists("unknown")).To(BeFalse())
		})
	})
})
