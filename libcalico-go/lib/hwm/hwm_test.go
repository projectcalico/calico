// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

package hwm_test

import (
	. "github.com/projectcalico/calico/libcalico-go/lib/hwm"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("HWM tracker", func() {
	var hwm *HighWatermarkTracker

	BeforeEach(func() {
		hwm = NewHighWatermarkTracker()
	})

	Describe("while tracking nested deletions", func() {
		BeforeEach(func() {
			hwm.StoreUpdate("/a/b/c/d", 200)
			hwm.StartTrackingDeletions()
			hwm.StoreDeletion("/a/b/c/d", 210)
			hwm.StoreDeletion("/a/b/c/", 220)
			hwm.StoreDeletion("/a/b/", 230)
		})

		It("should ignore an update to a doubly-deleted subtree", func() {
			// 225 is after /a/b/c/ is deleted but before /a/b/ so
			// it should be ignored.
			hwm.StoreUpdate("/a/b/c/e", 225)
			Expect(hwm.ToMap()).To(Equal(map[string]uint64{}))
		})
		It("should allow a new update to a doubly-deleted subtree", func() {
			hwm.StoreUpdate("/a/b/c/e", 235)
			Expect(hwm.ToMap()).To(Equal(map[string]uint64{
				"/a/b/c/e": 235,
			}))
		})
	})

	Describe("after storing some keys", func() {
		BeforeEach(func() {
			hwm.StoreUpdate("/foo/bar/", 100) // slash will be elided
			hwm.StoreUpdate("/foo/baz", 110)
			hwm.StoreUpdate("/foobar/baz", 110)
			hwm.StoreUpdate("/foo/ba", 120)
			hwm.StoreUpdate("/baz", 120)
		})
		It("should contain the keys", func() {
			// Table-stakes!
			Expect(hwm.ToMap()).To(Equal(map[string]uint64{
				"/foo/bar":    100,
				"/foo/baz":    110,
				"/foobar/baz": 110,
				"/foo/ba":     120,
				"/baz":        120,
			}))
		})
		It("after deleting /foo: should delete correct subtree", func() {
			hwm.StoreDeletion("/foo", 130)
			Expect(hwm.ToMap()).To(Equal(map[string]uint64{
				"/baz": 120,
				// /foobar shares common prefix but HWM should
				// convert /foo to /foo/ to avoid clashes.
				"/foobar/baz": 110,
			}))
		})
		It("after deleting /foo/ba: should contain other keys", func() {
			hwm.StoreDeletion("/foo/ba", 130)
			Expect(hwm.ToMap()).To(Equal(map[string]uint64{
				"/foo/bar":    100,
				"/foo/baz":    110,
				"/foobar/baz": 110,
				"/baz":        120,
			}))
		})
		It("should ignore updates with old indexes", func() {
			oldModIdx := hwm.StoreUpdate("/foo/bar/", 90)
			Expect(oldModIdx).To(Equal(uint64(100)))
			Expect(hwm.ToMap()).To(Equal(map[string]uint64{
				"/foo/bar":    100,
				"/foo/baz":    110,
				"/foobar/baz": 110,
				"/foo/ba":     120,
				"/baz":        120,
			}))
		})
		It("should ignore deletions with old indexes", func() {
			deletedKeys := hwm.StoreDeletion("/foo", 101)
			// /foo/bar gets deleted because it's older than the
			// delete index.
			Expect(deletedKeys).To(Equal([]string{"/foo/bar"}))
			Expect(hwm.ToMap()).To(Equal(map[string]uint64{
				"/foo/baz":    110,
				"/foobar/baz": 110,
				"/foo/ba":     120,
				"/baz":        120,
			}))
		})

		Describe("while tracking deletions", func() {
			BeforeEach(func() {
				hwm.StartTrackingDeletions()
			})

			It("should ignore the correct events after a deletion", func() {
				hwm.StoreDeletion("/foo", 130)
				Expect(hwm.ToMap()).To(Equal(map[string]uint64{
					"/baz":        120,
					"/foobar/baz": 110,
				}))

				By("Ignoring an update with old index")
				hwm.StoreUpdate("/foo/bar", 129)
				Expect(hwm.ToMap()).To(Equal(map[string]uint64{
					"/baz":        120,
					"/foobar/baz": 110,
				}))

				By("Allowing an update to another subtree with old index")
				hwm.StoreUpdate("/foobar/biff", 129)
				Expect(hwm.ToMap()).To(Equal(map[string]uint64{
					"/baz":         120,
					"/foobar/baz":  110,
					"/foobar/biff": 129,
				}))

				By("Allowing an update with new index")
				hwm.StoreUpdate("/foo/bar", 131)
				Expect(hwm.ToMap()).To(Equal(map[string]uint64{
					"/baz":         120,
					"/foo/bar":     131,
					"/foobar/baz":  110,
					"/foobar/biff": 129,
				}))
			})

			It("should stop tracking when told to", func() {
				hwm.StoreDeletion("/foo", 130)
				hwm.StoreUpdate("/foo/bar", 128) // Ignored
				hwm.StopTrackingDeletions()
				hwm.StoreUpdate("/foo/baz", 129)
				Expect(hwm.ToMap()).To(Equal(map[string]uint64{
					"/baz":        120,
					"/foobar/baz": 110,
					"/foo/baz":    129,
				}))
			})
		})
	})
})
