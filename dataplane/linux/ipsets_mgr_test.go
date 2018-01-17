// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/set"
)

var _ = Describe("IP Sets manager", func() {
	var (
		ipsetsMgr *ipSetsManager
		ipSets    *mockIPSets
	)

	BeforeEach(func() {
		ipSets = newMockIPSets()
		ipsetsMgr = newIPSetsManager(ipSets, 1024)
	})

	Describe("after sending a replace", func() {
		BeforeEach(func() {
			ipsetsMgr.OnUpdate(&proto.IPSetUpdate{
				Id:      "id1",
				Members: []string{"10.0.0.1", "10.0.0.2"},
			})
			ipsetsMgr.CompleteDeferredWork()
		})
		It("should create the IP set", func() {
			Expect(ipSets.AddOrReplaceCalled).To(BeTrue())
		})
		It("should add the right members", func() {
			Expect(ipSets.Members).To(HaveLen(1))
			expIPs := set.From("10.0.0.1", "10.0.0.2")
			Expect(ipSets.Members["id1"]).To(Equal(expIPs))
		})

		Describe("after sending a delta update", func() {
			BeforeEach(func() {
				ipSets.AddOrReplaceCalled = false
				ipsetsMgr.OnUpdate(&proto.IPSetDeltaUpdate{
					Id:             "id1",
					AddedMembers:   []string{"10.0.0.3", "10.0.0.4"},
					RemovedMembers: []string{"10.0.0.1"},
				})
				ipsetsMgr.CompleteDeferredWork()
			})
			It("should not replace the IP set", func() {
				Expect(ipSets.AddOrReplaceCalled).To(BeFalse())
			})
			It("should contain the right IPs", func() {
				expIPs := set.From("10.0.0.2", "10.0.0.3", "10.0.0.4")
				Expect(ipSets.Members["id1"]).To(Equal(expIPs))
			})

			Describe("after sending a delete", func() {
				BeforeEach(func() {
					ipsetsMgr.OnUpdate(&proto.IPSetRemove{
						Id: "id1",
					})
					ipsetsMgr.CompleteDeferredWork()
				})
				It("should remove the IP set", func() {
					Expect(ipSets.Members["id1"]).To(BeNil())
				})
			})
		})

		Describe("after sending another replace", func() {
			BeforeEach(func() {
				ipSets.AddOrReplaceCalled = false
				ipsetsMgr.OnUpdate(&proto.IPSetUpdate{
					Id:      "id1",
					Members: []string{"10.0.0.2", "10.0.0.3"},
				})
				ipsetsMgr.CompleteDeferredWork()
			})
			It("should replace the IP set", func() {
				Expect(ipSets.AddOrReplaceCalled).To(BeTrue())
			})
			It("should add the right members", func() {
				Expect(ipSets.Members).To(HaveLen(1))
				expIPs := set.From("10.0.0.2", "10.0.0.3")
				Expect(ipSets.Members["id1"]).To(Equal(expIPs))
			})
		})
	})
})
