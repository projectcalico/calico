// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.
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

package common

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// For now, we only need four IPSets to stage different scenarios around adding, removing and updating members.
const numMembers int = 4

// Basic structure for a test case. The idea is to have at least one for each IPSetType.
type IPSetsMgrTestCase struct {
	ipsetID      string
	ipsetType    proto.IPSetUpdate_IPSetType
	ipsetMembers [numMembers]string
}

// Main array of test cases. We pass each of these to the test routines during execution.
var ipsetsMgrTestCases = []IPSetsMgrTestCase{
	{
		ipsetID:      "id1",
		ipsetType:    proto.IPSetUpdate_IP,
		ipsetMembers: [numMembers]string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"},
	},
}

var _ = Describe("IP Sets manager", func() {
	var (
		ipsetsMgr *IPSetsManager
		ipSets    *MockIPSets
	)

	BeforeEach(func() {
		ipSets = NewMockIPSets()
		ipsetsMgr = NewIPSetsManager(ipSets, 1024)
	})

	// Generic assumptions used during tests. Having them here reduces code duplication and improves readability.
	AssertIPSetMembers := func(id string, members []string) {
		It("IPSet should have the right members", func() {
			Expect(ipSets.Members[id]).To(Equal(set.FromArray(members)))
		})
	}

	AssertIPSetNoMembers := func(id string) {
		It("IPSet should have no members", func() {
			Expect(ipSets.Members[id]).To(BeNil())
		})
	}

	AssertIPSetModified := func() {
		It("IPSet should be modified", func() {
			Expect(ipSets.AddOrReplaceCalled).To(BeTrue())
		})
	}

	AssertIPSetNotModified := func() {
		It("IPSet should not be modified", func() {
			Expect(ipSets.AddOrReplaceCalled).To(BeFalse())
		})
	}

	// Basic add/remove/update test case for different types of IPSets.
	IPsetsMgrTest1 := func(ipsetID string, ipsetType proto.IPSetUpdate_IPSetType, members [numMembers]string) {
		Describe("after creating an IPSet", func() {
			BeforeEach(func() {
				ipSets.AddOrReplaceCalled = false
				ipsetsMgr.OnUpdate(&proto.IPSetUpdate{
					Id:      ipsetID,
					Members: []string{members[0], members[1]},
					Type:    ipsetType,
				})
				err := ipsetsMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})

			AssertIPSetModified()

			AssertIPSetMembers(ipsetID, []string{members[0], members[1]})

			Describe("after sending a delta update", func() {
				BeforeEach(func() {
					ipSets.AddOrReplaceCalled = false
					ipsetsMgr.OnUpdate(&proto.IPSetDeltaUpdate{
						Id:             ipsetID,
						AddedMembers:   []string{members[2], members[3]},
						RemovedMembers: []string{members[0]},
					})
					err := ipsetsMgr.CompleteDeferredWork()
					Expect(err).ToNot(HaveOccurred())
				})

				AssertIPSetNotModified()

				AssertIPSetMembers(ipsetID, []string{members[1], members[2], members[3]})

				Describe("after sending a delete", func() {
					BeforeEach(func() {
						ipsetsMgr.OnUpdate(&proto.IPSetRemove{
							Id: ipsetID,
						})
						err := ipsetsMgr.CompleteDeferredWork()
						Expect(err).ToNot(HaveOccurred())
					})
					AssertIPSetNoMembers(ipsetID)
				})
			})

			Describe("after sending another replace", func() {
				BeforeEach(func() {
					ipSets.AddOrReplaceCalled = false
					ipsetsMgr.OnUpdate(&proto.IPSetUpdate{
						Id:      ipsetID,
						Members: []string{members[1], members[2]},
						Type:    ipsetType,
					})
					err := ipsetsMgr.CompleteDeferredWork()
					Expect(err).ToNot(HaveOccurred())
				})

				AssertIPSetModified()
				AssertIPSetMembers(ipsetID, []string{members[1], members[2]})
			})
		})
	}

	for _, testCase := range ipsetsMgrTestCases {
		IPsetsMgrTest1(testCase.ipsetID, testCase.ipsetType, testCase.ipsetMembers)
	}
})
