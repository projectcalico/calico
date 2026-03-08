// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
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

package calc_test

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var _ = Describe("NetworkSetLookupsCache IP tests", func() {
	ec := NewNetworkSetLookupsCache()

	DescribeTable(
		"Check adding/deleting networkset modifies the cache",
		func(key model.NetworkSetKey, netset *model.NetworkSet, ipAddr net.IP) {
			c := "NetworkSet(" + key.Name + ")"
			update := api.Update{
				KVPair: model.KVPair{
					Key:   key,
					Value: netset,
				},
				UpdateType: api.UpdateTypeKVNew,
			}
			var addrB [16]byte
			copy(addrB[:], ipAddr.To16()[:16])
			ec.OnUpdate(update)
			ed, ok := ec.GetNetworkSetFromIP(addrB)
			Expect(ok).To(BeTrue(), c)
			Expect(ed.Key()).To(Equal(key))

			update = api.Update{
				KVPair: model.KVPair{
					Key: key,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			}
			ec.OnUpdate(update)
			_, ok = ec.GetNetworkSetFromIP(addrB)
			Expect(ok).To(BeFalse(), c)
		},
		Entry("networkset with IPv4", netSet1Key, &netSet1, localWlEp1.IPv4Nets[0].IP),
		Entry("networkset with IPv6", netSet1Key, &netSet1, mustParseNet("feed:beef::1/128").IP),
	)

	It("should process networkSets with multiple CIDRs", func() {
		By("adding a networkset with multiple CIDRs")
		update := api.Update{
			KVPair: model.KVPair{
				Key:   netSet1Key,
				Value: &netSet1,
			},
			UpdateType: api.UpdateTypeKVNew,
		}
		origNetSetLabels := map[string]string{
			"a": "b",
		}
		ec.OnUpdate(update)

		verifyIpToNetworkset := func(key model.Key, ipAddr net.IP, exists bool, labels map[string]string) {
			name := "NetworkSet(" + key.(model.NetworkSetKey).Name + ")"
			var addrB [16]byte
			copy(addrB[:], ipAddr.To16()[:16])

			ed, ok := ec.GetNetworkSetFromIP(addrB)
			if exists {
				Expect(ok).To(BeTrue(), name+"\n"+ec.DumpNetworksets())
				Expect(ed.Key()).To(Equal(key), ec.DumpNetworksets())
				if labels != nil {
					Expect(ed.Labels()).To(Equal(uniquelabels.Make(labels)), ec.DumpNetworksets())
				}
			} else {
				Expect(ok).To(BeFalse(), name+".\n"+ec.DumpNetworksets())
			}
		}

		By("verifying all subnets of the networkset are present in the mapping")
		for _, cidr := range netSet1.Nets {
			verifyIpToNetworkset(netSet1Key, cidr.IP, true, origNetSetLabels)
		}

		By("adding networkset2")
		update = api.Update{
			KVPair: model.KVPair{
				Key:   netSet2Key,
				Value: &netSet2,
			},
			UpdateType: api.UpdateTypeKVNew,
		}
		netSet2Labels := map[string]string{
			"a": "b",
		}
		ec.OnUpdate(update)

		By("verifying networkset2 is in the mapping")
		// This check validates that netSet2 is found since one subnet is outside the range of netSet1's subnets.
		for _, cidr := range netSet2.Nets {
			// For overlapping CIDRs (12.0.0.0/24), lowest-lexicographic-name-wins applies
			// netSet1 ("netset-1") comes before netSet2 ("netset-2") lexicographically, so netSet1 wins
			// For unique CIDRs (13.1.0.0/24), netSet2 should still be returned
			var expectedKey model.Key
			var expectedLabels map[string]string
			if cidr.String() == "12.0.0.0/24" {
				// This overlaps with netSet1, so netSet1 should win due to lexicographic ordering
				expectedKey = netSet1Key
				expectedLabels = origNetSetLabels
			} else {
				// This is unique to netSet2
				expectedKey = netSet2Key
				expectedLabels = netSet2Labels
			}
			verifyIpToNetworkset(expectedKey, cidr.IP, true, expectedLabels)
		}

		By("deleting networkset2")
		update = api.Update{
			KVPair: model.KVPair{
				Key: netSet2Key,
			},
			UpdateType: api.UpdateTypeKVDeleted,
		}
		ec.OnUpdate(update)

		By("verifying the unique subnets of networkset2 are not present in the mapping")
		netSet2SubnetLen := len(netSet2.Nets)
		if netSet2SubnetLen > 0 {
			verifyIpToNetworkset(netSet2Key, netSet2.Nets[netSet2SubnetLen-1].IP, false, nil)
		}

		By("updating the networkset and adding new labels")
		update = api.Update{
			KVPair: model.KVPair{
				Key:   netSet1Key,
				Value: &netSet1WithBEqB,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		}
		ec.OnUpdate(update)

		updatedNetSetLabels := map[string]string{
			"foo": "bar",
			"b":   "b",
		}

		By("verifying the subnets are present with the updated labels")
		for _, cidr := range netSet1WithBEqB.Nets {
			verifyIpToNetworkset(netSet1Key, cidr.IP, true, updatedNetSetLabels)
		}

		By("updating the networkset keeping all the information as before")
		update = api.Update{
			KVPair: model.KVPair{
				Key:   netSet1Key,
				Value: &netSet1WithBEqB,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		}
		ec.OnUpdate(update)

		By("verifying the subnets are as they were before")
		for _, cidr := range netSet1WithBEqB.Nets {
			verifyIpToNetworkset(netSet1Key, cidr.IP, true, updatedNetSetLabels)
		}

		By("finally removing the networkset and no mapping is present")
		update = api.Update{
			KVPair: model.KVPair{
				Key: netSet1Key,
			},
			UpdateType: api.UpdateTypeKVDeleted,
		}
		ec.OnUpdate(update)

		By("verifying there is no mapping present")
		for _, cidr := range netSet1.Nets {
			verifyIpToNetworkset(netSet1Key, cidr.IP, false, nil)
		}
	})

	It("should longest prefix match for a given IP from multiple CIDRs", func() {
		By("adding a networkset with multiple overlapping CIDRs")
		update := api.Update{
			KVPair: model.KVPair{
				Key:   netSet3Key,
				Value: &netSet3,
			},
			UpdateType: api.UpdateTypeKVNew,
		}
		ec.OnUpdate(update)
		update = api.Update{
			KVPair: model.KVPair{
				Key:   netSet1Key,
				Value: &netSet1,
			},
			UpdateType: api.UpdateTypeKVNew,
		}
		ec.OnUpdate(update)
		verifyIpInCidrUsingLpm := func(key model.Key, ipAddr net.IP, exists bool) {
			name := "NetworkSet(" + key.(model.NetworkSetKey).Name + ")"
			var addrB [16]byte
			copy(addrB[:], ipAddr.To16()[:16])
			ed, ok := ec.GetNetworkSetFromIP(addrB)
			if exists {
				Expect(ok).To(BeTrue(), name+"\n"+ec.DumpNetworksets())
				Expect(ed.Key()).To(Equal(key))
			} else {
				Expect(ok).To(BeFalse(), name+".\n"+ec.DumpNetworksets())
			}
		}

		By("verifying all subnets of the networkset are present in the mapping")
		verifyIpInCidrUsingLpm(netSet1Key, netset3Ip1a, true)
		verifyIpInCidrUsingLpm(netSet3Key, netset3Ip1b, true)
	})
})
