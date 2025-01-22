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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/rules"
	v3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

const (
	endpointDataTTLAfterMarkedAsRemoved = 2 * config.DefaultConntrackPollingInterval
)

var (
	float1_0 = float64(1.0)
	float2_0 = float64(2.0)
)

var _ = Describe("EndpointLookupsCache tests: endpoints", func() {
	ec := NewEndpointLookupsCache()

	DescribeTable(
		"Check adding/deleting workload endpoint modifies the cache",
		func(key model.WorkloadEndpointKey, wep *model.WorkloadEndpoint, ipAddr net.IP) {
			c := "WEP(" + key.Hostname + "/" + key.OrchestratorID + "/" + key.WorkloadID + "/" + key.EndpointID + ")"

			// tests adding an endpoint
			update := api.Update{
				KVPair: model.KVPair{
					Key:   key,
					Value: wep,
				},
				UpdateType: api.UpdateTypeKVNew,
			}
			var addrB [16]byte
			copy(addrB[:], ipAddr.To16()[:16])

			ec.OnUpdate(update)

			// test GetEndpointByIP retrieves the endpointData
			ed, ok := ec.GetEndpoint(addrB)
			Expect(ok).To(BeTrue(), c)
			Expect(ed.Key).To(Equal(key))

			// test GetEndpointKeys
			keys := ec.GetEndpointKeys()
			Expect(len(keys)).To(Equal(1))
			Expect(keys).To(ConsistOf(ed.Key))

			// test GetAllEndpointData also contains the one
			// retrieved by the IP
			endpoints := ec.GetAllEndpointData()
			Expect(len(endpoints)).To(Equal(1))
			Expect(endpoints).To(ConsistOf(ed))

			// tests deleting an endpoint
			update = api.Update{
				KVPair: model.KVPair{
					Key: key,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			}

			// OnUpdate delays deletion with delay
			ec.OnUpdate(update)
			_, ok = ec.GetEndpoint(addrB)
			Expect(ok).To(BeTrue(), c)

			time.Sleep(endpointDataTTLAfterMarkedAsRemoved + 1*time.Second)

			_, ok = ec.GetEndpoint(addrB)
			Expect(ok).To(BeFalse(), c)

			// test GetEndpointKeys are empty after deletion
			keys = ec.GetEndpointKeys()
			Expect(len(keys)).To(Equal(0))
			Expect(keys).NotTo(ConsistOf(ed.Key))

			// test GetAllEndpointData are empty after deletion
			endpoints = ec.GetAllEndpointData()
			Expect(len(endpoints)).To(Equal(0))
			Expect(endpoints).NotTo(ConsistOf(ed))

		},
		Entry("remote WEP1 IPv4", remoteWlEpKey1, &remoteWlEp1DualStack, remoteWlEp1DualStack.IPv4Nets[0].IP),
		Entry("remote WEP1 IPv6", remoteWlEpKey1, &remoteWlEp1DualStack, remoteWlEp1DualStack.IPv6Nets[0].IP),
	)

	DescribeTable(
		"should cancel a previous endpoint data mark to be deleted and update the endpoint key with data in the new entry",
		func(key model.HostEndpointKey, hep *model.HostEndpoint, ipAddr net.IP) {
			// setup - add entry for key
			c := "HEP(" + key.Hostname + "/" + key.EndpointID + ")"
			update := api.Update{
				KVPair: model.KVPair{
					Key:   key,
					Value: hep,
				},
				UpdateType: api.UpdateTypeKVNew,
			}
			var addrB [16]byte
			copy(addrB[:], ipAddr.To16()[:16])

			ec.OnUpdate(update)
			ed, ok := ec.GetEndpoint(addrB)
			Expect(ok).To(BeTrue(), c)
			Expect(ed.Key).To(Equal(key))

			// deletion process
			update = api.Update{
				KVPair: model.KVPair{
					Key: key,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			}
			// OnUpdate delays deletion with time to live
			ec.OnUpdate(update)
			_, ok = ec.GetEndpoint(addrB)
			Expect(ok).To(BeTrue(), c)

			// re-add entry before the deletion is delegated
			update = api.Update{
				KVPair: model.KVPair{
					Key:   key,
					Value: hep,
				},
				UpdateType: api.UpdateTypeKVNew,
			}
			ec.OnUpdate(update)
			ed, ok = ec.GetEndpoint(addrB)
			Expect(ok).To(BeTrue(), c)
			Expect(ed.Key).To(Equal(key))

			// re-fetching the entry after expected time it was deleted
			time.Sleep(endpointDataTTLAfterMarkedAsRemoved + 1*time.Second)
			_, ok = ec.GetEndpoint(addrB)
			Expect(ok).To(BeTrue(), c)
		},
		Entry("Host Endpoint IPv4", hostEpWithNameKey, &hostEpWithName, hostEpWithName.ExpectedIPv4Addrs[0].IP),
		Entry("Host Endpoint IPv6", hostEpWithNameKey, &hostEpWithName, hostEpWithName.ExpectedIPv6Addrs[0].IP),
	)

	It("should process local endpoints correctly with no staged policies and one tier per ingress and egress", func() {
		By("adding a host endpoint with ingress policies in tier1 and egress policies in tier default")
		p1k := model.PolicyKey{Name: "tier1.pol1"}
		p1 := &model.Policy{
			Order:        &float1_0,
			Types:        []string{"ingress"},
			InboundRules: []model.Rule{{Action: "next-tier"}, {Action: "allow"}, {Action: "deny"}},
		}
		p1id := PolicyID{Name: "pol1", Tier: "tier1"}
		p1Metadata := ExtractPolicyMetadata(p1)

		p2k := model.PolicyKey{Name: "ns1/default.pol2"}
		p2 := &model.Policy{
			Namespace: "ns1",
			Order:     &float1_0,
			Types:     []string{"egress"},
		}
		p2id := PolicyID{Name: "pol2", Tier: "default", Namespace: "ns1"}
		p2Metadata := ExtractPolicyMetadata(p2)

		p3k := model.PolicyKey{Name: "ns1/default.pol3"}
		p3 := &model.Policy{
			Namespace: "ns1",
			Order:     &float2_0,
			Types:     []string{"egress"},
		}
		p3id := PolicyID{Name: "pol3", Tier: "default", Namespace: "ns1"}
		p3Metadata := ExtractPolicyMetadata(p3)

		t1 := NewTierInfo("tier1")
		t1.Order = &float1_0
		t1.Valid = true
		t1.OrderedPolicies = []PolKV{{Key: p1k, Value: &p1Metadata}}

		td := NewTierInfo("default")
		td.Order = &float2_0
		td.Valid = true
		td.OrderedPolicies = []PolKV{{Key: p2k, Value: &p2Metadata}, {Key: p3k, Value: &p3Metadata}}

		ts := newTierInfoSlice()
		ts = append(ts, *t1, *td)

		ed := ec.CreateEndpointData(hostEpWithNameKey, &hostEpWithName, ts)

		By("checking endpoint data")
		Expect(ed.Key).To(Equal(hostEpWithNameKey))
		Expect(ed.IsLocal).To(BeTrue())
		Expect(ed.Endpoint).To(Equal(&hostEpWithName))

		By("checking compiled ingress data")
		Expect(ed.Ingress).ToNot(BeNil())
		Expect(ed.Ingress.PolicyMatches).To(HaveLen(1))
		Expect(ed.Ingress.PolicyMatches).To(HaveKey(p1id))
		Expect(ed.Ingress.PolicyMatches[p1id]).To(Equal(0))
		Expect(ed.Ingress.ProfileMatchIndex).To(Equal(1))
		Expect(ed.Ingress.TierData).To(HaveLen(1))
		Expect(ed.Ingress.TierData).To(HaveKey("tier1"))
		Expect(ed.Ingress.TierData["tier1"]).ToNot(BeNil())
		Expect(ed.Ingress.TierData["tier1"].ImplicitDropRuleID).To(Equal(
			NewRuleID("tier1", "pol1", "", RuleIDIndexImplicitDrop, rules.RuleDirIngress, rules.RuleActionDeny)))
		Expect(ed.Ingress.TierData["tier1"].EndOfTierMatchIndex).To(Equal(0))

		By("checking compiled egress data")
		Expect(ed.Egress).ToNot(BeNil())
		Expect(ed.Egress.PolicyMatches).To(HaveLen(2))
		Expect(ed.Egress.PolicyMatches).To(HaveKey(p2id))
		Expect(ed.Egress.PolicyMatches[p2id]).To(Equal(0))
		Expect(ed.Egress.PolicyMatches).To(HaveKey(p3id))
		Expect(ed.Egress.PolicyMatches[p3id]).To(Equal(0))
		Expect(ed.Egress.ProfileMatchIndex).To(Equal(1))
		Expect(ed.Egress.TierData).To(HaveLen(1))
		Expect(ed.Egress.TierData).To(HaveKey("default"))
		Expect(ed.Egress.TierData["default"]).ToNot(BeNil())
		Expect(ed.Egress.TierData["default"].ImplicitDropRuleID).To(Equal(
			NewRuleID("default", "pol3", "ns1", RuleIDIndexImplicitDrop, rules.RuleDirEgress, rules.RuleActionDeny)))
		Expect(ed.Egress.TierData["default"].EndOfTierMatchIndex).To(Equal(0))
	})
})

var _ = Describe("EndpointLookupCache tests: Node lookup", func() {
	var elc *EndpointLookupsCache
	var updates []api.Update
	//localIP, _ := IPStringToArray("127.0.0.1")
	nodeIPStr := "100.0.0.0/26"
	nodeIP, _ := IPStringToArray(nodeIPStr)
	nodeIP2Str := "100.0.0.2/26"
	nodeIP2, _ := IPStringToArray(nodeIP2Str)
	nodeIP3Str := "100.0.0.3/26"
	nodeIP3, _ := IPStringToArray(nodeIP3Str)
	nodeIP4Str := "100.0.0.4/26"
	nodeIP4, _ := IPStringToArray(nodeIP4Str)

	BeforeEach(func() {
		elc = NewEndpointLookupsCache()

		By("adding a node and a service")
		updates = []api.Update{{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindNode, Name: "node1"},
				Value: &v3.Node{
					Spec: v3.NodeSpec{
						BGP: &v3.NodeBGPSpec{
							IPv4Address: nodeIPStr,
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		}}

		for _, u := range updates {
			elc.OnResourceUpdate(u)
		}
	})

	It("Should handle each type of lookup", func() {
		By("checking node IP attributable to one node")
		node, ok := elc.GetNode(nodeIP)
		Expect(ok).To(BeTrue())
		Expect(node).To(Equal("node1"))
	})

	It("Should handle deletion of config", func() {
		By("deleting all resources")
		for _, u := range updates {
			elc.OnResourceUpdate(api.Update{
				KVPair:     model.KVPair{Key: u.Key},
				UpdateType: api.UpdateTypeKVDeleted,
			})
		}

		By("checking nodes return no results")
		_, ok := elc.GetNode(nodeIP)
		Expect(ok).To(BeFalse())
	})

	Describe("It should handle reconfiguring the node resources", func() {
		BeforeEach(func() {
			By("updating the node and adding a new node")
			updates = []api.Update{{
				KVPair: model.KVPair{
					Key: model.ResourceKey{Kind: v3.KindNode, Name: "node1"},
					Value: &v3.Node{
						Spec: v3.NodeSpec{
							BGP: &v3.NodeBGPSpec{
								IPv4Address: nodeIPStr,
							},
							IPv4VXLANTunnelAddr: nodeIPStr,
						},
					},
				},
				UpdateType: api.UpdateTypeKVUpdated,
			}, {
				// 2nd node has duplicate main IP and also has other interface IPs assigned
				KVPair: model.KVPair{
					Key: model.ResourceKey{Kind: v3.KindNode, Name: "node2"},
					Value: &v3.Node{
						Spec: v3.NodeSpec{
							BGP: &v3.NodeBGPSpec{
								IPv4Address:        nodeIPStr,
								IPv4IPIPTunnelAddr: nodeIP2Str,
							},
							IPv4VXLANTunnelAddr: nodeIP3Str,
							Wireguard: &v3.NodeWireguardSpec{
								InterfaceIPv4Address: nodeIP4Str,
							},
						},
					},
				},
				UpdateType: api.UpdateTypeKVNew,
			}}

			for _, u := range updates {
				elc.OnResourceUpdate(u)
			}
		})

		It("should handle multiple assigned IPs to different nodes", func() {
			By("checking nodes return no results for duplicate IP")
			_, ok := elc.GetNode(nodeIP)
			Expect(ok).To(BeFalse())
		})

		It("should handle unique IPs on new node", func() {
			By("checking nodes returns results for unique IP")
			node, ok := elc.GetNode(nodeIP2)
			Expect(ok).To(BeTrue())
			Expect(node).To(Equal("node2"))

			node, ok = elc.GetNode(nodeIP3)
			Expect(ok).To(BeTrue())
			Expect(node).To(Equal("node2"))

			node, ok = elc.GetNode(nodeIP4)
			Expect(ok).To(BeTrue())
			Expect(node).To(Equal("node2"))
		})

		It("should handle reconfiguring node 2 so that node 1 IP is unique again", func() {
			By("Reconfiguring node 2")
			elc.OnResourceUpdate(api.Update{
				KVPair: model.KVPair{
					Key: model.ResourceKey{Kind: v3.KindNode, Name: "node2"},
					Value: &v3.Node{
						Spec: v3.NodeSpec{
							BGP: &v3.NodeBGPSpec{
								IPv4Address:        nodeIP2Str,
								IPv4IPIPTunnelAddr: nodeIP2Str,
							},
							IPv4VXLANTunnelAddr: nodeIP3Str,
							Wireguard: &v3.NodeWireguardSpec{
								InterfaceIPv4Address: nodeIP4Str,
							},
						},
					},
				},
				UpdateType: api.UpdateTypeKVUpdated,
			})

			By("checking nodes returns results for node 1 unique IP")
			node, ok := elc.GetNode(nodeIP)
			Expect(ok).To(BeTrue())
			Expect(node).To(Equal("node1"))
		})

		It("should handle reconfiguring node 1 so that node 2 IPs are all unique", func() {
			By("Reconfiguring node 1 to remove the main IP")
			elc.OnResourceUpdate(api.Update{
				KVPair: model.KVPair{
					Key: model.ResourceKey{Kind: v3.KindNode, Name: "node1"},
					Value: &v3.Node{
						Spec: v3.NodeSpec{
							BGP: &v3.NodeBGPSpec{
								IPv4IPIPTunnelAddr: nodeIPStr,
							},
						},
					},
				},
				UpdateType: api.UpdateTypeKVUpdated,
			})

			By("checking node1 and node 2 still share an IP")
			_, ok := elc.GetNode(nodeIP)
			Expect(ok).To(BeFalse())

			By("Reconfiguring node 1 to remove the remaining IP")
			elc.OnResourceUpdate(api.Update{
				KVPair: model.KVPair{
					Key: model.ResourceKey{Kind: v3.KindNode, Name: "node1"},
					Value: &v3.Node{
						Spec: v3.NodeSpec{},
					},
				},
				UpdateType: api.UpdateTypeKVUpdated,
			})

			By("checking node 2 has unique IPs")
			node, ok := elc.GetNode(nodeIP)
			Expect(ok).To(BeTrue())
			Expect(node).To(Equal("node2"))
		})
	})
})

func newTierInfoSlice() []TierInfo {
	return nil
}
