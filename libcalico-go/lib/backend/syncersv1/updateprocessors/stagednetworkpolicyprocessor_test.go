// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

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

package updateprocessors_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = Describe("Test the StagedNetworkPolicy update processor", func() {
	name1 := "name1"
	name2 := "name2"
	name3 := "mytier.name3"
	ns1 := "namespace1"
	ns2 := "namespace2"
	ns3 := "namespace3"
	mytier := "mytier"

	v3StagedNetworkPolicyKey1 := model.ResourceKey{
		Kind:      apiv3.KindStagedNetworkPolicy,
		Name:      name1,
		Namespace: ns1,
	}
	v3StagedNetworkPolicyKey2 := model.ResourceKey{
		Kind:      apiv3.KindStagedNetworkPolicy,
		Name:      name2,
		Namespace: ns2,
	}
	v3StagedNetworkPolicyKey3 := model.ResourceKey{
		Kind:      apiv3.KindStagedNetworkPolicy,
		Name:      name3,
		Namespace: ns3,
	}
	v1StagedNetworkPolicyKey1 := model.PolicyKey{
		Name: ns1 + "/" + model.PolicyNamePrefixStaged + name1,
		Tier: "default",
	}
	v1StagedNetworkPolicyKey2 := model.PolicyKey{
		Name: ns2 + "/" + model.PolicyNamePrefixStaged + name2,
		Tier: "default",
	}
	v1StagedNetworkPolicyKey3 := model.PolicyKey{
		Name: ns3 + "/" + model.PolicyNamePrefixStaged + name3,
		Tier: mytier,
	}

	It("should handle conversion of valid StagedNetworkPolicys", func() {
		up := updateprocessors.NewStagedNetworkPolicyUpdateProcessor()

		By("converting a StagedNetworkPolicy with minimum configuration")
		res := apiv3.NewStagedNetworkPolicy()
		res.Name = name1
		res.Namespace = ns1
		res.Spec.StagedAction = apiv3.StagedActionSet

		kvps, err := up.Process(&model.KVPair{
			Key:      v3StagedNetworkPolicyKey1,
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key: v1StagedNetworkPolicyKey1,
			Value: &model.Policy{
				Namespace:      ns1,
				Selector:       "projectcalico.org/namespace == 'namespace1'",
				ApplyOnForward: false,
				StagedAction:   &res.Spec.StagedAction,
			},
			Revision: "abcde",
		}))

		By("adding another StagedNetworkPolicy with a full configuration")
		res = apiv3.NewStagedNetworkPolicy()

		v4 := 4
		itype := 1
		intype := 3
		icode := 4
		incode := 6
		iproto := numorstring.ProtocolFromString("TCP")
		inproto := numorstring.ProtocolFromString("UDP")
		port80 := numorstring.SinglePort(uint16(80))
		port443 := numorstring.SinglePort(uint16(443))
		irule := apiv3.Rule{
			Action:    apiv3.Allow,
			IPVersion: &v4,
			Protocol:  &iproto,
			ICMP: &apiv3.ICMPFields{
				Type: &itype,
				Code: &icode,
			},
			NotProtocol: &inproto,
			NotICMP: &apiv3.ICMPFields{
				Type: &intype,
				Code: &incode,
			},
			Source: apiv3.EntityRule{
				Nets:        []string{"10.100.10.1"},
				Selector:    "mylabel = value1",
				Ports:       []numorstring.Port{port80},
				NotNets:     []string{"192.168.40.1"},
				NotSelector: "has(label1)",
				NotPorts:    []numorstring.Port{port443},
			},
			Destination: apiv3.EntityRule{
				Nets:        []string{"10.100.1.1"},
				Selector:    "",
				Ports:       []numorstring.Port{port443},
				NotNets:     []string{"192.168.80.1"},
				NotSelector: "has(label2)",
				NotPorts:    []numorstring.Port{port80},
			},
		}

		etype := 2
		entype := 7
		ecode := 5
		encode := 8
		eproto := numorstring.ProtocolFromInt(uint8(30))
		enproto := numorstring.ProtocolFromInt(uint8(62))
		erule := apiv3.Rule{
			Action:    apiv3.Allow,
			IPVersion: &v4,
			Protocol:  &eproto,
			ICMP: &apiv3.ICMPFields{
				Type: &etype,
				Code: &ecode,
			},
			NotProtocol: &enproto,
			NotICMP: &apiv3.ICMPFields{
				Type: &entype,
				Code: &encode,
			},
			Source: apiv3.EntityRule{
				Nets:        []string{"10.100.1.1"},
				Selector:    "pcns.namespacelabel1 == 'value1'",
				Ports:       []numorstring.Port{port443},
				NotNets:     []string{"192.168.80.1"},
				NotSelector: "has(label2)",
				NotPorts:    []numorstring.Port{port80},
			},
			Destination: apiv3.EntityRule{
				Nets:        []string{"10.100.10.1"},
				Selector:    "pcns.namespacelabel2 == 'value2'",
				Ports:       []numorstring.Port{port80},
				NotNets:     []string{"192.168.40.1"},
				NotSelector: "has(label1)",
				NotPorts:    []numorstring.Port{port443},
			},
		}
		order := float64(101)
		selector := "mylabel == selectme"

		res.Name = name2
		res.Namespace = ns2
		res.Spec.Order = &order
		res.Spec.Ingress = []apiv3.Rule{irule}
		res.Spec.Egress = []apiv3.Rule{erule}
		res.Spec.Selector = selector
		res.Spec.Types = []apiv3.PolicyType{apiv3.PolicyTypeIngress}
		kvps, err = up.Process(&model.KVPair{
			Key:      v3StagedNetworkPolicyKey2,
			Value:    res,
			Revision: "1234",
		})
		Expect(err).NotTo(HaveOccurred())

		namespacedSelector := "(" + selector + ") && projectcalico.org/namespace == '" + ns2 + "'"
		v1irule := updateprocessors.RuleAPIV3ToBackend(irule, ns2, false)
		v1erule := updateprocessors.RuleAPIV3ToBackend(erule, ns2, false)
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key: v1StagedNetworkPolicyKey2,
				Value: &model.Policy{
					Namespace:      ns2,
					Order:          &order,
					InboundRules:   []model.Rule{v1irule},
					OutboundRules:  []model.Rule{v1erule},
					Selector:       namespacedSelector,
					Types:          []string{"ingress"},
					ApplyOnForward: false,
				},
				Revision: "1234",
			},
		}))

		By("converting a tiered StagedNetworkPolicy with minimum policy configuration")
		res = apiv3.NewStagedNetworkPolicy()
		res.Name = name3
		res.Namespace = ns3
		res.Spec.Tier = mytier

		kvps, err = up.Process(&model.KVPair{
			Key:      v3StagedNetworkPolicyKey3,
			Value:    res,
			Revision: "xyz",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key: v1StagedNetworkPolicyKey3,
			Value: &model.Policy{
				Namespace:      "namespace3",
				Selector:       "projectcalico.org/namespace == 'namespace3'",
				ApplyOnForward: false,
			},
			Revision: "xyz",
		}))

		By("deleting the first network policy")

		kvps, err = up.Process(&model.KVPair{
			Key:   v3StagedNetworkPolicyKey1,
			Value: nil,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key:   v1StagedNetworkPolicyKey1,
				Value: nil,
			},
		}))

		By("deleting the network policy belonging to a tier other than default tier")

		kvps, err = up.Process(&model.KVPair{
			Key:   v3StagedNetworkPolicyKey3,
			Value: nil,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key:   v1StagedNetworkPolicyKey3,
				Value: nil,
			},
		}))
	})

	It("should fail to convert an invalid resource", func() {
		up := updateprocessors.NewStagedNetworkPolicyUpdateProcessor()

		By("trying to convert with the wrong key type")
		res := apiv3.NewStagedNetworkPolicy()

		_, err := up.Process(&model.KVPair{
			Key: model.GlobalBGPPeerKey{
				PeerIP: cnet.MustParseIP("1.2.3.4"),
			},
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())

		By("trying to convert with the wrong value type")
		wres := apiv3.NewHostEndpoint()

		kvps, err := up.Process(&model.KVPair{
			Key:      v3StagedNetworkPolicyKey1,
			Value:    wres,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key:   v1StagedNetworkPolicyKey1,
				Value: nil,
			},
		}))

		By("trying to convert without enough information to create a v1 key")
		eres := apiv3.NewStagedNetworkPolicy()
		v3StagedNetworkPolicyKeyEmpty := model.ResourceKey{
			Kind: apiv3.KindStagedNetworkPolicy,
		}

		_, err = up.Process(&model.KVPair{
			Key:      v3StagedNetworkPolicyKeyEmpty,
			Value:    eres,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())
	})
})
