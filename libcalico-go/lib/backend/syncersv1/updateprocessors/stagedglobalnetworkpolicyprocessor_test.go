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

var _ = Describe("Test the StagedGlobalNetworkPolicy update processor", func() {
	name1 := "name1"
	name2 := "name2"
	name3 := "mytier.name3"
	mytier := "mytier"

	v3StagedGlobalNetworkPolicyKey1 := model.ResourceKey{
		Kind: apiv3.KindStagedGlobalNetworkPolicy,
		Name: name1,
	}
	v3StagedGlobalNetworkPolicyKey2 := model.ResourceKey{
		Kind: apiv3.KindStagedGlobalNetworkPolicy,
		Name: name2,
	}
	v3StagedGlobalNetworkPolicyKey3 := model.ResourceKey{
		Kind: apiv3.KindStagedGlobalNetworkPolicy,
		Name: name3,
	}
	v1StagedGlobalNetworkPolicyKey1 := model.PolicyKey{
		Name: model.PolicyNamePrefixStaged + name1,
		Tier: "default",
	}
	v1StagedGlobalNetworkPolicyKey2 := model.PolicyKey{
		Name: model.PolicyNamePrefixStaged + name2,
		Tier: "default",
	}
	v1StagedGlobalNetworkPolicyKey3 := model.PolicyKey{
		Name: model.PolicyNamePrefixStaged + name3,
		Tier: mytier,
	}

	It("should handle conversion of valid StagedGlobalNetworkPolicys", func() {
		up := updateprocessors.NewStagedGlobalNetworkPolicyUpdateProcessor()

		By("converting a StagedGlobalNetworkPolicy with minimum configuration")
		res := apiv3.NewStagedGlobalNetworkPolicy()
		res.Spec.StagedAction = apiv3.StagedActionSet
		res.Spec.PreDNAT = true
		res.Spec.ApplyOnForward = true

		kvps, err := up.Process(&model.KVPair{
			Key:      v3StagedGlobalNetworkPolicyKey1,
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key: v1StagedGlobalNetworkPolicyKey1,
			Value: &model.Policy{
				PreDNAT:        true,
				ApplyOnForward: true,
				StagedAction:   &res.Spec.StagedAction,
			},
			Revision: "abcde",
		}))

		By("adding another StagedGlobalNetworkPolicy with a full configuration")
		res = apiv3.NewStagedGlobalNetworkPolicy()

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
				Selector:    "calico/k8s_ns == selector1",
				Ports:       []numorstring.Port{port80},
				NotNets:     []string{"192.168.40.1"},
				NotSelector: "has(label1)",
				NotPorts:    []numorstring.Port{port443},
			},
			Destination: apiv3.EntityRule{
				Nets:        []string{"10.100.1.1"},
				Selector:    "calico/k8s_ns == selector2",
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
				Selector:    "calico/k8s_ns == selector2",
				Ports:       []numorstring.Port{port443},
				NotNets:     []string{"192.168.80.1"},
				NotSelector: "has(label2)",
				NotPorts:    []numorstring.Port{port80},
			},
			Destination: apiv3.EntityRule{
				Nets:        []string{"10.100.10.1"},
				Selector:    "calico/k8s_ns == selector1",
				Ports:       []numorstring.Port{port80},
				NotNets:     []string{"192.168.40.1"},
				NotSelector: "has(label1)",
				NotPorts:    []numorstring.Port{port443},
			},
		}
		order := float64(101)
		selector := "calico/k8s_ns == selectme"

		res.Spec.Order = &order
		res.Spec.Ingress = []apiv3.Rule{irule}
		res.Spec.Egress = []apiv3.Rule{erule}
		res.Spec.Selector = selector
		res.Spec.DoNotTrack = true
		res.Spec.PreDNAT = false
		res.Spec.ApplyOnForward = true
		res.Spec.Types = []apiv3.PolicyType{apiv3.PolicyTypeIngress}
		kvps, err = up.Process(&model.KVPair{
			Key:      v3StagedGlobalNetworkPolicyKey2,
			Value:    res,
			Revision: "1234",
		})
		Expect(err).NotTo(HaveOccurred())

		v1irule := updateprocessors.RuleAPIV3ToBackend(irule, "", false)
		v1erule := updateprocessors.RuleAPIV3ToBackend(erule, "", false)
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key: v1StagedGlobalNetworkPolicyKey2,
				Value: &model.Policy{
					Order:          &order,
					InboundRules:   []model.Rule{v1irule},
					OutboundRules:  []model.Rule{v1erule},
					Selector:       selector,
					DoNotTrack:     true,
					PreDNAT:        false,
					ApplyOnForward: true,
					Types:          []string{"ingress"},
				},
				Revision: "1234",
			},
		}))

		By("converting a tiered StagedGlobalNetworkPolicy with minimum policy configuration")
		res = apiv3.NewStagedGlobalNetworkPolicy()
		res.Spec.Tier = mytier
		res.Spec.PreDNAT = true
		res.Spec.ApplyOnForward = true
		res.Spec.StagedAction = "Deleted"

		kvps, err = up.Process(&model.KVPair{
			Key:      v3StagedGlobalNetworkPolicyKey3,
			Value:    res,
			Revision: "xyz",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key: v1StagedGlobalNetworkPolicyKey3,
			Value: &model.Policy{
				PreDNAT:        true,
				ApplyOnForward: true,
				StagedAction:   &res.Spec.StagedAction,
			},
			Revision: "xyz",
		}))

		By("deleting the first network policy")
		kvps, err = up.Process(&model.KVPair{
			Key:   v3StagedGlobalNetworkPolicyKey1,
			Value: nil,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key:   v1StagedGlobalNetworkPolicyKey1,
				Value: nil,
			},
		}))

		By("deleting the tiered StagedGlobalNetworkPolicy")
		kvps, err = up.Process(&model.KVPair{
			Key:   v3StagedGlobalNetworkPolicyKey3,
			Value: nil,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key:   v1StagedGlobalNetworkPolicyKey3,
				Value: nil,
			},
		}))
	})

	It("should fail to convert an invalid resource", func() {
		up := updateprocessors.NewStagedGlobalNetworkPolicyUpdateProcessor()

		By("trying to convert with the wrong key type")
		res := apiv3.NewStagedGlobalNetworkPolicy()

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
			Key:      v3StagedGlobalNetworkPolicyKey1,
			Value:    wres,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key:   v1StagedGlobalNetworkPolicyKey1,
				Value: nil,
			},
		}))

		By("trying to convert without enough information to create a v1 key")
		eres := apiv3.NewStagedGlobalNetworkPolicy()
		v3StagedGlobalNetworkPolicyKeyEmpty := model.ResourceKey{
			Kind: apiv3.KindStagedGlobalNetworkPolicy,
		}

		_, err = up.Process(&model.KVPair{
			Key:      v3StagedGlobalNetworkPolicyKeyEmpty,
			Value:    eres,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())
	})
})
