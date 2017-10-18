// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

var _ = Describe("Test the GlobalNetworkPolicy update processor", func() {
	name1 := "name1"
	name2 := "name2"

	v2GlobalNetworkPolicyKey1 := model.ResourceKey{
		Kind: apiv2.KindGlobalNetworkPolicy,
		Name: name1,
	}
	v2GlobalNetworkPolicyKey2 := model.ResourceKey{
		Kind: apiv2.KindGlobalNetworkPolicy,
		Name: name2,
	}
	v1GlobalNetworkPolicyKey1 := model.PolicyKey{
		Name: name1,
	}
	v1GlobalNetworkPolicyKey2 := model.PolicyKey{
		Name: name2,
	}

	It("should handle conversion of valid GlobalNetworkPolicys", func() {
		up := updateprocessors.NewGlobalNetworkPolicyUpdateProcessor()

		By("converting a GlobalNetworkPolicy with minimum configuration")
		res := apiv2.NewGlobalNetworkPolicy()
		res.Spec.PreDNAT = true
		res.Spec.ApplyOnForward = true

		kvps, err := up.Process(&model.KVPair{
			Key:      v2GlobalNetworkPolicyKey1,
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key: v1GlobalNetworkPolicyKey1,
			Value: &model.Policy{
				PreDNAT:        true,
				ApplyOnForward: true,
			},
			Revision: "abcde",
		}))

		By("adding another GlobalNetworkPolicy with a full configuration")
		res = apiv2.NewGlobalNetworkPolicy()

		v4 := 4
		itype := 1
		intype := 3
		icode := 4
		incode := 6
		iproto := numorstring.ProtocolFromString("tcp")
		inproto := numorstring.ProtocolFromString("udp")
		port80 := numorstring.SinglePort(uint16(80))
		port443 := numorstring.SinglePort(uint16(443))
		irule := apiv2.Rule{
			Action:    apiv2.Allow,
			IPVersion: &v4,
			Protocol:  &iproto,
			ICMP: &apiv2.ICMPFields{
				Type: &itype,
				Code: &icode,
			},
			NotProtocol: &inproto,
			NotICMP: &apiv2.ICMPFields{
				Type: &intype,
				Code: &incode,
			},
			Source: apiv2.EntityRule{
				Tag:         "tag1",
				Nets:        []string{"10.100.10.1"},
				Selector:    "calico/k8s_ns == selector1",
				Ports:       []numorstring.Port{port80},
				NotTag:      "nottag1",
				NotNets:     []string{"192.168.40.1"},
				NotSelector: "has(label1)",
				NotPorts:    []numorstring.Port{port443},
			},
			Destination: apiv2.EntityRule{
				Tag:         "tag2",
				Nets:        []string{"10.100.1.1"},
				Selector:    "calico/k8s_ns == selector2",
				Ports:       []numorstring.Port{port443},
				NotTag:      "nottag2",
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
		erule := apiv2.Rule{
			Action:    apiv2.Allow,
			IPVersion: &v4,
			Protocol:  &eproto,
			ICMP: &apiv2.ICMPFields{
				Type: &etype,
				Code: &ecode,
			},
			NotProtocol: &enproto,
			NotICMP: &apiv2.ICMPFields{
				Type: &entype,
				Code: &encode,
			},
			Source: apiv2.EntityRule{
				Tag:         "tag2",
				Nets:        []string{"10.100.1.1"},
				Selector:    "calico/k8s_ns == selector2",
				Ports:       []numorstring.Port{port443},
				NotTag:      "nottag2",
				NotNets:     []string{"192.168.80.1"},
				NotSelector: "has(label2)",
				NotPorts:    []numorstring.Port{port80},
			},
			Destination: apiv2.EntityRule{
				Tag:         "tag1",
				Nets:        []string{"10.100.10.1"},
				Selector:    "calico/k8s_ns == selector1",
				Ports:       []numorstring.Port{port80},
				NotTag:      "nottag1",
				NotNets:     []string{"192.168.40.1"},
				NotSelector: "has(label1)",
				NotPorts:    []numorstring.Port{port443},
			},
		}
		order := float64(101)
		selector := "calico/k8s_ns == selectme"

		res.Spec.Order = &order
		res.Spec.IngressRules = []apiv2.Rule{irule}
		res.Spec.EgressRules = []apiv2.Rule{erule}
		res.Spec.Selector = selector
		res.Spec.DoNotTrack = true
		res.Spec.PreDNAT = false
		res.Spec.ApplyOnForward = true
		res.Spec.Types = []apiv2.PolicyType{apiv2.PolicyTypeIngress}
		kvps, err = up.Process(&model.KVPair{
			Key:      v2GlobalNetworkPolicyKey2,
			Value:    res,
			Revision: "1234",
		})
		Expect(err).NotTo(HaveOccurred())

		v1irule := updateprocessors.RuleAPIV2ToBackend(irule)
		v1erule := updateprocessors.RuleAPIV2ToBackend(erule)
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key: v1GlobalNetworkPolicyKey2,
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

		By("deleting the first network policy")
		kvps, err = up.Process(&model.KVPair{
			Key:   v2GlobalNetworkPolicyKey1,
			Value: nil,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key:   v1GlobalNetworkPolicyKey1,
				Value: nil,
			},
		}))
	})

	It("should fail to convert an invalid resource", func() {
		up := updateprocessors.NewGlobalNetworkPolicyUpdateProcessor()

		By("trying to convert with the wrong key type")
		res := apiv2.NewGlobalNetworkPolicy()

		_, err := up.Process(&model.KVPair{
			Key: model.GlobalBGPPeerKey{
				PeerIP: cnet.MustParseIP("1.2.3.4"),
			},
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())

		By("trying to convert with the wrong value type")
		wres := apiv2.NewHostEndpoint()

		kvps, err := up.Process(&model.KVPair{
			Key:      v2GlobalNetworkPolicyKey1,
			Value:    wres,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key:   v1GlobalNetworkPolicyKey1,
				Value: nil,
			},
		}))

		By("trying to convert without enough information to create a v1 key")
		eres := apiv2.NewGlobalNetworkPolicy()
		v2GlobalNetworkPolicyKeyEmpty := model.ResourceKey{
			Kind: apiv2.KindGlobalNetworkPolicy,
		}

		_, err = up.Process(&model.KVPair{
			Key:      v2GlobalNetworkPolicyKeyEmpty,
			Value:    eres,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())
	})
})
