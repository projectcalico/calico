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

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

var _ = Describe("Test the GlobalNetworkPolicy update processor", func() {
	name1 := "name1"
	name2 := "name2"

	v3GlobalNetworkPolicyKey1 := model.ResourceKey{
		Kind: apiv3.KindGlobalNetworkPolicy,
		Name: name1,
	}
	v3GlobalNetworkPolicyKey2 := model.ResourceKey{
		Kind: apiv3.KindGlobalNetworkPolicy,
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
		res := apiv3.NewGlobalNetworkPolicy()
		res.Spec.PreDNAT = true
		res.Spec.ApplyOnForward = true

		kvps, err := up.Process(&model.KVPair{
			Key:      v3GlobalNetworkPolicyKey1,
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
		res = apiv3.NewGlobalNetworkPolicy()

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
			Key:      v3GlobalNetworkPolicyKey2,
			Value:    res,
			Revision: "1234",
		})
		Expect(err).NotTo(HaveOccurred())

		v1irule := updateprocessors.RuleAPIV2ToBackend(irule, "")
		v1erule := updateprocessors.RuleAPIV2ToBackend(erule, "")
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
			Key:   v3GlobalNetworkPolicyKey1,
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
		res := apiv3.NewGlobalNetworkPolicy()

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
			Key:      v3GlobalNetworkPolicyKey1,
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
		eres := apiv3.NewGlobalNetworkPolicy()
		v3GlobalNetworkPolicyKeyEmpty := model.ResourceKey{
			Kind: apiv3.KindGlobalNetworkPolicy,
		}

		_, err = up.Process(&model.KVPair{
			Key:      v3GlobalNetworkPolicyKeyEmpty,
			Value:    eres,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())
	})
})
