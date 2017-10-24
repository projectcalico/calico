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

func mustParseCIDR(cidr string) *cnet.IPNet {
	ipn := cnet.MustParseCIDR(cidr)
	return &ipn
}

var _ = Describe("Test the NetworkPolicy update processor", func() {
	name1 := "name1"
	name2 := "name2"
	ns1 := "namespace1"
	ns2 := "namespace2"

	v2NetworkPolicyKey1 := model.ResourceKey{
		Kind:      apiv2.KindNetworkPolicy,
		Name:      name1,
		Namespace: ns1,
	}
	v2NetworkPolicyKey2 := model.ResourceKey{
		Kind:      apiv2.KindNetworkPolicy,
		Name:      name2,
		Namespace: ns2,
	}
	v1NetworkPolicyKey1 := model.PolicyKey{
		Name: ns1 + "/" + name1,
	}
	v1NetworkPolicyKey2 := model.PolicyKey{
		Name: ns2 + "/" + name2,
	}

	It("should handle conversion of valid NetworkPolicys", func() {
		up := updateprocessors.NewNetworkPolicyUpdateProcessor()

		By("converting a NetworkPolicy with minimum configuration")
		res := apiv2.NewNetworkPolicy()
		res.Name = name1
		res.Namespace = ns1
		res.Spec.PreDNAT = true
		res.Spec.ApplyOnForward = true

		kvps, err := up.Process(&model.KVPair{
			Key:      v2NetworkPolicyKey1,
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key: v1NetworkPolicyKey1,
			Value: &model.Policy{
				Selector:       "projectcalico.org/namespace == 'namespace1'",
				PreDNAT:        true,
				ApplyOnForward: true,
			},
			Revision: "abcde",
		}))

		By("adding another NetworkPolicy with a full configuration")
		res = apiv2.NewNetworkPolicy()

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
				Nets:        []string{"10.100.10.1"},
				Selector:    "mylabel = value1",
				Ports:       []numorstring.Port{port80},
				NotNets:     []string{"192.168.40.1"},
				NotSelector: "has(label1)",
				NotPorts:    []numorstring.Port{port443},
			},
			Destination: apiv2.EntityRule{
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
				Nets:        []string{"10.100.1.1"},
				Selector:    "pcns.namespacelabel1 == 'value1'",
				Ports:       []numorstring.Port{port443},
				NotNets:     []string{"192.168.80.1"},
				NotSelector: "has(label2)",
				NotPorts:    []numorstring.Port{port80},
			},
			Destination: apiv2.EntityRule{
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
		res.Spec.IngressRules = []apiv2.Rule{irule}
		res.Spec.EgressRules = []apiv2.Rule{erule}
		res.Spec.Selector = selector
		res.Spec.DoNotTrack = true
		res.Spec.PreDNAT = false
		res.Spec.ApplyOnForward = true
		res.Spec.Types = []apiv2.PolicyType{apiv2.PolicyTypeIngress}
		kvps, err = up.Process(&model.KVPair{
			Key:      v2NetworkPolicyKey2,
			Value:    res,
			Revision: "1234",
		})
		Expect(err).NotTo(HaveOccurred())

		// Correct number of entries returned
		Expect(kvps).To(HaveLen(1))
		kvp := kvps[0]

		// Correct Key and Revision
		Expect(kvp.Key).To(Equal(v1NetworkPolicyKey2))
		Expect(kvp.Revision).To(Equal("1234"))

		// Correct top level Policy field values
		value := kvp.Value.(*model.Policy)
		Expect(value.Order).To(Equal(&order))
		Expect(value.Selector).To(Equal("(mylabel == selectme) && projectcalico.org/namespace == 'namespace2'"))
		Expect(value.DoNotTrack).To(BeTrue())
		Expect(value.PreDNAT).To(BeFalse())
		Expect(value.ApplyOnForward).To(BeTrue())
		Expect(value.Types).To(Equal([]string{"ingress"}))
		Expect(value.InboundRules).To(HaveLen(1))
		Expect(value.OutboundRules).To(HaveLen(1))

		// Correct inbound rule
		rulev1 := value.InboundRules[0]
		Expect(rulev1.Action).To(Equal("allow"))
		Expect(rulev1.IPVersion).To(Equal(&v4))
		Expect(rulev1.Protocol).To(Equal(&iproto))
		Expect(rulev1.ICMPCode).To(Equal(&icode))
		Expect(rulev1.ICMPType).To(Equal(&itype))
		Expect(rulev1.NotProtocol).To(Equal(&inproto))
		Expect(rulev1.NotICMPCode).To(Equal(&incode))
		Expect(rulev1.NotICMPType).To(Equal(&intype))

		Expect(rulev1.SrcNets).To(Equal([]*cnet.IPNet{mustParseCIDR("10.100.10.1/32")}))
		Expect(rulev1.SrcSelector).To(Equal("(mylabel = value1) && projectcalico.org/namespace == 'namespace2'"))
		Expect(rulev1.SrcPorts).To(Equal([]numorstring.Port{port80}))
		Expect(rulev1.DstNets).To(Equal([]*cnet.IPNet{mustParseCIDR("10.100.1.1/32")}))
		Expect(rulev1.DstSelector).To(Equal("projectcalico.org/namespace == 'namespace2'"))
		Expect(rulev1.DstPorts).To(Equal([]numorstring.Port{port443}))

		Expect(rulev1.NotSrcNets).To(Equal([]*cnet.IPNet{mustParseCIDR("192.168.40.1/32")}))
		Expect(rulev1.NotSrcSelector).To(Equal("has(label1)"))
		Expect(rulev1.NotSrcPorts).To(Equal([]numorstring.Port{port443}))
		Expect(rulev1.NotDstNets).To(Equal([]*cnet.IPNet{mustParseCIDR("192.168.80.1/32")}))
		Expect(rulev1.NotDstSelector).To(Equal("has(label2)"))
		Expect(rulev1.NotDstPorts).To(Equal([]numorstring.Port{port80}))

		// Correct outbound rule
		rulev1 = value.OutboundRules[0]
		Expect(rulev1.IPVersion).To(Equal(&v4))
		Expect(rulev1.Protocol).To(Equal(&eproto))
		Expect(rulev1.ICMPCode).To(Equal(&ecode))
		Expect(rulev1.ICMPType).To(Equal(&etype))
		Expect(rulev1.NotProtocol).To(Equal(&enproto))
		Expect(rulev1.NotICMPCode).To(Equal(&encode))
		Expect(rulev1.NotICMPType).To(Equal(&entype))

		Expect(rulev1.SrcNets).To(Equal([]*cnet.IPNet{mustParseCIDR("10.100.1.1/32")}))
		Expect(rulev1.SrcSelector).To(Equal("pcns.namespacelabel1 == 'value1'"))
		Expect(rulev1.SrcPorts).To(Equal([]numorstring.Port{port443}))
		Expect(rulev1.DstNets).To(Equal([]*cnet.IPNet{mustParseCIDR("10.100.10.1/32")}))
		Expect(rulev1.DstSelector).To(Equal("pcns.namespacelabel2 == 'value2'"))
		Expect(rulev1.DstPorts).To(Equal([]numorstring.Port{port80}))

		Expect(rulev1.NotSrcNets).To(Equal([]*cnet.IPNet{mustParseCIDR("192.168.80.1/32")}))
		Expect(rulev1.NotSrcSelector).To(Equal("has(label2)"))
		Expect(rulev1.NotSrcPorts).To(Equal([]numorstring.Port{port80}))
		Expect(rulev1.NotDstNets).To(Equal([]*cnet.IPNet{mustParseCIDR("192.168.40.1/32")}))
		Expect(rulev1.NotDstSelector).To(Equal("has(label1)"))
		Expect(rulev1.NotDstPorts).To(Equal([]numorstring.Port{port443}))

		By("deleting the first network policy")

		kvps, err = up.Process(&model.KVPair{
			Key:   v2NetworkPolicyKey1,
			Value: nil,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key:   v1NetworkPolicyKey1,
				Value: nil,
			},
		}))
	})

	It("should fail to convert an invalid resource", func() {
		up := updateprocessors.NewNetworkPolicyUpdateProcessor()

		By("trying to convert with the wrong key type")
		res := apiv2.NewNetworkPolicy()

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
			Key:      v2NetworkPolicyKey1,
			Value:    wres,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key:   v1NetworkPolicyKey1,
				Value: nil,
			},
		}))

		By("trying to convert without enough information to create a v1 key")
		eres := apiv2.NewNetworkPolicy()
		v2NetworkPolicyKeyEmpty := model.ResourceKey{
			Kind: apiv2.KindNetworkPolicy,
		}

		_, err = up.Process(&model.KVPair{
			Key:      v2NetworkPolicyKeyEmpty,
			Value:    eres,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())
	})
})
