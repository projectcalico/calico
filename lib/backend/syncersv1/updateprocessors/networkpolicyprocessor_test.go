// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	kapiv1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/conversion"
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

	v3NetworkPolicyKey1 := model.ResourceKey{
		Kind:      apiv3.KindNetworkPolicy,
		Name:      name1,
		Namespace: ns1,
	}
	v3NetworkPolicyKey2 := model.ResourceKey{
		Kind:      apiv3.KindNetworkPolicy,
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
		res := apiv3.NewNetworkPolicy()
		res.Name = name1
		res.Namespace = ns1

		kvps, err := up.Process(&model.KVPair{
			Key:      v3NetworkPolicyKey1,
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key: v1NetworkPolicyKey1,
			Value: &model.Policy{
				Namespace:      ns1,
				Selector:       "projectcalico.org/namespace == 'namespace1'",
				ApplyOnForward: true,
			},
			Revision: "abcde",
		}))

		By("adding another NetworkPolicy with a full configuration")
		res = apiv3.NewNetworkPolicy()

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
			Key:      v3NetworkPolicyKey2,
			Value:    res,
			Revision: "1234",
		})
		Expect(err).NotTo(HaveOccurred())

		namespacedSelector := "(" + selector + ") && projectcalico.org/namespace == '" + ns2 + "'"
		v1irule := updateprocessors.RuleAPIV2ToBackend(irule, ns2)
		v1erule := updateprocessors.RuleAPIV2ToBackend(erule, ns2)
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key: v1NetworkPolicyKey2,
				Value: &model.Policy{
					Namespace:      ns2,
					Order:          &order,
					InboundRules:   []model.Rule{v1irule},
					OutboundRules:  []model.Rule{v1erule},
					Selector:       namespacedSelector,
					ApplyOnForward: true,
					Types:          []string{"ingress"},
				},
				Revision: "1234",
			},
		}))

		By("deleting the first network policy")

		kvps, err = up.Process(&model.KVPair{
			Key:   v3NetworkPolicyKey1,
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
		res := apiv3.NewNetworkPolicy()

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
			Key:      v3NetworkPolicyKey1,
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
		eres := apiv3.NewNetworkPolicy()
		v3NetworkPolicyKeyEmpty := model.ResourceKey{
			Kind: apiv3.KindNetworkPolicy,
		}

		_, err = up.Process(&model.KVPair{
			Key:      v3NetworkPolicyKeyEmpty,
			Value:    eres,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())
	})
})

// Define network policies and the corresponding expected v1 KVPairs.
//
// np1 is a NetworkPolicy with a single Egress rule, which contains ports only,
// and no selectors.
var protocol = kapiv1.ProtocolTCP
var port = intstr.FromInt(80)
var np1 = networkingv1.NetworkPolicy{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "test.policy",
		Namespace: "default",
	},
	Spec: networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{},
		Egress: []networkingv1.NetworkPolicyEgressRule{
			networkingv1.NetworkPolicyEgressRule{
				Ports: []networkingv1.NetworkPolicyPort{
					networkingv1.NetworkPolicyPort{
						Protocol: &protocol,
						Port:     &port,
					},
				},
			},
		},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
	},
}

// expected1 is the expected v1 KVPair representation of np1 from above.
var tcp = numorstring.ProtocolFromStringV1("tcp")
var port80 = numorstring.SinglePort(uint16(80))
var order float64 = 1000.0
var expected1 = []*model.KVPair{
	&model.KVPair{
		Key: model.PolicyKey{Name: "default/knp.default.test.policy"},
		Value: &model.Policy{
			Namespace:      "default",
			Order:          &order,
			Selector:       "(projectcalico.org/orchestrator == 'k8s') && projectcalico.org/namespace == 'default'",
			Types:          []string{"egress"},
			ApplyOnForward: true,
			OutboundRules: []model.Rule{
				{
					Action:      "allow",
					Protocol:    &tcp,
					SrcSelector: "",
					DstSelector: "",
					DstPorts:    []numorstring.Port{port80},
				},
			},
		},
	},
}

// np2 is a NeteworkPolicy with a single Ingress rule which allows from all namespaces.
var np2 = networkingv1.NetworkPolicy{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "test.policy",
		Namespace: "default",
	},
	Spec: networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{},
		Ingress: []networkingv1.NetworkPolicyIngressRule{
			networkingv1.NetworkPolicyIngressRule{
				From: []networkingv1.NetworkPolicyPeer{
					{
						NamespaceSelector: &metav1.LabelSelector{},
					},
				},
			},
		},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
	},
}
var expected2 = []*model.KVPair{
	&model.KVPair{
		Key: model.PolicyKey{Name: "default/knp.default.test.policy"},
		Value: &model.Policy{
			Namespace:      "default",
			Order:          &order,
			Selector:       "(projectcalico.org/orchestrator == 'k8s') && projectcalico.org/namespace == 'default'",
			Types:          []string{"ingress"},
			ApplyOnForward: true,
			InboundRules: []model.Rule{
				{
					Action:                       "allow",
					SrcSelector:                  "(has(projectcalico.org/namespace)) && (projectcalico.org/orchestrator == 'k8s')",
					DstSelector:                  "",
					OriginalSrcSelector:          "projectcalico.org/orchestrator == 'k8s'",
					OriginalSrcNamespaceSelector: "all()",
				},
			},
		},
	},
}

var _ = Describe("Test the NetworkPolicy update processor + conversion", func() {
	up := updateprocessors.NewNetworkPolicyUpdateProcessor()

	DescribeTable("NetworkPolicy update processor + conversion tests",
		func(np networkingv1.NetworkPolicy, expected []*model.KVPair) {
			// First, convert the NetworkPolicy using the k8s conversion logic.
			c := conversion.Converter{}
			kvp, err := c.K8sNetworkPolicyToCalico(&np)
			Expect(err).NotTo(HaveOccurred())

			// Next, run the policy through the update processor.
			out, err := up.Process(kvp)
			Expect(err).NotTo(HaveOccurred())

			// Finally, assert the expected result.
			Expect(out).To(Equal(expected))
		},

		Entry("should handle a NetworkPolicy with no rule selectors", np1, expected1),
		Entry("should handle a NetworkPolicy with an empty ns selector", np2, expected2),
	)

})
