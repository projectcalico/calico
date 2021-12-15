// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.

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
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	kapiv1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/selector/parser"
)

var _ = Describe("Test the NetworkPolicy update processor", func() {
	ns1 := "namespace1"
	ns2 := "namespace2"
	selector := `mylabel == 'selectme'`

	emptyNPKey := model.ResourceKey{Kind: apiv3.KindNetworkPolicy, Name: "empty", Namespace: ns1}
	emptyNP := apiv3.NewNetworkPolicy()

	minimalNPKey := model.ResourceKey{Kind: apiv3.KindNetworkPolicy, Name: "minimal", Namespace: ns1}
	minimalNP := apiv3.NewNetworkPolicy()
	minimalNP.Name = "minimal"
	minimalNP.Namespace = ns1

	fullNPKey := model.ResourceKey{Kind: apiv3.KindNetworkPolicy, Name: "full", Namespace: ns2}
	fullNP := fullNPv3("full", ns2, selector)

	// NetworkPolicies with valid, invalid and 'all()' ServiceAccountSelectors.
	validSASelectorKey := model.ResourceKey{Kind: apiv3.KindNetworkPolicy, Name: "valid-sa-selector", Namespace: ns2}
	validSASelector := fullNPv3("valid-sa-selector", ns2, selector)
	validSASelector.Spec.ServiceAccountSelector = "role == 'development'"

	invalidSASelectorKey := model.ResourceKey{Kind: apiv3.KindNetworkPolicy, Name: "invalid-sa-selector", Namespace: ns2}
	invalidSASelector := fullNPv3("invalid-sa-selector", ns2, selector)
	invalidSASelector.Spec.ServiceAccountSelector = "role 'development'"

	allSASelectorKey := model.ResourceKey{Kind: apiv3.KindNetworkPolicy, Name: "all-sa-selector", Namespace: ns2}
	allSASelector := fullNPv3("all-sa-selector", ns2, selector)
	allSASelector.Spec.ServiceAccountSelector = "all()"

	Context("test processing of a valid NetworkPolicy from V3 to V1", func() {
		up := updateprocessors.NewNetworkPolicyUpdateProcessor()

		It("should accept a NetworkPolicy with a minimal configuration", func() {
			kvps, err := up.Process(&model.KVPair{Key: minimalNPKey, Value: minimalNP, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())
			Expect(kvps).To(HaveLen(1))

			v1Key := model.PolicyKey{Name: ns1 + "/minimal"}
			Expect(kvps[0]).To(Equal(&model.KVPair{
				Key: v1Key,
				Value: &model.Policy{
					Namespace:      ns1,
					Selector:       "projectcalico.org/namespace == 'namespace1'",
					ApplyOnForward: true,
				},
				Revision: testRev,
			}))
		})

		It("should accept a NetworkPolicy with a full configuration", func() {
			kvps, err := up.Process(&model.KVPair{Key: fullNPKey, Value: fullNP, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullNPv1(ns2)
			policy.Selector = fmt.Sprintf("(mylabel == 'selectme') && projectcalico.org/namespace == '%s'", ns2)

			v1Key := model.PolicyKey{Name: ns2 + "/full"}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))

			By("should be able to delete the full network policy")
			kvps, err = up.Process(&model.KVPair{Key: fullNPKey, Value: nil})
			Expect(err).NotTo(HaveOccurred())
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: nil}}))
		})

		It("should NOT accept a NetworkPolicy with the wrong Key type", func() {
			_, err := up.Process(&model.KVPair{
				Key:      model.GlobalBGPPeerKey{PeerIP: cnet.MustParseIP("1.2.3.4")},
				Value:    emptyNP,
				Revision: "abcde",
			})
			Expect(err).To(HaveOccurred())
		})

		It("should NOT accept a NetworkPolicy with the wrong Value type", func() {
			kvps, err := up.Process(&model.KVPair{Key: emptyNPKey, Value: apiv3.NewHostEndpoint(), Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			v1Key := model.PolicyKey{Name: ns1 + "/empty"}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: nil}}))
		})

		It("should accept a NetworkPolicy with a ServiceAccountSelector", func() {
			kvps, err := up.Process(&model.KVPair{Key: validSASelectorKey, Value: validSASelector, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullNPv1(ns2)
			policy.Selector = `((mylabel == 'selectme') && projectcalico.org/namespace == 'namespace2') && pcsa.role == "development"`
			v1Key := model.PolicyKey{Name: ns2 + "/valid-sa-selector"}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

		It("should NOT add an invalid ServiceAccountSelector to the NP's Selector field", func() {
			kvps, err := up.Process(&model.KVPair{Key: invalidSASelectorKey, Value: invalidSASelector, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullNPv1(ns2)
			policy.Selector = `(mylabel == 'selectme') && projectcalico.org/namespace == 'namespace2'`
			v1Key := model.PolicyKey{Name: ns2 + "/invalid-sa-selector"}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

		It("should accept a NetworkPolicy with 'all()' as the ServiceAccountSelector", func() {
			kvps, err := up.Process(&model.KVPair{Key: allSASelectorKey, Value: allSASelector, Revision: testRev})
			Expect(err).NotTo(HaveOccurred())

			policy := fullNPv1(ns2)
			policy.Selector = `((mylabel == 'selectme') && projectcalico.org/namespace == 'namespace2') && all()`
			v1Key := model.PolicyKey{Name: ns2 + "/all-sa-selector"}
			Expect(kvps).To(Equal([]*model.KVPair{{Key: v1Key, Value: &policy, Revision: testRev}}))
		})

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
			{
				Ports: []networkingv1.NetworkPolicyPort{
					{
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
var expected1 = []*model.KVPair{
	{
		Key: model.PolicyKey{Name: "default/knp.default.test.policy"},
		Value: &model.Policy{
			Namespace:      "default",
			Order:          &testDefaultPolicyOrder,
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
			{
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
	{
		Key: model.PolicyKey{Name: "default/knp.default.test.policy"},
		Value: &model.Policy{
			Namespace:      "default",
			Order:          &testDefaultPolicyOrder,
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

var _ = Describe("Test the Kubernetes NetworkPolicy end-to-end conversion and updateprocessor logic", func() {
	up := updateprocessors.NewNetworkPolicyUpdateProcessor()

	DescribeTable("NetworkPolicy update processor + conversion tests",
		func(np networkingv1.NetworkPolicy, expected []*model.KVPair) {
			// First, convert the NetworkPolicy using the k8s conversion logic.
			c := conversion.NewConverter()
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

var _ = Describe("Test end-to-end pod and network policy processing", func() {

	// Define processors to use in the test.
	npProcessor := updateprocessors.NewNetworkPolicyUpdateProcessor()
	wepProcessor := updateprocessors.NewWorkloadEndpointUpdateProcessor()

	It("should handle a basic pod and network policy", func() {
		pod := kapiv1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "test-pod",
				Namespace:       "default",
				Labels:          map[string]string{"foo": "bar"},
				ResourceVersion: "1234",
			},
			Spec: kapiv1.PodSpec{
				NodeName: "node-a",
				Containers: []kapiv1.Container{
					{
						Ports: []kapiv1.ContainerPort{
							{
								Name:          "tcp-proto",
								Protocol:      kapiv1.ProtocolTCP,
								ContainerPort: 1024,
							},
							{
								Name:          "unkn-proto",
								Protocol:      kapiv1.Protocol("unknown"),
								ContainerPort: 567,
							},
						},
					},
				},
			},
			Status: kapiv1.PodStatus{
				PodIP: "192.168.0.1",
			},
		}
		policy := apiv3.NewNetworkPolicy()
		policy.Name = "test-policy"
		policy.Namespace = "default"
		policy.Spec.Selector = "all()"

		// Send the pod through conversion and processing to imitate
		// the pipeline executed when sending to Felix.

		// Convert the pod to a WorkloadEndpoint.
		c := conversion.NewConverter()
		kvps, err := c.PodToWorkloadEndpoints(&pod)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(kvps)).To(Equal(1))

		// Process
		kvps, err = wepProcessor.Process(kvps[0])
		Expect(err).NotTo(HaveOccurred())
		Expect(len(kvps)).To(Equal(1))
		wep := kvps[0].Value.(*model.WorkloadEndpoint)

		// Send the NP through processing.
		npkvp := &model.KVPair{
			Key: model.ResourceKey{
				Kind:      apiv3.KindNetworkPolicy,
				Name:      policy.Name,
				Namespace: policy.Namespace,
			},
			Value: policy,
		}
		kvps, err = npProcessor.Process(npkvp)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(kvps)).To(Equal(1))
		np := kvps[0].Value.(*model.Policy)

		// Expect that the NP matches the pod.
		s, err := parser.Parse(np.Selector)
		Expect(err).NotTo(HaveOccurred())
		matches := s.Evaluate(wep.Labels)
		Expect(matches).To(BeTrue(), fmt.Sprintf("%s does not match %+v", np.Selector, wep.Labels))
	})

	It("should not match pods in other namespaces", func() {
		pod := kapiv1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "test-pod",
				Namespace:       "not-default",
				Labels:          map[string]string{"foo": "bar"},
				ResourceVersion: "1234",
			},
			Spec: kapiv1.PodSpec{
				NodeName: "node-a",
				Containers: []kapiv1.Container{
					{
						Ports: []kapiv1.ContainerPort{
							{
								Name:          "tcp-proto",
								Protocol:      kapiv1.ProtocolTCP,
								ContainerPort: 1024,
							},
							{
								Name:          "unkn-proto",
								Protocol:      kapiv1.Protocol("unknown"),
								ContainerPort: 567,
							},
						},
					},
				},
			},
			Status: kapiv1.PodStatus{
				PodIP: "192.168.0.1",
			},
		}
		policy := apiv3.NewNetworkPolicy()
		policy.Name = "test-policy"
		policy.Namespace = "default"
		policy.Spec.Selector = "all()"

		// Send the pod through conversion and processing to imitate
		// the pipeline executed when sending to Felix.

		// Convert the pod to a WorkloadEndpoint.
		c := conversion.NewConverter()
		kvps, err := c.PodToWorkloadEndpoints(&pod)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(kvps)).To(Equal(1))

		// Process
		kvps, err = wepProcessor.Process(kvps[0])
		Expect(err).NotTo(HaveOccurred())
		Expect(len(kvps)).To(Equal(1))
		wep := kvps[0].Value.(*model.WorkloadEndpoint)

		// Send the NP through processing.
		npkvp := &model.KVPair{
			Key: model.ResourceKey{
				Kind:      apiv3.KindNetworkPolicy,
				Name:      policy.Name,
				Namespace: policy.Namespace,
			},
			Value: policy,
		}
		kvps, err = npProcessor.Process(npkvp)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(kvps)).To(Equal(1))
		np := kvps[0].Value.(*model.Policy)

		// Expect that the NP does NOT match the pod, since they are not in the same namespace.
		s, err := parser.Parse(np.Selector)
		Expect(err).NotTo(HaveOccurred())
		matches := s.Evaluate(wep.Labels)
		Expect(matches).To(BeFalse(), fmt.Sprintf("%s matches pod in other namespace %+v", np.Selector, wep.Labels))
	})

	It("should select service accounts by name in rules even when they are long", func() {
		longName := "service-account-with-a-name-that-exceeds-the-character-limit-for-a-kubernetes-label"
		pod := kapiv1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "test-pod",
				Namespace:       "default",
				Labels:          map[string]string{"foo": "bar"},
				ResourceVersion: "1234",
			},
			Spec: kapiv1.PodSpec{
				NodeName:           "node-a",
				ServiceAccountName: longName,
				Containers: []kapiv1.Container{
					{
						Ports: []kapiv1.ContainerPort{
							{
								Name:          "tcp-proto",
								Protocol:      kapiv1.ProtocolTCP,
								ContainerPort: 1024,
							},
							{
								Name:          "unkn-proto",
								Protocol:      kapiv1.Protocol("unknown"),
								ContainerPort: 567,
							},
						},
					},
				},
			},
			Status: kapiv1.PodStatus{
				PodIP: "192.168.0.1",
			},
		}
		policy := apiv3.NewNetworkPolicy()
		policy.Name = "test-policy"
		policy.Namespace = "default"
		policy.Spec.Selector = "all()"
		policy.Spec.Ingress = []apiv3.Rule{
			{
				Source: apiv3.EntityRule{
					ServiceAccounts: &apiv3.ServiceAccountMatch{
						Names: []string{longName},
					},
				},
			},
		}

		// Send the pod through conversion and processing to imitate
		// the pipeline executed when sending to Felix.

		// Convert the pod to a WorkloadEndpoint.
		c := conversion.NewConverter()
		kvps, err := c.PodToWorkloadEndpoints(&pod)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(kvps)).To(Equal(1))

		// Expect the serviceaccount name to be set on the resulting WEP.
		Expect(kvps[0].Value.(*libapiv3.WorkloadEndpoint).Spec.ServiceAccountName).To(Equal(longName))

		// Process
		kvps, err = wepProcessor.Process(kvps[0])
		Expect(err).NotTo(HaveOccurred())
		Expect(len(kvps)).To(Equal(1))
		wep := kvps[0].Value.(*model.WorkloadEndpoint)

		// Send the NP through processing.
		npkvp := &model.KVPair{
			Key: model.ResourceKey{
				Kind:      apiv3.KindNetworkPolicy,
				Name:      policy.Name,
				Namespace: policy.Namespace,
			},
			Value: policy,
		}
		kvps, err = npProcessor.Process(npkvp)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(kvps)).To(Equal(1))
		np := kvps[0].Value.(*model.Policy)
		Expect(len(np.InboundRules)).To(Equal(1))

		// Expect that the NP ingress rule matches the pod.
		s, err := parser.Parse(np.InboundRules[0].SrcSelector)
		Expect(err).NotTo(HaveOccurred())
		matches := s.Evaluate(wep.Labels)
		Expect(matches).To(BeTrue(), fmt.Sprintf("%s does not match %+v", np.Selector, wep.Labels))
	})

})
