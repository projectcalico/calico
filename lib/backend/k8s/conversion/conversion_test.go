// Copyright (c) 2016-2019 Tigera, Inc. All rights reserved.

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

package conversion

import (
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/numorstring"

	kapiv1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var _ = Describe("Test parsing strings", func() {

	// Use a single instance of the Converter for these tests.
	c := Converter{}

	It("should parse WorkloadEndpoint name", func() {
		wepName := "node-k8s-pod--name-eth0"
		weid, err := c.ParseWorkloadEndpointName(wepName)
		Expect(err).NotTo(HaveOccurred())
		Expect(weid.Node).To(Equal("node"))
		Expect(weid.Orchestrator).To(Equal("k8s"))
		Expect(weid.Endpoint).To(Equal("eth0"))
		Expect(weid.Pod).To(Equal("pod-name"))
	})

	It("generate a veth name with the right prefix", func() {
		os.Setenv("FELIX_INTERFACEPREFIX", "eni,veth,foo")
		defer os.Setenv("FELIX_INTERFACEPREFIX", "")

		name := VethNameForWorkload("namespace", "podname")
		Expect(name).To(Equal("eni82111e10a96"))
	})

	It("should parse valid profile names", func() {
		name := "kns.default"
		ns, err := c.ProfileNameToNamespace(name)
		Expect(ns).To(Equal("default"))
		Expect(err).NotTo(HaveOccurred())
	})

	It("should not parse invalid profile names", func() {
		name := "ns.projectcalico.org/default"
		ns, err := c.ProfileNameToNamespace(name)
		Expect(err).To(HaveOccurred())
		Expect(ns).To(Equal(""))
	})

	It("should parse valid sa profile names", func() {
		name := "ksa.default.test"
		ns, sa, err := c.ProfileNameToServiceAccount(name)
		Expect(sa).To(Equal("test"))
		Expect(ns).To(Equal("default"))
		Expect(err).NotTo(HaveOccurred())
	})

	It("should parse valid sa profile names with dot(.)", func() {
		name := "ksa.default.test.foo"
		ns, sa, err := c.ProfileNameToServiceAccount(name)
		Expect(sa).To(Equal("test.foo"))
		Expect(ns).To(Equal("default"))
		Expect(err).NotTo(HaveOccurred())
	})

	It("should not parse invalid sa profile names", func() {
		name := "ns.projectcalico.org/default"
		ns, sa, err := c.ProfileNameToServiceAccount(name)
		Expect(err).To(HaveOccurred())
		Expect(ns).To(Equal(""))
		Expect(sa).To(Equal(""))
	})
})

var _ = Describe("Test selector conversion", func() {
	DescribeTable("selector conversion table",
		func(inSelector *metav1.LabelSelector, selectorType selectorType, expected string) {
			// First, convert the NetworkPolicy using the k8s conversion logic.
			c := Converter{}

			converted := c.k8sSelectorToCalico(inSelector, selectorType)

			// Finally, assert the expected result.
			Expect(converted).To(Equal(expected))
		},

		Entry("should handle an empty pod selector", &metav1.LabelSelector{}, SelectorPod, "projectcalico.org/orchestrator == 'k8s'"),
		Entry("should handle an empty namespace selector", &metav1.LabelSelector{}, SelectorNamespace, "all()"),
		Entry("should handle an OpDoesNotExist namespace selector",
			&metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "toast", Operator: metav1.LabelSelectorOpDoesNotExist},
				},
			},
			SelectorNamespace,
			"! has(toast)",
		),
		Entry("should handle an OpExists namespace selector",
			&metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "toast", Operator: metav1.LabelSelectorOpExists},
				},
			},
			SelectorNamespace,
			"has(toast)",
		),
		Entry("should handle an OpIn namespace selector",
			&metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "toast", Operator: metav1.LabelSelectorOpIn, Values: []string{"butter", "jam"}},
				},
			},
			SelectorNamespace,
			"toast in { 'butter', 'jam' }",
		),
		Entry("should handle an OpNotIn namespace selector",
			&metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "toast", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"marmite", "milk"}},
				},
			},
			SelectorNamespace,
			"toast not in { 'marmite', 'milk' }",
		),
		Entry("should handle an OpDoesNotExist pod selector",
			&metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "toast", Operator: metav1.LabelSelectorOpDoesNotExist},
				},
			},
			SelectorPod,
			"projectcalico.org/orchestrator == 'k8s' && ! has(toast)",
		),
		Entry("should handle nil pod selector", nil, SelectorPod, "projectcalico.org/orchestrator == 'k8s'"),
		Entry("should handle nil namespace selector", nil, SelectorNamespace, ""),
	)
})

var _ = Describe("Test Pod conversion", func() {

	// Use a single instance of the Converter for these tests.
	c := Converter{}

	It("should parse a Pod with an IP to a WorkloadEndpoint", func() {
		pod := kapiv1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "podA",
				Namespace: "default",
				Annotations: map[string]string{
					"arbitrary": "annotation",
				},
				Labels: map[string]string{
					"labelA": "valueA",
					"labelB": "valueB",
				},
				ResourceVersion: "1234",
			},
			Spec: kapiv1.PodSpec{
				NodeName: "nodeA",
				Containers: []kapiv1.Container{
					{
						Ports: []kapiv1.ContainerPort{
							{
								ContainerPort: 5678,
							},
							{
								Name:          "no-proto",
								ContainerPort: 1234,
							},
						},
					},
					{
						Ports: []kapiv1.ContainerPort{
							{
								Name:          "tcp-proto",
								Protocol:      kapiv1.ProtocolTCP,
								ContainerPort: 1024,
							},
							{
								Name:          "tcp-proto-with-host-port",
								Protocol:      kapiv1.ProtocolTCP,
								ContainerPort: 8080,
								HostPort:      5678,
							},
							{
								Name:          "udp-proto",
								Protocol:      kapiv1.ProtocolUDP,
								ContainerPort: 432,
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

		wep, err := c.PodToWorkloadEndpoint(&pod)
		Expect(err).NotTo(HaveOccurred())

		// Make sure the type information is correct.
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).Kind).To(Equal(apiv3.KindWorkloadEndpoint))
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).APIVersion).To(Equal(apiv3.GroupVersionCurrent))

		// Assert key fields.
		Expect(wep.Key.(model.ResourceKey).Name).To(Equal("nodeA-k8s-podA-eth0"))
		Expect(wep.Key.(model.ResourceKey).Namespace).To(Equal("default"))
		Expect(wep.Key.(model.ResourceKey).Kind).To(Equal(apiv3.KindWorkloadEndpoint))

		Expect(wep.Value.(*apiv3.WorkloadEndpoint).Spec.Pod).To(Equal("podA"))
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).Spec.Node).To(Equal("nodeA"))
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).Spec.Endpoint).To(Equal("eth0"))
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).Spec.Orchestrator).To(Equal("k8s"))
		Expect(len(wep.Value.(*apiv3.WorkloadEndpoint).Spec.IPNetworks)).To(Equal(1))
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).Spec.IPNetworks[0]).To(Equal("192.168.0.1/32"))
		Expect(len(wep.Value.(*apiv3.WorkloadEndpoint).Spec.Profiles)).To(Equal(1))
		expectedLabels := map[string]string{
			"labelA":                         "valueA",
			"labelB":                         "valueB",
			"projectcalico.org/namespace":    "default",
			"projectcalico.org/orchestrator": "k8s",
		}
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).ObjectMeta.Labels).To(Equal(expectedLabels))

		nsProtoTCP := numorstring.ProtocolFromString("tcp")
		nsProtoUDP := numorstring.ProtocolFromString("udp")
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).Spec.Ports).To(ConsistOf(
			// No proto defaults to TCP (as defined in k8s API spec)
			apiv3.EndpointPort{Name: "no-proto", Port: 1234, Protocol: nsProtoTCP},
			// Explicit TCP proto is OK too.
			apiv3.EndpointPort{Name: "tcp-proto", Port: 1024, Protocol: nsProtoTCP},
			// Host port should be ignored.
			apiv3.EndpointPort{Name: "tcp-proto-with-host-port", Port: 8080, Protocol: nsProtoTCP},
			// UDP is also an option.
			apiv3.EndpointPort{Name: "udp-proto", Port: 432, Protocol: nsProtoUDP},
			// Unknown protocol port is ignored.
		))

		// Assert the interface name is fixed.  The calculation of this name should be consistent
		// between releases otherwise there will be issues upgrading a node with networked Pods.
		// If this fails, fix the code not this expect!
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).Spec.InterfaceName).To(Equal("cali7f94ce7c295"))

		// Assert ResourceVersion is present.
		Expect(wep.Revision).To(Equal("1234"))
	})

	It("should look in the calico annotation for the IP", func() {
		pod := kapiv1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "podA",
				Namespace: "default",
				Annotations: map[string]string{
					"arbitrary":                   "annotation",
					"cni.projectcalico.org/podIP": "192.168.0.1",
				},
				Labels: map[string]string{
					"labelA": "valueA",
					"labelB": "valueB",
				},
				ResourceVersion: "1234",
			},
			Spec: kapiv1.PodSpec{
				NodeName:   "nodeA",
				Containers: []kapiv1.Container{},
			},
		}

		wep, err := c.PodToWorkloadEndpoint(&pod)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.HasIPAddress(&pod)).To(BeTrue())
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).Spec.IPNetworks).To(ConsistOf("192.168.0.1/32"))
	})

	It("should look in the calico annotation for a floating IP", func() {
		pod := kapiv1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "podA",
				Namespace: "default",
				Annotations: map[string]string{
					"arbitrary":                         "annotation",
					"cni.projectcalico.org/podIP":       "192.168.0.1",
					"cni.projectcalico.org/floatingIPs": "[\"1.1.1.1\"]",
				},
				Labels: map[string]string{
					"labelA": "valueA",
					"labelB": "valueB",
				},
				ResourceVersion: "1234",
			},
			Spec: kapiv1.PodSpec{
				NodeName:   "nodeA",
				Containers: []kapiv1.Container{},
			},
		}

		wep, err := c.PodToWorkloadEndpoint(&pod)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.HasIPAddress(&pod)).To(BeTrue())
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).Spec.IPNetworks).To(ConsistOf("192.168.0.1/32"))

		// Assert that the endpoint contains the appropriate DNAT
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).Spec.IPNATs).To(ConsistOf(apiv3.IPNAT{InternalIP: "192.168.0.1", ExternalIP: "1.1.1.1"}))

	})

	It("should return an error for a bad pod IP", func() {
		pod := kapiv1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "podA",
				Namespace: "default",
				Annotations: map[string]string{
					"cni.projectcalico.org/podIP": "foobar",
				},
				ResourceVersion: "1234",
			},
			Spec: kapiv1.PodSpec{
				NodeName:   "nodeA",
				Containers: []kapiv1.Container{},
			},
		}

		_, err := c.PodToWorkloadEndpoint(&pod)
		Expect(err).To(HaveOccurred())
	})

	It("should return a value for a missing pod IP", func() {
		pod := kapiv1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "podA",
				Namespace:       "default",
				ResourceVersion: "1234",
			},
			Spec: kapiv1.PodSpec{
				NodeName:   "nodeA",
				Containers: []kapiv1.Container{},
			},
		}

		kvp, err := c.PodToWorkloadEndpoint(&pod)
		Expect(err).NotTo(HaveOccurred())
		Expect(kvp.Value).NotTo(BeNil())
	})

	It("should prioritise PodIP over the calico annotation for the IP", func() {
		pod := kapiv1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "podA",
				Namespace: "default",
				Annotations: map[string]string{
					"arbitrary":                   "annotation",
					"cni.projectcalico.org/podIP": "192.168.0.1",
				},
				Labels: map[string]string{
					"labelA": "valueA",
					"labelB": "valueB",
				},
				ResourceVersion: "1234",
			},
			Spec: kapiv1.PodSpec{
				NodeName:   "nodeA",
				Containers: []kapiv1.Container{},
			},
			Status: kapiv1.PodStatus{
				PodIP: "192.168.0.2",
			},
		}

		wep, err := c.PodToWorkloadEndpoint(&pod)
		Expect(err).NotTo(HaveOccurred())

		Expect(wep.Value.(*apiv3.WorkloadEndpoint).Spec.IPNetworks).To(ConsistOf("192.168.0.2/32"))
	})

	DescribeTable("PodToWorkloadEndpoint reject/accept phase tests",
		func(podPhase kapiv1.PodPhase, expectedResult bool) {
			pod := kapiv1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "podA",
					Namespace: "default",
					Annotations: map[string]string{
						"cni.projectcalico.org/podIP": "192.168.0.1",
					},
					ResourceVersion: "1234",
				},
				Spec: kapiv1.PodSpec{
					NodeName:   "nodeA",
					Containers: []kapiv1.Container{},
				},
				Status: kapiv1.PodStatus{
					PodIP: "192.168.0.1",
					Phase: podPhase,
				},
			}
			kvp, err := c.PodToWorkloadEndpoint(&pod)
			Expect(err).NotTo(HaveOccurred())
			if expectedResult {
				Expect(kvp.Value.(*apiv3.WorkloadEndpoint).Spec.IPNetworks).To(HaveLen(1))
			} else {
				Expect(kvp.Value.(*apiv3.WorkloadEndpoint).Spec.IPNetworks).To(HaveLen(0))
			}
		},
		Entry("Pending", kapiv1.PodPending, true),
		Entry("Running", kapiv1.PodRunning, true),
		// PodUnknown usually means that the Kubelet is out-of-touch with the API server.  It _might_ be
		// finished but I think we have to assume that it's still alive to avoid escalating the Kubelet failure
		// to a network outage for that pod.
		Entry("Unknown", kapiv1.PodUnknown, true),
		Entry("Pending", kapiv1.PodSucceeded, false),
		Entry("Failed", kapiv1.PodFailed, false),
		Entry("Completed", kapiv1.PodPhase("Completed"), false),
	)

	It("Pod without an IP should be valid but not ready", func() {
		pod := kapiv1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "podB",
				Namespace: "default",
				Annotations: map[string]string{
					"arbitrary": "annotation",
				},
				Labels: map[string]string{
					"labelA": "valueA",
					"labelB": "valueB",
				},
			},
			Spec: kapiv1.PodSpec{
				NodeName: "nodeA",
			},
			Status: kapiv1.PodStatus{},
		}

		Expect(c.IsValidCalicoWorkloadEndpoint(&pod)).To(BeTrue())
		_, err := c.PodToWorkloadEndpoint(&pod)
		Expect(err).NotTo(HaveOccurred())

		Expect(c.IsReadyCalicoPod(&pod)).To(BeFalse())
	})

	It("should parse a Pod with no labels", func() {
		pod := kapiv1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "podB",
				Namespace: "default",
			},
			Spec: kapiv1.PodSpec{
				NodeName: "nodeA",
			},
			Status: kapiv1.PodStatus{
				PodIP: "192.168.0.1",
			},
		}

		wep, err := c.PodToWorkloadEndpoint(&pod)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields.
		Expect(wep.Key.(model.ResourceKey).Name).To(Equal("nodeA-k8s-podB-eth0"))
		Expect(wep.Key.(model.ResourceKey).Namespace).To(Equal("default"))
		Expect(wep.Key.(model.ResourceKey).Kind).To(Equal(apiv3.KindWorkloadEndpoint))
		// Assert value fields.
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).Spec.Pod).To(Equal("podB"))
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).Spec.Node).To(Equal("nodeA"))
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).Spec.Endpoint).To(Equal("eth0"))
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).Spec.Orchestrator).To(Equal("k8s"))
		Expect(len(wep.Value.(*apiv3.WorkloadEndpoint).Spec.IPNetworks)).To(Equal(1))
		Expect(len(wep.Value.(*apiv3.WorkloadEndpoint).Spec.Profiles)).To(Equal(1))
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).ObjectMeta.Labels).To(Equal(map[string]string{
			"projectcalico.org/namespace":    "default",
			"projectcalico.org/orchestrator": "k8s",
		}))

		// Assert the interface name is fixed.  The calculation of this name should be consistent
		// between releases otherwise there will be issues upgrading a node with networked Pods.
		// If this fails, fix the code not this expect!
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).Spec.InterfaceName).To(Equal("cali92cf1f5e9f6"))
	})

	It("should not parse a Pod with no NodeName", func() {
		pod := kapiv1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "podA",
				Namespace: "default",
			},
			Spec: kapiv1.PodSpec{},
			Status: kapiv1.PodStatus{
				PodIP: "192.168.0.1",
			},
		}

		_, err := c.PodToWorkloadEndpoint(&pod)
		Expect(err).To(HaveOccurred())
	})

	It("should parse a Pod with serviceaccount", func() {
		pod := kapiv1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "podA",
				Namespace: "default",
				Annotations: map[string]string{
					"arbitrary": "annotation",
				},
				Labels: map[string]string{
					"labelA": "valueA",
					"labelB": "valueB",
				},
				ResourceVersion: "1234",
			},
			Spec: kapiv1.PodSpec{
				NodeName:           "nodeA",
				ServiceAccountName: "sa-test",
				Containers: []kapiv1.Container{
					{
						Ports: []kapiv1.ContainerPort{
							{
								ContainerPort: 5678,
							},
							{
								Name:          "no-proto",
								ContainerPort: 1234,
							},
						},
					},
					{
						Ports: []kapiv1.ContainerPort{
							{
								Name:          "tcp-proto",
								Protocol:      kapiv1.ProtocolTCP,
								ContainerPort: 1024,
							},
						},
					},
				},
			},
			Status: kapiv1.PodStatus{
				PodIP: "192.168.0.1",
			},
		}

		wep, err := c.PodToWorkloadEndpoint(&pod)
		Expect(err).NotTo(HaveOccurred())

		// Make sure the type information is correct.
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).Kind).To(Equal(apiv3.KindWorkloadEndpoint))
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).APIVersion).To(Equal(apiv3.GroupVersionCurrent))

		// Assert key fields.
		Expect(wep.Key.(model.ResourceKey).Name).To(Equal("nodeA-k8s-podA-eth0"))
		Expect(wep.Key.(model.ResourceKey).Namespace).To(Equal("default"))
		Expect(wep.Key.(model.ResourceKey).Kind).To(Equal(apiv3.KindWorkloadEndpoint))

		// Check for only values that are ServiceAccount related.
		Expect(len(wep.Value.(*apiv3.WorkloadEndpoint).Spec.Profiles)).To(Equal(2))
		expectedLabels := map[string]string{
			"labelA":                         "valueA",
			"labelB":                         "valueB",
			"projectcalico.org/namespace":    "default",
			"projectcalico.org/orchestrator": "k8s",
			apiv3.LabelServiceAccount:        "sa-test",
		}
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).ObjectMeta.Labels).To(Equal(expectedLabels))

		// Assert ResourceVersion is present.
		Expect(wep.Revision).To(Equal("1234"))
	})

	It("should parse a Pod with GenerateName set in metadata", func() {
		gname := "generatedname"
		pod := kapiv1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:         "podA",
				Namespace:    "default",
				GenerateName: gname,
			},
			Spec: kapiv1.PodSpec{
				NodeName: "nodeA",
			},
			Status: kapiv1.PodStatus{
				PodIP: "192.168.0.1",
			},
		}

		wep, err := c.PodToWorkloadEndpoint(&pod)
		Expect(err).NotTo(HaveOccurred())

		// Make sure the GenerateName information is correct.
		Expect(wep.Value.(*apiv3.WorkloadEndpoint).GenerateName).To(Equal(gname))
	})
})

var _ = Describe("Test NetworkPolicy conversion", func() {

	// Use a single instance of the Converter for these tests.
	c := Converter{}

	It("should parse a basic k8s NetworkPolicy to a NetworkPolicy", func() {
		port80 := intstr.FromInt(80)
		portFoo := intstr.FromString("foo")
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"label":  "value",
						"label2": "value2",
					},
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{Port: &port80},
							{Port: &portFoo},
						},
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k":  "v",
										"k2": "v2",
									},
								},
							},
						},
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}

		// Parse the policy.
		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		// Make sure the type information is correct.
		Expect(pol.Value.(*apiv3.NetworkPolicy).Kind).To(Equal(apiv3.KindNetworkPolicy))
		Expect(pol.Value.(*apiv3.NetworkPolicy).APIVersion).To(Equal(apiv3.GroupVersionCurrent))

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		// Check the selector is correct, and that the matches are sorted.
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal(
			"projectcalico.org/orchestrator == 'k8s' && label == 'value' && label2 == 'value2'"))
		protoTCP := numorstring.ProtocolFromString("TCP")
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Action:   "Allow",
				Protocol: &protoTCP, // Defaulted to TCP.
				Source: apiv3.EntityRule{
					Selector: "projectcalico.org/orchestrator == 'k8s' && k == 'v' && k2 == 'v2'",
				},
				Destination: apiv3.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(80)},
				},
			},
			apiv3.Rule{
				Action:   "Allow",
				Protocol: &protoTCP, // Defaulted to TCP.
				Source: apiv3.EntityRule{
					Selector: "projectcalico.org/orchestrator == 'k8s' && k == 'v' && k2 == 'v2'",
				},
				Destination: apiv3.EntityRule{
					Ports: []numorstring.Port{numorstring.NamedPort("foo")},
				},
			},
		))

		// There should be no Egress rules
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
	})

	It("should drop rules with invalid ports in a k8s NetworkPolicy", func() {
		port80 := intstr.FromInt(80)
		portFoo := intstr.FromString("foo")
		portBad := intstr.FromString("-50:-1")
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"label":  "value",
						"label2": "value2",
					},
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{Port: &port80},
							{Port: &portFoo},
						},
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k":  "v",
										"k2": "v2",
									},
								},
							},
						},
					},
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{Port: &port80},
							{Port: &portBad},
						},
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k":  "v",
										"k2": "v2",
									},
								},
							},
						},
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}

		// Parse the policy.
		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		protoTCP := numorstring.ProtocolFromString("TCP")

		// Only the two valid rules should exist. The third should have been dropped.
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(2))

		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Action:   "Allow",
				Protocol: &protoTCP, // Defaulted to TCP.
				Source: apiv3.EntityRule{
					Selector: "projectcalico.org/orchestrator == 'k8s' && k == 'v' && k2 == 'v2'",
				},
				Destination: apiv3.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(80)},
				},
			},
			apiv3.Rule{
				Action:   "Allow",
				Protocol: &protoTCP, // Defaulted to TCP.
				Source: apiv3.EntityRule{
					Selector: "projectcalico.org/orchestrator == 'k8s' && k == 'v' && k2 == 'v2'",
				},
				Destination: apiv3.EntityRule{
					Ports: []numorstring.Port{numorstring.NamedPort("foo")},
				},
			},
		))
	})

	It("should parse a NetworkPolicy with no rules", func() {
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}

		// Parse the policy.
		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && label == 'value'"))
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(0))

		// There should be no Egress rules
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
	})

	It("should parse a default-deny egress NetworkPolicy", func() {
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			},
		}

		pol, err := c.K8sNetworkPolicyToCalico(&np)
		By("parsing the policy", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		By("generating the correct name and namespace", func() {
			Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.testPolicy"))
			Expect(pol.Key.(model.ResourceKey).Namespace).To(Equal("default"))
		})

		By("generating the correct selector", func() {
			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		})

		By("generating the correct order", func() {
			Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		})

		By("generating no outbound rules", func() {
			Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))
		})

		By("generating no inbound rules", func() {
			Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(0))
		})

		By("generating the correct policy types", func() {
			Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeEgress))
		})
	})

	It("should parse a NetworkPolicy with multiple peers", func() {
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{},
						},
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k": "v",
									},
								},
							},
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k2": "v2",
									},
								},
							},
						},
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}

		var pol *model.KVPair
		var err error
		By("parsing the policy", func() {
			pol, err = c.K8sNetworkPolicyToCalico(&np)
			Expect(err).NotTo(HaveOccurred())
			Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))
			Expect(pol.Key.(model.ResourceKey).Namespace).To(Equal("default"))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Name).To(Equal("knp.default.test.policy"))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Namespace).To(Equal("default"))
			Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		})

		By("having the correct endpoint selector", func() {
			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && label == 'value'"))
		})

		By("having the correct peer selectors", func() {
			Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(2))

			// There should be no Egress rules.
			Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))

			// Check that Types field exists and has only 'ingress'
			Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))

			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k == 'v'"))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[1].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k2 == 'v2'"))
		})
	})

	It("should parse a k8s NetworkPolicy with a DoesNotExist expression ", func() {
		port80 := intstr.FromInt(80)
		portFoo := intstr.FromString("foo")
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"label":  "value",
						"label2": "value2",
					},
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{Port: &port80},
							{Port: &portFoo},
						},
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchExpressions: []metav1.LabelSelectorRequirement{
										{Key: "toast", Operator: metav1.LabelSelectorOpDoesNotExist},
									},
								},
							},
						},
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}

		// Parse the policy.
		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		// Make sure the type information is correct.
		Expect(pol.Value.(*apiv3.NetworkPolicy).Kind).To(Equal(apiv3.KindNetworkPolicy))
		Expect(pol.Value.(*apiv3.NetworkPolicy).APIVersion).To(Equal(apiv3.GroupVersionCurrent))

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		// Check the selector is correct, and that the matches are sorted.
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal(
			"projectcalico.org/orchestrator == 'k8s' && label == 'value' && label2 == 'value2'"))
		protoTCP := numorstring.ProtocolFromString("TCP")
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress).To(ConsistOf(
			apiv3.Rule{
				Action:   "Allow",
				Protocol: &protoTCP, // Defaulted to TCP.
				Source: apiv3.EntityRule{
					Selector: "projectcalico.org/orchestrator == 'k8s' && ! has(toast)",
				},
				Destination: apiv3.EntityRule{
					Ports: []numorstring.Port{numorstring.SinglePort(80)},
				},
			},
			apiv3.Rule{
				Action:   "Allow",
				Protocol: &protoTCP, // Defaulted to TCP.
				Source: apiv3.EntityRule{
					Selector: "projectcalico.org/orchestrator == 'k8s' && ! has(toast)",
				},
				Destination: apiv3.EntityRule{
					Ports: []numorstring.Port{numorstring.NamedPort("foo")},
				},
			},
		))

		// There should be no Egress rules
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
	})

	It("should parse a NetworkPolicy with multiple peers and ports", func() {
		tcp := kapiv1.ProtocolTCP
		udp := kapiv1.ProtocolUDP
		eighty := intstr.FromInt(80)
		ninety := intstr.FromInt(90)

		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Port:     &ninety,
								Protocol: &udp,
							},
							{
								Port:     &eighty,
								Protocol: &tcp,
							},
						},
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k": "v",
									},
								},
							},
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k2": "v2",
									},
								},
							},
						},
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}

		var pol *model.KVPair
		var err error
		By("parsing the policy", func() {
			pol, err = c.K8sNetworkPolicyToCalico(&np)
			Expect(err).NotTo(HaveOccurred())
			Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))
			Expect(pol.Key.(model.ResourceKey).Namespace).To(Equal("default"))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Name).To(Equal("knp.default.test.policy"))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Namespace).To(Equal("default"))
			Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		})

		By("having the correct endpoint selector", func() {
			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && label == 'value'"))
		})

		By("having the correct peer selectors", func() {
			eighty, _ := numorstring.PortFromString("80")
			ninety, _ := numorstring.PortFromString("90")
			Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(4))

			// There should be no Egress rules.
			Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))

			// Check that Types field exists and has only 'ingress'
			Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))

			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k == 'v'"))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Destination.Ports).To(Equal([]numorstring.Port{ninety}))

			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[1].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k2 == 'v2'"))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[1].Destination.Ports).To(Equal([]numorstring.Port{ninety}))

			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[2].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k == 'v'"))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[2].Destination.Ports).To(Equal([]numorstring.Port{eighty}))

			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[3].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k2 == 'v2'"))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[3].Destination.Ports).To(Equal([]numorstring.Port{eighty}))
		})
	})

	It("should parse a NetworkPolicy with empty podSelector", func() {
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}

		// Parse the policy.
		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(0))

		// There should be no Egress rules.
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
	})

	It("should parse a NetworkPolicy with a namespaceSelector", func() {
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						From: []networkingv1.NetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"namespaceRole": "dev",
										"namespaceFoo":  "bar",
									},
								},
							},
						},
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}

		// Parse the policy.
		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && label == 'value'"))
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Source.NamespaceSelector).To(Equal("namespaceFoo == 'bar' && namespaceRole == 'dev'"))

		// There should be no Egress rules.
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
	})

	It("should parse a NetworkPolicy with a nil namespace selector", func() {
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						From: []networkingv1.NetworkPolicyPeer{
							{
								NamespaceSelector: nil,
								PodSelector:       &metav1.LabelSelector{},
							},
						},
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}

		// Parse the policy.
		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && label == 'value'"))
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Source.NamespaceSelector).To(Equal(""))

		// There should be no Egress rules.
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
	})

	It("should parse a NetworkPolicy with an empty namespaceSelector", func() {
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						From: []networkingv1.NetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{},
								},
							},
						},
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}

		// Parse the policy.
		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && label == 'value'"))
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Source.NamespaceSelector).To(Equal("all()"))

		// There should be no Egress rules.
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
	})

	It("should parse a NetworkPolicy with pod and namespace selectors", func() {
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						From: []networkingv1.NetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"namespaceRole": "dev",
										"namespaceFoo":  "bar",
									},
								},
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"podA": "B",
										"podC": "D",
									},
								},
							},
						},
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}

		// Parse the policy.
		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && label == 'value'"))
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && podA == 'B' && podC == 'D'"))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Source.NamespaceSelector).To(Equal("namespaceFoo == 'bar' && namespaceRole == 'dev'"))

		// There should be no Egress rules.
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
	})

	It("should parse a NetworkPolicy with podSelector.MatchExpressions", func() {
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "k",
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{"v1", "v2"},
						},
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}

		// Parse the policy.
		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k in { 'v1', 'v2' }"))
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(0))

		// There should be no Egress rules.
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
	})

	It("should parse a NetworkPolicy with Ports only", func() {
		protocol := kapiv1.ProtocolTCP
		port := intstr.FromInt(80)
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: &protocol,
								Port:     &port,
							},
						},
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}

		// Parse the policy.
		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Protocol.String()).To(Equal("TCP"))
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Destination.Ports)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Destination.Ports[0].String()).To(Equal("80"))

		// There should be no Egress rules.
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
	})

	It("should parse a NetworkPolicy with Ports only (egress)", func() {
		protocol := kapiv1.ProtocolTCP
		port := intstr.FromInt(80)
		np := networkingv1.NetworkPolicy{
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

		// Parse the policy.
		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[0].Protocol.String()).To(Equal("TCP"))
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[0].Destination.Ports)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[0].Destination.Ports[0].String()).To(Equal("80"))

		// There should be no Ingress rules
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(0))

		// Check that Types field exists and has only 'egress'
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeEgress))
	})

	It("should parse a NetworkPolicy with an Ingress rule with an IPBlock Peer", func() {
		np := networkingv1.NetworkPolicy{
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
								IPBlock: &networkingv1.IPBlock{
									CIDR:   "192.168.0.0/16",
									Except: []string{"192.168.3.0/24", "192.168.4.0/24"},
								},
							},
						},
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		}

		// Parse the policy.
		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Source.Nets[0]).To(Equal("192.168.0.0/16"))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Source.NotNets[0]).To(Equal("192.168.3.0/24"))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Source.NotNets[1]).To(Equal("192.168.4.0/24"))

		// There should be no Egress rules.
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
	})

	It("should parse a NetworkPolicy with an Egress rule with an IPBlock Peer", func() {
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								IPBlock: &networkingv1.IPBlock{
									CIDR:   "192.168.0.0/16",
									Except: []string{"192.168.3.0/24", "192.168.4.0/24", "192.168.5.0/24"},
								},
							},
						},
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			},
		}

		// Parse the policy.
		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[0].Destination.Nets[0]).To(Equal("192.168.0.0/16"))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[0].Destination.NotNets[0]).To(Equal("192.168.3.0/24"))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[0].Destination.NotNets[1]).To(Equal("192.168.4.0/24"))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[0].Destination.NotNets[2]).To(Equal("192.168.5.0/24"))

		// There should be no Ingress
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(0))

		// Check that Types field exists and has only 'egress'
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeEgress))
	})

	It("should parse a NetworkPolicy with an Egress rule with IPBlock and Ports", func() {
		tcp := kapiv1.ProtocolTCP
		udp := kapiv1.ProtocolUDP
		eighty := intstr.FromInt(80)
		ninety := intstr.FromInt(90)

		np := networkingv1.NetworkPolicy{
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
								Port:     &ninety,
								Protocol: &udp,
							},
							{
								Port:     &eighty,
								Protocol: &tcp,
							},
						},
						To: []networkingv1.NetworkPolicyPeer{
							{
								IPBlock: &networkingv1.IPBlock{
									CIDR:   "192.168.0.0/16",
									Except: []string{"192.168.3.0/24", "192.168.4.0/24", "192.168.5.0/24"},
								},
							},
						},
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			},
		}

		// Parse the policy.
		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))

		eightyName, _ := numorstring.PortFromString("80")
		ninetyName, _ := numorstring.PortFromString("90")

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(2))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[0].Destination.Ports).To(Equal([]numorstring.Port{ninetyName}))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[0].Destination.Nets[0]).To(Equal("192.168.0.0/16"))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[0].Destination.NotNets[0]).To(Equal("192.168.3.0/24"))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[0].Destination.NotNets[1]).To(Equal("192.168.4.0/24"))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[0].Destination.NotNets[2]).To(Equal("192.168.5.0/24"))

		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[1].Destination.Ports).To(Equal([]numorstring.Port{eightyName}))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[1].Destination.Nets[0]).To(Equal("192.168.0.0/16"))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[1].Destination.NotNets[0]).To(Equal("192.168.3.0/24"))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[1].Destination.NotNets[1]).To(Equal("192.168.4.0/24"))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[1].Destination.NotNets[2]).To(Equal("192.168.5.0/24"))

		// There should be no Ingress
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(0))

		// Check that Types field exists and has only 'egress'
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeEgress))
	})

	It("should parse a NetworkPolicy with both an Egress and an Ingress rule", func() {
		np := networkingv1.NetworkPolicy{
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
								IPBlock: &networkingv1.IPBlock{
									CIDR:   "192.168.0.0/16",
									Except: []string{"192.168.3.0/24", "192.168.4.0/24"},
								},
							},
						},
					},
				},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								IPBlock: &networkingv1.IPBlock{
									CIDR:   "10.10.0.0/16",
									Except: []string{"192.168.13.0/24", "192.168.14.0/24", "192.168.15.0/24"},
								},
							},
						},
					},
				},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress, networkingv1.PolicyTypeIngress},
			},
		}

		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[0].Destination.Nets[0]).To(Equal("10.10.0.0/16"))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[0].Destination.NotNets[0]).To(Equal("192.168.13.0/24"))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[0].Destination.NotNets[1]).To(Equal("192.168.14.0/24"))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress[0].Destination.NotNets[2]).To(Equal("192.168.15.0/24"))

		// There should be one InboundRule
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(1))

		// Assert InboundRule fields are correct.
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Source.Nets[0]).To(Equal("192.168.0.0/16"))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Source.NotNets[0]).To(Equal("192.168.3.0/24"))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Source.NotNets[1]).To(Equal("192.168.4.0/24"))

		// Check that Types field exists and has both 'egress' and 'ingress'
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(2))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[1]).To(Equal(apiv3.PolicyTypeEgress))
	})
})

// This suite of tests is useful for ensuring we continue to support kubernetes apiserver
// versions <= 1.7.x, and can be removed when that is no longer required.
var _ = Describe("Test NetworkPolicy conversion (k8s <= 1.7, no policyTypes)", func() {

	// Use a single instance of the Converter for these tests.
	c := Converter{}

	It("should parse a basic NetworkPolicy to a Policy", func() {
		port80 := intstr.FromInt(80)
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"label":  "value",
						"label2": "value2",
					},
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{Port: &port80},
						},
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k":  "v",
										"k2": "v2",
									},
								},
							},
						},
					},
				},
			},
		}

		// Parse the policy.
		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		// Check the selector is correct, and that the matches are sorted.
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal(
			"projectcalico.org/orchestrator == 'k8s' && label == 'value' && label2 == 'value2'"))
		protoTCP := numorstring.ProtocolFromString("TCP")
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress).To(ConsistOf(apiv3.Rule{
			Action:   "Allow",
			Protocol: &protoTCP, // Defaulted to TCP.
			Source: apiv3.EntityRule{
				Selector: "projectcalico.org/orchestrator == 'k8s' && k == 'v' && k2 == 'v2'",
			},
			Destination: apiv3.EntityRule{
				Ports: []numorstring.Port{numorstring.SinglePort(80)},
			},
		}))

		// There should be no Egress rule.
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
	})

	It("should parse a NetworkPolicy with no rules", func() {
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
			},
		}

		// Parse the policy.
		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && label == 'value'"))
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(0))

		// There should be no Egress rule.
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
	})

	It("should parse a NetworkPolicy with multiple peers", func() {
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{},
						},
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k": "v",
									},
								},
							},
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k2": "v2",
									},
								},
							},
						},
					},
				},
			},
		}

		var pol *model.KVPair
		var err error
		By("parsing the policy", func() {
			pol, err = c.K8sNetworkPolicyToCalico(&np)
			Expect(err).NotTo(HaveOccurred())
			Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))
			Expect(pol.Key.(model.ResourceKey).Namespace).To(Equal("default"))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Name).To(Equal("knp.default.test.policy"))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Namespace).To(Equal("default"))
			Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		})

		By("having the correct endpoint selector", func() {
			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && label == 'value'"))
		})

		By("having the correct peer selectors", func() {
			Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(2))

			// There should be no Egress rule.
			Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))

			// Check that Types field exists and has only 'ingress'
			Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))

			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k == 'v'"))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[1].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k2 == 'v2'"))
		})
	})

	It("should parse a NetworkPolicy with multiple peers and ports", func() {
		tcp := kapiv1.ProtocolTCP
		udp := kapiv1.ProtocolUDP
		eighty := intstr.FromInt(80)
		ninety := intstr.FromInt(90)

		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"label": "value"},
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Port:     &ninety,
								Protocol: &udp,
							},
							{
								Port:     &eighty,
								Protocol: &tcp,
							},
						},
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k": "v",
									},
								},
							},
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"k2": "v2",
									},
								},
							},
						},
					},
				},
			},
		}

		var pol *model.KVPair
		var err error
		By("parsing the policy", func() {
			pol, err = c.K8sNetworkPolicyToCalico(&np)
			Expect(err).NotTo(HaveOccurred())
			Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))
			Expect(pol.Key.(model.ResourceKey).Namespace).To(Equal("default"))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Name).To(Equal("knp.default.test.policy"))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Namespace).To(Equal("default"))
			Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		})

		By("having the correct endpoint selector", func() {
			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && label == 'value'"))
		})

		By("having the correct peer selectors", func() {
			eighty, _ := numorstring.PortFromString("80")
			ninety, _ := numorstring.PortFromString("90")
			Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(4))

			// There should be no Egress rule.
			Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))

			// Check that Types field exists and has only 'ingress'
			Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))

			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k == 'v'"))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Destination.Ports).To(Equal([]numorstring.Port{ninety}))

			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[1].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k2 == 'v2'"))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[1].Destination.Ports).To(Equal([]numorstring.Port{ninety}))

			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[2].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k == 'v'"))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[2].Destination.Ports).To(Equal([]numorstring.Port{eighty}))

			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[3].Source.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k2 == 'v2'"))
			Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[3].Destination.Ports).To(Equal([]numorstring.Port{eighty}))
		})
	})

	It("should parse a NetworkPolicy with empty podSelector", func() {
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
			},
		}

		// Parse the policy.
		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(0))

		// There should be no Egress rule.
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
	})

	It("should parse a NetworkPolicy with podSelector.MatchExpressions", func() {
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "k",
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{"v1", "v2"},
						},
					},
				},
			},
		}

		// Parse the policy.
		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s' && k in { 'v1', 'v2' }"))
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(0))

		// There should be no Egress rule.
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
	})

	It("should parse a NetworkPolicy with Ports only", func() {
		protocol := kapiv1.ProtocolTCP
		port := intstr.FromInt(80)
		np := networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test.policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: &protocol,
								Port:     &port,
							},
						},
					},
				},
			},
		}

		// Parse the policy.
		pol, err := c.K8sNetworkPolicyToCalico(&np)
		Expect(err).NotTo(HaveOccurred())

		// Assert key fields are correct.
		Expect(pol.Key.(model.ResourceKey).Name).To(Equal("knp.default.test.policy"))

		// Assert value fields are correct.
		Expect(int(*pol.Value.(*apiv3.NetworkPolicy).Spec.Order)).To(Equal(1000))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Selector).To(Equal("projectcalico.org/orchestrator == 'k8s'"))
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Protocol.String()).To(Equal("TCP"))
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Destination.Ports)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Ingress[0].Destination.Ports[0].String()).To(Equal("80"))

		// There should be no Egress rule.
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Egress)).To(Equal(0))

		// Check that Types field exists and has only 'ingress'
		Expect(len(pol.Value.(*apiv3.NetworkPolicy).Spec.Types)).To(Equal(1))
		Expect(pol.Value.(*apiv3.NetworkPolicy).Spec.Types[0]).To(Equal(apiv3.PolicyTypeIngress))
	})
})

var _ = Describe("Test Namespace conversion", func() {

	// Use a single instance of the Converter for these tests.
	c := Converter{}

	It("should parse a Namespace to a Profile", func() {
		ns := kapiv1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
				Labels: map[string]string{
					"foo":   "bar",
					"roger": "rabbit",
				},
				Annotations: map[string]string{},
			},
			Spec: kapiv1.NamespaceSpec{},
		}

		p, err := c.NamespaceToProfile(&ns)
		Expect(err).NotTo(HaveOccurred())

		Expect(p.Key.(model.ResourceKey).Name).To(Equal("kns.default"))
		Expect(p.Key.(model.ResourceKey).Kind).To(Equal(apiv3.KindProfile))

		// Ensure rules are correct for profile.
		Ingress := p.Value.(*apiv3.Profile).Spec.Ingress
		Egress := p.Value.(*apiv3.Profile).Spec.Egress
		Expect(len(Ingress)).To(Equal(1))
		Expect(len(Egress)).To(Equal(1))

		// Ensure both inbound and outbound rules are set to allow.
		Expect(Ingress[0]).To(Equal(apiv3.Rule{Action: apiv3.Allow}))
		Expect(Egress[0]).To(Equal(apiv3.Rule{Action: apiv3.Allow}))

		// Check labels.
		labels := p.Value.(*apiv3.Profile).Spec.LabelsToApply
		Expect(labels["pcns.foo"]).To(Equal("bar"))
		Expect(labels["pcns.roger"]).To(Equal("rabbit"))
	})

	It("should parse a Namespace to a Profile with no labels", func() {
		ns := kapiv1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "default",
				Annotations: map[string]string{},
			},
			Spec: kapiv1.NamespaceSpec{},
		}

		p, err := c.NamespaceToProfile(&ns)
		Expect(err).NotTo(HaveOccurred())

		// Ensure rules are correct.
		Ingress := p.Value.(*apiv3.Profile).Spec.Ingress
		Egress := p.Value.(*apiv3.Profile).Spec.Egress
		Expect(len(Ingress)).To(Equal(1))
		Expect(len(Egress)).To(Equal(1))

		// Ensure both inbound and outbound rules are set to allow.
		Expect(Ingress[0]).To(Equal(apiv3.Rule{Action: apiv3.Allow}))
		Expect(Egress[0]).To(Equal(apiv3.Rule{Action: apiv3.Allow}))

		// Check labels.
		labels := p.Value.(*apiv3.Profile).Spec.LabelsToApply
		Expect(len(labels)).To(Equal(0))
	})

	It("should ignore the network-policy Namespace annotation", func() {
		ns := kapiv1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
				Annotations: map[string]string{
					"net.beta.kubernetes.io/network-policy": "{\"ingress\": {\"isolation\": \"DefaultDeny\"}}",
				},
			},
			Spec: kapiv1.NamespaceSpec{},
		}

		// Ensure it generates the correct Profile.
		p, err := c.NamespaceToProfile(&ns)
		Expect(err).NotTo(HaveOccurred())
		// Ensure rules are correct for profile.
		Ingress := p.Value.(*apiv3.Profile).Spec.Ingress
		Egress := p.Value.(*apiv3.Profile).Spec.Egress
		Expect(len(Ingress)).To(Equal(1))
		Expect(len(Egress)).To(Equal(1))

		// Ensure both inbound and outbound rules are set to allow.
		Expect(Ingress[0]).To(Equal(apiv3.Rule{Action: apiv3.Allow}))
		Expect(Egress[0]).To(Equal(apiv3.Rule{Action: apiv3.Allow}))

	})

	It("should not fail for malformed annotation", func() {
		ns := kapiv1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
				Annotations: map[string]string{
					"net.beta.kubernetes.io/network-policy": "invalidJSON",
				},
			},
			Spec: kapiv1.NamespaceSpec{},
		}

		By("converting to a Profile", func() {
			_, err := c.NamespaceToProfile(&ns)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	It("should handle a valid but not DefaultDeny annotation", func() {
		ns := kapiv1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
				Annotations: map[string]string{
					"net.beta.kubernetes.io/network-policy": "{}",
				},
			},
			Spec: kapiv1.NamespaceSpec{},
		}

		By("converting to a Profile", func() {
			p, err := c.NamespaceToProfile(&ns)
			Expect(err).NotTo(HaveOccurred())

			// Ensure it's a Profile.
			Expect(p.Value.(*apiv3.Profile).Kind).To(Equal(apiv3.KindProfile))
			Expect(p.Value.(*apiv3.Profile).APIVersion).To(Equal(apiv3.GroupVersionCurrent))

			// Ensure rules are correct.
			Ingress := p.Value.(*apiv3.Profile).Spec.Ingress
			Egress := p.Value.(*apiv3.Profile).Spec.Egress
			Expect(len(Ingress)).To(Equal(1))
			Expect(len(Egress)).To(Equal(1))

			// Ensure both inbound and outbound rules are set to allow.
			Expect(Ingress[0]).To(Equal(apiv3.Rule{Action: apiv3.Allow}))
			Expect(Egress[0]).To(Equal(apiv3.Rule{Action: apiv3.Allow}))
		})
	})

	It("should handle NetworkPolicy resource versions", func() {
		By("converting crd and k8s versions to the correct combined version")
		rev := c.JoinNetworkPolicyRevisions("1234", "5678")
		Expect(rev).To(Equal("1234/5678"))

		rev = c.JoinNetworkPolicyRevisions("", "5678")
		Expect(rev).To(Equal("/5678"))

		rev = c.JoinNetworkPolicyRevisions("1234", "")
		Expect(rev).To(Equal("1234/"))

		By("extracting crd and k8s versions from the combined version")
		crdRev, k8sRev, err := c.SplitNetworkPolicyRevision("")
		Expect(err).NotTo(HaveOccurred())
		Expect(crdRev).To(Equal(""))
		Expect(k8sRev).To(Equal(""))

		crdRev, k8sRev, err = c.SplitNetworkPolicyRevision("/")
		Expect(err).NotTo(HaveOccurred())
		Expect(crdRev).To(Equal(""))
		Expect(k8sRev).To(Equal(""))

		crdRev, k8sRev, err = c.SplitNetworkPolicyRevision("1234/5678")
		Expect(err).NotTo(HaveOccurred())
		Expect(crdRev).To(Equal("1234"))
		Expect(k8sRev).To(Equal("5678"))

		crdRev, k8sRev, err = c.SplitNetworkPolicyRevision("/5678")
		Expect(err).NotTo(HaveOccurred())
		Expect(crdRev).To(Equal(""))
		Expect(k8sRev).To(Equal("5678"))

		crdRev, k8sRev, err = c.SplitNetworkPolicyRevision("1234/")
		Expect(err).NotTo(HaveOccurred())
		Expect(crdRev).To(Equal("1234"))
		Expect(k8sRev).To(Equal(""))

		By("failing to convert an invalid combined version")
		_, _, err = c.SplitNetworkPolicyRevision("1234")
		Expect(err).To(HaveOccurred())

		_, _, err = c.SplitNetworkPolicyRevision("1234/5678/1313")
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("Test ServiceAccount conversion", func() {

	// Use a single instance of the Converter for these tests.
	c := Converter{}

	It("should parse a ServiceAccount in default namespace to a Profile", func() {
		sa := kapiv1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name: "sa-test",
				Labels: map[string]string{
					"foo":   "bar",
					"roger": "rabbit",
				},
				Annotations: map[string]string{},
			},
		}

		p, err := c.ServiceAccountToProfile(&sa)
		Expect(err).NotTo(HaveOccurred())

		Expect(p.Key.(model.ResourceKey).Name).To(Equal("ksa.default.sa-test"))
		Expect(p.Key.(model.ResourceKey).Kind).To(Equal(apiv3.KindProfile))

		// Ensure rules are correct for profile.
		Ingress := p.Value.(*apiv3.Profile).Spec.Ingress
		Egress := p.Value.(*apiv3.Profile).Spec.Egress
		Expect(len(Ingress)).To(Equal(0))
		Expect(len(Egress)).To(Equal(0))

		// Check labels.
		labels := p.Value.(*apiv3.Profile).Spec.LabelsToApply
		Expect(labels["pcsa.foo"]).To(Equal("bar"))
		Expect(labels["pcsa.roger"]).To(Equal("rabbit"))
	})

	It("should parse a ServiceAccount in Namespace to a Profile", func() {
		sa := kapiv1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "sa-test",
				Namespace:   "test",
				Annotations: map[string]string{},
			},
		}

		p, err := c.ServiceAccountToProfile(&sa)
		Expect(err).NotTo(HaveOccurred())

		Expect(p.Key.(model.ResourceKey).Name).To(Equal("ksa.test.sa-test"))
		Expect(p.Key.(model.ResourceKey).Kind).To(Equal(apiv3.KindProfile))
	})

	It("should parse a ServiceAccount with no labels to a Profile", func() {
		sa := kapiv1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name: "sa-test",
			},
		}

		p, err := c.ServiceAccountToProfile(&sa)
		Expect(err).NotTo(HaveOccurred())

		// Ensure rules are correct.
		Ingress := p.Value.(*apiv3.Profile).Spec.Ingress
		Egress := p.Value.(*apiv3.Profile).Spec.Egress
		Expect(len(Ingress)).To(Equal(0))
		Expect(len(Egress)).To(Equal(0))

		// Check labels.
		labels := p.Value.(*apiv3.Profile).Spec.LabelsToApply
		Expect(len(labels)).To(Equal(0))
	})

	It("should handle ServiceAccount resource versions", func() {
		By("converting ns and sa versions to the correct combined version")
		rev := c.JoinProfileRevisions("1234", "5678")
		Expect(rev).To(Equal("1234/5678"))

		rev = c.JoinProfileRevisions("", "5678")
		Expect(rev).To(Equal("/5678"))

		rev = c.JoinProfileRevisions("1234", "")
		Expect(rev).To(Equal("1234/"))

		By("extracting ns and sa versions from the combined version")
		nsRev, saRev, err := c.SplitProfileRevision("")
		Expect(err).NotTo(HaveOccurred())
		Expect(nsRev).To(Equal(""))
		Expect(saRev).To(Equal(""))

		nsRev, saRev, err = c.SplitProfileRevision("/")
		Expect(err).NotTo(HaveOccurred())
		Expect(nsRev).To(Equal(""))
		Expect(saRev).To(Equal(""))

		nsRev, saRev, err = c.SplitProfileRevision("1234/5678")
		Expect(err).NotTo(HaveOccurred())
		Expect(nsRev).To(Equal("1234"))
		Expect(saRev).To(Equal("5678"))

		nsRev, saRev, err = c.SplitProfileRevision("/5678")
		Expect(err).NotTo(HaveOccurred())
		Expect(nsRev).To(Equal(""))
		Expect(saRev).To(Equal("5678"))

		nsRev, saRev, err = c.SplitProfileRevision("1234/")
		Expect(err).NotTo(HaveOccurred())
		Expect(nsRev).To(Equal("1234"))
		Expect(saRev).To(Equal(""))

		By("failing to convert an invalid combined version")
		_, _, err = c.SplitProfileRevision("1234")
		Expect(err).To(HaveOccurred())

		_, _, err = c.SplitProfileRevision("1234/5678/1313")
		Expect(err).To(HaveOccurred())
	})
})
