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

package resources

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"

	k8sapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

var _ = Describe("Test Node conversion", func() {

	It("should parse a k8s Node to a Calico Node", func() {
		l := map[string]string{"net.beta.kubernetes.io/role": "master"}
		node := k8sapi.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "TestNode",
				Labels:          l,
				ResourceVersion: "1234",
				Annotations: map[string]string{
					nodeBgpIpv4AddrAnnotation: "172.17.17.10",
					nodeBgpAsnAnnotation:      "2546",
				},
			},
			Status: k8sapi.NodeStatus{
				Addresses: []k8sapi.NodeAddress{
					k8sapi.NodeAddress{
						Type:    k8sapi.NodeInternalIP,
						Address: "172.17.17.10",
					},
					k8sapi.NodeAddress{
						Type:    k8sapi.NodeExternalIP,
						Address: "192.168.1.100",
					},
					k8sapi.NodeAddress{
						Type:    k8sapi.NodeHostName,
						Address: "172-17-17-10",
					},
				},
			},
			Spec: k8sapi.NodeSpec{
				PodCIDR: "10.0.0.1/24",
			},
		}

		n, err := K8sNodeToCalico(&node)
		Expect(err).NotTo(HaveOccurred())

		// Ensure we got the correct values.
		bgpIpv4Address := n.Value.(*apiv3.Node).Spec.BGP.IPv4Address
		ipInIpAddr := n.Value.(*apiv3.Node).Spec.BGP.IPv4IPIPTunnelAddr
		asn := n.Value.(*apiv3.Node).Spec.BGP.ASNumber

		ip := net.ParseIP("172.17.17.10")

		Expect(bgpIpv4Address).To(Equal(ip.String()))
		Expect(ipInIpAddr).To(Equal("10.0.0.2"))
		Expect(asn.String()).To(Equal("2546"))
	})

	It("should parse a k8s Node to a Calico Node with RR cluster ID", func() {
		l := map[string]string{"net.beta.kubernetes.io/role": "master"}
		node := k8sapi.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "TestNode",
				Labels:          l,
				ResourceVersion: "1234",
				Annotations: map[string]string{
					nodeBgpIpv4AddrAnnotation: "172.17.17.10",
					nodeBgpAsnAnnotation:      "2546",
					nodeBgpCIDAnnotation:      "248.0.4.5",
				},
			},
			Status: k8sapi.NodeStatus{
				Addresses: []k8sapi.NodeAddress{
					k8sapi.NodeAddress{
						Type:    k8sapi.NodeInternalIP,
						Address: "172.17.17.10",
					},
					k8sapi.NodeAddress{
						Type:    k8sapi.NodeExternalIP,
						Address: "192.168.1.100",
					},
					k8sapi.NodeAddress{
						Type:    k8sapi.NodeHostName,
						Address: "172-17-17-10",
					},
				},
			},
			Spec: k8sapi.NodeSpec{
				PodCIDR: "10.0.0.1/24",
			},
		}

		n, err := K8sNodeToCalico(&node)
		Expect(err).NotTo(HaveOccurred())

		// Ensure we got the correct values.
		bgpIpv4Address := n.Value.(*apiv3.Node).Spec.BGP.IPv4Address
		ipInIpAddr := n.Value.(*apiv3.Node).Spec.BGP.IPv4IPIPTunnelAddr
		asn := n.Value.(*apiv3.Node).Spec.BGP.ASNumber
		rrClusterID := n.Value.(*apiv3.Node).Spec.BGP.RouteReflectorClusterID

		ip := net.ParseIP("172.17.17.10")

		Expect(bgpIpv4Address).To(Equal(ip.String()))
		Expect(ipInIpAddr).To(Equal("10.0.0.2"))
		Expect(asn.String()).To(Equal("2546"))
		Expect(rrClusterID).To(Equal("248.0.4.5"))
	})

	It("should parse a k8s Node to a Calico Node with IPv6", func() {
		l := map[string]string{"net.beta.kubernetes.io/role": "master"}
		node := k8sapi.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "TestNode",
				Labels:          l,
				ResourceVersion: "1234",
				Annotations: map[string]string{
					nodeBgpIpv6AddrAnnotation: "fd10::10",
					nodeBgpAsnAnnotation:      "2546",
				},
			},
			Status: k8sapi.NodeStatus{
				Addresses: []k8sapi.NodeAddress{
					k8sapi.NodeAddress{
						Type:    k8sapi.NodeInternalIP,
						Address: "fd10::10",
					},
					k8sapi.NodeAddress{
						Type:    k8sapi.NodeExternalIP,
						Address: "fd20::100",
					},
					k8sapi.NodeAddress{
						Type:    k8sapi.NodeHostName,
						Address: "fd10-10",
					},
				},
			},
			Spec: k8sapi.NodeSpec{
				PodCIDR: "feee::/122",
			},
		}

		n, err := K8sNodeToCalico(&node)
		Expect(err).NotTo(HaveOccurred())

		// Ensure we got the correct values.
		bgpIpv6Address := n.Value.(*apiv3.Node).Spec.BGP.IPv6Address
		ipInIpAddr := n.Value.(*apiv3.Node).Spec.BGP.IPv4IPIPTunnelAddr

		ip := net.ParseIP("fd10::10")

		Expect(bgpIpv6Address).To(Equal(ip.String()))
		Expect(ipInIpAddr).To(Equal(""))
	})

	It("should fail to parse a k8s Node to a Calico Node with bad PodCIDR", func() {
		l := map[string]string{"net.beta.kubernetes.io/role": "master"}
		node := k8sapi.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "TestNode",
				Labels:          l,
				ResourceVersion: "1234",
				Annotations: map[string]string{
					nodeBgpIpv4AddrAnnotation: "172.17.17.10",
					nodeBgpAsnAnnotation:      "2546",
				},
			},
			Status: k8sapi.NodeStatus{
				Addresses: []k8sapi.NodeAddress{
					k8sapi.NodeAddress{
						Type:    k8sapi.NodeInternalIP,
						Address: "172.17.17.10",
					},
					k8sapi.NodeAddress{
						Type:    k8sapi.NodeExternalIP,
						Address: "192.168.1.100",
					},
					k8sapi.NodeAddress{
						Type:    k8sapi.NodeHostName,
						Address: "172-17-17-10",
					},
				},
			},
			Spec: k8sapi.NodeSpec{
				PodCIDR: "10.0.a.1/24",
			},
		}

		_, err := K8sNodeToCalico(&node)
		Expect(err).To(HaveOccurred())
	})

	It("should parse a k8s Node to a Calico Node with podCIDR but no BGP config", func() {
		l := map[string]string{"net.beta.kubernetes.io/role": "master"}
		node := k8sapi.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "TestNode",
				Labels:          l,
				ResourceVersion: "1234",
			},
			Status: k8sapi.NodeStatus{},
			Spec: k8sapi.NodeSpec{
				PodCIDR: "10.0.0.0/24",
			},
		}

		n, err := K8sNodeToCalico(&node)
		Expect(err).NotTo(HaveOccurred())

		// Ensure we got the correct values.
		ipInIpAddr := n.Value.(*apiv3.Node).Spec.BGP.IPv4IPIPTunnelAddr
		Expect(ipInIpAddr).To(Equal("10.0.0.1"))
	})

	It("Should parse and remove BGP info when given Calico Node with empty BGP spec", func() {
		l := map[string]string{"net.beta.kubernetes.io/role": "master"}
		k8sNode := &k8sapi.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "TestNode",
				Labels:          l,
				ResourceVersion: "1234",
				Annotations: map[string]string{
					nodeBgpIpv4AddrAnnotation: "172.17.17.10",
					nodeBgpAsnAnnotation:      "2546",
				},
			},
			Spec: k8sapi.NodeSpec{},
		}

		calicoNode := apiv3.NewNode()

		newK8sNode, err := mergeCalicoNodeIntoK8sNode(calicoNode, k8sNode)
		Expect(err).NotTo(HaveOccurred())
		Expect(newK8sNode.Annotations).NotTo(HaveKey(nodeBgpIpv4AddrAnnotation))
		Expect(newK8sNode.Annotations).NotTo(HaveKey(nodeBgpAsnAnnotation))
	})

	It("Should merge Calico Nodes into K8s Nodes", func() {
		kl := map[string]string{"net.beta.kubernetes.io/role": "master"}
		cl := map[string]string{
			"label1": "foo",
			"label2": "bar",
		}
		ca := map[string]string{
			"anno1": "foo",
			"anno2": "bar",
		}
		k8sNode := &k8sapi.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "TestNode",
				Labels:          kl,
				ResourceVersion: "1234",
				Annotations:     make(map[string]string),
			},
			Spec: k8sapi.NodeSpec{},
		}

		asn, _ := numorstring.ASNumberFromString("2456")

		By("Merging calico node config into the k8s node")
		calicoNode := apiv3.NewNode()
		calicoNode.Name = "TestNode"
		calicoNode.ResourceVersion = "1234"
		calicoNode.Labels = cl
		calicoNode.Annotations = ca
		calicoNode.Spec = apiv3.NodeSpec{
			BGP: &apiv3.NodeBGPSpec{
				IPv4Address:             "172.17.17.10/24",
				IPv6Address:             "aa:bb:cc::ffff/120",
				ASNumber:                &asn,
				RouteReflectorClusterID: "245.0.0.3",
			},
		}

		newK8sNode, err := mergeCalicoNodeIntoK8sNode(calicoNode, k8sNode)
		Expect(err).NotTo(HaveOccurred())
		Expect(newK8sNode.Annotations).To(HaveKeyWithValue(nodeBgpIpv4AddrAnnotation, "172.17.17.10/24"))
		Expect(newK8sNode.Annotations).To(HaveKeyWithValue(nodeBgpIpv6AddrAnnotation, "aa:bb:cc::ffff/120"))
		Expect(newK8sNode.Annotations).To(HaveKeyWithValue(nodeBgpAsnAnnotation, "2456"))
		Expect(newK8sNode.Annotations).To(HaveKeyWithValue(nodeBgpCIDAnnotation, "245.0.0.3"))

		// The calico node annotations and labels should not have escaped directly into the node annotations
		// and labels.
		Expect(newK8sNode.Annotations["anno1"]).To(Equal(""))
		Expect(newK8sNode.Labels["label1"]).To(Equal(""))

		By("Converting the k8s node back into a calico node")
		// Set the PodCIDR so we can also test the IPIP tunnel field
		newK8sNode.Spec.PodCIDR = "172.100.0.0/24"
		calicoNode.Spec.BGP.IPv4IPIPTunnelAddr = "172.100.0.1"
		newCalicoNode, err := K8sNodeToCalico(newK8sNode)
		Expect(err).NotTo(HaveOccurred())

		calicoNodeWithMergedLabels := calicoNode.DeepCopy()
		calicoNodeWithMergedLabels.Annotations[nodeK8sLabelAnnotation] = "{\"net.beta.kubernetes.io/role\":\"master\"}"
		calicoNodeWithMergedLabels.Labels["net.beta.kubernetes.io/role"] = "master"
		Expect(newCalicoNode.Value).To(Equal(calicoNodeWithMergedLabels))
	})

	It("Should round trip shadowed labels correctly", func() {
		kl := map[string]string{
			"net.beta.kubernetes.io/role": "master",
			"shadowed":                    "k8s-value",
		}
		cl := map[string]string{
			"label1":   "foo",
			"label2":   "bar",
			"shadowed": "calico-value",
		}
		k8sNode := &k8sapi.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "TestNode",
				Labels:          kl,
				ResourceVersion: "1234",
				Annotations:     make(map[string]string),
			},
			Spec: k8sapi.NodeSpec{},
		}

		By("Merging calico node config into the k8s node")
		calicoNode := apiv3.NewNode()
		calicoNode.Name = "TestNode"
		calicoNode.ResourceVersion = "1234"
		calicoNode.Labels = cl

		newK8sNode, err := mergeCalicoNodeIntoK8sNode(calicoNode, k8sNode)
		Expect(err).NotTo(HaveOccurred())
		Expect(newK8sNode.Annotations).To(Equal(map[string]string{
			"projectcalico.org/labels": `{"label1":"foo","label2":"bar","shadowed":"calico-value"}`,
		}))
		Expect(newK8sNode.Labels).To(Equal(kl))

		By("Converting the k8s node back into a calico node")
		newCalicoNode, err := K8sNodeToCalico(newK8sNode)
		Expect(err).NotTo(HaveOccurred())

		// When we merge k8s into Calico, the k8s labels get stashed in an annotation along with the shadowed labels:
		calicoNodeWithMergedLabels := calicoNode.DeepCopy()
		calicoNodeWithMergedLabels.Annotations = map[string]string{}
		calicoNodeWithMergedLabels.Annotations[nodeK8sLabelAnnotation] = "{\"net.beta.kubernetes.io/role\":\"master\",\"shadowed\":\"k8s-value\"}"
		calicoNodeWithMergedLabels.Annotations[nodeShadowedLabelAnnotation] = "{\"shadowed\":\"calico-value\"}"
		// And, the k8s labels get merged in...
		calicoNodeWithMergedLabels.Labels["net.beta.kubernetes.io/role"] = "master"
		calicoNodeWithMergedLabels.Labels["shadowed"] = "k8s-value"
		Expect(newCalicoNode.Value).To(Equal(calicoNodeWithMergedLabels))

		// restoreCalicoLabels should undo the merge, removing the annotations and restoring the shadowed labels.
		calicoNodeRestored, err := restoreCalicoLabels(calicoNodeWithMergedLabels)
		Expect(calicoNodeRestored).To(Equal(calicoNode))
	})

	It("restoreCalicoLabels should error if annotations are malformed", func() {
		calicoNode := apiv3.NewNode()
		calicoNode.Annotations = map[string]string{}
		calicoNode.Annotations[nodeK8sLabelAnnotation] = "{}"
		calicoNode.Annotations[nodeShadowedLabelAnnotation] = "Garbage"
		_, err := restoreCalicoLabels(calicoNode)
		Expect(err).To(HaveOccurred())

		calicoNode.Annotations[nodeK8sLabelAnnotation] = "Garbage"
		calicoNode.Annotations[nodeShadowedLabelAnnotation] = "{}"
		_, err = restoreCalicoLabels(calicoNode)
		Expect(err).To(HaveOccurred())

		k8sNode := &k8sapi.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "TestNode",
				ResourceVersion: "1234",
				Annotations:     make(map[string]string),
			},
			Spec: k8sapi.NodeSpec{},
		}
		_, err = mergeCalicoNodeIntoK8sNode(calicoNode, k8sNode)
		Expect(err).To(HaveOccurred())
	})
})
