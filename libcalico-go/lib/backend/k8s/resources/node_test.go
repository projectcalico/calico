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

package resources

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"

	k8sapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/net"
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

		n, err := K8sNodeToCalico(&node, false)
		Expect(err).NotTo(HaveOccurred())

		// Ensure we got the correct values.
		bgpIpv4Address := n.Value.(*libapiv3.Node).Spec.BGP.IPv4Address
		ipInIpAddr := n.Value.(*libapiv3.Node).Spec.BGP.IPv4IPIPTunnelAddr
		asn := n.Value.(*libapiv3.Node).Spec.BGP.ASNumber

		ip := net.ParseIP("172.17.17.10")

		Expect(bgpIpv4Address).To(Equal(ip.String()))
		Expect(ipInIpAddr).To(Equal(""))
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

		n, err := K8sNodeToCalico(&node, false)
		Expect(err).NotTo(HaveOccurred())

		// Ensure we got the correct values.
		bgpIpv4Address := n.Value.(*libapiv3.Node).Spec.BGP.IPv4Address
		ipInIpAddr := n.Value.(*libapiv3.Node).Spec.BGP.IPv4IPIPTunnelAddr
		asn := n.Value.(*libapiv3.Node).Spec.BGP.ASNumber
		rrClusterID := n.Value.(*libapiv3.Node).Spec.BGP.RouteReflectorClusterID

		ip := net.ParseIP("172.17.17.10")

		Expect(bgpIpv4Address).To(Equal(ip.String()))
		Expect(ipInIpAddr).To(Equal(""))
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

		n, err := K8sNodeToCalico(&node, false)
		Expect(err).NotTo(HaveOccurred())

		// Ensure we got the correct values.
		bgpIpv6Address := n.Value.(*libapiv3.Node).Spec.BGP.IPv6Address
		ipInIpAddr := n.Value.(*libapiv3.Node).Spec.BGP.IPv4IPIPTunnelAddr

		ip := net.ParseIP("fd10::10")

		Expect(bgpIpv6Address).To(Equal(ip.String()))
		Expect(ipInIpAddr).To(Equal(""))
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

		n, err := K8sNodeToCalico(&node, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(n.Value.(*libapiv3.Node).Spec.BGP).To(BeNil())
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

		calicoNode := libapiv3.NewNode()

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
		calicoNode := libapiv3.NewNode()
		calicoNode.Name = "TestNode"
		calicoNode.ResourceVersion = "1234"
		calicoNode.Labels = cl
		calicoNode.Annotations = ca
		calicoNode.Spec = libapiv3.NodeSpec{
			BGP: &libapiv3.NodeBGPSpec{
				IPv4Address:             "172.17.17.10/24",
				IPv6Address:             "aa:bb:cc::ffff/120",
				ASNumber:                &asn,
				RouteReflectorClusterID: "245.0.0.3",
			},
			OrchRefs: []libapiv3.OrchRef{
				{NodeName: k8sNode.Name, Orchestrator: "k8s"},
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
		calicoNode.Spec.BGP.IPv4IPIPTunnelAddr = ""
		newCalicoNode, err := K8sNodeToCalico(newK8sNode, false)
		Expect(err).NotTo(HaveOccurred())

		calicoNodeWithMergedLabels := calicoNode.DeepCopy()
		calicoNodeWithMergedLabels.Annotations[nodeK8sLabelAnnotation] = "{\"net.beta.kubernetes.io/role\":\"master\"}"
		calicoNodeWithMergedLabels.Labels["net.beta.kubernetes.io/role"] = "master"
		calicoNodeWithMergedLabels.Spec.Addresses = []libapiv3.NodeAddress{
			libapiv3.NodeAddress{Address: "172.17.17.10/24", Type: libapiv3.CalicoNodeIP},
			libapiv3.NodeAddress{Address: "aa:bb:cc::ffff/120", Type: libapiv3.CalicoNodeIP},
		}
		Expect(newCalicoNode.Value).To(Equal(calicoNodeWithMergedLabels))
	})

	It("Should shadow labels correctly", func() {
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
		calicoNode := libapiv3.NewNode()
		calicoNode.Name = "TestNode"
		calicoNode.ResourceVersion = "1234"
		calicoNode.Labels = cl
		calicoNode.Spec.OrchRefs = []libapiv3.OrchRef{
			{NodeName: k8sNode.Name, Orchestrator: "k8s"},
		}

		newK8sNode, err := mergeCalicoNodeIntoK8sNode(calicoNode, k8sNode)
		Expect(err).NotTo(HaveOccurred())
		Expect(newK8sNode.Annotations).To(Equal(map[string]string{
			"projectcalico.org/labels": `{"label1":"foo","label2":"bar","shadowed":"calico-value"}`,
		}))
		Expect(newK8sNode.Labels).To(Equal(kl))

		By("Converting the k8s node back into a calico node")
		newCalicoNode, err := K8sNodeToCalico(newK8sNode, false)
		Expect(err).NotTo(HaveOccurred())

		// When we merge k8s into Calico, the k8s labels get stashed in an annotation along with the shadowed labels:
		calicoNodeWithMergedLabels := calicoNode.DeepCopy()
		calicoNodeWithMergedLabels.Annotations = map[string]string{}
		calicoNodeWithMergedLabels.Annotations[nodeK8sLabelAnnotation] = "{\"net.beta.kubernetes.io/role\":\"master\",\"shadowed\":\"k8s-value\"}"
		// And, the k8s labels get merged in...
		calicoNodeWithMergedLabels.Labels["net.beta.kubernetes.io/role"] = "master"
		calicoNodeWithMergedLabels.Labels["shadowed"] = "k8s-value"
		Expect(newCalicoNode.Value).To(Equal(calicoNodeWithMergedLabels))

		// restoreCalicoLabels should undo the merge, but the shadowed label will be lost.
		calicoNodeNoShadow := calicoNode.DeepCopy()
		delete(calicoNodeNoShadow.Labels, "shadowed")
		calicoNodeRestored, err := restoreCalicoLabels(calicoNodeWithMergedLabels)
		Expect(calicoNodeRestored).To(Equal(calicoNodeNoShadow))

		// For coverage, make a change to the shadowed label, this will log a warning.
		calicoNodeWithMergedLabels.Labels["shadowed"] = "some change"
		calicoNodeRestored, err = restoreCalicoLabels(calicoNodeWithMergedLabels)
		Expect(calicoNodeRestored).To(Equal(calicoNodeNoShadow))
	})

	It("restoreCalicoLabels should error if annotations are malformed", func() {
		calicoNode := libapiv3.NewNode()
		calicoNode.Annotations = map[string]string{}
		calicoNode.Annotations[nodeK8sLabelAnnotation] = "Garbage"
		_, err := restoreCalicoLabels(calicoNode)
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

	It("should parse a k8s Node to a Calico Node with an IPv4IPIPTunnelAddr", func() {
		l := map[string]string{"net.beta.kubernetes.io/role": "master"}
		node := k8sapi.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "TestNode",
				Labels:          l,
				ResourceVersion: "1234",
				Annotations: map[string]string{
					nodeBgpIpv4AddrAnnotation:           "172.17.17.10",
					nodeBgpIpv4IPIPTunnelAddrAnnotation: "10.0.0.24",
					nodeBgpAsnAnnotation:                "2546",
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

		n, err := K8sNodeToCalico(&node, false)
		Expect(err).NotTo(HaveOccurred())

		// Ensure we got the correct values.
		bgpIpv4Address := n.Value.(*libapiv3.Node).Spec.BGP.IPv4Address
		ipInIpAddr := n.Value.(*libapiv3.Node).Spec.BGP.IPv4IPIPTunnelAddr
		asn := n.Value.(*libapiv3.Node).Spec.BGP.ASNumber

		ip := net.ParseIP("172.17.17.10")

		Expect(bgpIpv4Address).To(Equal(ip.String()))
		Expect(ipInIpAddr).To(Equal("10.0.0.24"))
		Expect(asn.String()).To(Equal("2546"))
	})

	Context("using host-local IPAM backed by pod CIDR", func() {
		It("should parse a k8s Node to a Calico Node with an IPv4IPIPTunnelAddr and no wireguard tunnel addr if there is no public key", func() {
			node := k8sapi.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "TestNode",
					ResourceVersion: "1234",
					Annotations: map[string]string{
						nodeBgpIpv4AddrAnnotation: "172.17.17.10",
						nodeBgpAsnAnnotation:      "2546",
					},
				},
				Spec: k8sapi.NodeSpec{
					PodCIDR: "10.0.0.0/24",
				},
			}

			n, err := K8sNodeToCalico(&node, true)
			Expect(err).NotTo(HaveOccurred())

			// Ensure we got the correct values.
			bgpIpv4Address := n.Value.(*libapiv3.Node).Spec.BGP.IPv4Address
			ipInIpAddr := n.Value.(*libapiv3.Node).Spec.BGP.IPv4IPIPTunnelAddr
			wg := n.Value.(*libapiv3.Node).Spec.Wireguard
			asn := n.Value.(*libapiv3.Node).Spec.BGP.ASNumber
			ip := net.ParseIP("172.17.17.10")

			Expect(bgpIpv4Address).To(Equal(ip.String()))
			Expect(ipInIpAddr).To(Equal("10.0.0.1"))
			Expect(wg).To(BeNil())
			Expect(asn.String()).To(Equal("2546"))
		})

		It("should parse a k8s Node to a Calico Node with an IPv4IPIPTunnelAddr and a wireguard tunnel addr if there is a public key", func() {
			node := k8sapi.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "TestNode",
					ResourceVersion: "1234",
					Annotations: map[string]string{
						nodeBgpIpv4AddrAnnotation:        "172.17.17.10",
						nodeBgpAsnAnnotation:             "2546",
						nodeWireguardPublicKeyAnnotation: "abcd",
					},
				},
				Spec: k8sapi.NodeSpec{
					PodCIDR: "10.0.0.0/24",
				},
			}

			n, err := K8sNodeToCalico(&node, true)
			Expect(err).NotTo(HaveOccurred())

			// Ensure we got the correct values.
			bgpIpv4Address := n.Value.(*libapiv3.Node).Spec.BGP.IPv4Address
			ipInIpAddr := n.Value.(*libapiv3.Node).Spec.BGP.IPv4IPIPTunnelAddr
			wg := n.Value.(*libapiv3.Node).Spec.Wireguard
			asn := n.Value.(*libapiv3.Node).Spec.BGP.ASNumber
			ip := net.ParseIP("172.17.17.10")

			Expect(bgpIpv4Address).To(Equal(ip.String()))
			Expect(ipInIpAddr).To(Equal("10.0.0.1"))
			Expect(wg).ToNot(BeNil())
			Expect(wg.InterfaceIPv4Address).To(Equal("10.0.0.1"))
			Expect(asn.String()).To(Equal("2546"))
		})

		It("should handle an empty pod CIDR", func() {
			node := k8sapi.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "TestNode",
					ResourceVersion: "1234",
					Annotations: map[string]string{
						nodeBgpIpv4AddrAnnotation: "172.17.17.10",
						nodeBgpAsnAnnotation:      "2546",
					},
				},
				Spec: k8sapi.NodeSpec{},
			}

			n, err := K8sNodeToCalico(&node, true)
			Expect(err).NotTo(HaveOccurred())

			// Ensure we got the correct values.
			ipInIpAddr := n.Value.(*libapiv3.Node).Spec.BGP.IPv4IPIPTunnelAddr
			Expect(ipInIpAddr).To(Equal(""))
		})

	})

	It("should parse addresses of all types into Calico Node", func() {
		l := map[string]string{"net.beta.kubernetes.io/role": "master"}
		node := k8sapi.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "TestNode",
				Labels:          l,
				ResourceVersion: "1234",
				Annotations: map[string]string{
					nodeBgpIpv6AddrAnnotation:             "fd10::10",
					nodeBgpIpv4AddrAnnotation:             "172.17.17.10",
					nodeBgpAsnAnnotation:                  "2546",
					nodeBgpIpv4VXLANTunnelAddrAnnotation:  "1.2.3.4",
					nodeBgpVXLANTunnelMACAddrAnnotation:   "00:11:22:33:44:55",
					nodeBgpIpv6VXLANTunnelAddrAnnotation:  "fd10::11",
					nodeBgpVXLANTunnelMACAddrV6Annotation: "55:44:33:22:11:00",
					nodeBgpIpv4IPIPTunnelAddrAnnotation:   "5.4.5.4",
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
		}

		n, err := K8sNodeToCalico(&node, false)
		Expect(err).NotTo(HaveOccurred())

		addrs := n.Value.(*libapiv3.Node).Spec.Addresses
		Expect(addrs).To(ConsistOf([]libapiv3.NodeAddress{
			{Address: "fd10::10", Type: libapiv3.CalicoNodeIP},
			{Address: "172.17.17.10", Type: libapiv3.CalicoNodeIP}, // from BGP
			{Address: "172.17.17.10", Type: libapiv3.InternalIP},   // from k8s InternalIP
			{Address: "192.168.1.100", Type: libapiv3.ExternalIP},
		}))
	})
})
