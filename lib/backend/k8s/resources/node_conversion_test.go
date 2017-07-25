package resources

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/libcalico-go/lib/backend/model"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sapi "k8s.io/client-go/pkg/api/v1"

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
					nodeBgpIpv4CidrAnnotation: "172.17.17.10/24",
					nodeBgpAsnAnnotation:    "2546",
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
			Spec: k8sapi.NodeSpec{},
		}

		n, err := K8sNodeToCalico(&node)
		Expect(err).NotTo(HaveOccurred())

		// Ensure we got the correct values.
		felixAddress := *n.Value.(*model.Node).FelixIPv4
		bgpAddress := *n.Value.(*model.Node).BGPIPv4Addr
		bgpNet := *n.Value.(*model.Node).BGPIPv4Net
		labels := n.Value.(*model.Node).Labels
		asn := n.Value.(*model.Node).BGPASNumber

		ip, ipNet, _ := net.ParseCIDR("172.17.17.10/24")

		Expect(felixAddress).To(Equal(*ip))
		Expect(bgpAddress).To(Equal(*ip))
		Expect(bgpNet).To(Equal(*ipNet))
		Expect(labels).To(Equal(l))
		Expect(asn.String()).To(Equal("2546"))
	})

	It("should error on an invalid IP", func() {
		l := map[string]string{"net.beta.kubernetes.io/role": "master"}
		node := k8sapi.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "TestNode",
				Labels:          l,
				ResourceVersion: "1234",
				Annotations:     map[string]string{nodeBgpIpv4CidrAnnotation: "172.984.12.5/24"},
			},
			Spec: k8sapi.NodeSpec{},
		}

		_, err := K8sNodeToCalico(&node)
		Expect(err).To(HaveOccurred())
	})

	It("Should parse and remove BGP info when given Calico Node with empty BGP spec", func() {
		l := map[string]string{"net.beta.kubernetes.io/role": "master"}
		k8sNode := &k8sapi.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "TestNode",
				Labels:          l,
				ResourceVersion: "1234",
				Annotations: map[string]string{
					nodeBgpIpv4CidrAnnotation: "172.17.17.10/24",
					nodeBgpAsnAnnotation:    "2546",
				},
			},
			Spec: k8sapi.NodeSpec{},
		}

		calicoNode := &model.Node{}

		newK8sNode, err := mergeCalicoK8sNode(calicoNode, k8sNode)
		Expect(err).NotTo(HaveOccurred())
		Expect(newK8sNode.Annotations).NotTo(HaveKey(nodeBgpIpv4CidrAnnotation))
		Expect(newK8sNode.Annotations).NotTo(HaveKey(nodeBgpAsnAnnotation))
	})

	It("Should merger Calico Nodes into K8s Nodes", func() {
		l := map[string]string{"net.beta.kubernetes.io/role": "master"}
		k8sNode := &k8sapi.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "TestNode",
				Labels:          l,
				ResourceVersion: "1234",
				Annotations: make(map[string]string),
			},
			Spec: k8sapi.NodeSpec{},
		}

		ip, cidr, _ := net.ParseCIDR("172.17.17.10/24")
		asn, _ := numorstring.ASNumberFromString("2456")

		calicoNode := &model.Node{
			BGPIPv4Net: cidr,
			FelixIPv4: ip,
			BGPIPv4Addr: ip,
			BGPASNumber: &asn,
		}

		newK8sNode, err := mergeCalicoK8sNode(calicoNode, k8sNode)
		Expect(err).NotTo(HaveOccurred())
		Expect(newK8sNode.Annotations).To(HaveKeyWithValue(nodeBgpIpv4CidrAnnotation, "172.17.17.10/24"))
		Expect(newK8sNode.Annotations).To(HaveKeyWithValue(nodeBgpAsnAnnotation, "2456"))
	})
})

