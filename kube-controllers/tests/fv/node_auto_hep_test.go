// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
//
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

package fv_test

import (
	"context"
	"io/ioutil"
	"os"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = Describe("Auto Hostendpoint tests", func() {
	var (
		etcd              *containers.Container
		nodeController    *containers.Container
		apiserver         *containers.Container
		c                 client.Interface
		k8sClient         *kubernetes.Clientset
		controllerManager *containers.Container
		kconfigFile       *os.File
	)

	const kNodeName = "k8snodename"
	const cNodeName = "calinodename"

	// The profiles we expect auto host endpoints to specify.
	autoHepProfiles := []string{"projectcalico-default-allow"}

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()
		c = testutils.GetCalicoClient(apiconfig.EtcdV3, etcd.IP, "")

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)

		// Write out a kubeconfig file
		var err error
		kconfigFile, err = ioutil.TempFile("", "ginkgo-nodecontroller")
		Expect(err).NotTo(HaveOccurred())
		data := testutils.BuildKubeconfig(apiserver.IP)
		_, err = kconfigFile.Write([]byte(data))
		Expect(err).NotTo(HaveOccurred())

		// Make the kubeconfig readable by the container.
		Expect(kconfigFile.Chmod(os.ModePerm)).NotTo(HaveOccurred())

		k8sClient, err = testutils.GetK8sClient(kconfigFile.Name())
		Expect(err).NotTo(HaveOccurred())

		// Wait for the apiserver to be available.
		Eventually(func() error {
			_, err := k8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
			return err
		}, 30*time.Second, 1*time.Second).Should(BeNil())

		// Run controller manager.  Empirically it can take around 10s until the
		// controller manager is ready to create default service accounts, even
		// when the k8s image has already been downloaded to run the API
		// server.  We use Eventually to allow for possible delay when doing
		// initial pod creation below.
		controllerManager = testutils.RunK8sControllerManager(apiserver.IP)
	})

	AfterEach(func() {
		os.Remove(kconfigFile.Name())
		controllerManager.Stop()
		nodeController.Stop()
		apiserver.Stop()
		etcd.Stop()
	})

	It("should create and sync hostendpoints for Calico nodes", func() {
		// Run controller with auto HEP enabled
		nodeController = testutils.RunNodeController(apiconfig.EtcdV3, etcd.IP, kconfigFile.Name(), true)

		// Create a kubernetes node with some labels.
		kn := &v1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: kNodeName,
				Labels: map[string]string{
					"label1": "value1",
				},
			},
		}
		_, err := k8sClient.CoreV1().Nodes().Create(context.Background(), kn, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Create a Calico node with a reference to it.
		cn := calicoNode(c, cNodeName, kNodeName, map[string]string{"calico-label": "calico-value", "label1": "badvalue"})
		_, err = c.Nodes().Create(context.Background(), cn, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Expect the node label to sync.
		expectedNodeLabels := map[string]string{"label1": "value1", "calico-label": "calico-value"}
		Eventually(func() error { return testutils.ExpectNodeLabels(c, expectedNodeLabels, cNodeName) },
			time.Second*15, 500*time.Millisecond).Should(BeNil())

		expectedHepName := cn.Name + "-auto-hep"

		// Expect a wildcard hostendpoint to be created.
		expectedHepLabels := map[string]string{
			"label1":                       "value1",
			"calico-label":                 "calico-value",
			"projectcalico.org/created-by": "calico-kube-controllers",
		}
		expectedIPs := []string{"172.16.1.1", "fe80::1", "192.168.100.1"}
		Eventually(func() error {
			return testutils.ExpectHostendpoint(c, expectedHepName, expectedHepLabels, expectedIPs, autoHepProfiles)
		}, time.Second*15, 500*time.Millisecond).Should(BeNil())

		// Update the Kubernetes node labels.
		Expect(testutils.UpdateK8sNode(k8sClient, kn.Name, func(kn *v1.Node) {
			kn.Labels["label1"] = "value2"
		})).NotTo(HaveOccurred())

		// Expect the node labels to sync.
		expectedNodeLabels = map[string]string{"label1": "value2", "calico-label": "calico-value"}
		Eventually(func() error { return testutils.ExpectNodeLabels(c, expectedNodeLabels, cNodeName) },
			time.Second*15, 500*time.Millisecond).Should(BeNil())

		// Expect the hostendpoint labels to sync.
		expectedHepLabels["label1"] = "value2"
		Eventually(func() error {
			return testutils.ExpectHostendpoint(c, expectedHepName, expectedHepLabels, expectedIPs, autoHepProfiles)
		}, time.Second*15, 500*time.Millisecond).Should(BeNil())

		// Update the Calico node with new IPs.
		Expect(testutils.UpdateCalicoNode(c, cn.Name, func(cn *libapi.Node) {
			cn.Spec.BGP.IPv4Address = "172.100.2.3"
			cn.Spec.BGP.IPv4IPIPTunnelAddr = ""
			cn.Spec.IPv4VXLANTunnelAddr = "10.10.20.1"
			cn.Spec.IPv6VXLANTunnelAddr = "dead:beef::1"
		})).NotTo(HaveOccurred())

		// Expect the hostendpoint's expectedIPs to sync the new node IPs.
		expectedIPs = []string{"172.100.2.3", "fe80::1", "10.10.20.1", "dead:beef::1"}
		Eventually(func() error {
			return testutils.ExpectHostendpoint(c, expectedHepName, expectedHepLabels, expectedIPs, autoHepProfiles)
		}, time.Second*15, 500*time.Millisecond).Should(BeNil())

		// Update the wireguard IP.
		Expect(testutils.UpdateCalicoNode(c, cn.Name, func(cn *libapi.Node) {
			cn.Spec.Wireguard = &libapi.NodeWireguardSpec{
				InterfaceIPv4Address: "192.168.100.1",
			}
		})).NotTo(HaveOccurred())

		// Expect the HEP to include the wireguard IP.
		expectedIPs = []string{"172.100.2.3", "fe80::1", "10.10.20.1", "dead:beef::1", "192.168.100.1"}
		Eventually(func() error {
			return testutils.ExpectHostendpoint(c, expectedHepName, expectedHepLabels, expectedIPs, autoHepProfiles)
		}, time.Second*15, 500*time.Millisecond).Should(BeNil())

		// Add an internal IP and an external IP to the Addresses in the node spec.
		// Also add a duplicate IP and make sure it is not added.
		Expect(testutils.UpdateCalicoNode(c, cn.Name, func(cn *libapi.Node) {
			cn.Spec.Addresses = []libapi.NodeAddress{
				{Address: "192.168.200.1",
					Type: libapi.InternalIP},
				{Address: "192.168.200.2",
					Type: libapi.ExternalIP},
				{Address: "172.100.2.3",
					Type: libapi.InternalIP},
			}
		})).NotTo(HaveOccurred())

		// Expect the HEP to include the internal IP from Addresses.
		expectedIPs = []string{"172.100.2.3", "fe80::1", "10.10.20.1", "dead:beef::1", "192.168.100.1", "192.168.200.1"}
		Eventually(func() error {
			return testutils.ExpectHostendpoint(c, expectedHepName, expectedHepLabels, expectedIPs, autoHepProfiles)
		}, time.Second*15, 500*time.Millisecond).Should(BeNil())

		// Delete the Kubernetes node.
		err = k8sClient.CoreV1().Nodes().Delete(context.Background(), kNodeName, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
		Eventually(func() *libapi.Node {
			node, _ := c.Nodes().Get(context.Background(), cNodeName, options.GetOptions{})
			return node
		}, time.Second*2, 500*time.Millisecond).Should(BeNil())

		// Expect the hostendpoint for the node to be deleted.
		Eventually(func() error { return testutils.ExpectHostendpointDeleted(c, expectedHepName) },
			time.Second*2, 500*time.Millisecond).Should(BeNil())
	})

	It("should create a host endpoint for a Calico node if it can't find a k8s node", func() {
		// Run controller with auto HEP enabled
		nodeController = testutils.RunNodeController(apiconfig.EtcdV3, etcd.IP, kconfigFile.Name(), true)

		labels := map[string]string{"calico-label": "calico-value", "calico-label2": "value2"}

		// Create a Calico node with a reference to an non-existent k8s node.
		cn := calicoNode(c, cNodeName, kNodeName, labels)
		_, err := c.Nodes().Create(context.Background(), cn, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Expect the node label to sync.
		Eventually(func() error { return testutils.ExpectNodeLabels(c, labels, cNodeName) },
			time.Second*15, 500*time.Millisecond).Should(BeNil())

		expectedHepName := cn.Name + "-auto-hep"

		// Expect a wildcard hostendpoint to be created.
		expectedHepLabels := labels
		expectedHepLabels["projectcalico.org/created-by"] = "calico-kube-controllers"
		expectedIPs := []string{"172.16.1.1", "fe80::1", "192.168.100.1"}
		Eventually(func() error {
			return testutils.ExpectHostendpoint(c, expectedHepName, expectedHepLabels, expectedIPs, autoHepProfiles)
		}, time.Second*15, 500*time.Millisecond).Should(BeNil())
	})

	It("should clean up dangling hostendpoints and create hostendpoints for nodes without them", func() {
		// Create a wildcard HEP that matches what might have been created
		// automatically by kube-controllers. But we won't have a corresponding
		// node for this HEP.
		danglingHep := &api.HostEndpoint{
			ObjectMeta: metav1.ObjectMeta{
				Name: "dangling-auto-hep",
				Labels: map[string]string{
					"projectcalico.org/created-by": "calico-kube-controllers",
				},
			},
			Spec: api.HostEndpointSpec{
				Node:          "testnode",
				InterfaceName: "*",
				ExpectedIPs:   []string{"192.168.1.100"},
			},
		}
		_, err := c.HostEndpoints().Create(context.Background(), danglingHep, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Create another wildcard HEP but this one isn't managed by Calico.
		userHep := &api.HostEndpoint{
			ObjectMeta: metav1.ObjectMeta{
				Name: "user-managed-hep",
				Labels: map[string]string{
					"env": "staging",
				},
			},
			Spec: api.HostEndpointSpec{
				Node:          "testnode",
				InterfaceName: "*",
			},
		}
		_, err = c.HostEndpoints().Create(context.Background(), userHep, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Create a kubernetes node
		kn := &v1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: kNodeName,
				Labels: map[string]string{
					"auto": "hep",
				},
			},
		}
		_, err = k8sClient.CoreV1().Nodes().Create(context.Background(), kn, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Create a Calico node with a reference to the above node.
		cn := calicoNode(c, cNodeName, kNodeName, map[string]string{})
		_, err = c.Nodes().Create(context.Background(), cn, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Run the controller now.
		nodeController = testutils.RunNodeController(apiconfig.EtcdV3, etcd.IP, kconfigFile.Name(), true)

		// Expect the dangling hostendpoint to be deleted.
		Eventually(func() error { return testutils.ExpectHostendpointDeleted(c, danglingHep.Name) },
			time.Second*2, 500*time.Millisecond).Should(BeNil())

		// Expect the user's own hostendpoint to still exist.
		// (Empty values in the hostendpoint spec are nil slices)
		var noExpectedIPs []string
		var noProfiles []string
		Eventually(func() error {
			return testutils.ExpectHostendpoint(c, userHep.Name, map[string]string{"env": "staging"}, noExpectedIPs, noProfiles)
		}, time.Second*15, 500*time.Millisecond).Should(BeNil())

		// Expect an auto hostendpoint was created for the Calico node.
		autoHepName := cNodeName + "-auto-hep"
		expectedIPs := []string{"172.16.1.1", "fe80::1", "192.168.100.1"}
		expectedHepLabels := map[string]string{
			"auto":                         "hep",
			"projectcalico.org/created-by": "calico-kube-controllers",
		}
		Eventually(func() error {
			return testutils.ExpectHostendpoint(c, autoHepName, expectedHepLabels, expectedIPs, autoHepProfiles)
		}, time.Second*15, 500*time.Millisecond).Should(BeNil())
	})

	It("should delete hostendpoints when AUTO_HOST_ENDPOINTS is disabled", func() {
		nodeController = testutils.RunNodeController(apiconfig.EtcdV3, etcd.IP, kconfigFile.Name(), true)

		// Create a kubernetes node with some labels.
		kn := &v1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: kNodeName,
				Labels: map[string]string{
					"label1": "value1",
				},
			},
		}
		_, err := k8sClient.CoreV1().Nodes().Create(context.Background(), kn, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Create a Calico node with a reference to it.
		cn := libapi.NewNode()
		cn.Name = cNodeName
		cn.Labels = map[string]string{"calico-label": "calico-value"}
		cn.Spec = libapi.NodeSpec{
			BGP: &libapi.NodeBGPSpec{
				IPv4Address:        "172.16.1.1/24",
				IPv6Address:        "fe80::1",
				IPv4IPIPTunnelAddr: "192.168.100.1",
			},
			OrchRefs: []libapi.OrchRef{
				{
					NodeName:     kNodeName,
					Orchestrator: "k8s",
				},
			},
		}
		_, err = c.Nodes().Create(context.Background(), cn, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		expectedHepName := cn.Name + "-auto-hep"

		// Expect a wildcard hostendpoint to be created.
		expectedIPs := []string{"172.16.1.1", "fe80::1", "192.168.100.1"}
		expectedHepLabels := map[string]string{
			"label1":                       "value1",
			"calico-label":                 "calico-value",
			"projectcalico.org/created-by": "calico-kube-controllers",
		}
		Eventually(func() error {
			return testutils.ExpectHostendpoint(c, expectedHepName, expectedHepLabels, expectedIPs, autoHepProfiles)
		}, time.Second*15, 500*time.Millisecond).Should(BeNil())

		// Restart the controller but with auto hostendpoints disabled.
		nodeController.Stop()
		nodeController = testutils.RunNodeController(apiconfig.EtcdV3, etcd.IP, kconfigFile.Name(), false)

		// Expect the hostendpoint for the node to be deleted.
		Eventually(func() error { return testutils.ExpectHostendpointDeleted(c, expectedHepName) },
			time.Second*2, 500*time.Millisecond).Should(BeNil())
	})
})

func calicoNode(c client.Interface, name string, k8sNodeName string, labels map[string]string) *libapi.Node {
	// Create a Calico node with a reference to it.
	node := libapi.NewNode()
	node.Name = name
	node.Labels = make(map[string]string)
	for k, v := range labels {
		node.Labels[k] = v
	}

	node.Spec = libapi.NodeSpec{
		BGP: &libapi.NodeBGPSpec{
			IPv4Address:        "172.16.1.1/24",
			IPv6Address:        "fe80::1",
			IPv4IPIPTunnelAddr: "192.168.100.1",
		},
	}

	// Add in the orchRef if a k8s node was provided.
	if k8sNodeName != "" {
		node.Spec.OrchRefs = []libapi.OrchRef{{NodeName: k8sNodeName, Orchestrator: "k8s"}}
	}
	return node
}
