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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = Describe("kube-controllers IPAM FV tests (etcd mode)", func() {
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

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()
		c = testutils.GetCalicoClient(apiconfig.EtcdV3, etcd.IP, "")

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)

		// Write out a kubeconfig file we can mount into the container.
		var err error
		kconfigFile, err = ioutil.TempFile("", "ginkgo-nodecontroller")
		Expect(err).NotTo(HaveOccurred())
		data := testutils.BuildKubeconfig(apiserver.IP)
		_, err = kconfigFile.Write([]byte(data))
		Expect(err).NotTo(HaveOccurred())

		// Make the kubeconfig readable by the container.
		Expect(kconfigFile.Chmod(os.ModePerm)).NotTo(HaveOccurred())

		// Build a client we can use for the test.
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

		// Create an IP pool with room for 4 blocks.
		p := api.NewIPPool()
		p.Name = "test-ippool"
		p.Spec.CIDR = "192.168.0.0/24"
		p.Spec.BlockSize = 26
		p.Spec.NodeSelector = "all()"
		p.Spec.Disabled = false
		_, err = c.IPPools().Create(context.Background(), p, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		// Delete the IP pool.
		_, err := c.IPPools().Delete(context.Background(), "test-ippool", options.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		os.Remove(kconfigFile.Name())
		controllerManager.Stop()
		nodeController.Stop()
		apiserver.Stop()
		etcd.Stop()
	})

	// This test makes sure our IPAM garbage collection properly handles when the Kubernetes node name
	// does not match the Calico node name in etcd.
	It("should properly garbage collect IP addresses for mismatched node names", func() {
		// Run controller.
		nodeController = testutils.RunNodeController(apiconfig.EtcdV3, etcd.IP, kconfigFile.Name(), false)

		// Create a kubernetes node.
		kn := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: kNodeName}}
		_, err := k8sClient.CoreV1().Nodes().Create(context.Background(), kn, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Create a Calico node with a reference to it.
		cn := calicoNode(c, cNodeName, kNodeName, map[string]string{})
		_, err = c.Nodes().Create(context.Background(), cn, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Allocate an IP address on the Calico node.
		// Note: it refers to a pod that doesn't exist, but this is OK since we only clean up addressses
		// when their node goes away, and the node exists.
		handleA := "handleA"
		attrs := map[string]string{"node": cNodeName, "pod": "pod-a", "namespace": "default"}
		err = c.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
			IP: net.MustParseIP("192.168.0.1"), HandleID: &handleA, Attrs: attrs, Hostname: cNodeName,
		})
		Expect(err).NotTo(HaveOccurred())

		// Create and delete an unrelated node. This should trigger the controller
		// to do a sync.
		kn2 := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "other-node"}}
		_, err = k8sClient.CoreV1().Nodes().Create(context.Background(), kn2, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		err = k8sClient.CoreV1().Nodes().Delete(context.Background(), kn2.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		// The IPAM allocation should be untouched, since the Kubernetes node which is bound to
		// the Calico node is still present.
		Consistently(func() error {
			return assertIPsWithHandle(c.IPAM(), handleA, 1)
		}, 5*time.Second, 1*time.Second).ShouldNot(HaveOccurred())

		// Delete the Kubernetes node with the allocation.
		err = k8sClient.CoreV1().Nodes().Delete(context.Background(), kn.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Now the IP should have been cleaned up.
		Eventually(func() error {
			return assertIPsWithHandle(c.IPAM(), handleA, 0)
		}, 5*time.Second, 1*time.Second).ShouldNot(HaveOccurred())
	})

	It("should never garbage collect IP addresses that do not belong to Kubernetes pods", func() {
		// Run controller.
		nodeController = testutils.RunNodeController(apiconfig.EtcdV3, etcd.IP, kconfigFile.Name(), false)

		// Use the same name for k8s and Calico node.
		commonNodeName := "common-node-name"

		// Create a kubernetes node.
		kn := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: commonNodeName}}
		_, err := k8sClient.CoreV1().Nodes().Create(context.Background(), kn, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Create a Calico node without a node reference. Be extra tricky, by naming the calico node the
		// same name as the Kubernetes node. This makes sure we're really using the orchRef properly.
		cn := calicoNode(c, commonNodeName, "", map[string]string{})
		_, err = c.Nodes().Create(context.Background(), cn, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Allocate an IP address on the Calico node. Since this is mimicking an allocation on a non-k8s node,
		// don't include pod / namespace metadata.
		handleA := "handleA"
		attrs := map[string]string{"node": commonNodeName}
		err = c.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
			IP: net.MustParseIP("192.168.0.1"), HandleID: &handleA, Attrs: attrs, Hostname: commonNodeName,
		})
		Expect(err).NotTo(HaveOccurred())

		// Create and delete an unrelated Kubernetes node. This should trigger the controller
		// to do a sync.
		kn2 := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "other-node"}}
		_, err = k8sClient.CoreV1().Nodes().Create(context.Background(), kn2, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		err = k8sClient.CoreV1().Nodes().Delete(context.Background(), kn2.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		// The IPAM allocation should be untouched.
		Consistently(func() error {
			return assertIPsWithHandle(c.IPAM(), handleA, 1)
		}, 5*time.Second, 1*time.Second).ShouldNot(HaveOccurred())

		// Delete the Kubernetes node with the same name as the Calico node.
		err = k8sClient.CoreV1().Nodes().Delete(context.Background(), kn.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		// The IPAM allocation should still be untouched.
		Consistently(func() error {
			return assertIPsWithHandle(c.IPAM(), handleA, 1)
		}, 5*time.Second, 1*time.Second).ShouldNot(HaveOccurred())

		// Now delete the Calico node object.
		_, err = c.Nodes().Delete(context.Background(), cn.Name, options.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Create and delete an unrelated Kubernetes node. This should trigger the controller
		// to do a sync.
		// TODO: Right now we only trigger the controller off of k8s node events, not Calico node events.
		_, err = k8sClient.CoreV1().Nodes().Create(context.Background(), kn2, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		err = k8sClient.CoreV1().Nodes().Delete(context.Background(), kn2.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		// The IPAM allocation should still be untouched.
		Consistently(func() error {
			return assertIPsWithHandle(c.IPAM(), handleA, 1)
		}, 5*time.Second, 1*time.Second).ShouldNot(HaveOccurred())
	})

	It("should garbage collect IP addresses if there is no Calico node, even if there happens to be a Kubernetes node", func() {
		// Run controller.
		nodeController = testutils.RunNodeController(apiconfig.EtcdV3, etcd.IP, kconfigFile.Name(), false)

		// Create a kubernetes node.
		commonNodeName := "common-node-name"
		kn := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: commonNodeName}}
		_, err := k8sClient.CoreV1().Nodes().Create(context.Background(), kn, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Allocate an IP address on a node that doesn't exist.
		handleA := "handleA"
		attrs := map[string]string{"node": commonNodeName, "pod": "pod-a", "namespace": "default"}
		err = c.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
			IP: net.MustParseIP("192.168.0.1"), HandleID: &handleA, Attrs: attrs, Hostname: commonNodeName,
		})
		Expect(err).NotTo(HaveOccurred())

		// Create and delete an unrelated Kubernetes node. This should trigger the controller
		// to do a sync.
		kn2 := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "other-node"}}
		_, err = k8sClient.CoreV1().Nodes().Create(context.Background(), kn2, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		err = k8sClient.CoreV1().Nodes().Delete(context.Background(), kn2.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Now the allocation should be cleaned up.
		Eventually(func() error {
			return assertIPsWithHandle(c.IPAM(), handleA, 0)
		}, 5*time.Second, 1*time.Second).ShouldNot(HaveOccurred())
	})

	It("should garbage collect IP addresses if there is no Calico node AND no Kubernetes node", func() {
		// Run controller.
		nodeController = testutils.RunNodeController(apiconfig.EtcdV3, etcd.IP, kconfigFile.Name(), false)

		// Allocate an IP address on a node that doesn't exist.
		commonNodeName := "common-node-name"
		handleA := "handleA"
		attrs := map[string]string{"node": commonNodeName, "pod": "pod-a", "namespace": "default"}
		err := c.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
			IP: net.MustParseIP("192.168.0.1"), HandleID: &handleA, Attrs: attrs, Hostname: commonNodeName,
		})
		Expect(err).NotTo(HaveOccurred())

		// Create and delete an unrelated Kubernetes node. This should trigger the controller
		// to do a sync.
		kn2 := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "other-node"}}
		_, err = k8sClient.CoreV1().Nodes().Create(context.Background(), kn2, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		err = k8sClient.CoreV1().Nodes().Delete(context.Background(), kn2.Name, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		// The IP should have been cleaned up since it is not attached to any Kubernetes or Calico node.
		Eventually(func() error {
			return assertIPsWithHandle(c.IPAM(), handleA, 0)
		}, 5*time.Second, 1*time.Second).ShouldNot(HaveOccurred())
	})
})
