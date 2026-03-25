// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
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

package node_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/node"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/utils"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = Describe("kube-controllers IPAM FV tests (etcd mode)", Ordered, ContinueOnFailure, func() {
	var (
		etcd      *containers.Container
		c         client.Interface
		k8sClient *fake.Clientset
		stopCh    chan struct{}
	)

	const kNodeName = "k8snodename"
	const cNodeName = "calinodename"

	BeforeAll(func() {
		// Run etcd for the Calico datastore.
		etcd = testutils.RunEtcd()
		c = testutils.GetCalicoClient(apiconfig.EtcdV3, etcd.IP, "")

		// Create an IP pool with room for 4 blocks.
		p := api.NewIPPool()
		p.Name = "test-ippool"
		p.Spec.CIDR = "192.168.0.0/24"
		p.Spec.BlockSize = 26
		p.Spec.NodeSelector = "all()"
		p.Spec.Disabled = false
		_, err := c.IPPools().Create(context.Background(), p, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Create the fake K8s client and start the in-process node controller.
		// We use a single controller for all tests (matching how the Docker-based
		// tests share a single K8s apiserver) to avoid prometheus metric re-registration
		// panics from the IPAM controller's package-level metrics.
		k8sClient = fake.NewSimpleClientset()
		stopCh = make(chan struct{})

		factory := informers.NewSharedInformerFactory(k8sClient, 0)
		nodeInformer := factory.Core().V1().Nodes().Informer()
		podInformer := factory.Core().V1().Pods().Informer()

		dataFeed := utils.NewDataFeed(c, utils.Etcdv3)

		cfg := config.NodeControllerConfig{
			DeleteNodes:            true,
			AutoHostEndpointConfig: &config.AutoHostEndpointConfig{},
			LeakGracePeriod:        &metav1.Duration{Duration: 15 * time.Minute},
		}

		ctrl := node.NewNodeController(
			context.Background(),
			k8sClient,
			c,
			cfg,
			nodeInformer, podInformer,
			dataFeed,
			nil, nil,
		)

		go nodeInformer.Run(stopCh)
		go podInformer.Run(stopCh)
		go ctrl.Run(stopCh)
		dataFeed.Start()
	})

	AfterAll(func() {
		close(stopCh)

		_, err := c.IPPools().Delete(context.Background(), "test-ippool", options.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		_ = c.Close()
		etcd.Stop()
	})

	AfterEach(func() {
		ctx := context.Background()
		// Release IPAM allocations.
		cNodes, err := c.Nodes().List(ctx, options.ListOptions{})
		if err != nil {
			log.WithError(err).Warn("Failed to list Calico nodes during IPAM cleanup")
		}
		if cNodes != nil {
			for _, n := range cNodes.Items {
				affinityCfg := ipam.AffinityConfig{AffinityType: ipam.AffinityTypeHost, Host: n.Name}
				_ = c.IPAM().ReleaseHostAffinities(ctx, affinityCfg, true)
			}
		}
		_ = c.IPAM().ReleaseByHandle(ctx, "handleA")
		_ = c.IPAM().ReleaseByHandle(ctx, "handleB")
		_ = c.IPAM().ReleaseByHandle(ctx, "handleC")
		// Clean up K8s nodes.
		nodes, err := k8sClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			log.WithError(err).Warn("Failed to list k8s nodes during cleanup")
		}
		for _, n := range nodes.Items {
			if err := k8sClient.CoreV1().Nodes().Delete(ctx, n.Name, metav1.DeleteOptions{}); err != nil {
				log.WithError(err).WithField("node", n.Name).Debug("Failed to delete k8s node during cleanup")
			}
		}
		// Clean up Calico nodes.
		if cNodes != nil {
			for _, n := range cNodes.Items {
				if _, err := c.Nodes().Delete(ctx, n.Name, options.DeleteOptions{}); err != nil {
					log.WithError(err).WithField("node", n.Name).Debug("Failed to delete Calico node during cleanup")
				}
			}
		}
	})

	It("should properly garbage collect IP addresses for mismatched node names", func() {
		// Create a kubernetes node.
		kn := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: kNodeName}}
		_, err := k8sClient.CoreV1().Nodes().Create(context.Background(), kn, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Create a Calico node with a reference to the K8s node.
		cn := calicoNode(cNodeName, kNodeName, map[string]string{})
		_, err = c.Nodes().Create(context.Background(), cn, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Allocate an IP address on the Calico node.
		handleA := "handleA"
		attrs := map[string]string{"node": cNodeName, "pod": "pod-a", "namespace": "default"}
		err = c.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
			IP: net.MustParseIP("192.168.0.1"), HandleID: &handleA, Attrs: attrs, Hostname: cNodeName,
		})
		Expect(err).NotTo(HaveOccurred())

		// Create and delete an unrelated node to trigger a sync.
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
		commonNodeName := "common-node-name"

		// Create a kubernetes node.
		kn := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: commonNodeName}}
		_, err := k8sClient.CoreV1().Nodes().Create(context.Background(), kn, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Create a Calico node without a node reference. Be extra tricky, by naming the calico node the
		// same name as the Kubernetes node. This makes sure we're really using the orchRef properly.
		cn := calicoNode(commonNodeName, "", map[string]string{})
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

		// Create and delete an unrelated Kubernetes node to trigger a sync.
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

		// Create and delete an unrelated Kubernetes node to trigger a sync.
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
		commonNodeName := "common-node-name"

		// Create a kubernetes node.
		kn := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: commonNodeName}}
		_, err := k8sClient.CoreV1().Nodes().Create(context.Background(), kn, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Allocate an IP address on a node that doesn't exist in Calico.
		handleA := "handleA"
		attrs := map[string]string{"node": commonNodeName, "pod": "pod-a", "namespace": "default"}
		err = c.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
			IP: net.MustParseIP("192.168.0.1"), HandleID: &handleA, Attrs: attrs, Hostname: commonNodeName,
		})
		Expect(err).NotTo(HaveOccurred())

		// Create and delete an unrelated Kubernetes node to trigger a sync.
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
		// Allocate an IP address on a node that doesn't exist.
		commonNodeName := "common-node-name"
		handleA := "handleA"
		attrs := map[string]string{"node": commonNodeName, "pod": "pod-a", "namespace": "default"}
		err := c.IPAM().AssignIP(context.Background(), ipam.AssignIPArgs{
			IP: net.MustParseIP("192.168.0.1"), HandleID: &handleA, Attrs: attrs, Hostname: commonNodeName,
		})
		Expect(err).NotTo(HaveOccurred())

		// Create and delete an unrelated Kubernetes node to trigger a sync.
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
