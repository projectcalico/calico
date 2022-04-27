// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = Describe("Node labeling tests", func() {
	var (
		etcd              *containers.Container
		policyController  *containers.Container
		apiserver         *containers.Container
		c                 client.Interface
		k8sClient         *kubernetes.Clientset
		controllerManager *containers.Container
	)

	const kNodeName = "k8snodename"
	const cNodeName = "calinodename"

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()
		c = testutils.GetCalicoClient(apiconfig.EtcdV3, etcd.IP, "")

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)

		// Write out a kubeconfig file
		kconfigfile, err := ioutil.TempFile("", "ginkgo-policycontroller")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(kconfigfile.Name())
		data := testutils.BuildKubeconfig(apiserver.IP)
		_, err = kconfigfile.Write([]byte(data))
		Expect(err).NotTo(HaveOccurred())

		// Make the kubeconfig readable by the container.
		Expect(kconfigfile.Chmod(os.ModePerm)).NotTo(HaveOccurred())

		// Run the controller.
		policyController = testutils.RunPolicyController(apiconfig.EtcdV3, etcd.IP, kconfigfile.Name(), "")

		k8sClient, err = testutils.GetK8sClient(kconfigfile.Name())
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
		controllerManager.Stop()
		policyController.Stop()
		apiserver.Stop()
		etcd.Stop()
	})

	It("should sync labels from k8s -> calico", func() {
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
		cn := api.NewNode()
		cn.Name = cNodeName
		cn.Labels = map[string]string{"calico-label": "calico-value", "label1": "badvalue"}
		cn.Spec = api.NodeSpec{
			OrchRefs: []api.OrchRef{
				{
					NodeName:     kNodeName,
					Orchestrator: "k8s",
				},
			},
		}
		_, err = c.Nodes().Create(context.Background(), cn, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Expect the node label to sync.
		expected := map[string]string{"label1": "value1", "calico-label": "calico-value"}
		Eventually(func() error { return expectLabels(c, expected, cNodeName) },
			time.Second*15, 500*time.Millisecond).Should(BeNil())

		// Update the Kubernetes node labels.
		Expect(testutils.UpdateK8sNode(k8sClient, kn.Name, func(kn *v1.Node) {
			kn.Labels["label1"] = "value2"
		})).NotTo(HaveOccurred())

		// Expect the node label to sync.
		expected = map[string]string{"label1": "value2", "calico-label": "calico-value"}
		Eventually(func() error { return expectLabels(c, expected, cNodeName) },
			time.Second*15, 500*time.Millisecond).Should(BeNil())

		// Delete the label, add a different one.
		Expect(testutils.UpdateK8sNode(k8sClient, kn.Name, func(kn *v1.Node) {
			kn.Labels = map[string]string{"label2": "value1"}
		})).NotTo(HaveOccurred())

		// Expect the node labels to sync.
		expected = map[string]string{"label2": "value1", "calico-label": "calico-value"}
		Eventually(func() error { return expectLabels(c, expected, cNodeName) },
			time.Second*15, 500*time.Millisecond).Should(BeNil())

		// Delete the Kubernetes node.
		err = k8sClient.CoreV1().Nodes().Delete(context.Background(), kNodeName, metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
		Eventually(func() *api.Node {
			node, _ := c.Nodes().Get(context.Background(), cNodeName, options.GetOptions{})
			return node
		}, time.Second*2, 500*time.Millisecond).Should(BeNil())
	})
})

func expectLabels(c client.Interface, labels map[string]string, node string) error {
	cn, err := c.Nodes().Get(context.Background(), node, options.GetOptions{})
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(cn.Labels, labels) {
		s := fmt.Sprintf("Labels do not match.\n\nExpected: %#v\n  Actual: %#v\n", labels, cn.Labels)
		logrus.Warn(s)
		return fmt.Errorf(s)
	}
	return nil
}
