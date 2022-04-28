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
	"io/ioutil"
	"os"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = Describe("[Resilience] PolicyController", func() {
	var (
		calicoEtcd       *containers.Container
		policyController *containers.Container
		k8sEtcd          *containers.Container
		apiserver        *containers.Container
		calicoClient     client.Interface
		k8sClient        *kubernetes.Clientset

		policyName      string
		genPolicyName   string
		policyNamespace string
	)

	BeforeEach(func() {
		// Run etcd.
		calicoEtcd = testutils.RunEtcd()
		calicoClient = testutils.GetCalicoClient(apiconfig.EtcdV3, calicoEtcd.IP, "")

		// Run apiserver.
		k8sEtcd = testutils.RunEtcd()
		apiserver = testutils.RunK8sApiserver(k8sEtcd.IP)

		// Write out a kubeconfig file
		kconfigfile, err := ioutil.TempFile("", "ginkgo-policycontroller")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(kconfigfile.Name())
		data := testutils.BuildKubeconfig(apiserver.IP)
		_, err = kconfigfile.Write([]byte(data))
		Expect(err).NotTo(HaveOccurred())

		// Make the kubeconfig readable by the container.
		Expect(kconfigfile.Chmod(os.ModePerm)).NotTo(HaveOccurred())

		k8sClient, err = testutils.GetK8sClient(kconfigfile.Name())
		Expect(err).NotTo(HaveOccurred())

		// Wait for the apiserver to be available and for the default namespace to exist.
		Eventually(func() error {
			_, err := k8sClient.CoreV1().Namespaces().Get(context.Background(), "default", metav1.GetOptions{})
			return err
		}, 30*time.Second, 1*time.Second).Should(BeNil())

		// Create a Kubernetes NetworkPolicy.
		policyName = "jelly"
		genPolicyName = "knp.default." + policyName
		policyNamespace = "default"
		np := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      policyName,
				Namespace: policyNamespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"fools": "gold",
					},
				},
			},
		}

		// Create the NP.
		Eventually(func() error {
			_, err := k8sClient.NetworkingV1().NetworkPolicies(policyNamespace).Create(context.Background(),
				np, metav1.CreateOptions{})
			return err
		}, time.Second*5).ShouldNot(HaveOccurred())

		policyController = testutils.RunPolicyController(apiconfig.EtcdV3, calicoEtcd.IP, kconfigfile.Name(), "")

		// Wait for it to appear in Calico's etcd.
		Eventually(func() *api.NetworkPolicy {
			policy, _ := calicoClient.NetworkPolicies().Get(context.Background(), policyNamespace, genPolicyName, options.GetOptions{})
			return policy
		}, time.Second*5, 500*time.Millisecond).ShouldNot(BeNil())
	})

	AfterEach(func() {
		calicoEtcd.Stop()
		policyController.Stop()
		k8sEtcd.Stop()
		apiserver.Stop()
	})

	Context("when apiserver goes down momentarily and data is removed from calico's etcd", func() {
		It("should eventually add the data to calico's etcd", func() {
			Skip("TODO: improve FV framework to handle pod restart")
			testutils.Stop(apiserver)
			_, err := calicoClient.NetworkPolicies().Delete(context.Background(),
				policyNamespace, genPolicyName, options.DeleteOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			testutils.Start(apiserver)
			Eventually(func() error {
				_, err := calicoClient.NetworkPolicies().Get(context.Background(), policyNamespace, genPolicyName, options.GetOptions{})
				return err
			}, time.Second*15, 500*time.Millisecond).ShouldNot(HaveOccurred())
		})
	})
	Context("when calico's etcd goes down momentarily and data is removed from k8s-apiserver", func() {
		It("should eventually remove the data from calico's etcd", func() {
			Skip("TODO: improve FV framework to handle pod restart")
			// Delete the Policy.
			testutils.Stop(calicoEtcd)
			err := k8sClient.NetworkingV1().NetworkPolicies(policyNamespace).Delete(context.Background(),
				policyName, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			time.Sleep(10 * time.Second)
			testutils.Start(calicoEtcd)
			Eventually(func() error {
				_, err := calicoClient.NetworkPolicies().Get(context.Background(), policyNamespace, genPolicyName, options.GetOptions{})
				return err
			}, time.Second*15, 500*time.Millisecond).Should(HaveOccurred())
		})
	})
})
