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
	"fmt"
	"io/ioutil"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	extensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/k8s-policy/tests/testutils"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
)

var _ = Describe("[Resilience] PolicyController", func() {
	var (
		calicoEtcd       *containers.Container
		policyController *containers.Container
		k8sEtcd          *containers.Container
		apiserver        *containers.Container
		calicoClient     *client.Client
		k8sClient        *kubernetes.Clientset

		policyName    string
		genPolicyName string
	)

	BeforeEach(func() {
		// Run etcd.
		calicoEtcd = testutils.RunEtcd()
		calicoClient = testutils.GetCalicoClient(calicoEtcd.IP)
		err := calicoClient.EnsureInitialized()
		Expect(err).NotTo(HaveOccurred())

		// Run apiserver.
		k8sEtcd = testutils.RunEtcd()
		apiserver = testutils.RunK8sApiserver(k8sEtcd.IP)

		// Write out a kubeconfig file
		kfconfigfile, err := ioutil.TempFile("", "ginkgo-policycontroller")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(kfconfigfile.Name())
		data := fmt.Sprintf(testutils.KubeconfigTemplate, apiserver.IP)
		kfconfigfile.Write([]byte(data))

		k8sClient, err = testutils.GetK8sClient(kfconfigfile.Name())
		Expect(err).NotTo(HaveOccurred())

		// TODO: Use upcoming port checker functions to wait until apiserver is responding to requests.
		time.Sleep(time.Second * 15)

		// Create a Kubernetes NetworkPolicy.
		policyName = "jelly"
		genPolicyName = "knp.default.default." + policyName
		var np *extensions.NetworkPolicy
		np = &extensions.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      policyName,
				Namespace: "default",
			},
			Spec: extensions.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"fools": "gold",
					},
				},
			},
		}
		err = k8sClient.Extensions().RESTClient().
			Post().
			Resource("networkpolicies").
			Namespace("default").
			Body(np).
			Do().Error()
		Expect(err).NotTo(HaveOccurred())

		policyController = testutils.RunPolicyController(calicoEtcd.IP, kfconfigfile.Name())

		// Wait for it to appear in Calico's etcd.
		Eventually(func() *api.Policy {
			policy, _ := calicoClient.Policies().Get(api.PolicyMetadata{Name: genPolicyName})
			return policy
		}).ShouldNot(BeNil())
	})
	Context("when apiserver goes down momentarily and data is removed from calico's etcd", func() {
		It("should eventually add the data to calico's etcd", func() {
			testutils.Stop(apiserver)
			err := calicoClient.Policies().Delete(api.PolicyMetadata{Name: genPolicyName})
			Expect(err).ShouldNot(HaveOccurred())
			testutils.Start(apiserver)
			Eventually(func() error {
				_, err := calicoClient.Policies().Get(api.PolicyMetadata{Name: genPolicyName})
				return err
			}, time.Second*15, 500*time.Millisecond).ShouldNot(HaveOccurred())
		})
	})
	Context("when calico's etcd goes down momentarily and data is removed from k8s-apiserver", func() {
		It("should eventually remove the data from calico's etcd", func() {
			// Delete the Policy.
			testutils.Stop(calicoEtcd)
			err := k8sClient.Extensions().RESTClient().
				Delete().
				Resource("networkpolicies").
				Namespace("default").
				Name(policyName).
				Do().Error()
			Expect(err).NotTo(HaveOccurred())

			time.Sleep(10 * time.Second)
			testutils.Start(calicoEtcd)
			Eventually(func() error {
				_, err := calicoClient.Policies().Get(api.PolicyMetadata{Name: genPolicyName})
				return err
			}, time.Second*15, 500*time.Millisecond).Should(HaveOccurred())
		})
	})
})
