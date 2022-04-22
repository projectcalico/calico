// Copyright (c) 2017,2021 Tigera, Inc. All rights reserved.
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

package namespace_test

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
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = Describe("Calico namespace controller FV tests (etcd mode)", func() {
	var (
		etcd              *containers.Container
		policyController  *containers.Container
		apiserver         *containers.Container
		calicoClient      client.Interface
		k8sClient         *kubernetes.Clientset
		controllerManager *containers.Container
	)

	const kNodeName = "k8snodename"
	const cNodeName = "caliconodename"

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()
		calicoClient = testutils.GetCalicoClient(apiconfig.EtcdV3, etcd.IP, "")

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

	Context("Namespace Profile FV tests", func() {
		var profName string
		BeforeEach(func() {
			nsName := "peanutbutter"
			profName = "kns." + nsName
			ns := &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: nsName,
					Labels: map[string]string{
						"peanut": "butter",
					},
				},
				Spec: v1.NamespaceSpec{},
			}
			_, err := k8sClient.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() *api.Profile {
				profile, _ := calicoClient.Profiles().Get(context.Background(), profName, options.GetOptions{})
				return profile
			}, time.Second*15, 500*time.Millisecond).ShouldNot(BeNil())
		})

		It("should write new profiles in etcd to match namespaces in k8s ", func() {
			_, err := calicoClient.Profiles().Delete(context.Background(), profName, options.DeleteOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Eventually(func() error {
				_, err := calicoClient.Profiles().Get(context.Background(), profName, options.GetOptions{})
				return err
			}, time.Second*15, 500*time.Millisecond).ShouldNot(HaveOccurred())
		})

		It("should update existing profiles in etcd to match namespaces in k8s", func() {
			profile, err := calicoClient.Profiles().Get(context.Background(), profName, options.GetOptions{})
			By("getting the profile", func() {
				Expect(err).ShouldNot(HaveOccurred())
			})

			By("updating the profile to have no labels to apply", func() {
				profile.Spec.LabelsToApply = map[string]string{}
				profile, err := calicoClient.Profiles().Update(context.Background(), profile, options.SetOptions{})

				Expect(err).ShouldNot(HaveOccurred())
				Expect(profile.Spec.LabelsToApply).To(BeEmpty())
			})

			By("waiting for the controller to write back the original labels to apply", func() {
				Eventually(func() map[string]string {
					prof, _ := calicoClient.Profiles().Get(context.Background(), profName, options.GetOptions{})
					return prof.Spec.LabelsToApply
				}, time.Second*15, 500*time.Millisecond).ShouldNot(BeEmpty())
			})
		})
	})
})
