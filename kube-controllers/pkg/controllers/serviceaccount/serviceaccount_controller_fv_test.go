// Copyright (c) 2017-2026 Tigera, Inc. All rights reserved.
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

package serviceaccount_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = Describe("Calico serviceaccount controller FV tests (etcd mode)", Ordered, func() {
	var (
		etcd              *containers.Container
		kubeControllers   *containers.Container
		apiserver         *containers.Container
		calicoClient      client.Interface
		k8sClient         *kubernetes.Clientset
		controllerManager *containers.Container
		removeKubeconfig  func()
	)

	BeforeAll(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()
		calicoClient = testutils.GetCalicoClient(apiconfig.EtcdV3, etcd.IP, "")

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)

		// Write out a kubeconfig file
		var kconfigfile string
		kconfigfile, removeKubeconfig = testutils.BuildKubeconfig(apiserver.IP)

		kubeControllers = testutils.RunKubeControllers(apiconfig.EtcdV3, etcd.IP, kconfigfile, "")

		var err error
		k8sClient, err = testutils.GetK8sClient(kconfigfile)
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

	AfterAll(func() {
		_ = calicoClient.Close()
		controllerManager.Stop()
		kubeControllers.Stop()
		apiserver.Stop()
		etcd.Stop()
		removeKubeconfig()
	})

	AfterEach(func() {
		ctx := context.Background()
		profList, err := calicoClient.Profiles().List(ctx, options.ListOptions{})
		if err != nil {
			log.WithError(err).Warn("Failed to list profiles during cleanup")
		}
		if profList != nil {
			for _, prof := range profList.Items {
				if _, err := calicoClient.Profiles().Delete(ctx, prof.Name, options.DeleteOptions{}); err != nil {
					log.WithError(err).WithField("profile", prof.Name).Debug("Failed to delete profile during cleanup")
				}
			}
		}
		saList, err := k8sClient.CoreV1().ServiceAccounts("default").List(ctx, metav1.ListOptions{})
		if err != nil {
			log.WithError(err).Warn("Failed to list service accounts during cleanup")
		}
		if saList != nil {
			for _, sa := range saList.Items {
				if sa.Name == "default" {
					continue
				}
				if err := k8sClient.CoreV1().ServiceAccounts("default").Delete(ctx, sa.Name, metav1.DeleteOptions{}); err != nil {
					log.WithError(err).WithField("sa", sa.Name).Debug("Failed to delete service account during cleanup")
				}
			}
		}
	})

	Context("mainline functionality", func() {
		var profName string
		BeforeEach(func() {
			saName := "peanutbutter"
			nsName := "default"
			profName = "ksa." + nsName + "." + saName
			sa := &v1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      saName,
					Namespace: nsName,
					Labels: map[string]string{
						"peanut": "butter",
					},
				},
			}
			Eventually(func() error {
				_, err := k8sClient.CoreV1().ServiceAccounts(nsName).Create(context.Background(),
					sa, metav1.CreateOptions{})
				return err
			}, time.Second*10, 500*time.Millisecond).ShouldNot(HaveOccurred())

			Eventually(func() *api.Profile {
				profile, _ := calicoClient.Profiles().Get(context.Background(), profName, options.GetOptions{})
				return profile
			}, time.Second*15, 500*time.Millisecond).ShouldNot(BeNil())
		})

		It("should write new profiles in etcd to match service account in k8s ", func() {
			// Delete profile and then check if it is re-created.
			_, err := calicoClient.Profiles().Delete(context.Background(), profName, options.DeleteOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Eventually(func() error {
				_, err := calicoClient.Profiles().Get(context.Background(), profName, options.GetOptions{})
				return err
			}, time.Second*15, 500*time.Millisecond).ShouldNot(HaveOccurred())
		})

		It("should update existing profiles in etcd to match service account in k8s", func() {
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
