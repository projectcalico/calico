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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/serviceaccount"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = Describe("Calico serviceaccount controller FV tests (etcd mode)", Ordered, ContinueOnFailure, func() {
	var (
		etcd         *containers.Container
		calicoClient client.Interface
		k8sClient    *fake.Clientset
		stopCh       chan struct{}
	)

	BeforeAll(func() {
		// Run etcd for the Calico datastore.
		etcd = testutils.RunEtcd()
		calicoClient = testutils.GetCalicoClient(apiconfig.EtcdV3, etcd.IP, "")
	})

	AfterAll(func() {
		_ = calicoClient.Close()
		etcd.Stop()
	})

	AfterEach(func() {
		close(stopCh)

		// Clean up Calico profiles.
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
					UID:       types.UID("aa844ac0-87c8-440a-b270-307cdba8fd25"),
					Labels: map[string]string{
						"peanut": "butter",
					},
				},
			}

			// Create the K8s objects before starting the controller so the
			// informer's initial List picks them up deterministically,
			// avoiding any race with watch establishment.
			k8sClient = fake.NewSimpleClientset(sa)
			stopCh = make(chan struct{})

			ctrl := serviceaccount.NewServiceAccountController(
				context.Background(),
				k8sClient,
				calicoClient,
				config.GenericControllerConfig{
					ReconcilerPeriod: time.Second,
					NumberOfWorkers:  1,
				},
			)
			go ctrl.Run(stopCh)

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
