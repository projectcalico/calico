// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package tier_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
)

var _ = Describe("Tier lifecycle FV", func() {
	var (
		etcd      *containers.Container
		kubectrl  *containers.Container
		apiserver *containers.Container
		k8sClient *kubernetes.Clientset
		cli       ctrlclient.Client
		err       error
	)

	BeforeEach(func() {
		etcd = testutils.RunEtcd()

		var cfg *apiconfig.CalicoAPIConfig
		cfg, err = apiconfig.LoadClientConfigFromEnvironment()
		Expect(err).NotTo(HaveOccurred())
		if !k8s.UsingV3CRDs(&cfg.Spec) {
			Skip("Tier controller only runs against v3 CRDs")
		}

		apiserver = testutils.RunK8sApiserver(etcd.IP)
		kubeconfig, cleanup := testutils.BuildKubeconfig(apiserver.IP)
		defer cleanup()

		k8sClient, err = testutils.GetK8sClient(kubeconfig)
		Expect(err).NotTo(HaveOccurred())

		Expect(v3.AddToGlobalScheme()).NotTo(HaveOccurred())

		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		Expect(err).NotTo(HaveOccurred())
		cli, err = ctrlclient.New(config, ctrlclient.Options{})
		Expect(err).NotTo(HaveOccurred())

		Eventually(func() error {
			_, err := k8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
			return err
		}, 30*time.Second, 1*time.Second).Should(BeNil())

		testutils.ApplyCRDs(apiserver)

		mode := apiconfig.Kubernetes
		kubectrl = testutils.RunKubeControllers(mode, etcd.IP, kubeconfig, "")
	})

	AfterEach(func() {
		kubectrl.Stop()
		apiserver.Stop()
		etcd.Stop()
	})

	It("should add a finalizer to new tiers", func() {
		tier := &v3.Tier{
			ObjectMeta: metav1.ObjectMeta{Name: "test-tier"},
			Spec: v3.TierSpec{
				Order: ptr.To(float64(100)),
			},
		}
		Expect(cli.Create(context.Background(), tier)).NotTo(HaveOccurred())
		expectTierHasFinalizer(cli, "test-tier")
	})

	It("should block tier deletion while policies exist and allow it once they're removed", func() {
		ctx := context.Background()

		By("creating a tier")
		tier := &v3.Tier{
			ObjectMeta: metav1.ObjectMeta{Name: "test-tier"},
			Spec: v3.TierSpec{
				Order: ptr.To(float64(100)),
			},
		}
		Expect(cli.Create(ctx, tier)).NotTo(HaveOccurred())
		expectTierHasFinalizer(cli, "test-tier")

		By("creating a GlobalNetworkPolicy in the tier")
		gnp := &v3.GlobalNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "test-tier.my-policy"},
			Spec: v3.GlobalNetworkPolicySpec{
				Tier:     "test-tier",
				Selector: "all()",
			},
		}
		Expect(cli.Create(ctx, gnp)).NotTo(HaveOccurred())

		By("deleting the tier")
		Expect(cli.Delete(ctx, tier)).NotTo(HaveOccurred())

		By("verifying the tier still exists with a terminating status")
		expectTierTerminating(cli, "test-tier", "GlobalNetworkPolic")

		By("verifying the tier still has its finalizer")
		expectTierHasFinalizer(cli, "test-tier")

		By("deleting the policy")
		Expect(cli.Delete(ctx, gnp)).NotTo(HaveOccurred())

		By("verifying the tier is fully deleted")
		expectTierDeleted(cli, "test-tier")
	})

	It("should track multiple policy types in the status", func() {
		ctx := context.Background()

		By("creating a tier")
		tier := &v3.Tier{
			ObjectMeta: metav1.ObjectMeta{Name: "multi-tier"},
			Spec: v3.TierSpec{
				Order: ptr.To(float64(200)),
			},
		}
		Expect(cli.Create(ctx, tier)).NotTo(HaveOccurred())
		expectTierHasFinalizer(cli, "multi-tier")

		By("creating a GlobalNetworkPolicy and a NetworkPolicy in the tier")
		gnp := &v3.GlobalNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "multi-tier.gnp1"},
			Spec: v3.GlobalNetworkPolicySpec{
				Tier:     "multi-tier",
				Selector: "all()",
			},
		}
		np := &v3.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "multi-tier.np1",
				Namespace: "default",
			},
			Spec: v3.NetworkPolicySpec{
				Tier:     "multi-tier",
				Selector: "all()",
			},
		}
		Expect(cli.Create(ctx, gnp)).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, np)).NotTo(HaveOccurred())

		By("deleting the tier")
		Expect(cli.Delete(ctx, tier)).NotTo(HaveOccurred())

		By("verifying the status mentions both policy types")
		expectTierTerminating(cli, "multi-tier", "GlobalNetworkPolic")
		expectTierTerminating(cli, "multi-tier", "NetworkPolic")

		By("deleting the GNP — tier should still be blocked by the NP")
		Expect(cli.Delete(ctx, gnp)).NotTo(HaveOccurred())

		// Give the controller time to reconcile after GNP deletion, then
		// verify the tier still exists because the NP is still there.
		expectTierTerminating(cli, "multi-tier", "NetworkPolic")

		By("deleting the NP — tier should now be fully deleted")
		Expect(cli.Delete(ctx, np)).NotTo(HaveOccurred())
		expectTierDeleted(cli, "multi-tier")
	})
})

func expectTierHasFinalizer(cli ctrlclient.Client, name string) {
	tier := &v3.Tier{}
	EventuallyWithOffset(1, func() error {
		if err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: name}, tier); err != nil {
			return err
		}
		if slices.Contains(tier.Finalizers, v3.TierFinalizer) {
			return nil
		}
		return fmt.Errorf("finalizer not found on tier %s, finalizers: %v", name, tier.Finalizers)
	}, 10*time.Second, 1*time.Second).ShouldNot(HaveOccurred(), "tier should have finalizer")
}

func expectTierTerminating(cli ctrlclient.Client, name, messageSubstring string) {
	tier := &v3.Tier{}
	EventuallyWithOffset(1, func() error {
		if err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: name}, tier); err != nil {
			return err
		}
		for _, c := range tier.Status.Conditions {
			if c.Type == "Ready" && c.Status == metav1.ConditionFalse && c.Reason == "Terminating" {
				if messageSubstring != "" && !strings.Contains(c.Message, messageSubstring) {
					return fmt.Errorf("condition message %q does not contain %q", c.Message, messageSubstring)
				}
				return nil
			}
		}
		return fmt.Errorf("tier %s does not have Ready=False/Terminating condition; conditions: %+v", name, tier.Status.Conditions)
	}, 10*time.Second, 1*time.Second).ShouldNot(HaveOccurred(), "tier should be terminating")
}

func expectTierDeleted(cli ctrlclient.Client, name string) {
	tier := &v3.Tier{}
	EventuallyWithOffset(1, func() error {
		err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: name}, tier)
		if errors.IsNotFound(err) {
			return nil
		} else if err != nil {
			return err
		}
		return fmt.Errorf("tier %s still exists", name)
	}, 10*time.Second, 1*time.Second).ShouldNot(HaveOccurred(), "tier should be deleted")
}
