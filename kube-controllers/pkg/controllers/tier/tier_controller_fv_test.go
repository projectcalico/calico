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
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/tier"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	logutils "github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

var testEnv *testutils.TestEnv

func init() {
	logrus.SetFormatter(&logutils.Formatter{})
	logrus.SetLevel(logrus.DebugLevel)
}

func TestMain(m *testing.M) {
	var err error
	testEnv, err = testutils.NewTestEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "envtest setup: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := testEnv.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "envtest teardown: %v\n", err)
		}
	}()
	os.Exit(m.Run())
}

// startTierController creates informers and starts the tier controller in a
// background goroutine. The controller is stopped when the test ends.
func startTierController(t *testing.T, ctx context.Context) {
	t.Helper()
	factory := testEnv.NewCalicoInformerFactory()
	tierInformer := factory.Projectcalico().V3().Tiers().Informer()
	gnpInformer := factory.Projectcalico().V3().GlobalNetworkPolicies().Informer()
	npInformer := factory.Projectcalico().V3().NetworkPolicies().Informer()
	sgnpInformer := factory.Projectcalico().V3().StagedGlobalNetworkPolicies().Informer()
	snpInformer := factory.Projectcalico().V3().StagedNetworkPolicies().Informer()

	ctrl := tier.NewController(ctx, testEnv.CalicoClient, tierInformer, gnpInformer, npInformer, sgnpInformer, snpInformer)

	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })

	factory.Start(stop)
	go ctrl.Run(stop)
}

// TestFV_FinalizerAddedToNewTier verifies that the tier controller automatically
// adds the tier finalizer to newly created tiers.
func TestFV_FinalizerAddedToNewTier(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	startTierController(t, ctx)

	tierObj := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "test-finalizer"},
		Spec: v3.TierSpec{
			Order: ptr.To(float64(100)),
		},
	}
	g.Expect(testEnv.Client.Create(ctx, tierObj)).To(Succeed())
	t.Cleanup(func() {
		if err := testEnv.Client.Delete(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "test-finalizer"}}); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})

	expectTierHasFinalizer(g, "test-finalizer")
}

// TestFV_TierDeletionBlockedByPolicy verifies the full tier deletion lifecycle:
// the tier's finalizer prevents deletion while a policy references it, and the
// tier is garbage collected once the policy is removed.
func TestFV_TierDeletionBlockedByPolicy(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	startTierController(t, ctx)

	tierObj := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "test-blocked"},
		Spec: v3.TierSpec{
			Order: ptr.To(float64(100)),
		},
	}
	g.Expect(testEnv.Client.Create(ctx, tierObj)).To(Succeed())
	expectTierHasFinalizer(g, "test-blocked")

	gnp := &v3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-blocked.my-policy"},
		Spec: v3.GlobalNetworkPolicySpec{
			Tier:     "test-blocked",
			Selector: "all()",
		},
	}
	g.Expect(testEnv.Client.Create(ctx, gnp)).To(Succeed())

	// Delete the tier. It should remain because the finalizer blocks it.
	g.Expect(testEnv.Client.Delete(ctx, tierObj)).To(Succeed())
	expectTierTerminating(g, "test-blocked", "1 GlobalNetworkPolicy")
	expectTierHasFinalizer(g, "test-blocked")

	// Delete the policy. The tier should now be fully deleted.
	g.Expect(testEnv.Client.Delete(ctx, gnp)).To(Succeed())
	expectTierDeleted(g, "test-blocked")
}

// TestFV_MultiplePolicyTypes verifies that the tier controller tracks multiple
// policy types (GNP and NP) independently. The tier stays in Terminating until
// all referencing policies across all types are deleted.
func TestFV_MultiplePolicyTypes(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	startTierController(t, ctx)

	tierObj := &v3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "multi-tier"},
		Spec: v3.TierSpec{
			Order: ptr.To(float64(200)),
		},
	}
	g.Expect(testEnv.Client.Create(ctx, tierObj)).To(Succeed())
	expectTierHasFinalizer(g, "multi-tier")

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
	g.Expect(testEnv.Client.Create(ctx, gnp)).To(Succeed())
	g.Expect(testEnv.Client.Create(ctx, np)).To(Succeed())

	// Delete the tier. It should be blocked by both policies.
	g.Expect(testEnv.Client.Delete(ctx, tierObj)).To(Succeed())
	expectTierTerminating(g, "multi-tier", "1 GlobalNetworkPolicy")
	expectTierTerminating(g, "multi-tier", "1 NetworkPolicy")

	// Delete the GNP. Tier should still be blocked by the NP.
	g.Expect(testEnv.Client.Delete(ctx, gnp)).To(Succeed())
	expectTierTerminating(g, "multi-tier", "1 NetworkPolicy")

	// Delete the NP. Tier should now be fully deleted.
	g.Expect(testEnv.Client.Delete(ctx, np)).To(Succeed())
	expectTierDeleted(g, "multi-tier")
}

func expectTierHasFinalizer(g Gomega, name string) {
	cli := testEnv.Client
	tier := &v3.Tier{}
	g.Eventually(func() error {
		if err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: name}, tier); err != nil {
			return err
		}
		if slices.Contains(tier.Finalizers, v3.TierFinalizer) {
			return nil
		}
		return fmt.Errorf("finalizer not found on tier %s, finalizers: %v", name, tier.Finalizers)
	}, 10*time.Second, 200*time.Millisecond).Should(Succeed())
}

func expectTierTerminating(g Gomega, name, messageSubstring string) {
	cli := testEnv.Client
	tier := &v3.Tier{}
	g.Eventually(func() error {
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
	}, 10*time.Second, 200*time.Millisecond).Should(Succeed())
}

func expectTierDeleted(g Gomega, name string) {
	cli := testEnv.Client
	tier := &v3.Tier{}
	g.Eventually(func() error {
		err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: name}, tier)
		if errors.IsNotFound(err) {
			return nil
		} else if err != nil {
			return err
		}
		return fmt.Errorf("tier %s still exists", name)
	}, 10*time.Second, 200*time.Millisecond).Should(Succeed())
}
