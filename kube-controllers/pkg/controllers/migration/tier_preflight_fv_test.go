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

package migration

import (
	"context"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// v1TierKVP builds a v1 Tier KVPair for the mock backend.
func v1TierKVP(name string, order *float64, action apiv3.Action) *model.KVPair {
	return &model.KVPair{
		Key: model.ResourceKey{Kind: apiv3.KindTier, Name: name},
		Value: &apiv3.Tier{
			ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: v1InternalAnnotations},
			Spec:       apiv3.TierSpec{Order: order, DefaultAction: actionPtr(action)},
		},
	}
}

// tierOnlyV1Resources returns backend data containing just the given tiers.
func tierOnlyV1Resources(tiers ...*model.KVPair) map[string][]*model.KVPair {
	return map[string][]*model.KVPair{
		apiv3.KindTier:               tiers,
		apiv3.KindClusterInformation: {},
	}
}

// conformantBuiltInTiers returns the three built-in tiers with the order and
// default action the v3 API enforces.
func conformantBuiltInTiers() []*model.KVPair {
	return []*model.KVPair{
		v1TierKVP("default", ptr.To(apiv3.DefaultTierOrder), apiv3.Deny),
		v1TierKVP("kube-admin", ptr.To(apiv3.KubeAdminTierOrder), apiv3.Pass),
		v1TierKVP("kube-baseline", ptr.To(apiv3.KubeBaselineTierOrder), apiv3.Pass),
	}
}

// ensureV1CRD makes sure at least one crd.projectcalico.org CRD exists.
// TestLifecycle_DeletionBlockedThenCompleted deletes them all, and handlePending
// refuses to start a migration with no v1 CRDs to copy.
func ensureV1CRD(t *testing.T, ctx context.Context) {
	t.Helper()
	crd := &apiextv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "tiers.crd.projectcalico.org"},
		Spec: apiextv1.CustomResourceDefinitionSpec{
			Group: "crd.projectcalico.org",
			Scope: apiextv1.ClusterScoped,
			Names: apiextv1.CustomResourceDefinitionNames{
				Plural:   "tiers",
				Singular: "tier",
				Kind:     "Tier",
				ListKind: "TierList",
			},
			Versions: []apiextv1.CustomResourceDefinitionVersion{
				{
					Name:    "v1",
					Served:  true,
					Storage: true,
					Schema: &apiextv1.CustomResourceValidation{
						OpenAPIV3Schema: &apiextv1.JSONSchemaProps{
							Type:                   "object",
							XPreserveUnknownFields: ptr.To(true),
						},
					},
				},
			},
		},
	}
	crds := fvCRDClient.ApiextensionsV1().CustomResourceDefinitions()
	NewWithT(t).Eventually(func() error {
		existing, err := crds.Get(ctx, crd.Name, metav1.GetOptions{})
		if err == nil {
			if existing.DeletionTimestamp != nil {
				return fmt.Errorf("CRD %s is still terminating", crd.Name)
			}
			return nil
		}
		if !kerrors.IsNotFound(err) {
			return err
		}
		_, err = crds.Create(ctx, crd.DeepCopy(), metav1.CreateOptions{})
		return err
	}, 30*time.Second, 200*time.Millisecond).Should(Succeed())
}

// expectBlockedInPending waits for the controller to report the given substrings
// in the CR's status message without leaving the Pending phase, and asserts the
// APIService was left in place.
func expectBlockedInPending(t *testing.T, ctx context.Context, g *WithT, bc *mockBackendClient, substrings ...string) {
	t.Helper()

	ensureV1CRD(t, ctx)
	fakeAPIReg := startController(t, ctx, bc, nil)
	createMigrationCR(t, ctx)

	g.Eventually(func(g Gomega) {
		dm := &DatastoreMigration{}
		g.Expect(fvRTClient.Get(ctx, dmKey, dm)).To(Succeed())
		for _, s := range substrings {
			g.Expect(dm.Status.Message).To(ContainSubstring(s))
		}
		g.Expect(dm.Status.Phase).To(BeElementOf(DatastoreMigrationPhase(""), DatastoreMigrationPhasePending))
	}, 15*time.Second, 200*time.Millisecond).Should(Succeed())

	// The block must happen before anything destructive, so the aggregated
	// APIService is still registered.
	_, err := fakeAPIReg.ApiregistrationV1().APIServices().Get(ctx, apiServiceName, metav1.GetOptions{})
	g.Expect(err).NotTo(HaveOccurred(), "APIService should not be deleted while the pre-flight check is blocking")

	// Stays blocked rather than sliding into Migrating on a later reconcile.
	g.Consistently(func() DatastoreMigrationPhase {
		dm := &DatastoreMigration{}
		if err := fvRTClient.Get(ctx, dmKey, dm); err != nil {
			return DatastoreMigrationPhaseFailed
		}
		return dm.Status.Phase
	}, 2*time.Second, 200*time.Millisecond).Should(BeElementOf(DatastoreMigrationPhase(""), DatastoreMigrationPhasePending))
}

// TestPreflight_DriftedKubeAdminOrderBlocks verifies that a kube-admin tier
// carrying an order the v3 CEL rules reject stops the migration in Pending.
func TestPreflight_DriftedKubeAdminOrderBlocks(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	bc := &mockBackendClient{
		resources: tierOnlyV1Resources(
			v1TierKVP("default", ptr.To(apiv3.DefaultTierOrder), apiv3.Deny),
			v1TierKVP("kube-admin", ptr.To(float64(42)), apiv3.Pass),
		),
		clusterInfo: mainlineV1ClusterInfo(),
	}

	expectBlockedInPending(t, ctx, g, bc, `tier "kube-admin" has order 42, expected 1000`)
}

// TestPreflight_DriftedDefaultActionBlocks verifies that a built-in tier with
// the wrong defaultAction stops the migration in Pending.
func TestPreflight_DriftedDefaultActionBlocks(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	bc := &mockBackendClient{
		resources: tierOnlyV1Resources(
			v1TierKVP("default", ptr.To(apiv3.DefaultTierOrder), apiv3.Deny),
			v1TierKVP("kube-baseline", ptr.To(apiv3.KubeBaselineTierOrder), apiv3.Deny),
		),
		clusterInfo: mainlineV1ClusterInfo(),
	}

	expectBlockedInPending(t, ctx, g, bc, `tier "kube-baseline" has defaultAction "Deny", expected "Pass"`)
}

// TestPreflight_MultipleDriftedTiersReported verifies that every offending tier
// is named in a single status message so the user can fix them in one pass.
func TestPreflight_MultipleDriftedTiersReported(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	bc := &mockBackendClient{
		resources: tierOnlyV1Resources(
			v1TierKVP("default", ptr.To(apiv3.DefaultTierOrder), apiv3.Pass),
			v1TierKVP("kube-admin", ptr.To(float64(42)), apiv3.Deny),
			v1TierKVP("kube-baseline", nil, apiv3.Pass),
		),
		clusterInfo: mainlineV1ClusterInfo(),
	}

	expectBlockedInPending(t, ctx, g, bc,
		`tier "default" has defaultAction "Pass", expected "Deny"`,
		`tier "kube-admin" has order 42, expected 1000`,
		`tier "kube-admin" has defaultAction "Deny", expected "Pass"`,
		`tier "kube-baseline" has no order, expected 10000000`,
	)
}

// TestPreflight_DriftedDefaultTierOrderBlocks verifies that the default tier is
// held to the same standard as the other built-ins.
func TestPreflight_DriftedDefaultTierOrderBlocks(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	bc := &mockBackendClient{
		resources: tierOnlyV1Resources(
			v1TierKVP("default", ptr.To(float64(42)), apiv3.Deny),
		),
		clusterInfo: mainlineV1ClusterInfo(),
	}

	expectBlockedInPending(t, ctx, g, bc, `tier "default" has order 42, expected 1000000`)
}

// TestPreflight_ConformantBuiltInTiersProceed verifies that conformant built-in
// tiers migrate as before.
func TestPreflight_ConformantBuiltInTiersProceed(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	h := newFVHelper(t, g, ctx)

	bc := &mockBackendClient{
		resources:   tierOnlyV1Resources(conformantBuiltInTiers()...),
		clusterInfo: mainlineV1ClusterInfo(),
	}

	ensureV1CRD(t, ctx)
	startController(t, ctx, bc, nil)
	createMigrationCR(t, ctx)

	g.Eventually(func(g Gomega) {
		fvh := newFVHelper(t, g, ctx)
		fvh.expectPhase(DatastoreMigrationPhaseConverged)
	}, 30*time.Second, 200*time.Millisecond).Should(Succeed())

	for _, name := range []string{"default", "kube-admin", "kube-baseline"} {
		tier := &apiv3.Tier{}
		h.getV3Resource(name, tier)
	}
}
