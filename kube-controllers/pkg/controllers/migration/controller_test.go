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
	"testing"

	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	fakeapiregclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"
	"k8s.io/utils/ptr"
	rtclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// testScheme returns a scheme with the core, Calico v3, and migration types.
func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, apiv3.AddToScheme, AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatalf("building scheme: %v", err)
		}
	}
	return scheme
}

// crdObj returns an unstructured CustomResourceDefinition in the given group.
func crdObj(name, group string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "apiextensions.k8s.io/v1",
			"kind":       "CustomResourceDefinition",
			"metadata":   map[string]any{"name": name},
			"spec":       map[string]any{"group": group},
		},
	}
}

// newFakeController builds a migration controller backed entirely by fake
// clients. crds seeds the CRD list that the v1 pre-check reads.
func newFakeController(
	t *testing.T,
	objects []rtclient.Object,
	crds []*unstructured.Unstructured,
) (*migrationController, rtclient.Client) {
	t.Helper()
	scheme := testScheme(t)

	rt := ctrlfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		WithStatusSubresource(&DatastoreMigration{}).
		Build()

	crdObjects := make([]runtime.Object, 0, len(crds))
	for _, crd := range crds {
		crdObjects = append(crdObjects, crd)
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{crdGVR: "CustomResourceDefinitionList"},
		crdObjects...,
	)

	bc := &mockBackendClient{
		resources:   mainlineV1Resources(),
		clusterInfo: mainlineV1ClusterInfo(),
	}

	return &migrationController{
		ctx:           context.Background(),
		k8sClient:     k8sfake.NewSimpleClientset(),
		backendClient: bc,
		rtClient:      rt,
		dynamicClient: dyn,
		apiregClient:  fakeapiregclient.NewSimpleClientset().ApiregistrationV1(),
		migrators:     NewMigrators(bc, rt),
	}, rt
}

// migratedTier returns a v3 Tier annotated as created by the given migration.
func migratedTier(name, migrationID string) *apiv3.Tier {
	tier := &apiv3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       apiv3.TierSpec{Order: ptr.To(float64(200)), DefaultAction: actionPtr(apiv3.Deny)},
	}
	if migrationID != "" {
		tier.Annotations = map[string]string{migratedByAnnotation: migrationID}
	}
	return tier
}

// tierNames lists the names of all v3 Tiers currently in the datastore.
func tierNames(g Gomega, rt rtclient.Client) []string {
	list := &apiv3.TierList{}
	g.ExpectWithOffset(1, rt.List(context.Background(), list)).To(Succeed())
	names := make([]string, 0, len(list.Items))
	for _, tier := range list.Items {
		names = append(names, tier.Name)
	}
	return names
}

// TestAbortOnMigratedCluster verifies that creating and deleting a CR on an
// already-migrated cluster leaves the migrated data alone.
func TestAbortOnMigratedCluster(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	dm := &DatastoreMigration{
		ObjectMeta: metav1.ObjectMeta{Name: defaultMigrationName, UID: "second-migration"},
		Spec:       DatastoreMigrationSpec{Type: DatastoreMigrationTypeAPIServerToCRDs},
	}
	objects := []rtclient.Object{
		dm,
		migratedTier("default", "first-migration"),
		migratedTier("security", "first-migration"),
	}

	// Only v3 CRDs remain: the first migration deleted the v1 ones.
	m, rt := newFakeController(t, objects, []*unstructured.Unstructured{
		crdObj("tiers.projectcalico.org", "projectcalico.org"),
	})

	err := m.reconcile()
	g.Expect(err).To(HaveOccurred())
	g.Expect(isTerminal(err)).To(BeTrue(), "expected a terminal error, got %v", err)
	m.handleTerminalError(err)

	failed := &DatastoreMigration{}
	g.Expect(rt.Get(ctx, dmKey, failed)).To(Succeed())
	g.Expect(failed.Status.Phase).To(Equal(DatastoreMigrationPhaseFailed))
	g.Expect(hasFinalizer(failed)).To(BeFalse(), "a CR that cannot migrate must not carry the finalizer")

	// Tidying up the failed CR must not touch the migrated data.
	g.Expect(rt.Delete(ctx, failed)).To(Succeed())
	g.Expect(m.reconcile()).To(Succeed())
	g.Expect(kerrors.IsNotFound(rt.Get(ctx, dmKey, &DatastoreMigration{}))).To(BeTrue())
	g.Expect(tierNames(g, rt)).To(ConsistOf("default", "security"))
}

// TestAbortSkipsCleanupBeforeMigrationStarts verifies that aborting before the
// Migrating phase deletes no v3 resources.
func TestAbortSkipsCleanupBeforeMigrationStarts(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	dm := &DatastoreMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:       defaultMigrationName,
			UID:        "migration-a",
			Finalizers: []string{finalizerName},
		},
		Spec:   DatastoreMigrationSpec{Type: DatastoreMigrationTypeAPIServerToCRDs},
		Status: DatastoreMigrationStatus{Phase: DatastoreMigrationPhasePending},
	}
	objects := []rtclient.Object{dm, migratedTier("security", "migration-a")}
	m, rt := newFakeController(t, objects, []*unstructured.Unstructured{
		crdObj("tiers.crd.projectcalico.org", "crd.projectcalico.org"),
	})

	// StartedAt is only set on the transition into Migrating, so it is nil here.
	g.Expect(dm.Status.StartedAt).To(BeNil())
	g.Expect(rt.Delete(ctx, dm)).To(Succeed())
	g.Expect(m.reconcile()).To(Succeed())

	g.Expect(kerrors.IsNotFound(rt.Get(ctx, dmKey, &DatastoreMigration{}))).To(BeTrue(), "finalizer should have been removed")
	g.Expect(tierNames(g, rt)).To(ConsistOf("security"))
}

// TestAbortOnlyDeletesOwnResources verifies that abort deletes only the v3
// resources this migration created.
func TestAbortOnlyDeletesOwnResources(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	startedAt := metav1.Now()
	dm := &DatastoreMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:       defaultMigrationName,
			UID:        "migration-b",
			Finalizers: []string{finalizerName},
		},
		Spec: DatastoreMigrationSpec{Type: DatastoreMigrationTypeAPIServerToCRDs},
		Status: DatastoreMigrationStatus{
			Phase:     DatastoreMigrationPhaseMigrating,
			StartedAt: &startedAt,
		},
	}
	objects := []rtclient.Object{
		dm,
		migratedTier("from-earlier-run", "migration-a"),
		migratedTier("from-this-run", "migration-b"),
		migratedTier("user-created", ""),
	}
	m, rt := newFakeController(t, objects, []*unstructured.Unstructured{
		crdObj("tiers.crd.projectcalico.org", "crd.projectcalico.org"),
	})

	g.Expect(rt.Delete(ctx, dm)).To(Succeed())
	g.Expect(m.reconcile()).To(Succeed())

	g.Expect(kerrors.IsNotFound(rt.Get(ctx, dmKey, &DatastoreMigration{}))).To(BeTrue(), "finalizer should have been removed")
	g.Expect(tierNames(g, rt)).To(ConsistOf("from-earlier-run", "user-created"))
}
