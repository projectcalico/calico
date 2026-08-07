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
	"github.com/sirupsen/logrus"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	fakeapiregclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"
	"k8s.io/utils/ptr"
	rtclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	migrationv1 "github.com/projectcalico/calico/kube-controllers/pkg/apis/migration/v1"
)

// testScheme returns a scheme with the core, Calico v3, and migration types.
func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, apiv3.AddToScheme, migrationv1.AddToScheme} {
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
		WithStatusSubresource(&migrationv1.DatastoreMigration{}).
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

// v3ClusterInfo returns a v3 ClusterInformation with the given DatastoreReady
// value and annotations.
func v3ClusterInfo(ready bool, annotations map[string]string) *apiv3.ClusterInformation {
	return &apiv3.ClusterInformation{
		ObjectMeta: metav1.ObjectMeta{Name: clusterInfoName, Annotations: annotations},
		Spec: apiv3.ClusterInformationSpec{
			ClusterGUID:    "test-guid-12345",
			DatastoreReady: ptr.To(ready),
		},
	}
}

// v1ClusterInfo returns the v1 ClusterInformation held by the mock backend.
func v1ClusterInfo(g Gomega, m *migrationController) *apiv3.ClusterInformation {
	bc, ok := m.backendClient.(*mockBackendClient)
	g.ExpectWithOffset(1, ok).To(BeTrue(), "backend client should be the test mock")
	ci, ok := bc.clusterInfo.Value.(*apiv3.ClusterInformation)
	g.ExpectWithOffset(1, ok).To(BeTrue(), "unexpected type for v1 ClusterInformation")
	return ci
}

// getV3ClusterInfo reads the v3 ClusterInformation from the datastore.
func getV3ClusterInfo(g Gomega, rt rtclient.Client) *apiv3.ClusterInformation {
	ci := &apiv3.ClusterInformation{}
	g.ExpectWithOffset(1, rt.Get(context.Background(), types.NamespacedName{Name: clusterInfoName}, ci)).To(Succeed())
	return ci
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

	dm := &migrationv1.DatastoreMigration{
		ObjectMeta: metav1.ObjectMeta{Name: defaultMigrationName, UID: "second-migration"},
		Spec:       migrationv1.DatastoreMigrationSpec{Type: migrationv1.DatastoreMigrationTypeAPIServerToCRDs},
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
	g.Expect(m.handleTerminalError(err)).To(Succeed())

	failed := &migrationv1.DatastoreMigration{}
	g.Expect(rt.Get(ctx, dmKey, failed)).To(Succeed())
	g.Expect(failed.Status.Phase).To(Equal(migrationv1.DatastoreMigrationPhaseFailed))
	g.Expect(hasFinalizer(failed)).To(BeFalse(), "a CR that cannot migrate must not carry the finalizer")

	// Tidying up the failed CR must not touch the migrated data.
	g.Expect(rt.Delete(ctx, failed)).To(Succeed())
	g.Expect(m.reconcile()).To(Succeed())
	g.Expect(kerrors.IsNotFound(rt.Get(ctx, dmKey, &migrationv1.DatastoreMigration{}))).To(BeTrue())
	g.Expect(tierNames(g, rt)).To(ConsistOf("default", "security"))
}

// TestAbortSkipsCleanupBeforeMigrationStarts verifies that aborting before the
// Migrating phase deletes no v3 resources.
func TestAbortSkipsCleanupBeforeMigrationStarts(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	dm := &migrationv1.DatastoreMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:       defaultMigrationName,
			UID:        "migration-a",
			Finalizers: []string{finalizerName},
		},
		Spec:   migrationv1.DatastoreMigrationSpec{Type: migrationv1.DatastoreMigrationTypeAPIServerToCRDs},
		Status: migrationv1.DatastoreMigrationStatus{Phase: migrationv1.DatastoreMigrationPhasePending},
	}
	objects := []rtclient.Object{dm, migratedTier("security", "migration-a")}
	m, rt := newFakeController(t, objects, []*unstructured.Unstructured{
		crdObj("tiers.crd.projectcalico.org", "crd.projectcalico.org"),
	})

	// StartedAt is only set on the transition into Migrating, so it is nil here.
	g.Expect(dm.Status.StartedAt).To(BeNil())
	g.Expect(rt.Delete(ctx, dm)).To(Succeed())
	g.Expect(m.reconcile()).To(Succeed())

	g.Expect(kerrors.IsNotFound(rt.Get(ctx, dmKey, &migrationv1.DatastoreMigration{}))).To(BeTrue(), "finalizer should have been removed")
	g.Expect(tierNames(g, rt)).To(ConsistOf("security"))
}

// TestAbortBeforeMigrationStartsLeavesClusterInfoAlone verifies that aborting
// before the Migrating phase writes to neither ClusterInformation of an
// already-migrated cluster.
func TestAbortBeforeMigrationStartsLeavesClusterInfoAlone(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	dm := &migrationv1.DatastoreMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:       defaultMigrationName,
			UID:        "migration-b",
			Finalizers: []string{finalizerName},
		},
		Spec:   migrationv1.DatastoreMigrationSpec{Type: migrationv1.DatastoreMigrationTypeAPIServerToCRDs},
		Status: migrationv1.DatastoreMigrationStatus{Phase: migrationv1.DatastoreMigrationPhasePending},
	}
	liveClusterInfo := v3ClusterInfo(true, map[string]string{migratedByAnnotation: "migration-a"})
	m, rt := newFakeController(t, []rtclient.Object{dm, liveClusterInfo}, []*unstructured.Unstructured{
		crdObj("tiers.crd.projectcalico.org", "crd.projectcalico.org"),
	})
	v1ClusterInfo(g, m).Spec.DatastoreReady = ptr.To(false)

	g.Expect(dm.Status.StartedAt).To(BeNil())
	g.Expect(rt.Delete(ctx, dm)).To(Succeed())
	g.Expect(m.reconcile()).To(Succeed())

	g.Expect(kerrors.IsNotFound(rt.Get(ctx, dmKey, &migrationv1.DatastoreMigration{}))).To(BeTrue(), "finalizer should have been removed")
	g.Expect(v1ClusterInfo(g, m).Spec.DatastoreReady).To(Equal(ptr.To(false)))

	v3CI := getV3ClusterInfo(g, rt)
	g.Expect(v3CI.Spec.DatastoreReady).To(Equal(ptr.To(true)))
	g.Expect(v3CI.Annotations).To(HaveKeyWithValue(migratedByAnnotation, "migration-a"))
}

// TestAbortDeletesClusterInfoItCreated verifies that abort deletes the v3
// ClusterInformation this migration created and unlocks the v1 one.
func TestAbortDeletesClusterInfoItCreated(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	startedAt := metav1.Now()
	dm := &migrationv1.DatastoreMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:       defaultMigrationName,
			UID:        "migration-c",
			Finalizers: []string{finalizerName},
		},
		Spec: migrationv1.DatastoreMigrationSpec{Type: migrationv1.DatastoreMigrationTypeAPIServerToCRDs},
		Status: migrationv1.DatastoreMigrationStatus{
			Phase:     migrationv1.DatastoreMigrationPhaseMigrating,
			StartedAt: &startedAt,
		},
	}
	created := v3ClusterInfo(false, map[string]string{migratedByAnnotation: "migration-c"})
	m, rt := newFakeController(t, []rtclient.Object{dm, created}, []*unstructured.Unstructured{
		crdObj("tiers.crd.projectcalico.org", "crd.projectcalico.org"),
	})
	v1ClusterInfo(g, m).Spec.DatastoreReady = ptr.To(false)

	g.Expect(rt.Delete(ctx, dm)).To(Succeed())
	g.Expect(m.reconcile()).To(Succeed())

	err := rt.Get(ctx, types.NamespacedName{Name: clusterInfoName}, &apiv3.ClusterInformation{})
	g.Expect(kerrors.IsNotFound(err)).To(BeTrue(), "v3 ClusterInformation should have been deleted, got: %v", err)
	g.Expect(v1ClusterInfo(g, m).Spec.DatastoreReady).To(Equal(ptr.To(true)))
}

// TestAbortUnlocksClusterInfoItLocked verifies that abort restores, rather than
// deletes, a v3 ClusterInformation that pre-dated the migration.
func TestAbortUnlocksClusterInfoItLocked(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	startedAt := metav1.Now()
	dm := &migrationv1.DatastoreMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:       defaultMigrationName,
			UID:        "migration-d",
			Finalizers: []string{finalizerName},
		},
		Spec: migrationv1.DatastoreMigrationSpec{Type: migrationv1.DatastoreMigrationTypeAPIServerToCRDs},
		Status: migrationv1.DatastoreMigrationStatus{
			Phase:     migrationv1.DatastoreMigrationPhaseMigrating,
			StartedAt: &startedAt,
		},
	}
	locked := v3ClusterInfo(false, map[string]string{
		migratedByAnnotation: "migration-a",
		lockedByAnnotation:   "migration-d",
	})
	m, rt := newFakeController(t, []rtclient.Object{dm, locked}, []*unstructured.Unstructured{
		crdObj("tiers.crd.projectcalico.org", "crd.projectcalico.org"),
	})

	g.Expect(rt.Delete(ctx, dm)).To(Succeed())
	g.Expect(m.reconcile()).To(Succeed())

	v3CI := getV3ClusterInfo(g, rt)
	g.Expect(v3CI.Spec.DatastoreReady).To(Equal(ptr.To(true)))
	g.Expect(v3CI.Annotations).NotTo(HaveKey(lockedByAnnotation))
	g.Expect(v3CI.Annotations).To(HaveKeyWithValue(migratedByAnnotation, "migration-a"))
}

// TestLockDatastoreMarksClusterInfo verifies that locking records whether the
// migration created the v3 ClusterInformation or only locked an existing one.
func TestLockDatastoreMarksClusterInfo(t *testing.T) {
	g := NewWithT(t)
	logCtx := logrus.WithField("test", t.Name())

	dm := &migrationv1.DatastoreMigration{
		ObjectMeta: metav1.ObjectMeta{Name: defaultMigrationName, UID: "migration-e"},
		Spec:       migrationv1.DatastoreMigrationSpec{Type: migrationv1.DatastoreMigrationTypeAPIServerToCRDs},
	}
	crds := []*unstructured.Unstructured{crdObj("tiers.crd.projectcalico.org", "crd.projectcalico.org")}

	m, rt := newFakeController(t, []rtclient.Object{dm}, crds)
	g.Expect(m.lockDatastore(logCtx, dm)).To(Succeed())

	created := getV3ClusterInfo(g, rt)
	g.Expect(created.Spec.DatastoreReady).To(Equal(ptr.To(false)))
	g.Expect(created.Spec.ClusterGUID).To(Equal("test-guid-12345"), "spec should be copied from the v1 resource")
	g.Expect(created.Annotations).To(HaveKeyWithValue(migratedByAnnotation, "migration-e"))
	g.Expect(created.Annotations).NotTo(HaveKey(lockedByAnnotation))

	m, rt = newFakeController(t, []rtclient.Object{dm, v3ClusterInfo(true, nil)}, crds)
	g.Expect(m.lockDatastore(logCtx, dm)).To(Succeed())

	existing := getV3ClusterInfo(g, rt)
	g.Expect(existing.Spec.DatastoreReady).To(Equal(ptr.To(false)))
	g.Expect(existing.Annotations).To(HaveKeyWithValue(lockedByAnnotation, "migration-e"))
	g.Expect(existing.Annotations).NotTo(HaveKey(migratedByAnnotation))
}

// TestAbortOnlyDeletesOwnResources verifies that abort deletes only the v3
// resources this migration created.
func TestAbortOnlyDeletesOwnResources(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	startedAt := metav1.Now()
	dm := &migrationv1.DatastoreMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:       defaultMigrationName,
			UID:        "migration-b",
			Finalizers: []string{finalizerName},
		},
		Spec: migrationv1.DatastoreMigrationSpec{Type: migrationv1.DatastoreMigrationTypeAPIServerToCRDs},
		Status: migrationv1.DatastoreMigrationStatus{
			Phase:     migrationv1.DatastoreMigrationPhaseMigrating,
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

	g.Expect(kerrors.IsNotFound(rt.Get(ctx, dmKey, &migrationv1.DatastoreMigration{}))).To(BeTrue(), "finalizer should have been removed")
	g.Expect(tierNames(g, rt)).To(ConsistOf("from-earlier-run", "user-created"))
}
