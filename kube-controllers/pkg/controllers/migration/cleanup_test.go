// Copyright (c) 2026 Tigera, Inc. All rights reserved.
package migration

import (
	"slices"
	"testing"

	"github.com/sirupsen/logrus"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	rtclient "sigs.k8s.io/controller-runtime/pkg/client"

	migrationv1 "github.com/projectcalico/calico/kube-controllers/pkg/apis/migration/v1"
)

// terminatingCRDObj returns a v1 CRD that the API server has accepted for deletion but
// whose cleanup finalizer has not finished.
func terminatingCRDObj(name string) *unstructured.Unstructured {
	crd := crdObj(name, "crd.projectcalico.org")
	now := metav1.Now()
	crd.SetDeletionTimestamp(&now)
	return crd
}

// finalizingMigration returns a Complete migration that is being deleted, so the
// controller runs the completed-cleanup path.
func finalizingMigration() *migrationv1.DatastoreMigration {
	now := metav1.Now()
	return &migrationv1.DatastoreMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:              defaultMigrationName,
			Finalizers:        []string{finalizerName},
			DeletionTimestamp: &now,
		},
		Status: migrationv1.DatastoreMigrationStatus{Phase: migrationv1.DatastoreMigrationPhaseComplete},
	}
}

// TestCompletedCleanup_KeepsFinalizerWhileCRDsTerminate checks that the migration CR is held
// until the v1 CRDs are gone, not released while they are still terminating.
func TestCompletedCleanup_KeepsFinalizerWhileCRDsTerminate(t *testing.T) {
	dm := finalizingMigration()
	m, rt := newFakeController(t, []rtclient.Object{dm}, []*unstructured.Unstructured{
		terminatingCRDObj("felixconfigurations.crd.projectcalico.org"),
	})

	err := m.handleCompletedCleanup(logrus.NewEntry(logrus.StandardLogger()), dm)
	if err == nil {
		t.Fatal("expected an error so the item is requeued while the CRD is still terminating")
	}

	got := &migrationv1.DatastoreMigration{}
	if err := rt.Get(m.ctx, rtclient.ObjectKeyFromObject(dm), got); err != nil {
		t.Fatalf("getting migration: %v", err)
	}
	if !slices.Contains(got.Finalizers, finalizerName) {
		t.Errorf("finalizer was removed while a v1 CRD was still terminating, finalizers=%v", got.Finalizers)
	}
}

// TestCompletedCleanup_RemovesFinalizerWhenCRDsGone checks the finalizer is released once
// no crd.projectcalico.org CRDs remain.
func TestCompletedCleanup_RemovesFinalizerWhenCRDsGone(t *testing.T) {
	dm := finalizingMigration()
	m, rt := newFakeController(t, []rtclient.Object{dm}, []*unstructured.Unstructured{
		crdObj("installations.operator.tigera.io", "operator.tigera.io"),
	})

	if err := m.handleCompletedCleanup(logrus.NewEntry(logrus.StandardLogger()), dm); err != nil {
		t.Fatalf("handleCompletedCleanup: %v", err)
	}

	// Removing the last finalizer on an object that is being deleted completes the deletion.
	got := &migrationv1.DatastoreMigration{}
	err := rt.Get(m.ctx, rtclient.ObjectKeyFromObject(dm), got)
	if err == nil {
		t.Fatalf("migration still present with finalizers=%v, want it released", got.Finalizers)
	}
	if !kerrors.IsNotFound(err) {
		t.Fatalf("getting migration: %v", err)
	}
}
