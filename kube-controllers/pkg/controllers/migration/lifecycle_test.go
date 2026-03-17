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
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	rtclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// withTestRegistry temporarily installs the given migrators in the global
// registry for the duration of the test, restoring the original on cleanup.
func withTestRegistry(t *testing.T, migrators []ResourceMigrator) {
	t.Helper()
	registryMu.Lock()
	saved := registry
	registry = migrators
	registryMu.Unlock()
	t.Cleanup(func() {
		registryMu.Lock()
		registry = saved
		registryMu.Unlock()
	})
}

// tierMigrator creates a test ResourceMigrator for Tiers that uses the controller's rtClient.
func tierMigrator() ResourceMigrator {
	return ResourceMigrator{
		Kind:         apiv3.KindTier,
		Order:        OrderTiers,
		V3Object:     func() rtclient.Object { return &apiv3.Tier{} },
		V3ObjectList: func() rtclient.ObjectList { return &apiv3.TierList{} },
		GetSpec:      func(obj rtclient.Object) any { return obj.(*apiv3.Tier).Spec },
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindTier)
		},
		Convert: func(kvp *model.KVPair) (rtclient.Object, error) {
			v1 := kvp.Value.(*apiv3.Tier)
			v3 := &apiv3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	}
}

// gnpMigrator creates a test ResourceMigrator for GlobalNetworkPolicies.
func gnpMigrator() ResourceMigrator {
	return ResourceMigrator{
		Kind:         apiv3.KindGlobalNetworkPolicy,
		Order:        OrderPolicy,
		V3Object:     func() rtclient.Object { return &apiv3.GlobalNetworkPolicy{} },
		V3ObjectList: func() rtclient.ObjectList { return &apiv3.GlobalNetworkPolicyList{} },
		GetSpec:      func(obj rtclient.Object) any { return obj.(*apiv3.GlobalNetworkPolicy).Spec },
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindGlobalNetworkPolicy)
		},
		Convert: func(kvp *model.KVPair) (rtclient.Object, error) {
			v1 := kvp.Value.(*apiv3.GlobalNetworkPolicy)
			v3Name := migratedPolicyName(v1.Name, v1.Spec.Tier)
			v3 := &apiv3.GlobalNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: v3Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	}
}

// getFromRT is a helper to read a v3 object from the rtClient in tests.
func getFromRT(t *testing.T, c *migrationController, obj rtclient.Object, name string) {
	t.Helper()
	if err := c.rtClient.Get(c.ctx, types.NamespacedName{Name: name}, obj); err != nil {
		t.Fatalf("getting %T %s from rtClient: %v", obj, name, err)
	}
}

// createAggregatedAPIService creates an aggregated (non-automanaged) APIService in the controller's fake apiregistration client.
func createAggregatedAPIService(t *testing.T, c *migrationController) {
	t.Helper()
	apiSvc := &apiregv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			Name: apiServiceName,
		},
		Spec: apiregv1.APIServiceSpec{
			Group:                "projectcalico.org",
			Version:              "v3",
			GroupPriorityMinimum: 1500,
			VersionPriority:      200,
			Service: &apiregv1.ServiceReference{
				Namespace: "calico-apiserver",
				Name:      "calico-api",
			},
		},
	}
	if _, err := c.apiregClient.APIServices().Create(c.ctx, apiSvc, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating test APIService: %v", err)
	}
}

// TestLifecycle_FullMigration exercises the complete happy-path lifecycle:
// Pending → (add finalizer) → (pre-validate) → Migrating → Converged → Complete,
// with actual resource types registered and migrated.
func TestLifecycle_FullMigration(t *testing.T) {
	withTestRegistry(t, []ResourceMigrator{
		tierMigrator(),
		gnpMigrator(),
	})

	tierUID := types.UID("v1-tier-security-uid")
	cr := createTestCR(t, defaultMigrationName, "")
	v1CRD := createV1CRD("tiers.crd.projectcalico.org")
	c, _ := testController(t, cr, v1CRD)

	// Set up v1 resources in the mock backend.
	bc := c.backendClient.(*mockBackendClient)
	bc.resources = map[string][]*model.KVPair{
		apiv3.KindTier: {
			{
				Key: model.ResourceKey{Kind: apiv3.KindTier, Name: "default"},
				Value: &apiv3.Tier{
					ObjectMeta: metav1.ObjectMeta{Name: "default", UID: "v1-tier-default-uid"},
					Spec:       apiv3.TierSpec{Order: floatPtr(100)},
				},
			},
			{
				Key: model.ResourceKey{Kind: apiv3.KindTier, Name: "security"},
				Value: &apiv3.Tier{
					ObjectMeta: metav1.ObjectMeta{Name: "security", UID: tierUID},
					Spec:       apiv3.TierSpec{Order: floatPtr(200)},
				},
			},
		},
		apiv3.KindGlobalNetworkPolicy: {
			{
				Key: model.ResourceKey{Kind: apiv3.KindGlobalNetworkPolicy, Name: "default.test-deny-all"},
				Value: &apiv3.GlobalNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "default.test-deny-all",
						UID:  "v1-gnp-deny-all-uid",
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: "projectcalico.org/v3",
								Kind:       "Tier",
								Name:       "security",
								UID:        tierUID,
							},
						},
					},
					Spec: apiv3.GlobalNetworkPolicySpec{Tier: "default"},
				},
			},
			{
				Key: model.ResourceKey{Kind: apiv3.KindGlobalNetworkPolicy, Name: "security.test-allow-dns"},
				Value: &apiv3.GlobalNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "security.test-allow-dns", UID: "v1-gnp-allow-dns-uid"},
					Spec:       apiv3.GlobalNetworkPolicySpec{Tier: "security"},
				},
			},
		},
	}

	// Set up v1 ClusterInformation.
	ready := true
	bc.clusterInfo = &model.KVPair{
		Key: model.ResourceKey{Kind: apiv3.KindClusterInformation, Name: clusterInfoName},
		Value: &apiv3.ClusterInformation{
			ObjectMeta: metav1.ObjectMeta{Name: clusterInfoName},
			Spec:       apiv3.ClusterInformationSpec{DatastoreReady: &ready},
		},
		Revision: "1",
	}

	// Create an aggregated APIService (required for pre-validation).
	createAggregatedAPIService(t, c)

	// Reconcile 1: handlePending adds finalizer, pre-validates, transitions to Migrating.
	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile 1 (Pending → Migrating): %v", err)
	}
	dm, err := c.migClient.Get(c.ctx, defaultMigrationName)
	if err != nil {
		t.Fatalf("getting CR after reconcile 1: %v", err)
	}
	if !hasFinalizer(dm) {
		t.Fatal("expected finalizer after reconcile 1")
	}
	if dm.Status.Phase != DatastoreMigrationPhaseMigrating {
		t.Fatalf("expected Migrating after reconcile 1, got %s", dm.Status.Phase)
	}
	if dm.Status.StartedAt == nil {
		t.Error("expected StartedAt to be set")
	}

	// Reconcile 2: runs migration, transitions to Converged.
	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile 2 (Migrating → Converged): %v", err)
	}
	dm, err = c.migClient.Get(c.ctx, defaultMigrationName)
	if err != nil {
		t.Fatalf("getting CR after reconcile 2: %v", err)
	}
	if dm.Status.Phase != DatastoreMigrationPhaseConverged {
		t.Fatalf("expected Converged after reconcile 2, got %s", dm.Status.Phase)
	}

	// Verify progress tracking.
	if dm.Status.Progress.TotalTypes != 2 {
		t.Errorf("expected 2 total types, got %d", dm.Status.Progress.TotalTypes)
	}
	if dm.Status.Progress.CompletedTypes != 2 {
		t.Errorf("expected 2 completed types, got %d", dm.Status.Progress.CompletedTypes)
	}
	if dm.Status.Progress.Migrated != 4 {
		t.Errorf("expected 4 migrated resources (2 tiers + 2 GNPs), got %d", dm.Status.Progress.Migrated)
	}
	if len(dm.Status.Progress.TypeDetails) != 2 {
		t.Errorf("expected 2 type details, got %d", len(dm.Status.Progress.TypeDetails))
	}

	// Verify tiers were migrated.
	tierDefault := &apiv3.Tier{}
	if getErr := c.rtClient.Get(c.ctx, types.NamespacedName{Name: "default"}, tierDefault); getErr != nil {
		t.Error("tier 'default' not found in v3 store")
	}
	tierSecurity := &apiv3.Tier{}
	if getErr := c.rtClient.Get(c.ctx, types.NamespacedName{Name: "security"}, tierSecurity); getErr != nil {
		t.Error("tier 'security' not found in v3 store")
	}

	// Verify GNP names: default.test-deny-all → test-deny-all (prefix stripped).
	gnpDeny := &apiv3.GlobalNetworkPolicy{}
	if getErr := c.rtClient.Get(c.ctx, types.NamespacedName{Name: "test-deny-all"}, gnpDeny); getErr != nil {
		t.Error("GNP 'test-deny-all' not found (expected default. prefix stripped)")
	}
	// Non-default tier policy keeps its name.
	gnpAllow := &apiv3.GlobalNetworkPolicy{}
	if getErr := c.rtClient.Get(c.ctx, types.NamespacedName{Name: "security.test-allow-dns"}, gnpAllow); getErr != nil {
		t.Error("GNP 'security.test-allow-dns' not found")
	}

	// Verify OwnerRef remapping: the GNP that had an ownerRef to the v1 security
	// tier should now point to the v3 UID.
	ownerRefs := gnpDeny.GetOwnerReferences()
	if len(ownerRefs) != 1 {
		t.Fatalf("expected 1 ownerRef on GNP, got %d", len(ownerRefs))
	}
	v3TierUID := tierSecurity.GetUID()
	if ownerRefs[0].UID != v3TierUID {
		t.Errorf("expected GNP ownerRef UID to be remapped to v3 tier UID %s, got %s", v3TierUID, ownerRefs[0].UID)
	}

	// Verify v3 ClusterInformation was unlocked.
	v3ci := &apiv3.ClusterInformation{}
	if getErr := c.rtClient.Get(c.ctx, types.NamespacedName{Name: clusterInfoName}, v3ci); getErr != nil {
		t.Fatalf("getting v3 ClusterInformation: %v", getErr)
	}
	if v3ci.Spec.DatastoreReady == nil || !*v3ci.Spec.DatastoreReady {
		t.Error("expected v3 ClusterInformation DatastoreReady=true after Converged")
	}

	// Verify APIService was deleted (or replaced by automanaged).
	_, err = c.apiregClient.APIServices().Get(c.ctx, apiServiceName, metav1.GetOptions{})
	if err == nil {
		t.Error("expected APIService to be deleted after migration")
	} else if !kerrors.IsNotFound(err) {
		t.Errorf("unexpected error checking APIService: %v", err)
	}

	// Verify saved APIService annotation was set on the CR.
	if dm.Annotations == nil || dm.Annotations[savedAPIServiceAnnotation] == "" {
		t.Error("expected saved APIService annotation on CR")
	}

	// Simulate the operator rolling out calico-node with the v3 API group env var.
	createReadyCalicoNodeDS(t, c)

	// Reconcile 3: transitions from Converged to Complete.
	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile 3 (Converged → Complete): %v", err)
	}
	dm, err = c.migClient.Get(c.ctx, defaultMigrationName)
	if err != nil {
		t.Fatalf("getting CR after reconcile 3: %v", err)
	}
	if dm.Status.Phase != DatastoreMigrationPhaseComplete {
		t.Fatalf("expected Complete after reconcile 3, got %s", dm.Status.Phase)
	}
	if dm.Status.CompletedAt == nil {
		t.Error("expected CompletedAt to be set")
	}

	// Reconcile 4: Complete is a no-op.
	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile 4 (Complete no-op): %v", err)
	}
}

// TestLifecycle_APIServiceSaveRestore verifies that the APIService is saved to
// an annotation during migration and can be restored on abort.
func TestLifecycle_APIServiceSaveRestore(t *testing.T) {
	withTestRegistry(t, nil)

	cr := createTestCR(t, defaultMigrationName, DatastoreMigrationPhaseMigrating)
	v1CRD := createV1CRD("tiers.crd.projectcalico.org")
	c, _ := testController(t, cr, v1CRD)

	bc := c.backendClient.(*mockBackendClient)
	ready := true
	bc.clusterInfo = &model.KVPair{
		Key: model.ResourceKey{Kind: apiv3.KindClusterInformation, Name: clusterInfoName},
		Value: &apiv3.ClusterInformation{
			ObjectMeta: metav1.ObjectMeta{Name: clusterInfoName},
			Spec:       apiv3.ClusterInformationSpec{DatastoreReady: &ready},
		},
		Revision: "1",
	}

	// Create an aggregated APIService.
	createAggregatedAPIService(t, c)

	// Run migration reconcile — should save and delete the APIService.
	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile (Migrating): %v", err)
	}

	// Verify APIService is gone.
	_, err := c.apiregClient.APIServices().Get(c.ctx, apiServiceName, metav1.GetOptions{})
	if !kerrors.IsNotFound(err) {
		t.Fatalf("expected APIService to be deleted, got err: %v", err)
	}

	// Verify annotation was saved.
	dm, err := c.migClient.Get(c.ctx, defaultMigrationName)
	if err != nil {
		t.Fatalf("getting CR: %v", err)
	}
	savedData := dm.Annotations[savedAPIServiceAnnotation]
	if savedData == "" {
		t.Fatal("expected saved APIService annotation")
	}

	// Verify the saved data deserializes correctly.
	apiSvc := &apiregv1.APIService{}
	if err := json.Unmarshal([]byte(savedData), apiSvc); err != nil {
		t.Fatalf("deserializing saved APIService: %v", err)
	}
	if apiSvc.Spec.Service == nil || apiSvc.Spec.Service.Name != "calico-api" {
		t.Errorf("expected saved APIService to have service calico-api, got %v", apiSvc.Spec.Service)
	}
	if apiSvc.ResourceVersion != "" {
		t.Error("expected saved APIService to have ResourceVersion cleared")
	}
	if apiSvc.UID != "" {
		t.Error("expected saved APIService to have UID cleared")
	}

	// Now simulate abort: create a deletion-marked CR with the saved annotation.
	crAbort := createTestCRWithDeletion(t, defaultMigrationName, DatastoreMigrationPhaseMigrating)
	crAbort.Object["metadata"].(map[string]interface{})["annotations"] = map[string]interface{}{
		savedAPIServiceAnnotation: savedData,
	}

	cAbort, _ := testController(t, crAbort)
	bcAbort := cAbort.backendClient.(*mockBackendClient)
	readyFalse := false
	bcAbort.clusterInfo = &model.KVPair{
		Key: model.ResourceKey{Kind: apiv3.KindClusterInformation, Name: clusterInfoName},
		Value: &apiv3.ClusterInformation{
			ObjectMeta: metav1.ObjectMeta{Name: clusterInfoName},
			Spec:       apiv3.ClusterInformationSpec{DatastoreReady: &readyFalse},
		},
		Revision: "1",
	}

	// Reconcile the abort.
	if err := cAbort.reconcile(); err != nil {
		t.Fatalf("reconcile (abort): %v", err)
	}

	// Verify APIService was restored.
	restored, err := cAbort.apiregClient.APIServices().Get(cAbort.ctx, apiServiceName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected restored APIService, got: %v", err)
	}
	if restored.Spec.Service == nil || restored.Spec.Service.Name != "calico-api" {
		t.Errorf("restored APIService has wrong service: %v", restored.Spec.Service)
	}

	// Verify v1 ClusterInformation was restored to ready.
	ci := bcAbort.clusterInfo.Value.(*apiv3.ClusterInformation)
	if ci.Spec.DatastoreReady == nil || !*ci.Spec.DatastoreReady {
		t.Error("expected v1 ClusterInformation DatastoreReady=true after abort")
	}
}

// TestLifecycle_AbortCleansUpPartialV3Resources verifies that aborting a
// migration deletes any v3 resources that were partially created.
func TestLifecycle_AbortCleansUpPartialV3Resources(t *testing.T) {
	withTestRegistry(t, []ResourceMigrator{tierMigrator()})

	cr := createTestCRWithDeletion(t, defaultMigrationName, DatastoreMigrationPhaseMigrating)
	c, _ := testController(t, cr)

	// Pre-populate the v3 store as if migration created some tiers
	// (with the migration annotation that gets stamped during create).
	if err := c.rtClient.Create(c.ctx, &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{
		Name:        "default",
		Annotations: map[string]string{migratedByAnnotation: "v1-to-v3"},
	}}); err != nil {
		t.Fatalf("creating tier: %v", err)
	}
	if err := c.rtClient.Create(c.ctx, &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{
		Name:        "security",
		Annotations: map[string]string{migratedByAnnotation: "v1-to-v3"},
	}}); err != nil {
		t.Fatalf("creating tier: %v", err)
	}

	bc := c.backendClient.(*mockBackendClient)
	ready := false
	bc.clusterInfo = &model.KVPair{
		Key: model.ResourceKey{Kind: apiv3.KindClusterInformation, Name: clusterInfoName},
		Value: &apiv3.ClusterInformation{
			ObjectMeta: metav1.ObjectMeta{Name: clusterInfoName},
			Spec:       apiv3.ClusterInformationSpec{DatastoreReady: &ready},
		},
		Revision: "1",
	}

	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile (abort): %v", err)
	}

	// Verify partial v3 resources were cleaned up.
	tierDefault := &apiv3.Tier{}
	if err := c.rtClient.Get(c.ctx, types.NamespacedName{Name: "default"}, tierDefault); !kerrors.IsNotFound(err) {
		t.Error("expected tier 'default' to be deleted during abort cleanup")
	}
	tierSecurity := &apiv3.Tier{}
	if err := c.rtClient.Get(c.ctx, types.NamespacedName{Name: "security"}, tierSecurity); !kerrors.IsNotFound(err) {
		t.Error("expected tier 'security' to be deleted during abort cleanup")
	}

	// Verify finalizer was removed.
	dm, err := c.migClient.Get(c.ctx, defaultMigrationName)
	if err != nil {
		t.Fatalf("getting CR: %v", err)
	}
	if hasFinalizer(dm) {
		t.Error("expected finalizer to be removed after abort")
	}
}

// TestLifecycle_V1CRDCleanupOnDelete verifies that deleting the CR after
// migration completes triggers deletion of v1 CRDs.
func TestLifecycle_V1CRDCleanupOnDelete(t *testing.T) {
	withTestRegistry(t, nil)

	v1CRD1 := createV1CRD("tiers.crd.projectcalico.org")
	v1CRD2 := createV1CRD("globalnetworkpolicies.crd.projectcalico.org")
	// A non-v1 CRD that should not be deleted.
	v3CRD := createV3CRD("tiers.projectcalico.org")

	cr := createTestCRWithDeletion(t, defaultMigrationName, DatastoreMigrationPhaseComplete)
	c, _ := testController(t, cr, v1CRD1, v1CRD2, v3CRD)

	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile (completed cleanup): %v", err)
	}

	// Verify v1 CRDs were deleted.
	crdClient := c.dynamicClient.Resource(crdGVR)
	crdList, err := crdClient.List(c.ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatalf("listing CRDs: %v", err)
	}

	for _, crd := range crdList.Items {
		group, _, _ := unstructured.NestedString(crd.Object, "spec", "group")
		if group == "crd.projectcalico.org" {
			t.Errorf("v1 CRD %s should have been deleted by finalizer", crd.GetName())
		}
	}

	// Verify the v3 CRD was not deleted.
	found := false
	for _, crd := range crdList.Items {
		if crd.GetName() == "tiers.projectcalico.org" {
			found = true
		}
	}
	if !found {
		t.Error("v3 CRD tiers.projectcalico.org should not have been deleted")
	}

	// Verify finalizer was removed.
	dm, err := c.migClient.Get(c.ctx, defaultMigrationName)
	if err != nil {
		t.Fatalf("getting CR: %v", err)
	}
	if hasFinalizer(dm) {
		t.Error("expected finalizer removed after completed cleanup")
	}
}

// TestLifecycle_ResumeMidMigration verifies that if the controller restarts
// while in the Migrating phase, re-reconciling picks up where it left off
// (idempotent: resources already migrated are skipped).
func TestLifecycle_ResumeMidMigration(t *testing.T) {
	withTestRegistry(t, []ResourceMigrator{tierMigrator()})

	cr := createTestCR(t, defaultMigrationName, DatastoreMigrationPhaseMigrating)
	v1CRD := createV1CRD("tiers.crd.projectcalico.org")
	c, _ := testController(t, cr, v1CRD)

	// Simulate restart: one tier was already migrated.
	if err := c.rtClient.Create(c.ctx, &apiv3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       apiv3.TierSpec{Order: floatPtr(100)},
	}); err != nil {
		t.Fatalf("pre-creating tier: %v", err)
	}

	bc := c.backendClient.(*mockBackendClient)
	bc.resources = map[string][]*model.KVPair{
		apiv3.KindTier: {
			{
				Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "default"},
				Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: apiv3.TierSpec{Order: floatPtr(100)}},
			},
			{
				Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "security"},
				Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "security"}, Spec: apiv3.TierSpec{Order: floatPtr(200)}},
			},
		},
	}
	ready := true
	bc.clusterInfo = &model.KVPair{
		Key: model.ResourceKey{Kind: apiv3.KindClusterInformation, Name: clusterInfoName},
		Value: &apiv3.ClusterInformation{
			ObjectMeta: metav1.ObjectMeta{Name: clusterInfoName},
			Spec:       apiv3.ClusterInformationSpec{DatastoreReady: &ready},
		},
		Revision: "1",
	}

	// Reconcile should skip the already-migrated tier and migrate the new one.
	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile (resume): %v", err)
	}

	dm, err := c.migClient.Get(c.ctx, defaultMigrationName)
	if err != nil {
		t.Fatalf("getting CR: %v", err)
	}
	if dm.Status.Phase != DatastoreMigrationPhaseConverged {
		t.Fatalf("expected Converged after resume, got %s", dm.Status.Phase)
	}
	if dm.Status.Progress.Migrated != 1 {
		t.Errorf("expected 1 migrated (new), got %d", dm.Status.Progress.Migrated)
	}
	if dm.Status.Progress.Skipped != 1 {
		t.Errorf("expected 1 skipped (existing), got %d", dm.Status.Progress.Skipped)
	}

	// Verify both tiers exist in the store.
	td := &apiv3.Tier{}
	if getErr := c.rtClient.Get(c.ctx, types.NamespacedName{Name: "default"}, td); getErr != nil {
		t.Error("tier 'default' not in v3 store")
	}
	ts := &apiv3.Tier{}
	if getErr := c.rtClient.Get(c.ctx, types.NamespacedName{Name: "security"}, ts); getErr != nil {
		t.Error("tier 'security' not in v3 store")
	}
}

// TestLifecycle_MigrationWithConflicts verifies the conflict resolution
// lifecycle: conflicts transition to WaitingForConflictResolution, and
// resolving them transitions back to Migrating.
func TestLifecycle_MigrationWithConflicts(t *testing.T) {
	withTestRegistry(t, []ResourceMigrator{tierMigrator()})

	cr := createTestCR(t, defaultMigrationName, DatastoreMigrationPhaseMigrating)
	c, _ := testController(t, cr)

	// Pre-populate a conflicting v3 tier with a different spec.
	if err := c.rtClient.Create(c.ctx, &apiv3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       apiv3.TierSpec{Order: floatPtr(999)},
	}); err != nil {
		t.Fatalf("creating conflicting tier: %v", err)
	}

	bc := c.backendClient.(*mockBackendClient)
	bc.resources = map[string][]*model.KVPair{
		apiv3.KindTier: {
			{
				Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "default"},
				Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: apiv3.TierSpec{Order: floatPtr(100)}},
			},
		},
	}
	ready := true
	bc.clusterInfo = &model.KVPair{
		Key: model.ResourceKey{Kind: apiv3.KindClusterInformation, Name: clusterInfoName},
		Value: &apiv3.ClusterInformation{
			ObjectMeta: metav1.ObjectMeta{Name: clusterInfoName},
			Spec:       apiv3.ClusterInformationSpec{DatastoreReady: &ready},
		},
		Revision: "1",
	}

	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	dm, err := c.migClient.Get(c.ctx, defaultMigrationName)
	if err != nil {
		t.Fatalf("getting CR: %v", err)
	}

	// Should transition to WaitingForConflictResolution.
	if dm.Status.Phase != DatastoreMigrationPhaseWaitingForConflictResolution {
		t.Errorf("expected WaitingForConflictResolution, got %s", dm.Status.Phase)
	}
	if dm.Status.Progress.Conflicts != 1 {
		t.Errorf("expected 1 conflict, got %d", dm.Status.Progress.Conflicts)
	}

	// Resolve the conflict by updating the existing tier to match v1 spec.
	existing := &apiv3.Tier{}
	if getErr := c.rtClient.Get(c.ctx, types.NamespacedName{Name: "default"}, existing); getErr != nil {
		t.Fatalf("getting tier for update: %v", getErr)
	}
	existing.Spec.Order = floatPtr(100)
	if updateErr := c.rtClient.Update(c.ctx, existing); updateErr != nil {
		t.Fatalf("updating tier: %v", updateErr)
	}

	// Reconcile should transition back to Migrating.
	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile (after resolution): %v", err)
	}

	dm, err = c.migClient.Get(c.ctx, defaultMigrationName)
	if err != nil {
		t.Fatalf("getting CR: %v", err)
	}
	if dm.Status.Phase != DatastoreMigrationPhaseMigrating {
		t.Errorf("expected Migrating after conflict resolution, got %s", dm.Status.Phase)
	}
}

// TestLifecycle_OwnerRefRemapping_NativeOwner verifies that OwnerReferences
// pointing to native K8s resources (e.g., Namespace) are preserved as-is
// during migration — only Calico OwnerRefs get remapped.
func TestLifecycle_OwnerRefRemapping_NativeOwner(t *testing.T) {
	withTestRegistry(t, []ResourceMigrator{gnpMigrator()})

	nsUID := types.UID("namespace-uid-12345")
	cr := createTestCR(t, defaultMigrationName, DatastoreMigrationPhaseMigrating)
	c, _ := testController(t, cr)

	bc := c.backendClient.(*mockBackendClient)
	bc.resources = map[string][]*model.KVPair{
		apiv3.KindGlobalNetworkPolicy: {
			{
				Key: model.ResourceKey{Kind: apiv3.KindGlobalNetworkPolicy, Name: "default.my-policy"},
				Value: &apiv3.GlobalNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: "default.my-policy",
						UID:  "v1-gnp-uid",
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: "v1",
								Kind:       "Namespace",
								Name:       "test-ns",
								UID:        nsUID,
							},
						},
					},
					Spec: apiv3.GlobalNetworkPolicySpec{Tier: "default"},
				},
			},
		},
	}
	ready := true
	bc.clusterInfo = &model.KVPair{
		Key: model.ResourceKey{Kind: apiv3.KindClusterInformation, Name: clusterInfoName},
		Value: &apiv3.ClusterInformation{
			ObjectMeta: metav1.ObjectMeta{Name: clusterInfoName},
			Spec:       apiv3.ClusterInformationSpec{DatastoreReady: &ready},
		},
		Revision: "1",
	}

	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// Verify the native OwnerRef UID was preserved (not remapped).
	gnp := &apiv3.GlobalNetworkPolicy{}
	if getErr := c.rtClient.Get(c.ctx, types.NamespacedName{Name: "my-policy"}, gnp); getErr != nil {
		t.Fatal("GNP 'my-policy' not found in v3 store")
	}
	ownerRefs := gnp.GetOwnerReferences()
	if len(ownerRefs) != 1 {
		t.Fatalf("expected 1 ownerRef, got %d", len(ownerRefs))
	}
	if ownerRefs[0].UID != nsUID {
		t.Errorf("expected native ownerRef UID to be preserved (%s), got %s", nsUID, ownerRefs[0].UID)
	}
	if ownerRefs[0].Kind != "Namespace" {
		t.Errorf("expected ownerRef kind Namespace, got %s", ownerRefs[0].Kind)
	}
}

// TestLifecycle_MigrationError verifies that a fatal error during resource
// migration transitions the CR to Failed.
func TestLifecycle_MigrationError(t *testing.T) {
	failingMigrator := ResourceMigrator{
		Kind:         "FailType",
		Order:        OrderTiers,
		V3Object:     func() rtclient.Object { return &apiv3.Tier{} },
		V3ObjectList: func() rtclient.ObjectList { return &apiv3.TierList{} },
		GetSpec:      func(obj rtclient.Object) any { return nil },
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return nil, fmt.Errorf("simulated list failure")
		},
	}
	withTestRegistry(t, []ResourceMigrator{failingMigrator})

	cr := createTestCR(t, defaultMigrationName, DatastoreMigrationPhaseMigrating)
	c, _ := testController(t, cr)

	bc := c.backendClient.(*mockBackendClient)
	ready := true
	bc.clusterInfo = &model.KVPair{
		Key: model.ResourceKey{Kind: apiv3.KindClusterInformation, Name: clusterInfoName},
		Value: &apiv3.ClusterInformation{
			ObjectMeta: metav1.ObjectMeta{Name: clusterInfoName},
			Spec:       apiv3.ClusterInformationSpec{DatastoreReady: &ready},
		},
		Revision: "1",
	}

	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	dm, err := c.migClient.Get(c.ctx, defaultMigrationName)
	if err != nil {
		t.Fatalf("getting CR: %v", err)
	}
	if dm.Status.Phase != DatastoreMigrationPhaseFailed {
		t.Errorf("expected Failed, got %s", dm.Status.Phase)
	}
	foundFailed := false
	for _, cond := range dm.Status.Conditions {
		if cond.Type == conditionTypeFailed {
			foundFailed = true
		}
	}
	if !foundFailed {
		t.Error("expected Failed condition")
	}
}

// createV3CRD creates a fake v3 CRD as unstructured for test assertions.
func createV3CRD(name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.k8s.io/v1",
			"kind":       "CustomResourceDefinition",
			"metadata": map[string]interface{}{
				"name": name,
			},
			"spec": map[string]interface{}{
				"group": "projectcalico.org",
			},
		},
	}
}

// felixConfigMigrator creates a test ResourceMigrator for FelixConfiguration.
func felixConfigMigrator() ResourceMigrator {
	return ResourceMigrator{
		Kind:         apiv3.KindFelixConfiguration,
		Order:        OrderConfigSingletons,
		V3Object:     func() rtclient.Object { return &apiv3.FelixConfiguration{} },
		V3ObjectList: func() rtclient.ObjectList { return &apiv3.FelixConfigurationList{} },
		GetSpec:      func(obj rtclient.Object) any { return obj.(*apiv3.FelixConfiguration).Spec },
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindFelixConfiguration)
		},
		Convert: func(kvp *model.KVPair) (rtclient.Object, error) {
			v1 := kvp.Value.(*apiv3.FelixConfiguration)
			v3 := &apiv3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	}
}

// ipPoolMigrator creates a test ResourceMigrator for IPPool.
func ipPoolMigrator() ResourceMigrator {
	return ResourceMigrator{
		Kind:         apiv3.KindIPPool,
		Order:        OrderNetworkInfra,
		V3Object:     func() rtclient.Object { return &apiv3.IPPool{} },
		V3ObjectList: func() rtclient.ObjectList { return &apiv3.IPPoolList{} },
		GetSpec:      func(obj rtclient.Object) any { return obj.(*apiv3.IPPool).Spec },
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindIPPool)
		},
		Convert: func(kvp *model.KVPair) (rtclient.Object, error) {
			v1 := kvp.Value.(*apiv3.IPPool)
			v3 := &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	}
}

// bgpPeerMigrator creates a test ResourceMigrator for BGPPeer.
func bgpPeerMigrator() ResourceMigrator {
	return ResourceMigrator{
		Kind:         apiv3.KindBGPPeer,
		Order:        OrderNetworkInfra,
		V3Object:     func() rtclient.Object { return &apiv3.BGPPeer{} },
		V3ObjectList: func() rtclient.ObjectList { return &apiv3.BGPPeerList{} },
		GetSpec:      func(obj rtclient.Object) any { return obj.(*apiv3.BGPPeer).Spec },
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindBGPPeer)
		},
		Convert: func(kvp *model.KVPair) (rtclient.Object, error) {
			v1 := kvp.Value.(*apiv3.BGPPeer)
			v3 := &apiv3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	}
}

// TestLifecycle_FullMigrationWithContentVerification exercises a full migration
// with multiple diverse resource types and verifies that spec fields are
// faithfully preserved in the v3 resources.
func TestLifecycle_FullMigrationWithContentVerification(t *testing.T) {
	withTestRegistry(t, []ResourceMigrator{
		tierMigrator(),
		felixConfigMigrator(),
		ipPoolMigrator(),
		bgpPeerMigrator(),
	})

	cr := createTestCR(t, defaultMigrationName, "")
	v1CRD := createV1CRD("tiers.crd.projectcalico.org")
	c, _ := testController(t, cr, v1CRD)

	bc := c.backendClient.(*mockBackendClient)

	// Build diverse v1 resources.
	boolTrue := true
	floatingIP := apiv3.FloatingIPsEnabled
	int32Val := int32(90)
	v1FelixSpec := apiv3.FelixConfigurationSpec{
		LogSeverityScreen: "Debug",
		IPIPEnabled:       &boolTrue,
		FloatingIPs:       &floatingIP,
	}
	v1IPPoolSpec := apiv3.IPPoolSpec{
		CIDR:         "10.244.0.0/16",
		NATOutgoing:  true,
		NodeSelector: "all()",
		BlockSize:    26,
		VXLANMode:    apiv3.VXLANModeAlways,
	}
	v1BGPPeerSpec := apiv3.BGPPeerSpec{
		PeerIP:   "192.168.1.1",
		ASNumber: 64512,
		MaxRestartTime: &metav1.Duration{
			Duration: 120000000000,
		},
		KeepOriginalNextHop:      true,
		NumAllowedLocalASNumbers: &int32Val,
	}

	bc.resources = map[string][]*model.KVPair{
		apiv3.KindTier: {
			{
				Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "default"},
				Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "default", UID: "tier-uid"}, Spec: apiv3.TierSpec{Order: floatPtr(100)}},
			},
		},
		apiv3.KindFelixConfiguration: {
			{
				Key: model.ResourceKey{Kind: apiv3.KindFelixConfiguration, Name: "default"},
				Value: &apiv3.FelixConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: "default", UID: "fc-uid"},
					Spec:       v1FelixSpec,
				},
			},
		},
		apiv3.KindIPPool: {
			{
				Key: model.ResourceKey{Kind: apiv3.KindIPPool, Name: "default-pool"},
				Value: &apiv3.IPPool{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "default-pool",
						UID:    "pool-uid",
						Labels: map[string]string{"env": "test"},
					},
					Spec: v1IPPoolSpec,
				},
			},
		},
		apiv3.KindBGPPeer: {
			{
				Key: model.ResourceKey{Kind: apiv3.KindBGPPeer, Name: "peer1"},
				Value: &apiv3.BGPPeer{
					ObjectMeta: metav1.ObjectMeta{Name: "peer1", UID: "peer-uid"},
					Spec:       v1BGPPeerSpec,
				},
			},
		},
	}

	ready := true
	bc.clusterInfo = &model.KVPair{
		Key: model.ResourceKey{Kind: apiv3.KindClusterInformation, Name: clusterInfoName},
		Value: &apiv3.ClusterInformation{
			ObjectMeta: metav1.ObjectMeta{Name: clusterInfoName},
			Spec:       apiv3.ClusterInformationSpec{DatastoreReady: &ready},
		},
		Revision: "1",
	}

	createAggregatedAPIService(t, c)

	// Reconcile 1: Pending -> Migrating.
	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile 1: %v", err)
	}

	// Reconcile 2: Migrating -> Converged.
	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile 2: %v", err)
	}

	dm, err := c.migClient.Get(c.ctx, defaultMigrationName)
	if err != nil {
		t.Fatalf("getting CR: %v", err)
	}
	if dm.Status.Phase != DatastoreMigrationPhaseConverged {
		t.Fatalf("expected Converged, got %s", dm.Status.Phase)
	}
	if dm.Status.Progress.Migrated != 4 {
		t.Errorf("expected 4 migrated resources, got %d", dm.Status.Progress.Migrated)
	}

	// Verify FelixConfiguration content.
	v3Felix := &apiv3.FelixConfiguration{}
	if err := c.rtClient.Get(c.ctx, types.NamespacedName{Name: "default"}, v3Felix); err != nil {
		t.Fatal("FelixConfiguration 'default' not found in v3")
	}
	if v3Felix.Spec.LogSeverityScreen != v1FelixSpec.LogSeverityScreen {
		t.Errorf("FelixConfiguration LogSeverityScreen mismatch: got %s, want %s", v3Felix.Spec.LogSeverityScreen, v1FelixSpec.LogSeverityScreen)
	}
	if !reflect.DeepEqual(v3Felix.Spec.IPIPEnabled, v1FelixSpec.IPIPEnabled) {
		t.Errorf("FelixConfiguration IPIPEnabled mismatch: got %v", v3Felix.Spec.IPIPEnabled)
	}

	// Verify IPPool content.
	v3Pool := &apiv3.IPPool{}
	if err := c.rtClient.Get(c.ctx, types.NamespacedName{Name: "default-pool"}, v3Pool); err != nil {
		t.Fatal("IPPool 'default-pool' not found in v3")
	}
	if v3Pool.Spec.CIDR != v1IPPoolSpec.CIDR {
		t.Errorf("IPPool CIDR mismatch: got %s, want %s", v3Pool.Spec.CIDR, v1IPPoolSpec.CIDR)
	}
	if v3Pool.Spec.NATOutgoing != v1IPPoolSpec.NATOutgoing {
		t.Errorf("IPPool NATOutgoing mismatch: got %v", v3Pool.Spec.NATOutgoing)
	}
	if v3Pool.Spec.BlockSize != v1IPPoolSpec.BlockSize {
		t.Errorf("IPPool BlockSize mismatch: got %d, want %d", v3Pool.Spec.BlockSize, v1IPPoolSpec.BlockSize)
	}
	if v3Pool.Spec.VXLANMode != v1IPPoolSpec.VXLANMode {
		t.Errorf("IPPool VXLANMode mismatch: got %s, want %s", v3Pool.Spec.VXLANMode, v1IPPoolSpec.VXLANMode)
	}
	if v3Pool.Labels["env"] != "test" {
		t.Errorf("IPPool label 'env' not preserved: got %v", v3Pool.Labels)
	}

	// Verify BGPPeer content.
	v3Peer := &apiv3.BGPPeer{}
	if err := c.rtClient.Get(c.ctx, types.NamespacedName{Name: "peer1"}, v3Peer); err != nil {
		t.Fatal("BGPPeer 'peer1' not found in v3")
	}
	if v3Peer.Spec.PeerIP != v1BGPPeerSpec.PeerIP {
		t.Errorf("BGPPeer PeerIP mismatch: got %s, want %s", v3Peer.Spec.PeerIP, v1BGPPeerSpec.PeerIP)
	}
	if v3Peer.Spec.ASNumber != v1BGPPeerSpec.ASNumber {
		t.Errorf("BGPPeer ASNumber mismatch: got %v, want %v", v3Peer.Spec.ASNumber, v1BGPPeerSpec.ASNumber)
	}
	if v3Peer.Spec.KeepOriginalNextHop != true {
		t.Errorf("BGPPeer KeepOriginalNextHop mismatch: got %v", v3Peer.Spec.KeepOriginalNextHop)
	}
	if !reflect.DeepEqual(v3Peer.Spec.MaxRestartTime, v1BGPPeerSpec.MaxRestartTime) {
		t.Errorf("BGPPeer MaxRestartTime mismatch: got %v, want %v", v3Peer.Spec.MaxRestartTime, v1BGPPeerSpec.MaxRestartTime)
	}
}

// createReadyCalicoNodeDS creates a calico-node DaemonSet with the CALICO_API_GROUP
// env var set and a fully rolled out status, simulating what the operator does after
// detecting that migration has converged.
func createReadyCalicoNodeDS(t *testing.T, c *migrationController) {
	t.Helper()
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "calico-node",
			Namespace:  "calico-system",
			Generation: 1,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s-app": "calico-node"},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"k8s-app": "calico-node"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "calico-node",
							Image: "calico/node:latest",
							Env: []corev1.EnvVar{
								{Name: "CALICO_API_GROUP", Value: "projectcalico.org/v3"},
							},
						},
					},
				},
			},
		},
		Status: appsv1.DaemonSetStatus{
			ObservedGeneration:     1,
			DesiredNumberScheduled: 3,
			CurrentNumberScheduled: 3,
			UpdatedNumberScheduled: 3,
			NumberAvailable:        3,
			NumberReady:            3,
		},
	}
	_, err := c.k8sClient.AppsV1().DaemonSets("calico-system").Create(c.ctx, ds, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("creating calico-node DaemonSet: %v", err)
	}
}
