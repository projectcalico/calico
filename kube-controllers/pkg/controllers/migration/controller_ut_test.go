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
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	fakedynamic "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	fakeapiregclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"
	"k8s.io/utils/ptr"
	rtclient "sigs.k8s.io/controller-runtime/pkg/client"
	fakertclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// testController bundles the migrationController with its underlying object tracker,
// which is needed to seed deletion-marked objects (the fake client strips DeletionTimestamp
// on Create, so we use tracker.Add for those).
type testController struct {
	*migrationController
	tracker k8stesting.ObjectTracker
}

// newTestController creates a migrationController with fake clients for unit testing.
// The dynamicObjects parameter should only contain unstructured objects for the dynamic
// client (e.g., CRDs). DatastoreMigration CRs should be created via createMigrationCR.
func newTestController(t *testing.T, dynamicObjects ...runtime.Object) (*testController, *fakedynamic.FakeDynamicClient) {
	t.Helper()

	scheme := runtime.NewScheme()
	scheme.AddKnownTypeWithName(
		schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}.GroupVersion().WithKind("CustomResourceDefinitionList"),
		&unstructured.UnstructuredList{},
	)

	dynClient := fakedynamic.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			crdGVR: "CustomResourceDefinitionList",
		},
		dynamicObjects...,
	)

	k8sClient := fake.NewSimpleClientset()
	apiregCS := fakeapiregclient.NewSimpleClientset()
	bc := &mockBackendClient{
		resources: make(map[string][]*model.KVPair),
	}

	rtScheme := runtime.NewScheme()
	if err := apiv3.AddToScheme(rtScheme); err != nil {
		t.Fatalf("failed to add Calico v3 types to scheme: %v", err)
	}
	if err := AddToScheme(rtScheme); err != nil {
		t.Fatalf("failed to add migration types to scheme: %v", err)
	}
	codecs := serializer.NewCodecFactory(rtScheme)
	tracker := k8stesting.NewObjectTracker(rtScheme, codecs.UniversalDecoder())
	fakeRT := fakertclient.NewClientBuilder().WithScheme(rtScheme).WithObjectTracker(tracker).WithStatusSubresource(&DatastoreMigration{}).Build()

	c := &testController{
		migrationController: &migrationController{
			ctx:           context.Background(),
			k8sClient:     k8sClient,
			backendClient: bc,
			rtClient:      &uidAssigningClient{Client: fakeRT},
			dynamicClient: dynClient,
			apiregClient:  apiregCS.ApiregistrationV1(),
		},
		tracker: tracker,
	}
	return c, dynClient
}

// createMigrationCR creates a DatastoreMigration CR for testing. Objects with a
// DeletionTimestamp are added directly via the tracker (the fake client strips
// DeletionTimestamp on Create); all others go through the normal client.
func createMigrationCR(t *testing.T, c *testController, dm *DatastoreMigration) {
	t.Helper()
	if dm.DeletionTimestamp != nil {
		// tracker.Add requires a ResourceVersion.
		if dm.ResourceVersion == "" {
			dm.ResourceVersion = "1"
		}
		if err := c.tracker.Add(dm); err != nil {
			t.Fatalf("adding DatastoreMigration CR to tracker: %v", err)
		}
		return
	}
	if err := c.rtClient.Create(context.Background(), dm); err != nil {
		t.Fatalf("creating DatastoreMigration CR: %v", err)
	}
}

// newTestCR creates a typed DatastoreMigration for testing.
func newTestCR(t *testing.T, name string, phase DatastoreMigrationPhase) *DatastoreMigration {
	t.Helper()
	dm := &DatastoreMigration{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       DatastoreMigrationSpec{Type: DatastoreMigrationTypeAPIServerToCRDs},
	}
	if phase != "" {
		dm.Status.Phase = phase
	}
	return dm
}

// newTestCRWithDeletion creates a DatastoreMigration CR with a finalizer and deletion timestamp.
func newTestCRWithDeletion(t *testing.T, name string, phase DatastoreMigrationPhase) *DatastoreMigration {
	t.Helper()
	now := metav1.Now()
	dm := &DatastoreMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Finalizers:        []string{finalizerName},
			DeletionTimestamp: &now,
		},
		Spec: DatastoreMigrationSpec{Type: DatastoreMigrationTypeAPIServerToCRDs},
	}
	dm.Status.Phase = phase
	return dm
}

// newV1CRD creates a fake v1 CRD as unstructured for pre-validation tests.
func newV1CRD(name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "apiextensions.k8s.io/v1",
			"kind":       "CustomResourceDefinition",
			"metadata": map[string]any{
				"name": name,
			},
			"spec": map[string]any{
				"group": "crd.projectcalico.org",
			},
		},
	}
}

func testLogEntry() *logrus.Entry {
	return logrus.WithField("test", true)
}

// getMigrationCR fetches the DatastoreMigration CR from the rtClient.
func getMigrationCR(t *testing.T, c *testController, name string) *DatastoreMigration {
	t.Helper()
	dm := &DatastoreMigration{}
	if err := c.rtClient.Get(c.ctx, types.NamespacedName{Name: name}, dm); err != nil {
		t.Fatalf("getting DatastoreMigration CR %q: %v", name, err)
	}
	return dm
}

// TestReconcile_NoCR verifies that reconcile is a no-op when no DatastoreMigration CR exists.
func TestReconcile_NoCR(t *testing.T) {
	c, _ := newTestController(t)

	// No CR exists — reconcile should be a no-op.
	if err := c.reconcile(); err != nil {
		t.Fatalf("expected no error when no CR exists, got: %v", err)
	}
}

// TestReconcile_PendingToMigrating verifies the Pending-to-Migrating transition including finalizer addition and pre-validation.
func TestReconcile_PendingToMigrating(t *testing.T) {
	v1CRD := newV1CRD("bgppeers.crd.projectcalico.org")
	c, _ := newTestController(t, v1CRD)
	createMigrationCR(t, c, newTestCR(t, defaultMigrationName, ""))

	// First reconcile: adds finalizer.
	if err := c.reconcile(); err != nil {
		t.Fatalf("first reconcile (add finalizer) failed: %v", err)
	}

	dm := getMigrationCR(t, c, defaultMigrationName)
	if !hasFinalizer(dm) {
		t.Error("expected finalizer to be added after first reconcile")
	}

	// Second reconcile: pre-validation passes, transitions through
	// Migrating to Converged (no resources to migrate with empty registry).
	if err := c.reconcile(); err != nil {
		t.Fatalf("second reconcile failed: %v", err)
	}

	dm = getMigrationCR(t, c, defaultMigrationName)

	// With no registered migrators, the controller runs through the entire
	// migration in a single reconcile: Pending -> Migrating -> Converged.
	if dm.Status.Phase != DatastoreMigrationPhaseConverged {
		t.Errorf("expected phase Converged (no resources to migrate), got %s", dm.Status.Phase)
	}
	if dm.Status.StartedAt == nil {
		t.Error("expected StartedAt to be set")
	}
}

// TestReconcile_CompleteIsNoOp verifies that the Complete phase is a terminal no-op.
func TestReconcile_CompleteIsNoOp(t *testing.T) {
	c, _ := newTestController(t)
	createMigrationCR(t, c, newTestCR(t, defaultMigrationName, DatastoreMigrationPhaseComplete))

	if err := c.reconcile(); err != nil {
		t.Fatalf("expected no error for Complete phase, got: %v", err)
	}

	dm := getMigrationCR(t, c, defaultMigrationName)
	if dm.Status.Phase != DatastoreMigrationPhaseComplete {
		t.Errorf("expected phase Complete, got %s", dm.Status.Phase)
	}
}

// TestReconcile_FailedIsNoOp verifies that the Failed phase is a terminal no-op.
func TestReconcile_FailedIsNoOp(t *testing.T) {
	c, _ := newTestController(t)
	createMigrationCR(t, c, newTestCR(t, defaultMigrationName, DatastoreMigrationPhaseFailed))

	if err := c.reconcile(); err != nil {
		t.Fatalf("expected no error for Failed phase, got: %v", err)
	}

	dm := getMigrationCR(t, c, defaultMigrationName)
	if dm.Status.Phase != DatastoreMigrationPhaseFailed {
		t.Errorf("expected phase Failed, got %s", dm.Status.Phase)
	}
}

// TestPreValidation_NoV1CRDs verifies that pre-validation returns a terminal error when no v1 CRDs exist.
func TestPreValidation_NoV1CRDs(t *testing.T) {
	c, _ := newTestController(t)
	createMigrationCR(t, c, newTestCR(t, defaultMigrationName, ""))

	// Reconcile adds the finalizer and then runs pre-validation in the same
	// pass — no v1 CRDs should return a terminal error.
	err := c.reconcile()
	if err == nil {
		t.Fatal("expected terminal error when no v1 CRDs exist")
	}
	if !isTerminal(err) {
		t.Errorf("expected terminal error, got: %v", err)
	}
}

// TestPreValidation_AutomanagedAPIService verifies that pre-validation fails when the APIService is CRD-backed (automanaged).
func TestPreValidation_AutomanagedAPIService(t *testing.T) {
	v1CRD := newV1CRD("bgppeers.crd.projectcalico.org")
	c, _ := newTestController(t, v1CRD)
	createMigrationCR(t, c, newTestCR(t, defaultMigrationName, ""))

	// Create an automanaged (CRD-backed) APIService.
	apiSvc := &apiregv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			Name: apiServiceName,
			Labels: map[string]string{
				"kube-aggregator.kubernetes.io/automanaged": "true",
			},
		},
		Spec: apiregv1.APIServiceSpec{
			Group:                "projectcalico.org",
			Version:              "v3",
			GroupPriorityMinimum: 100,
			VersionPriority:      100,
		},
	}
	if _, err := c.apiregClient.APIServices().Create(c.ctx, apiSvc, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating APIService: %v", err)
	}

	// Reconcile adds the finalizer and then runs pre-validation — automanaged
	// APIService should return a terminal error.
	err := c.reconcile()
	if err == nil {
		t.Fatal("expected terminal error for automanaged APIService")
	}
	if !isTerminal(err) {
		t.Errorf("expected terminal error, got: %v", err)
	}
}

// TestLockDatastore verifies that lockDatastore sets DatastoreReady=false on both v1 and v3 ClusterInformation.
func TestLockDatastore(t *testing.T) {
	c, _ := newTestController(t)

	// Set up v1 ClusterInformation via backend client mock.
	bc, ok := c.backendClient.(*mockBackendClient)
	if !ok {
		t.Fatalf("expected backendClient to be *mockBackendClient, got %T", c.backendClient)
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

	logCtx := testLogEntry()
	if err := c.lockDatastore(logCtx); err != nil {
		t.Fatalf("lockDatastore failed: %v", err)
	}

	// Verify v3 ClusterInformation was created with DatastoreReady=false.
	v3ci := &apiv3.ClusterInformation{}
	if err := c.rtClient.Get(c.ctx, types.NamespacedName{Name: clusterInfoName}, v3ci); err != nil {
		t.Fatalf("getting v3 ClusterInformation: %v", err)
	}
	if v3ci.Spec.DatastoreReady == nil || *v3ci.Spec.DatastoreReady {
		t.Error("expected v3 ClusterInformation DatastoreReady=false after lock")
	}

	// Verify v1 was locked.
	ci, ok := bc.clusterInfo.Value.(*apiv3.ClusterInformation)
	if !ok {
		t.Fatalf("expected v1 ClusterInformation to be *apiv3.ClusterInformation, got %T", bc.clusterInfo.Value)
	}
	if ci.Spec.DatastoreReady == nil || *ci.Spec.DatastoreReady {
		t.Error("expected v1 ClusterInformation DatastoreReady=false after lock")
	}
}

// TestUnlockDatastore verifies that unlockV3CRDDatastore unlocks v3 while leaving v1 locked.
func TestUnlockDatastore(t *testing.T) {
	c, _ := newTestController(t)

	// Pre-create v3 ClusterInformation as locked.
	ready := false
	if err := c.rtClient.Create(c.ctx, &apiv3.ClusterInformation{
		ObjectMeta: metav1.ObjectMeta{Name: clusterInfoName},
		Spec:       apiv3.ClusterInformationSpec{DatastoreReady: &ready},
	}); err != nil {
		t.Fatalf("creating v3 ClusterInformation: %v", err)
	}

	// Set up v1 as locked.
	bc, ok := c.backendClient.(*mockBackendClient)
	if !ok {
		t.Fatalf("expected backendClient to be *mockBackendClient, got %T", c.backendClient)
	}
	bc.clusterInfo = &model.KVPair{
		Key: model.ResourceKey{Kind: apiv3.KindClusterInformation, Name: clusterInfoName},
		Value: &apiv3.ClusterInformation{
			ObjectMeta: metav1.ObjectMeta{Name: clusterInfoName},
			Spec:       apiv3.ClusterInformationSpec{DatastoreReady: &ready},
		},
		Revision: "1",
	}

	logCtx := testLogEntry()
	if err := c.unlockV3CRDDatastore(logCtx); err != nil {
		t.Fatalf("unlockV3CRDDatastore failed: %v", err)
	}

	// Verify v3 was unlocked.
	v3ci := &apiv3.ClusterInformation{}
	if getErr := c.rtClient.Get(c.ctx, types.NamespacedName{Name: clusterInfoName}, v3ci); getErr != nil {
		t.Fatalf("getting v3 ClusterInformation: %v", getErr)
	}
	if v3ci.Spec.DatastoreReady == nil || !*v3ci.Spec.DatastoreReady {
		t.Error("expected v3 ClusterInformation DatastoreReady=true after unlock")
	}

	// Verify v1 remains locked — v1 stays locked intentionally so that
	// components still reading v1 block CNI operations until they roll
	// out with v3 mode.
	ci, ok := bc.clusterInfo.Value.(*apiv3.ClusterInformation)
	if !ok {
		t.Fatalf("expected v1 ClusterInformation to be *apiv3.ClusterInformation, got %T", bc.clusterInfo.Value)
	}
	if ci.Spec.DatastoreReady == nil || *ci.Spec.DatastoreReady {
		t.Error("expected v1 ClusterInformation DatastoreReady=false (should stay locked)")
	}
}

// TestHandleDeletion_Complete verifies that the finalizer is removed when a Complete CR is deleted.
func TestHandleDeletion_Complete(t *testing.T) {
	c, _ := newTestController(t)
	createMigrationCR(t, c, newTestCRWithDeletion(t, defaultMigrationName, DatastoreMigrationPhaseComplete))

	// Reconcile should run the completed cleanup path (delete v1 CRDs).
	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile for Complete deletion failed: %v", err)
	}

	// The CR should be fully deleted (finalizer removed, DeletionTimestamp was set).
	dm := &DatastoreMigration{}
	err := c.rtClient.Get(c.ctx, types.NamespacedName{Name: defaultMigrationName}, dm)
	if !kerrors.IsNotFound(err) {
		t.Errorf("expected CR to be deleted after completed cleanup, got err: %v", err)
	}
}

// TestHandleDeletion_Abort verifies that aborting a non-Complete CR restores v1 ClusterInformation and removes the finalizer.
func TestHandleDeletion_Abort(t *testing.T) {
	c, _ := newTestController(t)
	createMigrationCR(t, c, newTestCRWithDeletion(t, defaultMigrationName, DatastoreMigrationPhaseMigrating))

	// Set up v1 backend mock as locked.
	bc, ok := c.backendClient.(*mockBackendClient)
	if !ok {
		t.Fatalf("expected backendClient to be *mockBackendClient, got %T", c.backendClient)
	}
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
		t.Fatalf("reconcile for abort failed: %v", err)
	}

	// The CR should be fully deleted (finalizer removed, DeletionTimestamp was set).
	dm := &DatastoreMigration{}
	if err := c.rtClient.Get(c.ctx, types.NamespacedName{Name: defaultMigrationName}, dm); !kerrors.IsNotFound(err) {
		t.Errorf("expected CR to be deleted after abort, got err: %v", err)
	}

	// Verify v1 ClusterInformation was restored to ready.
	ci, ok := bc.clusterInfo.Value.(*apiv3.ClusterInformation)
	if !ok {
		t.Fatalf("expected v1 ClusterInformation to be *apiv3.ClusterInformation, got %T", bc.clusterInfo.Value)
	}
	if ci.Spec.DatastoreReady == nil || !*ci.Spec.DatastoreReady {
		t.Error("expected v1 ClusterInformation DatastoreReady=true after abort")
	}
}

// TestMigrateResourceType_TransientError verifies that transient API errors are retried with backoff.
func TestMigrateResourceType_TransientError(t *testing.T) {
	ctx := context.Background()

	bc := &mockBackendClient{
		resources: map[string][]*model.KVPair{
			apiv3.KindTier: {
				{
					Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "default"},
					Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: apiv3.TierSpec{Order: ptr.To[float64](100)}},
				},
			},
		},
	}

	rtScheme := runtime.NewScheme()
	if err := apiv3.AddToScheme(rtScheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	// Use a wrapper that injects a transient error on the first Create.
	calls := 0
	inner := fakertclient.NewClientBuilder().WithScheme(rtScheme).WithObjectTracker(k8stesting.NewObjectTracker(rtScheme, serializer.NewCodecFactory(rtScheme).UniversalDecoder())).Build()
	wrapper := &retryTestClient{Client: inner, createCalls: &calls}

	migrator := ResourceMigrator{
		Kind:         apiv3.KindTier,
		Order:        OrderTiers,
		V3Object:     func() rtclient.Object { return &apiv3.Tier{} },
		V3ObjectList: func() rtclient.ObjectList { return &apiv3.TierList{} },
		GetSpec:      func(obj rtclient.Object) any { return obj.(*apiv3.Tier).Spec },
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindTier)
		},
		Convert: func(kvp *model.KVPair) (rtclient.Object, error) {
			v1, ok := kvp.Value.(*apiv3.Tier)
			if !ok {
				return nil, fmt.Errorf("unexpected type: %T", kvp.Value)
			}
			return &apiv3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}, nil
		},
	}

	result, err := MigrateResourceType(ctx, bc, wrapper, migrator)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Migrated != 1 {
		t.Errorf("expected 1 migrated after retry, got %d", result.Migrated)
	}
	if calls < 2 {
		t.Errorf("expected at least 2 Create calls (initial + retry), got %d", calls)
	}
}

// TestMigrateResourceType_ContentMatch verifies that migrated resources preserve spec, labels, and annotations.
func TestMigrateResourceType_ContentMatch(t *testing.T) {
	ctx := context.Background()

	action := apiv3.Action("Deny")
	originalSpec := apiv3.TierSpec{Order: ptr.To[float64](42), DefaultAction: &action}
	bc := &mockBackendClient{
		resources: map[string][]*model.KVPair{
			apiv3.KindTier: {
				{
					Key: model.ResourceKey{Kind: apiv3.KindTier, Name: "my-tier"},
					Value: &apiv3.Tier{
						ObjectMeta: metav1.ObjectMeta{
							Name:        "my-tier",
							Labels:      map[string]string{"env": "prod"},
							Annotations: map[string]string{"note": "important"},
						},
						Spec: originalSpec,
					},
				},
			},
		},
	}

	rtScheme := runtime.NewScheme()
	if err := apiv3.AddToScheme(rtScheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}
	fakeRT := fakertclient.NewClientBuilder().WithScheme(rtScheme).WithObjectTracker(k8stesting.NewObjectTracker(rtScheme, serializer.NewCodecFactory(rtScheme).UniversalDecoder())).Build()

	migrator := ResourceMigrator{
		Kind:         apiv3.KindTier,
		Order:        OrderTiers,
		V3Object:     func() rtclient.Object { return &apiv3.Tier{} },
		V3ObjectList: func() rtclient.ObjectList { return &apiv3.TierList{} },
		GetSpec:      func(obj rtclient.Object) any { return obj.(*apiv3.Tier).Spec },
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindTier)
		},
		Convert: func(kvp *model.KVPair) (rtclient.Object, error) {
			v1, ok := kvp.Value.(*apiv3.Tier)
			if !ok {
				return nil, fmt.Errorf("unexpected type: %T", kvp.Value)
			}
			v3 := &apiv3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	}

	result, err := MigrateResourceType(ctx, bc, fakeRT, migrator)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Migrated != 1 {
		t.Fatalf("expected 1 migrated, got %d", result.Migrated)
	}

	// Verify the created object by reading it back from the fake client.
	tier := &apiv3.Tier{}
	if getErr := fakeRT.Get(ctx, types.NamespacedName{Name: "my-tier"}, tier); getErr != nil {
		t.Fatalf("failed to get created tier: %v", getErr)
	}
	if tier.Spec.Order == nil || *tier.Spec.Order != 42 {
		t.Errorf("expected Order 42, got %v", tier.Spec.Order)
	}
	if tier.Spec.DefaultAction == nil || *tier.Spec.DefaultAction != apiv3.Action("Deny") {
		t.Errorf("expected DefaultAction Deny, got %v", tier.Spec.DefaultAction)
	}
	if tier.Labels["env"] != "prod" {
		t.Errorf("expected label env=prod, got %v", tier.Labels)
	}
}

// TestMigrateResourceType_ConvertError verifies that a conversion error propagates as a migration failure.
func TestMigrateResourceType_ConvertError(t *testing.T) {
	ctx := context.Background()

	bc := &mockBackendClient{
		resources: map[string][]*model.KVPair{
			apiv3.KindTier: {
				{
					Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "bad-tier"},
					Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "bad-tier"}},
				},
			},
		},
	}

	rtScheme := runtime.NewScheme()
	if err := apiv3.AddToScheme(rtScheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}
	fakeRT := fakertclient.NewClientBuilder().WithScheme(rtScheme).WithObjectTracker(k8stesting.NewObjectTracker(rtScheme, serializer.NewCodecFactory(rtScheme).UniversalDecoder())).Build()

	migrator := ResourceMigrator{
		Kind:         apiv3.KindTier,
		Order:        OrderTiers,
		V3Object:     func() rtclient.Object { return &apiv3.Tier{} },
		V3ObjectList: func() rtclient.ObjectList { return &apiv3.TierList{} },
		GetSpec:      func(obj rtclient.Object) any { return obj.(*apiv3.Tier).Spec },
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindTier)
		},
		Convert: func(kvp *model.KVPair) (rtclient.Object, error) {
			return nil, fmt.Errorf("intentional convert error")
		},
	}

	_, err := MigrateResourceType(ctx, bc, fakeRT, migrator)
	if err == nil {
		t.Fatal("expected error from Convert failure")
	}
	if !isTerminal(err) {
		t.Errorf("expected terminal error for conversion failure, got: %v", err)
	}
}

// TestConflictDetection_PhaseTransition verifies that when a v3 resource
// exists with a different spec than the v1 source, the controller detects
// the conflict, transitions to WaitingForConflictResolution, and records
// the conflict details in the CR status.
func TestConflictDetection_PhaseTransition(t *testing.T) {
	withTestRegistry(t, []ResourceMigrator{tierMigrator(), gnpMigrator()})

	c, _ := newTestController(t)
	createMigrationCR(t, c, newTestCR(t, defaultMigrationName, DatastoreMigrationPhaseMigrating))

	// Pre-create a conflicting GNP with a different spec than the v1 source.
	if err := c.rtClient.Create(c.ctx, &apiv3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-deny-all"},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Tier: "security",
		},
	}); err != nil {
		t.Fatalf("creating conflicting GNP: %v", err)
	}

	bc := c.backendClient.(*mockBackendClient)
	bc.resources = map[string][]*model.KVPair{
		apiv3.KindTier: {
			{
				Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "default"},
				Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: apiv3.TierSpec{Order: ptr.To[float64](100)}},
			},
		},
		apiv3.KindGlobalNetworkPolicy: {
			{
				Key: model.ResourceKey{Kind: apiv3.KindGlobalNetworkPolicy, Name: "default.test-deny-all"},
				Value: &apiv3.GlobalNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "default.test-deny-all"},
					Spec:       apiv3.GlobalNetworkPolicySpec{Tier: "default"},
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

	dm := getMigrationCR(t, c, defaultMigrationName)

	// Should transition to WaitingForConflictResolution.
	if dm.Status.Phase != DatastoreMigrationPhaseWaitingForConflictResolution {
		t.Errorf("expected WaitingForConflictResolution, got %s", dm.Status.Phase)
	}
	if dm.Status.Progress.Conflicts != 1 {
		t.Errorf("expected 1 conflict, got %d", dm.Status.Progress.Conflicts)
	}

	// Verify condition details.
	found := false
	for _, cond := range dm.Status.Conditions {
		if cond.Type == conditionTypeConflict && cond.Status == metav1.ConditionTrue {
			found = true
			if cond.Reason != conditionReasonResourceMismatch {
				t.Errorf("expected reason %s, got %s", conditionReasonResourceMismatch, cond.Reason)
			}
		}
	}
	if !found {
		t.Error("expected Conflict condition with ConditionTrue")
	}

	// The tier should have been migrated successfully despite the GNP conflict.
	tier := &apiv3.Tier{}
	if getErr := c.rtClient.Get(c.ctx, types.NamespacedName{Name: "default"}, tier); getErr != nil {
		t.Error("tier 'default' should have been migrated even with GNP conflict")
	}
}

// TestAbortRollback_CleansUpMigratedResources verifies that when a migration
// is aborted (CR deleted mid-migration), partial v3 resources are cleaned up,
// the APIService is restored, and v1 ClusterInformation is unlocked.
func TestAbortRollback_CleansUpMigratedResources(t *testing.T) {
	withTestRegistry(t, []ResourceMigrator{tierMigrator(), gnpMigrator()})

	// Simulate mid-migration: CR is being deleted while in Migrating phase.
	// The saved APIService annotation allows restore.
	savedAPIService := &apiregv1.APIService{
		ObjectMeta: metav1.ObjectMeta{Name: apiServiceName},
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
	apiSvcJSON, err := json.Marshal(savedAPIService)
	if err != nil {
		t.Fatalf("marshaling APIService: %v", err)
	}

	cr := newTestCRWithDeletion(t, defaultMigrationName, DatastoreMigrationPhaseMigrating)
	cr.Annotations = map[string]string{
		savedAPIServiceAnnotation: string(apiSvcJSON),
	}

	c, _ := newTestController(t)
	createMigrationCR(t, c, cr)

	// Simulate partial v3 resources that were created by migration.
	if err := c.rtClient.Create(c.ctx, &apiv3.Tier{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "default",
			Annotations: map[string]string{migratedByAnnotation: "v1-to-v3"},
		},
		Spec: apiv3.TierSpec{Order: ptr.To[float64](100)},
	}); err != nil {
		t.Fatalf("creating tier: %v", err)
	}
	if err := c.rtClient.Create(c.ctx, &apiv3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-policy",
			Annotations: map[string]string{migratedByAnnotation: "v1-to-v3"},
		},
		Spec: apiv3.GlobalNetworkPolicySpec{Tier: "default"},
	}); err != nil {
		t.Fatalf("creating GNP: %v", err)
	}
	// A pre-existing v3 resource (no migration annotation) should be preserved.
	if err := c.rtClient.Create(c.ctx, &apiv3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "preexisting"},
		Spec:       apiv3.TierSpec{Order: ptr.To[float64](50)},
	}); err != nil {
		t.Fatalf("creating preexisting tier: %v", err)
	}

	bc := c.backendClient.(*mockBackendClient)
	readyFalse := false
	bc.clusterInfo = &model.KVPair{
		Key: model.ResourceKey{Kind: apiv3.KindClusterInformation, Name: clusterInfoName},
		Value: &apiv3.ClusterInformation{
			ObjectMeta: metav1.ObjectMeta{Name: clusterInfoName},
			Spec:       apiv3.ClusterInformationSpec{DatastoreReady: &readyFalse},
		},
		Revision: "1",
	}

	// Reconcile the abort.
	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile (abort): %v", err)
	}

	// Verify migrated v3 resources were cleaned up.
	tier := &apiv3.Tier{}
	if err := c.rtClient.Get(c.ctx, types.NamespacedName{Name: "default"}, tier); !kerrors.IsNotFound(err) {
		t.Errorf("expected migrated tier 'default' to be deleted, err: %v", err)
	}
	gnp := &apiv3.GlobalNetworkPolicy{}
	if err := c.rtClient.Get(c.ctx, types.NamespacedName{Name: "test-policy"}, gnp); !kerrors.IsNotFound(err) {
		t.Errorf("expected migrated GNP 'test-policy' to be deleted, err: %v", err)
	}

	// Verify pre-existing v3 resource was NOT deleted.
	preexisting := &apiv3.Tier{}
	if err := c.rtClient.Get(c.ctx, types.NamespacedName{Name: "preexisting"}, preexisting); err != nil {
		t.Error("pre-existing tier 'preexisting' should NOT have been deleted during abort")
	}

	// Verify APIService was restored.
	restored, err := c.apiregClient.APIServices().Get(c.ctx, apiServiceName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected APIService to be restored, got: %v", err)
	}
	if restored.Spec.Service == nil || restored.Spec.Service.Name != "calico-api" {
		t.Errorf("restored APIService has wrong service: %v", restored.Spec.Service)
	}

	// Verify v1 ClusterInformation was restored to ready.
	ci, ok := bc.clusterInfo.Value.(*apiv3.ClusterInformation)
	if !ok {
		t.Fatalf("unexpected type: %T", bc.clusterInfo.Value)
	}
	if ci.Spec.DatastoreReady == nil || !*ci.Spec.DatastoreReady {
		t.Error("expected v1 ClusterInformation DatastoreReady=true after abort")
	}

	// The CR should be fully deleted (finalizer removed, DeletionTimestamp was set).
	dm := &DatastoreMigration{}
	if err := c.rtClient.Get(c.ctx, types.NamespacedName{Name: defaultMigrationName}, dm); !kerrors.IsNotFound(err) {
		t.Errorf("expected CR to be deleted after abort, got err: %v", err)
	}
}

// TestMigrateResourceType_EmptyList verifies that an empty v1 list produces an empty migration result.
func TestMigrateResourceType_EmptyList(t *testing.T) {
	ctx := context.Background()

	bc := &mockBackendClient{
		resources: map[string][]*model.KVPair{
			apiv3.KindTier: {},
		},
	}

	rtScheme := runtime.NewScheme()
	if err := apiv3.AddToScheme(rtScheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}
	fakeRT := fakertclient.NewClientBuilder().WithScheme(rtScheme).WithObjectTracker(k8stesting.NewObjectTracker(rtScheme, serializer.NewCodecFactory(rtScheme).UniversalDecoder())).Build()

	migrator := ResourceMigrator{
		Kind:         apiv3.KindTier,
		Order:        OrderTiers,
		V3Object:     func() rtclient.Object { return &apiv3.Tier{} },
		V3ObjectList: func() rtclient.ObjectList { return &apiv3.TierList{} },
		GetSpec:      func(obj rtclient.Object) any { return obj.(*apiv3.Tier).Spec },
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindTier)
		},
		Convert: func(kvp *model.KVPair) (rtclient.Object, error) {
			t.Fatal("Convert should not be called for empty list")
			return nil, nil
		},
	}

	result, err := MigrateResourceType(ctx, bc, fakeRT, migrator)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Migrated != 0 || result.Skipped != 0 || len(result.Conflicts) != 0 {
		t.Errorf("expected empty result for empty list, got migrated=%d skipped=%d conflicts=%d",
			result.Migrated, result.Skipped, len(result.Conflicts))
	}
}
