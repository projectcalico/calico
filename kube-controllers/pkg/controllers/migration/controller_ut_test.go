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

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	calicofake "github.com/projectcalico/api/pkg/client/clientset_generated/clientset/fake"
	log "github.com/sirupsen/logrus"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakedynamic "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	fakeapiregclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// testController creates a migrationController with fake clients for unit testing.
func testController(t *testing.T, objects ...runtime.Object) (*migrationController, *fakedynamic.FakeDynamicClient) {
	t.Helper()

	scheme := runtime.NewScheme()
	scheme.AddKnownTypeWithName(
		schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}.GroupVersion().WithKind("CustomResourceDefinitionList"),
		&unstructured.UnstructuredList{},
	)
	scheme.AddKnownTypeWithName(
		DatastoreMigrationGVR.GroupVersion().WithKind("DatastoreMigration"),
		&unstructured.Unstructured{},
	)
	scheme.AddKnownTypeWithName(
		DatastoreMigrationGVR.GroupVersion().WithKind("DatastoreMigrationList"),
		&unstructured.UnstructuredList{},
	)

	dynClient := fakedynamic.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			DatastoreMigrationGVR: "DatastoreMigrationList",
			crdGVR:                "CustomResourceDefinitionList",
		},
		objects...,
	)

	k8sClient := fake.NewSimpleClientset()
	apiregCS := fakeapiregclient.NewSimpleClientset()
	bc := &mockBackendClient{
		resources: make(map[string][]*model.KVPair),
	}

	calicoCli := calicofake.NewSimpleClientset()

	c := &migrationController{
		ctx:           context.Background(),
		k8sClient:     k8sClient,
		backendClient: bc,
		v3Client:      calicoCli.ProjectcalicoV3(),
		dynamicClient: dynClient,
		apiregClient:  apiregCS.ApiregistrationV1(),
		migClient:     newMigrationClient(dynClient),
	}
	return c, dynClient
}

// createTestCR creates a DatastoreMigration CR as unstructured for the fake dynamic client.
func createTestCR(t *testing.T, name string, phase DatastoreMigrationPhase) *unstructured.Unstructured {
	t.Helper()
	dm := &DatastoreMigration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: Group + "/" + Version,
			Kind:       "DatastoreMigration",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: DatastoreMigrationSpec{
			Type: DatastoreMigrationTypeV1ToV3,
		},
	}
	if phase != "" {
		dm.Status.Phase = phase
	}
	uns, err := toUnstructured(dm)
	if err != nil {
		t.Fatalf("failed to create test CR: %v", err)
	}
	return uns
}

// createTestCRWithDeletion creates a DatastoreMigration CR with a finalizer and deletion timestamp.
func createTestCRWithDeletion(t *testing.T, name string, phase DatastoreMigrationPhase) *unstructured.Unstructured {
	t.Helper()
	now := metav1.Now()
	dm := &DatastoreMigration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: Group + "/" + Version,
			Kind:       "DatastoreMigration",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Finalizers:        []string{finalizerName},
			DeletionTimestamp: &now,
		},
		Spec: DatastoreMigrationSpec{
			Type: DatastoreMigrationTypeV1ToV3,
		},
	}
	dm.Status.Phase = phase
	uns, err := toUnstructured(dm)
	if err != nil {
		t.Fatalf("failed to create test CR with deletion: %v", err)
	}
	return uns
}

// createV1CRD creates a fake v1 CRD as unstructured for pre-validation tests.
func createV1CRD(name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apiextensions.k8s.io/v1",
			"kind":       "CustomResourceDefinition",
			"metadata": map[string]interface{}{
				"name": name,
			},
			"spec": map[string]interface{}{
				"group": "crd.projectcalico.org",
			},
		},
	}
}

func testLogEntry() *log.Entry {
	return log.WithField("test", true)
}

func TestReconcile_NoCR(t *testing.T) {
	c, _ := testController(t)

	// No CR exists — reconcile should be a no-op.
	if err := c.reconcile(); err != nil {
		t.Fatalf("expected no error when no CR exists, got: %v", err)
	}
}

func TestReconcile_PendingToMigrating(t *testing.T) {
	cr := createTestCR(t, defaultMigrationName, "")
	v1CRD := createV1CRD("bgppeers.crd.projectcalico.org")

	c, _ := testController(t, cr, v1CRD)

	// First reconcile: adds finalizer.
	if err := c.reconcile(); err != nil {
		t.Fatalf("first reconcile (add finalizer) failed: %v", err)
	}

	dm, err := c.migClient.Get(c.ctx, defaultMigrationName)
	if err != nil {
		t.Fatalf("getting CR after first reconcile: %v", err)
	}
	if !hasFinalizer(dm) {
		t.Error("expected finalizer to be added after first reconcile")
	}

	// Second reconcile: pre-validation passes, transitions through
	// Migrating to Converged (no resources to migrate with empty registry).
	if err := c.reconcile(); err != nil {
		t.Fatalf("second reconcile failed: %v", err)
	}

	dm, err = c.migClient.Get(c.ctx, defaultMigrationName)
	if err != nil {
		t.Fatalf("getting CR after second reconcile: %v", err)
	}

	// With no registered migrators, the controller runs through the entire
	// migration in a single reconcile: Pending -> Migrating -> Converged.
	if dm.Status.Phase != DatastoreMigrationPhaseConverged {
		t.Errorf("expected phase Converged (no resources to migrate), got %s", dm.Status.Phase)
	}
	if dm.Status.StartedAt == nil {
		t.Error("expected StartedAt to be set")
	}
}

func TestReconcile_CompleteIsNoOp(t *testing.T) {
	cr := createTestCR(t, defaultMigrationName, DatastoreMigrationPhaseComplete)
	c, _ := testController(t, cr)

	if err := c.reconcile(); err != nil {
		t.Fatalf("expected no error for Complete phase, got: %v", err)
	}

	dm, err := c.migClient.Get(c.ctx, defaultMigrationName)
	if err != nil {
		t.Fatalf("getting CR: %v", err)
	}
	if dm.Status.Phase != DatastoreMigrationPhaseComplete {
		t.Errorf("expected phase Complete, got %s", dm.Status.Phase)
	}
}

func TestReconcile_FailedIsNoOp(t *testing.T) {
	cr := createTestCR(t, defaultMigrationName, DatastoreMigrationPhaseFailed)
	c, _ := testController(t, cr)

	if err := c.reconcile(); err != nil {
		t.Fatalf("expected no error for Failed phase, got: %v", err)
	}

	dm, err := c.migClient.Get(c.ctx, defaultMigrationName)
	if err != nil {
		t.Fatalf("getting CR: %v", err)
	}
	if dm.Status.Phase != DatastoreMigrationPhaseFailed {
		t.Errorf("expected phase Failed, got %s", dm.Status.Phase)
	}
}

func TestPreValidation_NoV1CRDs(t *testing.T) {
	cr := createTestCR(t, defaultMigrationName, "")
	c, _ := testController(t, cr)

	// First reconcile adds the finalizer.
	if err := c.reconcile(); err != nil {
		t.Fatalf("first reconcile failed: %v", err)
	}

	// Second reconcile runs pre-validation — no v1 CRDs should cause Failed.
	if err := c.reconcile(); err != nil {
		t.Fatalf("second reconcile failed: %v", err)
	}

	dm, err := c.migClient.Get(c.ctx, defaultMigrationName)
	if err != nil {
		t.Fatalf("getting CR: %v", err)
	}

	if dm.Status.Phase != DatastoreMigrationPhaseFailed {
		t.Errorf("expected Failed phase when no v1 CRDs exist, got %s", dm.Status.Phase)
	}

	// Check for appropriate condition message.
	found := false
	for _, cond := range dm.Status.Conditions {
		if cond.Type == conditionTypeFailed && cond.Reason == conditionReasonMigrationError {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Failed condition with MigrationError reason")
	}
}

func TestPreValidation_AutomanagedAPIService(t *testing.T) {
	cr := createTestCR(t, defaultMigrationName, "")
	v1CRD := createV1CRD("bgppeers.crd.projectcalico.org")

	c, _ := testController(t, cr, v1CRD)

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

	// First reconcile adds the finalizer.
	if err := c.reconcile(); err != nil {
		t.Fatalf("first reconcile failed: %v", err)
	}

	// Second reconcile should fail because APIService is automanaged.
	if err := c.reconcile(); err != nil {
		t.Fatalf("second reconcile failed: %v", err)
	}

	dm, err := c.migClient.Get(c.ctx, defaultMigrationName)
	if err != nil {
		t.Fatalf("getting CR: %v", err)
	}

	if dm.Status.Phase != DatastoreMigrationPhaseFailed {
		t.Errorf("expected Failed phase for automanaged APIService, got %s", dm.Status.Phase)
	}
}

func TestLockDatastore(t *testing.T) {
	c, _ := testController(t)

	// Set up v1 ClusterInformation via backend client mock.
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

	logCtx := testLogEntry()
	if err := c.lockDatastore(logCtx); err != nil {
		t.Fatalf("lockDatastore failed: %v", err)
	}

	// Verify v3 ClusterInformation was created with DatastoreReady=false.
	v3ci, err := c.v3Client.ClusterInformations().Get(c.ctx, clusterInfoName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting v3 ClusterInformation: %v", err)
	}
	if v3ci.Spec.DatastoreReady == nil || *v3ci.Spec.DatastoreReady {
		t.Error("expected v3 ClusterInformation DatastoreReady=false after lock")
	}

	// Verify v1 was locked.
	ci := bc.clusterInfo.Value.(*apiv3.ClusterInformation)
	if ci.Spec.DatastoreReady == nil || *ci.Spec.DatastoreReady {
		t.Error("expected v1 ClusterInformation DatastoreReady=false after lock")
	}
}

func TestUnlockDatastore(t *testing.T) {
	c, _ := testController(t)

	// Pre-create v3 ClusterInformation as locked.
	ready := false
	_, err := c.v3Client.ClusterInformations().Create(c.ctx, &apiv3.ClusterInformation{
		ObjectMeta: metav1.ObjectMeta{Name: clusterInfoName},
		Spec:       apiv3.ClusterInformationSpec{DatastoreReady: &ready},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("creating v3 ClusterInformation: %v", err)
	}

	// Set up v1 as locked.
	bc := c.backendClient.(*mockBackendClient)
	bc.clusterInfo = &model.KVPair{
		Key: model.ResourceKey{Kind: apiv3.KindClusterInformation, Name: clusterInfoName},
		Value: &apiv3.ClusterInformation{
			ObjectMeta: metav1.ObjectMeta{Name: clusterInfoName},
			Spec:       apiv3.ClusterInformationSpec{DatastoreReady: &ready},
		},
		Revision: "1",
	}

	logCtx := testLogEntry()
	if err := c.unlockDatastore(logCtx); err != nil {
		t.Fatalf("unlockDatastore failed: %v", err)
	}

	// Verify v3 was unlocked.
	v3ci, err := c.v3Client.ClusterInformations().Get(c.ctx, clusterInfoName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting v3 ClusterInformation: %v", err)
	}
	if v3ci.Spec.DatastoreReady == nil || !*v3ci.Spec.DatastoreReady {
		t.Error("expected v3 ClusterInformation DatastoreReady=true after unlock")
	}

	// Verify v1 was unlocked.
	ci := bc.clusterInfo.Value.(*apiv3.ClusterInformation)
	if ci.Spec.DatastoreReady == nil || !*ci.Spec.DatastoreReady {
		t.Error("expected v1 ClusterInformation DatastoreReady=true after unlock")
	}
}

func TestHandleDeletion_Complete(t *testing.T) {
	cr := createTestCRWithDeletion(t, defaultMigrationName, DatastoreMigrationPhaseComplete)
	c, _ := testController(t, cr)

	// Reconcile should run the completed cleanup path (delete v1 CRDs).
	if err := c.reconcile(); err != nil {
		t.Fatalf("reconcile for Complete deletion failed: %v", err)
	}

	// The CR should have its finalizer removed.
	dm, err := c.migClient.Get(c.ctx, defaultMigrationName)
	if err != nil {
		t.Fatalf("getting CR: %v", err)
	}
	if hasFinalizer(dm) {
		t.Error("expected finalizer to be removed after completed cleanup")
	}
}

func TestHandleDeletion_Abort(t *testing.T) {
	cr := createTestCRWithDeletion(t, defaultMigrationName, DatastoreMigrationPhaseMigrating)
	c, _ := testController(t, cr)

	// Set up v1 backend mock as locked.
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
		t.Fatalf("reconcile for abort failed: %v", err)
	}

	dm, err := c.migClient.Get(c.ctx, defaultMigrationName)
	if err != nil {
		t.Fatalf("getting CR: %v", err)
	}
	if hasFinalizer(dm) {
		t.Error("expected finalizer to be removed after abort")
	}

	// Verify v1 ClusterInformation was restored to ready.
	ci := bc.clusterInfo.Value.(*apiv3.ClusterInformation)
	if ci.Spec.DatastoreReady == nil || !*ci.Spec.DatastoreReady {
		t.Error("expected v1 ClusterInformation DatastoreReady=true after abort")
	}
}

func TestMigrateResourceType_TransientError(t *testing.T) {
	ctx := context.Background()

	bc := &mockBackendClient{
		resources: map[string][]*model.KVPair{
			apiv3.KindTier: {
				{
					Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "default"},
					Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: apiv3.TierSpec{Order: floatPtr(100)}},
				},
			},
		},
	}

	calls := 0
	migrator := ResourceMigrator{
		Kind:  apiv3.KindTier,
		Order: OrderTiers,
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindTier)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.Tier)
			return &apiv3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			calls++
			if calls == 1 {
				return kerrors.NewServiceUnavailable("transient")
			}
			return nil
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			return nil, nil
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return false
		},
	}

	result, err := MigrateResourceType(ctx, bc, migrator)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Migrated != 1 {
		t.Errorf("expected 1 migrated after retry, got %d", result.Migrated)
	}
	if calls < 2 {
		t.Errorf("expected at least 2 CreateV3 calls (initial + retry), got %d", calls)
	}
}

func TestMigrateResourceType_ContentMatch(t *testing.T) {
	ctx := context.Background()

	action := apiv3.Action("Deny")
	originalSpec := apiv3.TierSpec{Order: floatPtr(42), DefaultAction: &action}
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

	var createdObj metav1.Object
	migrator := ResourceMigrator{
		Kind:  apiv3.KindTier,
		Order: OrderTiers,
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindTier)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.Tier)
			v3 := &apiv3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			createdObj = obj
			return nil
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			return nil, nil
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return false
		},
	}

	result, err := MigrateResourceType(ctx, bc, migrator)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Migrated != 1 {
		t.Fatalf("expected 1 migrated, got %d", result.Migrated)
	}

	// Verify the created object matches the original.
	tier := createdObj.(*apiv3.Tier)
	if tier.Name != "my-tier" {
		t.Errorf("expected name my-tier, got %s", tier.Name)
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
	if tier.Annotations["note"] != "important" {
		t.Errorf("expected annotation note=important, got %v", tier.Annotations)
	}
}

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

	migrator := ResourceMigrator{
		Kind:  apiv3.KindTier,
		Order: OrderTiers,
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindTier)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			return nil, fmt.Errorf("intentional convert error")
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			t.Fatal("CreateV3 should not be called when Convert fails")
			return nil
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			return nil, nil
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return false
		},
	}

	_, err := MigrateResourceType(ctx, bc, migrator)
	if err == nil {
		t.Fatal("expected error from Convert failure")
	}
}

func TestMigrateResourceType_EmptyList(t *testing.T) {
	ctx := context.Background()

	bc := &mockBackendClient{
		resources: map[string][]*model.KVPair{
			apiv3.KindTier: {},
		},
	}

	migrator := ResourceMigrator{
		Kind:  apiv3.KindTier,
		Order: OrderTiers,
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindTier)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			t.Fatal("Convert should not be called for empty list")
			return nil, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			t.Fatal("CreateV3 should not be called for empty list")
			return nil
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			return nil, nil
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return false
		},
	}

	result, err := MigrateResourceType(ctx, bc, migrator)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Migrated != 0 || result.Skipped != 0 || len(result.Conflicts) != 0 {
		t.Errorf("expected empty result for empty list, got migrated=%d skipped=%d conflicts=%d",
			result.Migrated, result.Skipped, len(result.Conflicts))
	}
}
