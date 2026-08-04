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
	"errors"
	"testing"

	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/util/workqueue"
	fakeapiregclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"
	"k8s.io/utils/ptr"
	rtclient "sigs.k8s.io/controller-runtime/pkg/client"
	rtfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/migration/migrators"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// recordingMigrator is a no-op ResourceMigrator that records whether the
// migration actually reached the copy phase.
type recordingMigrator struct {
	listV1Called bool
}

func (r *recordingMigrator) Kind() string {
	return apiv3.KindTier
}

func (r *recordingMigrator) Order() int {
	return 1
}

func (r *recordingMigrator) ListV1(_ context.Context) ([]rtclient.Object, error) {
	r.listV1Called = true
	return nil, nil
}

func (r *recordingMigrator) GetV3(_ context.Context, _, _ string) (rtclient.Object, error) {
	return nil, nil
}

func (r *recordingMigrator) CreateV3(_ context.Context, _ rtclient.Object) error {
	return nil
}

func (r *recordingMigrator) UpdateV3(_ context.Context, _ rtclient.Object) error {
	return nil
}

func (r *recordingMigrator) ListV3(_ context.Context) ([]rtclient.Object, error) {
	return nil, nil
}

func (r *recordingMigrator) DeleteV3(_ context.Context, _ rtclient.Object) error {
	return nil
}

func (r *recordingMigrator) SpecsEqual(_, _ rtclient.Object) bool {
	return true
}

var _ migrators.ResourceMigrator = &recordingMigrator{}

// lockedV1ClusterInfo returns a v1 ClusterInformation KVPair with
// DatastoreReady=false, as it appears once migration has locked the datastore.
func lockedV1ClusterInfo() *model.KVPair {
	kvp := mainlineV1ClusterInfo()
	ci, ok := kvp.Value.(*apiv3.ClusterInformation)
	if !ok {
		panic("unexpected ClusterInformation type")
	}
	ci.Spec.DatastoreReady = ptr.To(false)
	return kvp
}

// v1DatastoreReady returns DatastoreReady from the v1 ClusterInformation the
// mock backend currently has stored.
func v1DatastoreReady(g Gomega, bc *mockBackendClient) *bool {
	kvp := bc.getClusterInfo()
	g.ExpectWithOffset(1, kvp).NotTo(BeNil())
	ci, ok := kvp.Value.(*apiv3.ClusterInformation)
	g.ExpectWithOffset(1, ok).To(BeTrue())
	return ci.Spec.DatastoreReady
}

// savedAPIServiceJSON serializes an aggregated APIService for the
// saved-apiservice annotation, so the abort path has something to restore.
func savedAPIServiceJSON(t *testing.T) string {
	t.Helper()
	data, err := json.Marshal(newAggregatedAPIServiceObj())
	if err != nil {
		t.Fatalf("marshalling APIService: %v", err)
	}
	return string(data)
}

// newErrorTestController builds a migration controller backed by a fake
// controller-runtime client, an empty fake apiregistration client, and a single
// recording migrator. It returns the controller plus both for assertions.
func newErrorTestController(
	t *testing.T,
	bc *mockBackendClient,
	dm *DatastoreMigration,
) (*migrationController, *fakeapiregclient.Clientset, *recordingMigrator) {
	t.Helper()

	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, apiv3.AddToScheme, AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatalf("building scheme: %v", err)
		}
	}

	rtCli := rtfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(dm).
		WithStatusSubresource(&DatastoreMigration{}).
		Build()

	rec := &recordingMigrator{}
	fakeAPIReg := fakeapiregclient.NewSimpleClientset()
	m := &migrationController{
		ctx:           context.Background(),
		backendClient: bc,
		rtClient:      rtCli,
		apiregClient:  fakeAPIReg.ApiregistrationV1(),
		migrators:     []migrators.ResourceMigrator{rec},
		queue:         workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}
	t.Cleanup(m.queue.ShutDown)
	return m, fakeAPIReg, rec
}

// migratingCR returns a DatastoreMigration CR in the Migrating phase with the
// finalizer and a saved APIService annotation.
func migratingCR(t *testing.T) *DatastoreMigration {
	t.Helper()
	return &DatastoreMigration{
		ObjectMeta: metav1.ObjectMeta{
			Name:        defaultMigrationName,
			Finalizers:  []string{finalizerName},
			Annotations: map[string]string{savedAPIServiceAnnotation: savedAPIServiceJSON(t)},
		},
		Spec:   DatastoreMigrationSpec{Type: DatastoreMigrationTypeAPIServerToCRDs},
		Status: DatastoreMigrationStatus{Phase: DatastoreMigrationPhaseMigrating},
	}
}

// TestLockDatastore_BackendUpdateError verifies that a failure to lock the v1
// ClusterInformation aborts the Migrating phase and is retried, rather than
// letting the migration copy the datastore while CNI can still allocate IPs.
func TestLockDatastore_BackendUpdateError(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	bc := &mockBackendClient{
		clusterInfo:          mainlineV1ClusterInfo(),
		clusterInfoUpdateErr: errors.New("simulated backend unavailable"),
	}
	m, _, rec := newErrorTestController(t, bc, migratingCR(t))

	m.queue.Add(defaultMigrationName)
	g.Expect(m.processNextWorkItem()).To(BeTrue())

	g.Expect(rec.listV1Called).To(BeFalse(), "no migrator should run while the v1 lock is unset")
	g.Expect(m.queue.NumRequeues(defaultMigrationName)).To(Equal(1), "the failure should be retried, not dropped")

	dm := &DatastoreMigration{}
	g.Expect(m.rtClient.Get(ctx, types.NamespacedName{Name: defaultMigrationName}, dm)).To(Succeed())
	g.Expect(dm.Status.Phase).To(Equal(DatastoreMigrationPhaseMigrating))
	g.Expect(dm.Status.Message).To(ContainSubstring("locking v1 ClusterInformation"))
	g.Expect(dm.Status.Message).To(ContainSubstring("simulated backend unavailable"))

	g.Expect(v1DatastoreReady(g, bc)).To(Equal(ptr.To(true)), "a failed lock must not record the datastore as locked")
}

// TestAbort_BackendUpdateError verifies that a failure to unlock the v1
// ClusterInformation during abort holds the finalizer and leaves the APIService
// unrestored, so the workqueue can retry the unlock.
func TestAbort_BackendUpdateError(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	bc := &mockBackendClient{
		clusterInfo:          lockedV1ClusterInfo(),
		clusterInfoUpdateErr: cerrors.ErrorResourceUpdateConflict{Identifier: clusterInfoName},
	}
	m, fakeAPIReg, _ := newErrorTestController(t, bc, migratingCR(t))

	dm := &DatastoreMigration{}
	g.Expect(m.rtClient.Get(ctx, types.NamespacedName{Name: defaultMigrationName}, dm)).To(Succeed())
	g.Expect(m.rtClient.Delete(ctx, dm)).To(Succeed())

	m.queue.Add(defaultMigrationName)
	g.Expect(m.processNextWorkItem()).To(BeTrue())

	g.Expect(m.queue.NumRequeues(defaultMigrationName)).To(Equal(1), "the failed unlock should be retried")

	g.Expect(m.rtClient.Get(ctx, types.NamespacedName{Name: defaultMigrationName}, dm)).To(Succeed())
	g.Expect(hasFinalizer(dm)).To(BeTrue(), "finalizer must hold until v1 is unlocked")

	_, err := fakeAPIReg.ApiregistrationV1().APIServices().Get(ctx, apiServiceName, metav1.GetOptions{})
	g.Expect(kerrors.IsNotFound(err)).To(BeTrue(), "APIService must not be restored while v1 is still locked")

	g.Expect(v1DatastoreReady(g, bc)).To(Equal(ptr.To(false)), "a failed unlock must not record the datastore as unlocked")
}

// TestAbort_V1ClusterInfoDoesNotExist verifies that a missing v1
// ClusterInformation is tolerated: there is nothing to unlock, so the abort
// restores the APIService and drops the finalizer.
func TestAbort_V1ClusterInfoDoesNotExist(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	bc := &mockBackendClient{
		clusterInfoGetErr: cerrors.ErrorResourceDoesNotExist{Identifier: clusterInfoName},
	}
	m, fakeAPIReg, _ := newErrorTestController(t, bc, migratingCR(t))

	dm := &DatastoreMigration{}
	g.Expect(m.rtClient.Get(ctx, types.NamespacedName{Name: defaultMigrationName}, dm)).To(Succeed())
	g.Expect(m.rtClient.Delete(ctx, dm)).To(Succeed())

	m.queue.Add(defaultMigrationName)
	g.Expect(m.processNextWorkItem()).To(BeTrue())

	g.Expect(m.queue.NumRequeues(defaultMigrationName)).To(Equal(0), "abort should have succeeded")

	err := m.rtClient.Get(ctx, types.NamespacedName{Name: defaultMigrationName}, &DatastoreMigration{})
	g.Expect(kerrors.IsNotFound(err)).To(BeTrue(), "finalizer should be removed so the CR is collected")

	apiSvc, err := fakeAPIReg.ApiregistrationV1().APIServices().Get(ctx, apiServiceName, metav1.GetOptions{})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(apiSvc.Spec.Service).NotTo(BeNil())
}
