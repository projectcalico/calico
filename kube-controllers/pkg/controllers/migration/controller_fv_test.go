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
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	fakeapiregclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"
	"k8s.io/utils/ptr"
	rtclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

var (
	fvK8sClient     kubernetes.Interface
	fvDynamicClient dynamic.Interface
	fvCRDClient     apiextclient.Interface
	fvRTClient      rtclient.WithWatch
	fvTestEnv       *envtest.Environment
)

// repoRoot is the path from this package to the monorepo root.
const repoRoot = "../../../.."

// expectNoError fatally exits if err is non-nil. Used in TestMain where there
// is no *testing.T available.
func expectNoError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "envtest setup: %v\n", err)
		os.Exit(1)
	}
}

// TestMain starts a real kube-apiserver via envtest with all Calico CRDs
// installed (v3, v1, and DatastoreMigration). The apiserver runs for the
// lifetime of the test binary; individual tests get real API semantics
// (status subresources, finalizer/deletion, informers) without needing a
// full cluster.
func TestMain(m *testing.M) {
	fvTestEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join(repoRoot, "api", "config", "crd"),
			filepath.Join(repoRoot, "libcalico-go", "config", "crd"),
			filepath.Join(repoRoot, "kube-controllers", "pkg", "controllers", "migration", "crd"),
		},
	}

	cfg, err := fvTestEnv.Start()
	expectNoError(err)
	defer func() {
		expectNoError(fvTestEnv.Stop())
	}()

	scheme := runtime.NewScheme()
	expectNoError(clientgoscheme.AddToScheme(scheme))
	expectNoError(apiv3.AddToScheme(scheme))
	expectNoError(AddToScheme(scheme))

	fvRTClient, err = rtclient.NewWithWatch(cfg, rtclient.Options{Scheme: scheme})
	expectNoError(err)
	fvK8sClient, err = kubernetes.NewForConfig(cfg)
	expectNoError(err)
	fvDynamicClient, err = dynamic.NewForConfig(cfg)
	expectNoError(err)
	fvCRDClient, err = apiextclient.NewForConfig(cfg)
	expectNoError(err)

	os.Exit(m.Run())
}

// newAggregatedAPIServiceObj returns an aggregated (non-automanaged) APIService
// for v3.projectcalico.org, suitable for seeding the fake apiregistration client.
func newAggregatedAPIServiceObj() *apiregv1.APIService {
	return &apiregv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			Name: apiServiceName,
		},
		Spec: apiregv1.APIServiceSpec{
			Group:                "projectcalico.org",
			Version:              "v3",
			GroupPriorityMinimum: 1500,
			VersionPriority:      200,
			Service: &apiregv1.ServiceReference{
				Namespace: "calico-system",
				Name:      "calico-api",
			},
		},
	}
}

// TestLifecycle_Mainline exercises the full migration lifecycle against a real
// kube-apiserver: seed v1 resources in a mock backend, create a DatastoreMigration
// CR, and verify the controller drives through Pending → Migrating → Converged →
// Complete with correct v3 resources, OwnerRef remapping, progress tracking, and
// APIService save/delete behavior.
func TestLifecycle_Mainline(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	h := newFVHelper(t, g, ctx)

	bc := &mockBackendClient{
		resources:   mainlineV1Resources(),
		clusterInfo: mainlineV1ClusterInfo(),
	}

	// Fake APIService client (avoids envtest auto-recreating automanaged APIServices)
	fakeAPIReg := fakeapiregclient.NewSimpleClientset(newAggregatedAPIServiceObj())

	// Set up phase gate to observe intermediate states.
	gate := newPhaseGate(
		DatastoreMigrationPhaseMigrating,
		DatastoreMigrationPhaseConverged,
	)
	gatedClient := gate.wrapClient(fvRTClient)

	// Build and start the controller.
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })

	ctrl := NewController(ControllerConfig{
		Ctx:           ctx,
		K8sClient:     fvK8sClient,
		BackendClient: bc,
		RTClient:      gatedClient,
		DynamicClient: fvDynamicClient,
		APIRegClient:  fakeAPIReg.ApiregistrationV1(),
		CRDClient:     fvCRDClient,
		Migrators:     NewMigrators(bc, fvRTClient),
	})
	go ctrl.Run(stop)

	// Create the DatastoreMigration CR.
	dm := &DatastoreMigration{
		ObjectMeta: metav1.ObjectMeta{Name: defaultMigrationName},
		Spec:       DatastoreMigrationSpec{Type: DatastoreMigrationTypeAPIServerToCRDs},
	}
	g.Expect(fvRTClient.Create(ctx, dm)).To(Succeed())
	t.Cleanup(func() { cleanupMigrationResources(t, ctx) })

	// Phase: Migrating
	g.Expect(gate.waitForPhase(DatastoreMigrationPhaseMigrating, 10*time.Second)).To(Succeed())

	dm = h.expectPhase(DatastoreMigrationPhaseMigrating)
	g.Expect(dm.Status.StartedAt).NotTo(BeNil())
	g.Expect(hasFinalizer(dm)).To(BeTrue())

	gate.release(DatastoreMigrationPhaseMigrating)

	// Phase: Converged
	g.Expect(gate.waitForPhase(DatastoreMigrationPhaseConverged, 10*time.Second)).To(Succeed())
	dm = h.expectPhase(DatastoreMigrationPhaseConverged)

	// Tiers should exist in v3 with the internal annotation stripped.
	tier1 := &apiv3.Tier{}
	h.getV3Resource("default", tier1)
	g.Expect(tier1.Spec.Order).To(Equal(ptr.To(float64(100))))
	g.Expect(tier1.Annotations).NotTo(HaveKey("projectcalico.org/metadata"))

	tier2 := &apiv3.Tier{}
	h.getV3Resource("security", tier2)
	g.Expect(tier2.Spec.Order).To(Equal(ptr.To(float64(200))))

	// GNP should have default. prefix stripped.
	gnp := &apiv3.GlobalNetworkPolicy{}
	h.getV3Resource("deny-all", gnp)
	g.Expect(gnp.Spec.Selector).To(Equal("all()"))

	// OwnerRef UID should have been remapped to the v3 Tier's UID.
	g.Expect(gnp.OwnerReferences).To(HaveLen(1))
	g.Expect(gnp.OwnerReferences[0].Name).To(Equal("default"))
	g.Expect(gnp.OwnerReferences[0].UID).To(Equal(tier1.UID), "OwnerRef UID should be remapped to v3 Tier UID")

	// Progress tracking should be populated. All migrators are registered
	// but only the seeded types (Tier, GNP) produce resources; the rest
	// report zero.
	g.Expect(dm.Status.Progress.Migrated).To(Equal(3), "2 tiers + 1 GNP = 3 migrated")
	g.Expect(dm.Status.Progress.TypeDetails).To(HaveLen(len(NewMigrators(bc, fvRTClient))))

	// v3 ClusterInformation should have DatastoreReady=true (unlocked after converging).
	ci := &apiv3.ClusterInformation{}
	h.getV3Resource(clusterInfoName, ci)
	g.Expect(ci.Spec.DatastoreReady).To(Equal(ptr.To(true)))

	// APIService should have been deleted from the fake client.
	_, err := fakeAPIReg.ApiregistrationV1().APIServices().Get(ctx, apiServiceName, metav1.GetOptions{})
	g.Expect(err).To(HaveOccurred(), "APIService should have been deleted during migration")

	// Saved APIService annotation should be present on the CR.
	g.Expect(dm.Annotations).To(HaveKey(savedAPIServiceAnnotation))

	gate.release(DatastoreMigrationPhaseConverged)

	// Create calico-node DaemonSet and wait for Complete.
	h.createReadyCalicoNodeDS()

	g.Eventually(func(g Gomega) {
		fvh := newFVHelper(t, g, ctx)
		dm := fvh.expectPhase(DatastoreMigrationPhaseComplete)
		g.Expect(dm.Status.CompletedAt).NotTo(BeNil())
	}, 10*time.Second, 200*time.Millisecond).Should(Succeed())
}

// TestLifecycle_ConflictResolution verifies that when a v3 resource exists with
// a different spec than v1, the controller transitions to
// WaitingForConflictResolution with a Conflict condition, then proceeds through
// to Converged once the user fixes the conflict.
func TestLifecycle_ConflictResolution(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	h := newFVHelper(t, g, ctx)

	bc := &mockBackendClient{
		resources:   conflictV1Resources(),
		clusterInfo: mainlineV1ClusterInfo(),
	}

	// Pre-create a v3 Tier with a different spec than the v1 source.
	// This triggers conflict detection in handlePending.
	deny := apiv3.Deny
	conflictingTier := &apiv3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       apiv3.TierSpec{Order: ptr.To(float64(999)), DefaultAction: &deny},
	}
	g.Expect(fvRTClient.Create(ctx, conflictingTier)).To(Succeed())
	t.Cleanup(func() {
		if err := fvRTClient.Delete(ctx, &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "default"}}); err != nil {
			t.Logf("cleanup: deleting tier: %v", err)
		}
	})

	// Gate at WaitingForConflictResolution and Converged.
	gate := newPhaseGate(
		DatastoreMigrationPhaseWaitingForConflictResolution,
		DatastoreMigrationPhaseConverged,
	)
	startController(t, ctx, bc, gate)
	createMigrationCR(t, ctx)

	// Wait for the controller to detect the conflict.
	g.Expect(gate.waitForPhase(DatastoreMigrationPhaseWaitingForConflictResolution, 10*time.Second)).To(Succeed())

	dm := h.expectPhase(DatastoreMigrationPhaseWaitingForConflictResolution)
	g.Expect(dm.Status.Conditions).To(HaveLen(1))
	g.Expect(dm.Status.Conditions[0].Type).To(Equal(conditionTypeConflict))
	g.Expect(dm.Status.Conditions[0].Reason).To(Equal(conditionReasonResourceMismatch))
	g.Expect(dm.Status.Conditions[0].Message).To(ContainSubstring("Tier/default"))

	gate.release(DatastoreMigrationPhaseWaitingForConflictResolution)

	// Fix the conflict by updating the v3 Tier to match the v1 spec.
	tier := &apiv3.Tier{}
	h.getV3Resource("default", tier)
	tier.Spec.Order = ptr.To(float64(100))
	g.Expect(fvRTClient.Update(ctx, tier)).To(Succeed())

	// The controller should re-check, find no conflicts, transition through
	// Pending → Migrating → Converged.
	g.Expect(gate.waitForPhase(DatastoreMigrationPhaseConverged, 10*time.Second)).To(Succeed())
	dm = h.expectPhase(DatastoreMigrationPhaseConverged)

	// The previously-conflicting tier should now be skipped (specs match),
	// so Migrated=0, Skipped=1 for that type.
	g.Expect(dm.Status.Progress.Skipped).To(BeNumerically(">=", 1))

	// Conflict conditions should be cleared.
	g.Expect(dm.Status.Conditions).To(BeEmpty())

	gate.release(DatastoreMigrationPhaseConverged)

	// Complete the lifecycle.
	h.createReadyCalicoNodeDS()

	g.Eventually(func(g Gomega) {
		fvh := newFVHelper(t, g, ctx)
		fvh.expectPhase(DatastoreMigrationPhaseComplete)
	}, 10*time.Second, 200*time.Millisecond).Should(Succeed())
}
