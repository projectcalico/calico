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
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"
	fakeapiregclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"
	rtclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// fvHelper bundles the gomega instance, context, and testing.T for FV test
// assertions. Methods use ExpectWithOffset so failures report the caller's
// line number.
type fvHelper struct {
	t   *testing.T
	g   Gomega
	ctx context.Context
}

// newFVHelper creates an fvHelper for use in a test function.
func newFVHelper(t *testing.T, g Gomega, ctx context.Context) *fvHelper {
	t.Helper()
	return &fvHelper{t: t, g: g, ctx: ctx}
}

// getMigration fetches the DatastoreMigration CR by the well-known name.
func (h *fvHelper) getMigration() *DatastoreMigration {
	dm := &DatastoreMigration{}
	h.g.ExpectWithOffset(1, fvRTClient.Get(h.ctx, types.NamespacedName{Name: defaultMigrationName}, dm)).To(Succeed())
	return dm
}

// expectPhase fetches the CR and asserts its phase matches.
func (h *fvHelper) expectPhase(phase DatastoreMigrationPhase) *DatastoreMigration {
	dm := h.getMigration()
	h.g.ExpectWithOffset(1, dm.Status.Phase).To(Equal(phase))
	return dm
}

// getV3Resource fetches a cluster-scoped v3 resource by name.
func (h *fvHelper) getV3Resource(name string, obj rtclient.Object) {
	h.g.ExpectWithOffset(1, fvRTClient.Get(h.ctx, types.NamespacedName{Name: name}, obj)).To(Succeed())
}

// createReadyCalicoNodeDS creates a calico-node DaemonSet with
// CALICO_API_GROUP=projectcalico.org/v3 and a fully-rolled-out status.
func (h *fvHelper) createReadyCalicoNodeDS() {
	installNS := "calico-system"
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: installNS}}
	h.g.ExpectWithOffset(1, rtclient.IgnoreAlreadyExists(fvRTClient.Create(h.ctx, ns))).To(Succeed())
	h.t.Cleanup(func() {
		if err := fvRTClient.Delete(h.ctx, &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "calico-node", Namespace: installNS}}); err != nil {
			h.t.Logf("cleanup: deleting calico-node DaemonSet: %v", err)
		}
	})

	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "calico-node",
			Namespace:  installNS,
			Generation: 1,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "calico-node"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"k8s-app": "calico-node"}},
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
	}
	h.g.ExpectWithOffset(1, fvRTClient.Create(h.ctx, ds)).To(Succeed())

	ds.Status = appsv1.DaemonSetStatus{
		ObservedGeneration:     ds.Generation,
		DesiredNumberScheduled: 1,
		CurrentNumberScheduled: 1,
		UpdatedNumberScheduled: 1,
		NumberAvailable:        1,
		NumberReady:            1,
	}
	h.g.ExpectWithOffset(1, fvRTClient.Status().Update(h.ctx, ds)).To(Succeed())
}

// startController creates a migration controller with a fake APIService client
// and the given phase gate wrapping the rtClient. It starts the controller in a
// goroutine and registers cleanup to stop it when the test ends. Returns the
// fake apiregistration client for assertions on APIService state.
func startController(
	t *testing.T,
	ctx context.Context,
	bc *mockBackendClient,
	gate *phaseGate,
) *fakeapiregclient.Clientset {
	t.Helper()
	fakeAPIReg := fakeapiregclient.NewSimpleClientset(newAggregatedAPIServiceObj()) //nolint:staticcheck // NewClientset not available for kube-aggregator

	rt := rtclient.WithWatch(fvRTClient)
	if gate != nil {
		rt = gate.wrapClient(fvRTClient)
	}

	ctrl := NewController(ControllerConfig{
		Ctx:                 ctx,
		K8sClient:           fvK8sClient,
		BackendClient:       bc,
		RTClient:            rt,
		DynamicClient:       fvDynamicClient,
		APIRegClient:        fakeAPIReg.ApiregistrationV1(),
		CRDClient:           fvCRDClient,
		Migrators:           NewMigrators(bc, fvRTClient),
		WaitingPollInterval: 500 * time.Millisecond,
		DrainPeriod:         100 * time.Millisecond,
		RestartFunc:         func() {},
	})

	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go ctrl.Run(stop)
	return fakeAPIReg
}

// Side effects recorded by orderLog.
const (
	eventLockV1           = "lockV1"
	eventLockV3           = "lockV3"
	eventDeleteAPIService = "deleteAPIService"
)

// orderLog records the order in which the controller performs its side effects,
// so tests can assert on sequencing rather than just the end state.
type orderLog struct {
	mu     sync.Mutex
	events []string
}

func (l *orderLog) record(event string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}

func (l *orderLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

// recordingAPIRegClient returns a fake apiregistration client seeded with an
// aggregated APIService that logs deletes to the given order log.
func recordingAPIRegClient(log *orderLog) *fakeapiregclient.Clientset {
	c := fakeapiregclient.NewSimpleClientset(newAggregatedAPIServiceObj())
	c.PrependReactor("delete", "apiservices", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		log.record(eventDeleteAPIService)
		return false, nil, nil
	})
	return c
}

// recordingRTClient wraps a client so that locking the v3 ClusterInformation
// (DatastoreReady=false) is written to the given order log.
func recordingRTClient(c rtclient.WithWatch, log *orderLog) rtclient.WithWatch {
	recordLock := func(obj rtclient.Object) {
		ci, ok := obj.(*apiv3.ClusterInformation)
		if ok && ci.Spec.DatastoreReady != nil && !*ci.Spec.DatastoreReady {
			log.record(eventLockV3)
		}
	}
	return interceptor.NewClient(c, interceptor.Funcs{
		Create: func(ctx context.Context, client rtclient.WithWatch, obj rtclient.Object, opts ...rtclient.CreateOption) error {
			if err := client.Create(ctx, obj, opts...); err != nil {
				return err
			}
			recordLock(obj)
			return nil
		},
		Update: func(ctx context.Context, client rtclient.WithWatch, obj rtclient.Object, opts ...rtclient.UpdateOption) error {
			if err := client.Update(ctx, obj, opts...); err != nil {
				return err
			}
			recordLock(obj)
			return nil
		},
	})
}

// newTestController builds a migration controller that tests drive by calling
// phase handlers directly, bypassing the informer and workqueue.
func newTestController(
	ctx context.Context,
	bc *mockBackendClient,
	apiReg *fakeapiregclient.Clientset,
	rt rtclient.WithWatch,
	drainPeriod time.Duration,
) *migrationController {
	return &migrationController{
		ctx:                 ctx,
		k8sClient:           fvK8sClient,
		backendClient:       bc,
		rtClient:            rt,
		dynamicClient:       fvDynamicClient,
		apiregClient:        apiReg.ApiregistrationV1(),
		migrators:           NewMigrators(bc, fvRTClient),
		waitingPollInterval: 500 * time.Millisecond,
		drainPeriod:         drainPeriod,
		restartFunc:         func() {},
	}
}

// createMigrationCR creates the well-known DatastoreMigration CR and registers
// a cleanup to delete it (and all migrated resources) when the test ends.
func createMigrationCR(t *testing.T, ctx context.Context) {
	t.Helper()
	dm := &DatastoreMigration{
		ObjectMeta: metav1.ObjectMeta{Name: defaultMigrationName},
		Spec:       DatastoreMigrationSpec{Type: DatastoreMigrationTypeAPIServerToCRDs},
	}
	if err := fvRTClient.Create(ctx, dm); err != nil {
		t.Fatalf("creating DatastoreMigration CR: %v", err)
	}
	t.Cleanup(func() { cleanupMigrationResources(t, ctx) })
}

// cleanupMigrationResources removes the DatastoreMigration CR (stripping its
// finalizer first so deletion isn't blocked) and all v3 Calico resources that
// may have been created during migration.
func cleanupMigrationResources(t *testing.T, ctx context.Context) {
	t.Helper()

	// Strip the finalizer so the CR can be deleted even if the controller
	// is already stopped. Retry on conflict since the controller may still
	// be writing to the CR.
	for range 5 {
		dm := &DatastoreMigration{}
		if err := fvRTClient.Get(ctx, types.NamespacedName{Name: defaultMigrationName}, dm); err != nil {
			break
		}
		dm.Finalizers = nil
		if err := fvRTClient.Update(ctx, dm); err != nil {
			t.Logf("cleanup: removing finalizer (will retry): %v", err)
			continue
		}
		if err := fvRTClient.Delete(ctx, dm); err != nil {
			t.Logf("cleanup: deleting DatastoreMigration: %v", err)
		}
		break
	}

	for _, err := range []error{
		fvRTClient.DeleteAllOf(ctx, &apiv3.Tier{}),
		fvRTClient.DeleteAllOf(ctx, &apiv3.GlobalNetworkPolicy{}),
		fvRTClient.DeleteAllOf(ctx, &apiv3.ClusterInformation{}),
	} {
		if err != nil {
			t.Logf("cleanup: %v", err)
		}
	}
}
