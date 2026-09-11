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
	"sync/atomic"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	fakeapiregclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/fake"

	migrationv1 "github.com/projectcalico/calico/kube-controllers/pkg/apis/migration/v1"
)

// apiServicesGVR addresses APIServices in the fake clientset's object tracker.
var apiServicesGVR = apiregv1.SchemeGroupVersion.WithResource("apiservices")

// newAutomanagedAPIServiceObj returns the CRD-backed APIService that
// kube-aggregator's autoregister controller maintains for v3.projectcalico.org
// while the v3 CRDs are installed.
func newAutomanagedAPIServiceObj() *apiregv1.APIService {
	return &apiregv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			Name:   apiServiceName,
			Labels: map[string]string{automanagedLabel: "true"},
		},
		Spec: apiregv1.APIServiceSpec{
			Group:                "projectcalico.org",
			Version:              "v3",
			GroupPriorityMinimum: 1000,
			VersionPriority:      100,
		},
	}
}

// autoregisteringAPIRegClient models kube-aggregator's autoregister controller:
// deleting v3.projectcalico.org puts an automanaged, CRD-backed APIService
// straight back. The counter reports how often that happened.
func autoregisteringAPIRegClient(objects ...runtime.Object) (*fakeapiregclient.Clientset, *atomic.Int32) {
	c := fakeapiregclient.NewSimpleClientset(objects...)
	recreations := &atomic.Int32{}

	c.PrependReactor("delete", "apiservices", func(action k8stesting.Action) (bool, runtime.Object, error) {
		del, ok := action.(k8stesting.DeleteAction)
		if !ok || del.GetName() != apiServiceName {
			return false, nil, nil
		}
		if _, err := c.Tracker().Get(apiServicesGVR, "", del.GetName()); err != nil {
			return true, nil, err
		}
		if err := c.Tracker().Delete(apiServicesGVR, "", del.GetName()); err != nil {
			return true, nil, err
		}
		recreations.Add(1)
		return true, nil, c.Tracker().Add(newAutomanagedAPIServiceObj())
	})

	return c, recreations
}

// TestAbort_RestoresAPIServiceAgainstAutoregister covers CORE-13612. The abort
// has to hand v3.projectcalico.org back to the aggregated API server even
// though the v3 CRDs are still installed, so autoregister keeps re-creating a
// CRD-backed one.
func TestAbort_RestoresAPIServiceAgainstAutoregister(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	bc := &mockBackendClient{clusterInfo: lockedV1ClusterInfo()}
	m, _, _ := newErrorTestController(t, bc, migratingCR(t))

	// The forward path already replaced the aggregated APIService with the
	// automanaged one, which is the state the abort has to undo.
	apiReg, recreations := autoregisteringAPIRegClient(newAutomanagedAPIServiceObj())
	m.apiregClient = apiReg.ApiregistrationV1()

	dm := &migrationv1.DatastoreMigration{}
	g.Expect(m.rtClient.Get(ctx, dmKey, dm)).To(Succeed())
	g.Expect(m.rtClient.Delete(ctx, dm)).To(Succeed())

	m.queue.Add(defaultMigrationName)
	g.Expect(m.processNextWorkItem()).To(BeTrue())
	g.Expect(m.queue.NumRequeues(defaultMigrationName)).To(Equal(0), "abort should have succeeded")

	apiSvc, err := apiReg.ApiregistrationV1().APIServices().Get(ctx, apiServiceName, metav1.GetOptions{})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(apiSvc.Labels).NotTo(HaveKey(automanagedLabel), "the restored APIService must not stay CRD-backed")
	g.Expect(apiSvc.Spec.Service).To(Equal(&apiregv1.ServiceReference{Namespace: "calico-system", Name: "calico-api"}))
	g.Expect(recreations.Load()).To(BeZero(), "the restore must not delete the APIService — autoregister puts a CRD-backed one straight back")
}

// TestRestoreAPIService pins the branches that must keep working alongside the
// in-place overwrite.
func TestRestoreAPIService(t *testing.T) {
	ctx := context.Background()
	logCtx := logrus.WithField("test", t.Name())

	t.Run("leaves an already-aggregated APIService alone", func(t *testing.T) {
		g := NewWithT(t)

		live := newAggregatedAPIServiceObj()
		live.Spec.GroupPriorityMinimum = 4242
		apiReg, _ := autoregisteringAPIRegClient(live)
		m := &migrationController{ctx: ctx, apiregClient: apiReg.ApiregistrationV1()}

		g.Expect(m.restoreAPIService(logCtx, migratingCR(t))).To(Succeed())

		apiSvc, err := apiReg.ApiregistrationV1().APIServices().Get(ctx, apiServiceName, metav1.GetOptions{})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(apiSvc.Spec.GroupPriorityMinimum).To(Equal(int32(4242)), "whoever re-registered the APIService should win over the saved copy")
	})

	t.Run("creates the saved APIService when none exists", func(t *testing.T) {
		g := NewWithT(t)

		apiReg, _ := autoregisteringAPIRegClient()
		m := &migrationController{ctx: ctx, apiregClient: apiReg.ApiregistrationV1()}

		g.Expect(m.restoreAPIService(logCtx, migratingCR(t))).To(Succeed())

		apiSvc, err := apiReg.ApiregistrationV1().APIServices().Get(ctx, apiServiceName, metav1.GetOptions{})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(apiSvc.Spec.Service).NotTo(BeNil())
	})

	t.Run("leaves the CRD-backed APIService in place with nothing saved", func(t *testing.T) {
		g := NewWithT(t)

		apiReg, _ := autoregisteringAPIRegClient(newAutomanagedAPIServiceObj())
		m := &migrationController{ctx: ctx, apiregClient: apiReg.ApiregistrationV1()}

		dm := migratingCR(t)
		dm.Annotations = nil
		g.Expect(m.restoreAPIService(logCtx, dm)).To(Succeed())

		apiSvc, err := apiReg.ApiregistrationV1().APIServices().Get(ctx, apiServiceName, metav1.GetOptions{})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(apiSvc.Labels).To(HaveKeyWithValue(automanagedLabel, "true"))
	})
}
