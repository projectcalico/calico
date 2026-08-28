// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package initializer

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/dns"
)

func NewTestConditionController(
	cli client.Client,
	scheme *runtime.Scheme,
	clusterDomain string,
) (*LogStorageConditions, error) {
	opts := options.ControllerOptions{
		ClusterDomain:   clusterDomain,
		ShutdownContext: context.TODO(),
		Variant:         operatorv1.CalicoEnterprise,
	}

	r := &LogStorageConditions{
		client:      cli,
		scheme:      scheme,
		multiTenant: opts.MultiTenant,
	}
	return r, nil
}

var _ = Describe("LogStorage Conditions controller", func() {
	var (
		cli       client.Client
		readyFlag *utils.ReadyFlag
		scheme    *runtime.Scheme
		ctx       context.Context
	)

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).ShouldNot(HaveOccurred())
		Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(admissionv1beta1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		readyFlag = &utils.ReadyFlag{}
		readyFlag.MarkAsReady()
	})

	generation := int64(2)
	subControllers := []string{
		TigeraStatusName, TigeraStatusLogStorageAccess,
		TigeraStatusLogStorageElastic, TigeraStatusLogStorageSecrets,
	}

	It("should reconcile with one item in tigerastatus conditions", func() {
		lsControllers := append(subControllers, TigeraStatusLogStorageESMetrics, TigeraStatusLogStorageKubeController, TigeraStatusLogStorageDashboards)
		for _, ls := range lsControllers {
			createTigeraStatus(cli, ctx, ls, generation, []operatorv1.TigeraStatusCondition{{
				Type:               operatorv1.ComponentAvailable,
				Status:             operatorv1.ConditionTrue,
				Reason:             string(operatorv1.AllObjectsAvailable),
				Message:            "All Objects are available",
				ObservedGeneration: generation,
			}})
		}

		CreateLogStorage(cli, &operatorv1.LogStorage{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "tigera-secure",
				Generation: 3,
			},
			Spec: operatorv1.LogStorageSpec{
				Nodes: &operatorv1.Nodes{
					Count: int64(1),
				},
			},
			Status: operatorv1.LogStorageStatus{
				State: operatorv1.TigeraStatusReady,
			},
		})

		r, err := NewTestConditionController(cli, scheme, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())

		result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      "log-storage",
			Namespace: "",
		}})
		Expect(err).ShouldNot(HaveOccurred())
		// Expect to be waiting for Elasticsearch and Kibana to be functional
		Expect(result).Should(Equal(reconcile.Result{}))

		By("asserting the finalizers have been set on the LogStorage CR")
		instance := &operatorv1.LogStorage{}
		Expect(cli.Get(ctx, types.NamespacedName{Name: "tigera-secure"}, instance)).ShouldNot(HaveOccurred())
		Expect(instance.Status.Conditions).To(HaveLen(3))

		By("asserting Ready to be true")
		actualConditions := getCurrentConditions(instance.Status.Conditions)
		readyCondition, ok := actualConditions["Ready"]
		Expect(ok).To(BeTrue())
		Expect(string(readyCondition.Status)).To(Equal(string(operatorv1.ConditionTrue)))
		Expect(readyCondition.Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
		Expect(readyCondition.Message).To(Equal("All sub-controllers are available"))
		Expect(readyCondition.ObservedGeneration).To(Equal(generation))

		degCondition, ok := actualConditions["Degraded"]
		Expect(ok).To(BeTrue())
		Expect(string(degCondition.Status)).To(Equal(string(operatorv1.ConditionFalse)))
		Expect(degCondition.Reason).To(Equal(string(operatorv1.Unknown)))
		Expect(degCondition.Message).To(Equal(""))
		progCondition, ok := actualConditions["Progressing"]
		Expect(ok).To(BeTrue())
		Expect(string(progCondition.Status)).To(Equal(string(operatorv1.ConditionFalse)))
		Expect(progCondition.Reason).To(Equal(string(operatorv1.Unknown)))
		Expect(progCondition.Message).To(Equal(""))
	})

	It("should reconcile with empty tigerastatus conditions", func() {
		lsControllers := append(subControllers, TigeraStatusLogStorageESMetrics, TigeraStatusLogStorageKubeController, TigeraStatusLogStorageDashboards)
		for _, ls := range lsControllers {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: ls},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status:     operatorv1.TigeraStatusStatus{},
			}
			Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())
		}

		CreateLogStorage(cli, &operatorv1.LogStorage{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "tigera-secure",
				Generation: 3,
			},
			Spec: operatorv1.LogStorageSpec{
				Nodes: &operatorv1.Nodes{
					Count: int64(1),
				},
			},
			Status: operatorv1.LogStorageStatus{
				State: operatorv1.TigeraStatusReady,
			},
		})

		r, err := NewTestConditionController(cli, scheme, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())
		result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      "log-storage",
			Namespace: "",
		}})
		Expect(err).ShouldNot(HaveOccurred())
		// Expect to be waiting for Elasticsearch and Kibana to be functional
		Expect(result).Should(Equal(reconcile.Result{}))

		By("asserting the finalizers have been set on the LogStorage CR")
		instance := &operatorv1.LogStorage{}
		Expect(cli.Get(ctx, types.NamespacedName{Name: "tigera-secure"}, instance)).ShouldNot(HaveOccurred())
		Expect(instance.Status.Conditions).To(HaveLen(3))

		By("asserting all the status set to be False")
		actualConditions := getCurrentConditions(instance.Status.Conditions)
		readyCondition, ok := actualConditions["Ready"]
		Expect(ok).To(BeTrue())
		Expect(string(readyCondition.Status)).To(Equal(string(operatorv1.ConditionFalse)))
		Expect(readyCondition.Reason).To(Equal(string(operatorv1.Unknown)))
		Expect(readyCondition.Message).To(Equal(""))
		degCondition, ok := actualConditions["Degraded"]
		Expect(ok).To(BeTrue())
		Expect(string(degCondition.Status)).To(Equal(string(operatorv1.ConditionFalse)))
		Expect(degCondition.Reason).To(Equal(string(operatorv1.Unknown)))
		Expect(degCondition.Message).To(Equal(""))
		progCondition, ok := actualConditions["Progressing"]
		Expect(ok).To(BeTrue())
		Expect(string(progCondition.Status)).To(Equal(string(operatorv1.ConditionFalse)))
		Expect(progCondition.Reason).To(Equal(string(operatorv1.Unknown)))
		Expect(progCondition.Message).To(Equal(""))
	})

	It("should reconcile multiple conditions as true", func() {
		lsControllers := append(subControllers, TigeraStatusLogStorageKubeController, TigeraStatusLogStorageDashboards)
		for _, ls := range lsControllers {
			createTigeraStatus(cli, ctx, ls, generation, []operatorv1.TigeraStatusCondition{})
		}

		// Create esmetrics with multiple conditions true
		createTigeraStatus(cli, ctx, TigeraStatusLogStorageESMetrics, generation, []operatorv1.TigeraStatusCondition{
			{
				Type:               operatorv1.ComponentAvailable,
				Status:             operatorv1.ConditionTrue,
				Reason:             string(operatorv1.AllObjectsAvailable),
				Message:            "All Objects are available",
				ObservedGeneration: generation,
			},
			{
				Type:               operatorv1.ComponentProgressing,
				Status:             operatorv1.ConditionTrue,
				Reason:             string(operatorv1.ResourceNotReady),
				Message:            "Progressing Installation.operatorv1.tigera.io",
				ObservedGeneration: generation,
			},
			{
				Type:               operatorv1.ComponentDegraded,
				Status:             operatorv1.ConditionTrue,
				Reason:             string(operatorv1.ResourceUpdateError),
				Message:            "Error resolving ImageSet for components",
				ObservedGeneration: generation,
			},
		})

		CreateLogStorage(cli, &operatorv1.LogStorage{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "tigera-secure",
				Generation: 3,
			},
			Spec: operatorv1.LogStorageSpec{
				Nodes: &operatorv1.Nodes{
					Count: int64(1),
				},
			},
			Status: operatorv1.LogStorageStatus{
				State: operatorv1.TigeraStatusReady,
			},
		})

		r, err := NewTestConditionController(cli, scheme, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())
		result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      "log-storage",
			Namespace: "",
		}})
		Expect(err).ShouldNot(HaveOccurred())
		// Expect to be waiting for Elasticsearch and Kibana to be functional
		Expect(result).Should(Equal(reconcile.Result{}))

		By("asserting the finalizers have been set on the LogStorage CR")
		instance := &operatorv1.LogStorage{}
		Expect(cli.Get(ctx, types.NamespacedName{Name: "tigera-secure"}, instance)).ShouldNot(HaveOccurred())
		Expect(instance.Status.Conditions).To(HaveLen(3))

		actualConditions := getCurrentConditions(instance.Status.Conditions)

		By("asserting degraded is marked as true with esmetrics subcontroller")
		degraded, ok := actualConditions["Degraded"]
		Expect(ok).To(BeTrue())

		msg := "The following sub-controllers are in this condition: [log-storage-esmetrics]"
		Expect(string(degraded.Status)).To(Equal(string(operatorv1.ConditionTrue)))
		Expect(degraded.Reason).To(Equal(string(operatorv1.ResourceNotReady)))
		Expect(degraded.Message).To(Equal(msg))
		Expect(degraded.ObservedGeneration).To(Equal(int64(2)))

		By("asserting progressing is marked as True with esmetrics subcontroller")
		progressing, ok := actualConditions["Progressing"]
		Expect(ok).To(BeTrue())
		Expect(string(progressing.Status)).To(Equal(string(operatorv1.ConditionTrue)))
		Expect(progressing.Reason).To(Equal(string(operatorv1.ResourceNotReady)))
		Expect(progressing.Message).To(Equal(msg))
		Expect(progressing.ObservedGeneration).To(Equal(int64(2)))

		By("asserting available is marked as True")
		readyCondition, ok := actualConditions["Ready"]
		Expect(ok).To(BeTrue())
		Expect(string(readyCondition.Status)).To(Equal(string(operatorv1.ConditionTrue)))
		Expect(readyCondition.Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
		Expect(readyCondition.ObservedGeneration).To(Equal(int64(2)))
	})

	It("should reconcile with all log-storage-* tigerastatus conditions as Available and later move to degraded", func() {
		subControllers = append(subControllers, TigeraStatusLogStorageUsers)
		for _, ls := range subControllers {
			createTigeraStatus(cli, ctx, ls, generation, []operatorv1.TigeraStatusCondition{})
		}
		CreateLogStorage(cli, &operatorv1.LogStorage{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "tigera-secure",
				Generation: 3,
			},
			Spec: operatorv1.LogStorageSpec{
				Nodes: &operatorv1.Nodes{
					Count: int64(1),
				},
			},
			Status: operatorv1.LogStorageStatus{
				State: operatorv1.TigeraStatusReady,
			},
		})

		r, err := NewTestConditionController(cli, scheme, dns.DefaultClusterDomain)
		r.multiTenant = true
		Expect(err).ShouldNot(HaveOccurred())

		result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      "log-storage",
			Namespace: "",
		}})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(result).Should(Equal(reconcile.Result{}))

		instance := &operatorv1.LogStorage{}
		Expect(cli.Get(ctx, types.NamespacedName{Name: "tigera-secure"}, instance)).ShouldNot(HaveOccurred())
		Expect(instance.Status.Conditions).To(HaveLen(3))

		actualConditions := getCurrentConditions(instance.Status.Conditions)

		By("asserting Ready status to be true")
		readyCondition, ok := actualConditions["Ready"]
		Expect(ok).To(BeTrue())
		Expect(string(readyCondition.Status)).To(Equal(string(operatorv1.ConditionTrue)))
		Expect(readyCondition.Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
		Expect(readyCondition.Message).To(Equal("All sub-controllers are available"))
		Expect(readyCondition.ObservedGeneration).To(Equal(generation))

		// Update the instance condition times so that we can verify they're changed after subsequent calls to Reconcile.
		for i := range instance.Status.Conditions {
			instance.Status.Conditions[i].LastTransitionTime = metav1.NewTime(time.Now().Add(-2 * time.Minute))
		}

		Expect(cli.Status().Update(ctx, instance)).ShouldNot(HaveOccurred())

		recentTransitionTime := instance.Status.Conditions[1].LastTransitionTime

		// Expect tigerstatus transition time remain unchanged when there is no changes to the  condition
		result, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      "log-storage",
			Namespace: "",
		}})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(result).Should(Equal(reconcile.Result{}))
		instance = &operatorv1.LogStorage{}

		By("Assert last transition time is not affected when tigerastatus condition is untouched")
		Expect(cli.Get(ctx, types.NamespacedName{Name: "tigera-secure"}, instance)).ShouldNot(HaveOccurred())
		Expect(instance.Status.Conditions).To(HaveLen(3))

		actualConditions = getCurrentConditions(instance.Status.Conditions)

		By("asserting Ready status remains untouched after reconcilation")
		readyCondition, ok = actualConditions["Ready"]
		Expect(ok).To(BeTrue())
		Expect(string(readyCondition.Status)).To(Equal(string(operatorv1.ConditionTrue)))
		Expect(readyCondition.Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
		Expect(readyCondition.Message).To(Equal("All sub-controllers are available"))
		Expect(readyCondition.ObservedGeneration).To(Equal(generation))
		Expect(readyCondition.LastTransitionTime.Time.Equal(recentTransitionTime.Time)).To(BeTrue())
		recentTransitionTime = instance.Status.Conditions[1].LastTransitionTime

		// Expect tigerastatus set to be degraded with a different transistion time.
		// update LogStorageUsers  Tigerastatus to degraded
		tsUser := operatorv1.TigeraStatus{}
		_ = cli.Get(ctx, client.ObjectKey{
			Name: TigeraStatusLogStorageUsers,
		}, &tsUser)

		tsUser.Status.Conditions = []operatorv1.TigeraStatusCondition{
			{
				Type:               operatorv1.ComponentAvailable,
				Status:             operatorv1.ConditionFalse,
				Reason:             string(operatorv1.ResourceNotReady),
				Message:            "",
				ObservedGeneration: int64(1),
			},
			{
				Type:               operatorv1.ComponentProgressing,
				Status:             operatorv1.ConditionFalse,
				Reason:             string(operatorv1.ResourceNotReady),
				Message:            "",
				ObservedGeneration: int64(1),
			},
			{
				Type:               operatorv1.ComponentDegraded,
				Status:             operatorv1.ConditionTrue,
				Reason:             string(operatorv1.ResourceNotReady),
				Message:            "no active connection found: no Elasticsearch node available",
				ObservedGeneration: int64(1),
			},
		}

		Expect(cli.Status().Update(ctx, &tsUser)).NotTo(HaveOccurred())

		result, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
			Name:      "log-storage",
			Namespace: "",
		}})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(result).Should(Equal(reconcile.Result{}))
		instance = &operatorv1.LogStorage{}

		Expect(cli.Get(ctx, types.NamespacedName{Name: "tigera-secure"}, instance)).ShouldNot(HaveOccurred())
		Expect(instance.Status.Conditions).To(HaveLen(3))

		actualConditions = getCurrentConditions(instance.Status.Conditions)

		By("asserting degraded is marked as true and observed generation is updated to the oldest")
		degraded, ok := actualConditions["Degraded"]
		Expect(ok).To(BeTrue())

		degradedMsg := "The following sub-controllers are in this condition: [log-storage-users]"
		Expect(string(degraded.Status)).To(Equal(string(operatorv1.ConditionTrue)))
		Expect(degraded.Reason).To(Equal(string(operatorv1.ResourceNotReady)))
		Expect(degraded.Message).To(Equal(degradedMsg))
		Expect(degraded.ObservedGeneration).To(Equal(int64(1)))

		By("asserting available is marked as false")
		readyCondition, ok = actualConditions["Ready"]
		Expect(ok).To(BeTrue())
		Expect(string(readyCondition.Status)).To(Equal(string(operatorv1.ConditionFalse)))
		Expect(instance.Status.Conditions[1].ObservedGeneration).To(Equal(int64(1)))

		By("assert transition time should be after the previously recorded transition time")
		Expect(readyCondition.LastTransitionTime.Time.After(recentTransitionTime.Time)).To(BeTrue())

		By("asserting progressing should remain unchanged")
		progressing, ok := actualConditions["Progressing"]
		Expect(ok).To(BeTrue())
		Expect(string(progressing.Status)).To(Equal(string(operatorv1.ConditionFalse)))
		Expect(progressing.Reason).To(Equal(string(operatorv1.Unknown)))
		Expect(progressing.Message).To(Equal(""))
		Expect(progressing.ObservedGeneration).To(Equal(int64(1)))
	})
})

// CreateLogStorage creates a LogStorage object with the given parameters after filling in defaults,
// and asserts that the creation succeeds.
func CreateLogStorage(client client.Client, ls *operatorv1.LogStorage) {
	// First, simulate the initializing controller being run by filling defaults.
	FillDefaults(ls)

	// Create the LogStorage object.
	ExpectWithOffset(1, client.Create(context.Background(), ls)).ShouldNot(HaveOccurred())
}

func createTigeraStatus(cli client.Client, ctx context.Context, name string, generation int64, conditions []operatorv1.TigeraStatusCondition) {
	// set All objects Available by default
	if len(conditions) == 0 {
		conditions = []operatorv1.TigeraStatusCondition{
			{
				Type:               operatorv1.ComponentAvailable,
				Status:             operatorv1.ConditionTrue,
				Reason:             string(operatorv1.AllObjectsAvailable),
				Message:            "All Objects are available",
				ObservedGeneration: generation,
			},
			{
				Type:               operatorv1.ComponentProgressing,
				Status:             operatorv1.ConditionFalse,
				Reason:             string(operatorv1.AllObjectsAvailable),
				Message:            "All Objects are available",
				ObservedGeneration: generation,
			},
			{
				Type:               operatorv1.ComponentDegraded,
				Status:             operatorv1.ConditionFalse,
				Reason:             string(operatorv1.AllObjectsAvailable),
				Message:            "All Objects are available",
				ObservedGeneration: generation,
			},
		}
	}

	ts := &operatorv1.TigeraStatus{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       operatorv1.TigeraStatusSpec{},
		Status: operatorv1.TigeraStatusStatus{
			Conditions: conditions,
		},
	}

	Expect(cli.Create(ctx, ts)).NotTo(HaveOccurred())
}
