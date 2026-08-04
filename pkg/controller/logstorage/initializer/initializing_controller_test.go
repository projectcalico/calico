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
	"reflect"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/logstorage/kibana"
)

func NewTestInitializer(
	cli client.Client,
	scheme *runtime.Scheme,
	status status.StatusManager,
	provider operatorv1.Provider,
	clusterDomain string,
) (*LogStorageInitializer, error) {
	opts := options.ControllerOptions{
		DetectedProvider: provider,
		ClusterDomain:    clusterDomain,
		ShutdownContext:  context.TODO(),
		Variant:          operatorv1.CalicoEnterprise,
	}

	r := &LogStorageInitializer{
		client:      cli,
		scheme:      scheme,
		status:      status,
		provider:    opts.DetectedProvider,
		multiTenant: opts.MultiTenant,
	}
	r.status.Run(opts.ShutdownContext)
	return r, nil
}

var _ = Describe("LogStorage Initializing controller", func() {
	var (
		cli        client.Client
		mockStatus *status.MockStatus
		readyFlag  *utils.ReadyFlag
		scheme     *runtime.Scheme
		ctx        context.Context
		install    *operatorv1.Installation
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

	Context("Controller tests", func() {
		BeforeEach(func() {
			// Create a basic Installation.
			var replicas int32 = 2
			install = &operatorv1.Installation{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Status: operatorv1.InstallationStatus{
					Variant:  operatorv1.CalicoEnterprise,
					Computed: &operatorv1.InstallationSpec{},
				},
				Spec: operatorv1.InstallationSpec{
					ControlPlaneReplicas: &replicas,
					Variant:              operatorv1.CalicoEnterprise,
					ImagePullSecrets: []corev1.LocalObjectReference{{
						Name: "tigera-pull-secret",
					}},
				},
			}
			Expect(cli.Create(ctx, install)).ShouldNot(HaveOccurred())
			Expect(cli.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: common.OperatorNamespace()}})).NotTo(HaveOccurred())

			mockStatus = &status.MockStatus{}
			mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return().Maybe()
			mockStatus.On("ClearWarning", mock.Anything).Return().Maybe()
			mockStatus.On("Run")
			mockStatus.On("OnCRFound")
			mockStatus.On("SetMetaData", mock.Anything)
			mockStatus.On("ReadyToMonitor")
			mockStatus.On("ClearDegraded")
			mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			mockStatus.On("OnCRNotFound")
		})

		It("fills defaults on an empty LogStorage", func() {
			// Create a LogStorage with no fields set.
			ls := &operatorv1.LogStorage{}
			ls.Name = "tigera-secure"
			Expect(cli.Create(ctx, ls)).ShouldNot(HaveOccurred())

			// Run the reconciler. It should fill in defaults.
			r, err := NewTestInitializer(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
			Expect(err).ShouldNot(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Expect the LogStorage to be updated with defaults.
			ls = &operatorv1.LogStorage{}
			expected := &operatorv1.LogStorage{}
			FillDefaults(expected)
			Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-secure"}, ls)).ShouldNot(HaveOccurred())
			Expect(ls.Spec).Should(Equal(expected.Spec))
			Expect(ls.Status.State).Should(Equal(operatorv1.TigeraStatusReady))
		})

		It("sets a degraded status when an invalid LogStorage is given", func() {
			// Create a LogStorage instance with invalid fields. Specifically, one with
			// component resources that are not valid.
			ls := &operatorv1.LogStorage{}
			ls.Name = "tigera-secure"
			FillDefaults(ls)
			ls.Spec.ComponentResources[0].ComponentName = "invalid"
			Expect(cli.Create(ctx, ls)).ShouldNot(HaveOccurred())

			// Run the reconciler. Expect an error and a degraded status.
			r, err := NewTestInitializer(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
			Expect(err).ShouldNot(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
			Expect(mockStatus.AssertNumberOfCalls(GinkgoT(), "SetDegraded", 1)).Should(BeTrue())

			// Get the LogStorage and expect the degraded status to be set.
			ls = &operatorv1.LogStorage{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-secure"}, ls)).ShouldNot(HaveOccurred())
			Expect(ls.Status.State).Should(Equal(operatorv1.TigeraStatusDegraded))

			// Fixing the invalid field should clear the degraded status.
			ls.Spec.ComponentResources[0].ComponentName = "ECKOperator"
			Expect(cli.Update(ctx, ls)).ShouldNot(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Get the LogStorage and expect the degraded status to be cleared.
			ls = &operatorv1.LogStorage{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-secure"}, ls)).ShouldNot(HaveOccurred())
			Expect(ls.Status.State).Should(Equal(operatorv1.TigeraStatusReady))
		})

		It("sets a degraded status when replicas >= node count", func() {
			var replicas int32 = 1
			ls := &operatorv1.LogStorage{}
			ls.Name = "tigera-secure"
			FillDefaults(ls)
			ls.Spec.Indices.Replicas = &replicas
			ls.Spec.Nodes.Count = 1
			Expect(cli.Create(ctx, ls)).ShouldNot(HaveOccurred())

			r, err := NewTestInitializer(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
			Expect(err).ShouldNot(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
			Expect(mockStatus.AssertNumberOfCalls(GinkgoT(), "SetDegraded", 1)).Should(BeTrue())

			ls = &operatorv1.LogStorage{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-secure"}, ls)).ShouldNot(HaveOccurred())
			Expect(ls.Status.State).Should(Equal(operatorv1.TigeraStatusDegraded))
		})

		It("handles LogStorage deletion", func() {
			// Create a LogStorage instance.
			ls := &operatorv1.LogStorage{}
			ls.Name = "tigera-secure"
			Expect(cli.Create(ctx, ls)).ShouldNot(HaveOccurred())

			// Run the reconciler and expect an OK status.
			r, err := NewTestInitializer(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
			Expect(err).ShouldNot(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(mockStatus.AssertNumberOfCalls(GinkgoT(), "SetDegraded", 0)).Should(BeTrue())

			// Delete the LogStorage instance.
			Expect(cli.Delete(ctx, ls)).ShouldNot(HaveOccurred())

			// Run the reconciler and expect an OK status.
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(mockStatus.AssertNumberOfCalls(GinkgoT(), "SetDegraded", 0)).Should(BeTrue())

			// Expect OnCRNotFound to be called.
			Expect(mockStatus.AssertNumberOfCalls(GinkgoT(), "OnCRNotFound", 1)).Should(BeTrue())
		})

		It("should return an error if LogStorage exists on a managed cluster", func() {
			// Create a LogStorage instance.
			ls := &operatorv1.LogStorage{}
			ls.Name = "tigera-secure"
			Expect(cli.Create(ctx, ls)).ShouldNot(HaveOccurred())

			// Run the reconciler and expect everyting to be ok
			r, err := NewTestInitializer(cli, scheme, mockStatus, operatorv1.ProviderOpenShift, dns.DefaultClusterDomain)
			Expect(err).ShouldNot(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(mockStatus.AssertNumberOfCalls(GinkgoT(), "SetDegraded", 0)).Should(BeTrue())

			// Create a ManagementClusterConnection instance.
			mcc := &operatorv1.ManagementClusterConnection{}
			mcc.Name = "tigera-secure"
			Expect(cli.Create(ctx, mcc)).ShouldNot(HaveOccurred())

			// Run the reconciler again.
			_, err = r.Reconcile(ctx, reconcile.Request{})

			// We don't return an error in this case because we don't want to retry, but we do set the status as degraded.
			Expect(err).ShouldNot(HaveOccurred())
			Expect(mockStatus.AssertNumberOfCalls(GinkgoT(), "SetDegraded", 1)).Should(BeTrue())

			// Query the LogStorage instance and expect the status to be degraded.
			ls = &operatorv1.LogStorage{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-secure"}, ls)).ShouldNot(HaveOccurred())
			Expect(ls.Status.State).Should(Equal(operatorv1.TigeraStatusDegraded))
		})

		It("should set spec.componentResources to the default settings", func() {
			// Create the expected value.
			limits := corev1.ResourceList{}
			requests := corev1.ResourceList{}
			limits[corev1.ResourceMemory] = resource.MustParse(defaultEckOperatorMemorySetting)
			requests[corev1.ResourceMemory] = resource.MustParse(defaultEckOperatorMemorySetting)
			expectedComponentResources := []operatorv1.LogStorageComponentResource{
				{
					ComponentName: operatorv1.ComponentNameECKOperator,
					ResourceRequirements: &corev1.ResourceRequirements{
						Limits:   limits,
						Requests: requests,
					},
				},
			}

			// Create a LogStorage instance and reconcile it.
			ls := &operatorv1.LogStorage{}
			ls.Name = "tigera-secure"
			Expect(cli.Create(ctx, ls)).ShouldNot(HaveOccurred())
			r, err := NewTestInitializer(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
			Expect(err).ShouldNot(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// Get the LogStorage and assert the component resources are set to the expected value.
			ls = &operatorv1.LogStorage{}
			Expect(cli.Get(ctx, client.ObjectKey{Name: "tigera-secure"}, ls)).ShouldNot(HaveOccurred())
			Expect(ls.Spec.ComponentResources).NotTo(BeNil())
			Expect(reflect.DeepEqual(expectedComponentResources, ls.Spec.ComponentResources)).To(BeTrue())
		})

		It("create namespace, operator secrets role and pull secrets", func() {
			ls := &operatorv1.LogStorage{}
			ls.Name = "tigera-secure"
			Expect(cli.Create(ctx, ls)).ShouldNot(HaveOccurred())

			// Run the reconciler. It should fill in defaults.
			r, err := NewTestInitializer(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
			Expect(err).ShouldNot(HaveOccurred())
			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(0 * time.Second))

			// Expect namespace to be created
			esNamespace := corev1.Namespace{
				TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			}
			Expect(cli.Get(ctx, client.ObjectKey{
				Name: render.ElasticsearchNamespace,
			}, &esNamespace)).NotTo(HaveOccurred())
			Expect(esNamespace.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("privileged"))
			Expect(esNamespace.Labels["pod-security.kubernetes.io/enforce-version"]).To(Equal("latest"))

			// Expect operator rolebinding to be created
			esRb := rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{},
			}
			Expect(cli.Get(ctx, client.ObjectKey{
				Name:      render.TigeraOperatorSecrets,
				Namespace: render.ElasticsearchNamespace,
			}, &esRb)).NotTo(HaveOccurred())
			Expect(esRb.OwnerReferences).To(HaveLen(1))
			Expect(esRb.OwnerReferences[0].Kind).To(Equal("LogStorage"))

			// Expect pull secrets to be created
			esPullSecrets := corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			}
			Expect(cli.Get(ctx, client.ObjectKey{
				Name:      "tigera-pull-secret",
				Namespace: render.ElasticsearchNamespace,
			}, &esPullSecrets)).NotTo(HaveOccurred())
			Expect(esPullSecrets.OwnerReferences).To(HaveLen(1))
			pullSecret := esPullSecrets.OwnerReferences[0]
			Expect(pullSecret.Kind).To(Equal("LogStorage"))

			kbNamespace := corev1.Namespace{
				TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			}
			Expect(cli.Get(ctx, client.ObjectKey{
				Name: kibana.Namespace,
			}, &kbNamespace)).NotTo(HaveOccurred())
			Expect(esNamespace.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("privileged"))
			Expect(esNamespace.Labels["pod-security.kubernetes.io/enforce-version"]).To(Equal("latest"))

			// Expect operator rolebinding to be created
			rb := rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{},
			}
			Expect(cli.Get(ctx, client.ObjectKey{
				Name:      render.TigeraOperatorSecrets,
				Namespace: kibana.Namespace,
			}, &rb)).NotTo(HaveOccurred())
			Expect(rb.OwnerReferences).To(HaveLen(1))
			ownerRoleBinding := rb.OwnerReferences[0]
			Expect(ownerRoleBinding.Kind).To(Equal("LogStorage"))

			// Expect pull secrets to be created
			kbPullSecrets := corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			}
			Expect(cli.Get(ctx, client.ObjectKey{
				Name:      "tigera-pull-secret",
				Namespace: kibana.Namespace,
			}, &kbPullSecrets)).NotTo(HaveOccurred())
			Expect(kbPullSecrets.OwnerReferences).To(HaveLen(1))
			kbPullSecret := kbPullSecrets.OwnerReferences[0]
			Expect(kbPullSecret.Kind).To(Equal("LogStorage"))
		})
	})

	Context("validateReplicasForNodeCount", func() {
		It("should return an error when replicas is 1 and node count is 1", func() {
			var replicas int32 = 1
			spec := &operatorv1.LogStorageSpec{
				Nodes:   &operatorv1.Nodes{Count: 1},
				Indices: &operatorv1.Indices{Replicas: &replicas},
			}
			Expect(validateReplicasForNodeCount(spec)).NotTo(BeNil())
		})

		It("should return an error when replicas equals node count", func() {
			var replicas int32 = 2
			spec := &operatorv1.LogStorageSpec{
				Nodes:   &operatorv1.Nodes{Count: 2},
				Indices: &operatorv1.Indices{Replicas: &replicas},
			}
			Expect(validateReplicasForNodeCount(spec)).NotTo(BeNil())
		})

		It("should return no error when node count exceeds replicas", func() {
			var replicas int32 = 1
			spec := &operatorv1.LogStorageSpec{
				Nodes:   &operatorv1.Nodes{Count: 3},
				Indices: &operatorv1.Indices{Replicas: &replicas},
			}
			Expect(validateReplicasForNodeCount(spec)).To(BeNil())
		})

		It("should return no error when replicas is 0 and node count is 1", func() {
			var replicas int32 = 0
			spec := &operatorv1.LogStorageSpec{
				Nodes:   &operatorv1.Nodes{Count: 1},
				Indices: &operatorv1.Indices{Replicas: &replicas},
			}
			Expect(validateReplicasForNodeCount(spec)).To(BeNil())
		})

		It("should return no error when indices is nil", func() {
			spec := &operatorv1.LogStorageSpec{
				Nodes: &operatorv1.Nodes{Count: 1},
			}
			Expect(validateReplicasForNodeCount(spec)).To(BeNil())
		})

		It("should return no error when nodes is nil", func() {
			var replicas int32 = 1
			spec := &operatorv1.LogStorageSpec{
				Indices: &operatorv1.Indices{Replicas: &replicas},
			}
			Expect(validateReplicasForNodeCount(spec)).To(BeNil())
		})
	})

	Context("validateComponentResources", func() {
		ls := operatorv1.LogStorage{Spec: operatorv1.LogStorageSpec{}}

		It("should return an error when spec.ComponentResources is nil", func() {
			Expect(validateComponentResources(&ls.Spec)).NotTo(BeNil())
		})

		It("should return an error when spec.ComponentResources.ComponentName is not ECKOperator", func() {
			ls.Spec.ComponentResources = []operatorv1.LogStorageComponentResource{
				{
					ComponentName: "Typha",
				},
			}
			Expect(validateComponentResources(&ls.Spec)).NotTo(BeNil())
		})

		It("should return an error when spec.ComponentResources has more than one entry", func() {
			ls.Spec.ComponentResources = append(ls.Spec.ComponentResources, operatorv1.LogStorageComponentResource{
				ComponentName: "KubeControllers",
			})
			Expect(validateComponentResources(&ls.Spec)).NotTo(BeNil())
		})

		It("should return nil when spec.ComponentResources has 1 entry for ECKOperator", func() {
			ls.Spec.ComponentResources = []operatorv1.LogStorageComponentResource{
				{
					ComponentName: operatorv1.ComponentNameECKOperator,
				},
			}
			Expect(validateComponentResources(&ls.Spec)).To(BeNil())
		})
	})

	Context("FillDefaults", func() {
		It("should set the replica values to the default settings", func() {
			retain8 := int32(8)
			retain91 := int32(91)
			// Create LogStorage and fill defaults.
			ls := &operatorv1.LogStorage{}
			ls.Name = "tigera-secure"
			FillDefaults(ls)
			Expect(ls.Spec.Retention.Flows).To(Equal(&retain8))
			Expect(ls.Spec.Retention.AuditReports).To(Equal(&retain91))
			Expect(ls.Spec.Retention.ComplianceReports).To(Equal(&retain91))
			Expect(ls.Spec.Retention.Snapshots).To(Equal(&retain91))
			Expect(ls.Spec.Retention.DNSLogs).To(Equal(&retain8))
			Expect(ls.Spec.Retention.BGPLogs).To(Equal(&retain8))
		})

		It("should set the retention values to the default settings", func() {
			ls := &operatorv1.LogStorage{}
			ls.Name = "tigera-secure"
			FillDefaults(ls)
			var replicas int32 = render.DefaultElasticsearchReplicas
			Expect(ls.Spec.Indices.Replicas).To(Equal(&replicas))
		})

		It("should set the storage class to the default settings", func() {
			ls := &operatorv1.LogStorage{}
			ls.Name = "tigera-secure"
			FillDefaults(ls)
			Expect(ls.Spec.StorageClassName).To(Equal(DefaultElasticsearchStorageClass))
		})

		It("should default the spec.nodes structure", func() {
			ls := &operatorv1.LogStorage{}
			ls.Name = "tigera-secure"
			FillDefaults(ls)
			Expect(ls.Spec.Nodes).NotTo(BeNil())
			Expect(ls.Spec.Nodes.Count).To(Equal(int64(1)))
		})

		It("should fill defaults to the expected values", func() {
			ls := operatorv1.LogStorage{Spec: operatorv1.LogStorageSpec{}}
			FillDefaults(&ls)

			var fr int32 = 8
			var arr int32 = 91
			var sr int32 = 91
			var crr int32 = 91
			var dlr int32 = 8
			var bgp int32 = 8
			var replicas int32 = render.DefaultElasticsearchReplicas
			var kibanaReplicas int32 = 1
			limits := corev1.ResourceList{}
			requests := corev1.ResourceList{}
			limits[corev1.ResourceMemory] = resource.MustParse(defaultEckOperatorMemorySetting)
			requests[corev1.ResourceMemory] = resource.MustParse(defaultEckOperatorMemorySetting)

			expectedSpec := operatorv1.LogStorageSpec{
				Nodes: &operatorv1.Nodes{Count: 1},
				Retention: &operatorv1.Retention{
					Flows:             &fr,
					AuditReports:      &arr,
					Snapshots:         &sr,
					ComplianceReports: &crr,
					DNSLogs:           &dlr,
					BGPLogs:           &bgp,
				},
				Indices: &operatorv1.Indices{
					Replicas: &replicas,
				},
				Kibana: &operatorv1.Kibana{
					Spec: &operatorv1.KibanaSpec{
						Replicas: &kibanaReplicas,
					},
				},
				StorageClassName: DefaultElasticsearchStorageClass,
				ComponentResources: []operatorv1.LogStorageComponentResource{
					{
						ComponentName: operatorv1.ComponentNameECKOperator,
						ResourceRequirements: &corev1.ResourceRequirements{
							Limits:   limits,
							Requests: requests,
						},
					},
				},
			}
			Expect(ls.Spec).To(Equal(expectedSpec))
		})
	})
})
