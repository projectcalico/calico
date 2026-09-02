// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package dashboards

import (
	"context"
	"fmt"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/components"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/dns"
	"github.com/projectcalico/calico/operator/pkg/enterprise/controller/logstorage/initializer"
	"github.com/projectcalico/calico/operator/pkg/render"
	"github.com/projectcalico/calico/operator/pkg/render/logstorage/dashboards"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
	"github.com/projectcalico/calico/operator/test"
)

var successResult = reconcile.Result{}

func NewDashboardsControllerWithShims(
	cli client.Client,
	scheme *runtime.Scheme,
	status status.StatusManager,
	provider operatorv1.Provider,
	clusterDomain string,
	multiTenant bool,
	externalElastic bool,
) (*DashboardsSubController, error) {
	opts := options.ControllerOptions{
		DetectedProvider: provider,
		ClusterDomain:    clusterDomain,
		ShutdownContext:  context.TODO(),
		MultiTenant:      multiTenant,
		ElasticExternal:  externalElastic,
		Variant:          operatorv1.CalicoEnterprise,
	}

	r := &DashboardsSubController{
		client:          cli,
		scheme:          scheme,
		status:          status,
		clusterDomain:   opts.ClusterDomain,
		variant:         opts.Variant,
		multiTenant:     opts.MultiTenant,
		elasticExternal: opts.ElasticExternal,
		tierWatchReady:  &utils.ReadyFlag{},
	}
	r.tierWatchReady.MarkAsReady()
	r.status.Run(opts.ShutdownContext)
	return r, nil
}

var _ = Describe("LogStorage Dashboards controller", func() {
	var (
		cli        client.Client
		scheme     *runtime.Scheme
		ctx        context.Context
		install    *operatorv1.Installation
		mockStatus *status.MockStatus
		r          *DashboardsSubController
	)

	BeforeEach(func() {
		// This BeforeEach contains common preparation for all tests - both single-tenant and multi-tenant.
		// Any test-specific preparation should be done in subsequen BeforeEach blocks in the Contexts below.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).ShouldNot(HaveOccurred())
		Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(batchv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(admissionv1beta1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		ctx = context.Background()
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		// Create a basic Installation.
		var replicas int32 = 2
		install = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Status: operatorv1.InstallationStatus{
				Variant: operatorv1.CalicoEnterprise,
			},
			Spec: operatorv1.InstallationSpec{
				ControlPlaneReplicas: &replicas,
				Variant:              operatorv1.CalicoEnterprise,
				Registry:             "some.registry.org/",
			},
		}
		install.Status.Computed = &install.Spec
		Expect(cli.Create(ctx, install)).ShouldNot(HaveOccurred())

		// Create a basic LogStorage.
		ls := &operatorv1.LogStorage{}
		ls.Name = "tigera-secure"
		ls.Status.State = operatorv1.TigeraStatusReady
		initializer.FillDefaults(ls)
		Expect(cli.Create(ctx, ls)).ShouldNot(HaveOccurred())

		// Create a basic Elasticsearch instance.
		es := &esv1.Elasticsearch{}
		es.Name = "tigera-secure"
		es.Namespace = render.ElasticsearchNamespace
		es.Status.Phase = esv1.ElasticsearchReadyPhase
		Expect(cli.Create(ctx, es)).ShouldNot(HaveOccurred())

		// Create the calico-system Tier, since the controller blocks on its existence.
		tier := &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}}
		Expect(cli.Create(ctx, tier)).ShouldNot(HaveOccurred())
	})

	Context("Zero tenant", func() {
		BeforeEach(func() {
			mockStatus = &status.MockStatus{}
			mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return().Maybe()
			mockStatus.On("ClearWarning", mock.Anything).Return().Maybe()
			mockStatus.On("Run").Return()
			mockStatus.On("AddDaemonsets", mock.Anything)
			mockStatus.On("AddDeployments", mock.Anything)
			mockStatus.On("AddStatefulSets", mock.Anything)
			mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
			mockStatus.On("AddCronJobs", mock.Anything)
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("ReadyToMonitor")
			mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			mockStatus.On("ClearDegraded")

			// Create a CA secret for the test, and create its KeyPair.
			cm, err := certificatemanager.Create(cli, &install.Spec, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cli.Create(ctx, cm.KeyPair().Secret(common.OperatorNamespace()))).ShouldNot(HaveOccurred())

			// Create secrets needed for successful installation.
			bundle := cm.CreateTrustedBundle()
			Expect(cli.Create(ctx, bundle.ConfigMap(render.ElasticsearchNamespace))).ShouldNot(HaveOccurred())

			// Create the ES user secret. Generally this is created by either es-kube-controllers or the user controller in this operator.
			userSecret := &corev1.Secret{}
			userSecret.Name = dashboards.ElasticCredentialsSecret
			userSecret.Namespace = render.ElasticsearchNamespace
			userSecret.Data = map[string][]byte{"username": []byte("test-username"), "password": []byte("test-password")}
			Expect(cli.Create(ctx, userSecret)).ShouldNot(HaveOccurred())

			// Create the reconciler for the tests.
			r, err = NewDashboardsControllerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain, false, false)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should wait for the cluster CA to be provisioned", func() {
			// Delete the CA secret for this test.
			caSecret := &corev1.Secret{}
			caSecret.Name = certificatemanagement.CASecretName
			caSecret.Namespace = common.OperatorNamespace()
			Expect(cli.Delete(ctx, caSecret)).ShouldNot(HaveOccurred())

			// Run the reconciler.
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).Should(ContainSubstring("CA secret"))
		})

		It("should reconcile resources for a standalone cluster/management cluster", func() {
			// Run the reconciler.
			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).Should(Equal(successResult))

			// Check that K8s Job was created as expected. We don't need to check every resource in detail, since
			// the render package has its own tests which cover this in more detail.
			dashboardJob := batchv1.Job{
				TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      dashboards.Name,
					Namespace: render.ElasticsearchNamespace,
				},
			}
			Expect(test.GetResource(cli, &dashboardJob)).To(BeNil())
		})

		It("should not reconcile resources for a managed cluster", func() {
			managementClusterConnection := &operatorv1.ManagementClusterConnection{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tigera-secure",
				},
			}
			Expect(cli.Create(ctx, managementClusterConnection)).ShouldNot(HaveOccurred())

			// Run the reconciler.
			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).Should(Equal(successResult))

			// Check that K8s Job was not created
			dashboardJob := batchv1.Job{
				TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      dashboards.Name,
					Namespace: render.ElasticsearchNamespace,
				},
			}
			Expect(test.GetResource(cli, &dashboardJob)).To(HaveOccurred())
		})

		It("should use images from ImageSet", func() {
			Expect(cli.Create(ctx, &operatorv1.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/intrusion-detection-job-installer", Digest: "sha256:dashboardhash"},
						{Image: "tigera/calico", Digest: "sha256:deadbeef0123456789"},
					},
				},
			})).ToNot(HaveOccurred())

			// Reconcile the resources
			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).Should(Equal(successResult))

			dashboardJob := batchv1.Job{
				TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      dashboards.Name,
					Namespace: render.ElasticsearchNamespace,
				},
			}
			Expect(test.GetResource(cli, &dashboardJob)).To(BeNil())
			dashboardInstaller := test.GetContainer(dashboardJob.Spec.Template.Spec.Containers, dashboards.Name)
			Expect(dashboardInstaller).ToNot(BeNil())
			Expect(dashboardInstaller.Image).To(Equal(fmt.Sprintf("some.registry.org/%s%s@%s", components.TigeraImagePath, components.ComponentElasticTseeInstaller.Image, "sha256:dashboardhash")))
		})
	})
})
