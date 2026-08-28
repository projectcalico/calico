// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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

package kubecontrollers

import (
	"context"
	"fmt"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/test"
	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/logstorage/initializer"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/enterprise"
	entkubecontrollers "github.com/tigera/operator/pkg/enterprise/kubecontrollers"
	eoptions "github.com/tigera/operator/pkg/enterprise/options"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/logstorage"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var successResult = reconcile.Result{}

func NewControllerWithShims(
	cli client.Client,
	scheme *runtime.Scheme,
	status status.StatusManager,
	provider operatorv1.Provider,
	clusterDomain string,
	multiTenant bool,
	tierWatchReady *utils.ReadyFlag,
) (*ESKubeControllersController, error) {
	opts := options.ControllerOptions{
		DetectedProvider: provider,
		ClusterDomain:    clusterDomain,
		ShutdownContext:  context.TODO(),
		MultiTenant:      multiTenant,
		Variant:          operatorv1.CalicoEnterprise,
		Extensions:       enterprise.New(operatorv1.CalicoEnterprise, eoptions.Options{}),
	}

	r := &ESKubeControllersController{
		client:         cli,
		scheme:         scheme,
		status:         status,
		clusterDomain:  opts.ClusterDomain,
		variant:        opts.Variant,
		tierWatchReady: tierWatchReady,
		multiTenant:    multiTenant,
	}
	r.status.Run(opts.ShutdownContext)
	return r, nil
}

var _ = Describe("LogStorage ES kube-controllers controller", func() {
	var (
		cli        client.Client
		readyFlag  *utils.ReadyFlag
		scheme     *runtime.Scheme
		ctx        context.Context
		install    *operatorv1.Installation
		mockStatus *status.MockStatus
		r          *ESKubeControllersController
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
				ImagePullSecrets: []corev1.LocalObjectReference{{
					Name: "tigera-pull-secret",
				}},
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

		pullSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: common.OperatorNamespace()},
		}
		Expect(cli.Create(ctx, pullSecret)).NotTo(HaveOccurred())

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

		// Create ESGW admin secret. This is normally created by the ECK operator.
		esAdminUserSecret := &corev1.Secret{}
		esAdminUserSecret.Name = render.ElasticsearchAdminUserSecret
		esAdminUserSecret.Namespace = render.ElasticsearchNamespace
		esAdminUserSecret.Data = map[string][]byte{"username": []byte("password")}
		Expect(cli.Create(ctx, esAdminUserSecret)).ShouldNot(HaveOccurred())

		// Create a CA secret for the test, and create its KeyPair.
		cm, err := certificatemanager.Create(cli, &install.Spec, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cli.Create(ctx, cm.KeyPair().Secret(common.OperatorNamespace()))).ShouldNot(HaveOccurred())

		// Create ESGW key pair.
		kp, err := cm.GetOrCreateKeyPair(cli, render.TigeraElasticsearchGatewaySecret, common.OperatorNamespace(), []string{"localhost"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cli.Create(ctx, kp.Secret(common.OperatorNamespace()))).ShouldNot(HaveOccurred())

		// Create secrets needed for successful installation.
		bundle := cm.CreateTrustedBundle()
		Expect(cli.Create(ctx, bundle.ConfigMap(render.ElasticsearchNamespace))).ShouldNot(HaveOccurred())
		Expect(cli.Create(ctx, bundle.ConfigMap(common.CalicoNamespace))).ShouldNot(HaveOccurred())

		// Create the reconciler for the tests.
		r, err = NewControllerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain, false, readyFlag)
		Expect(err).ShouldNot(HaveOccurred())

		// Create the calico-system Tier, since the controller blocks on its existence.
		tier := &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}}
		Expect(cli.Create(ctx, tier)).ShouldNot(HaveOccurred())
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

	It("should wait for elasticsearch to be provisioned", func() {
		// Delete the Elasticsearch CR. This is created for ECK only.
		Expect(cli.Delete(ctx, &esv1.Elasticsearch{
			ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace},
		})).NotTo(HaveOccurred())

		// Run the reconciler.
		result, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(result).ShouldNot(Equal(successResult))
	})

	It("should reconcile resources for a standlone cluster", func() {
		// Run the reconciler.
		result, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(result).Should(Equal(successResult))

		// SetDegraded should not have been called.
		mockStatus.AssertNumberOfCalls(GinkgoT(), "SetDegraded", 0)

		// Check that kube-controllers was created as expected. We don't need to check every resource in detail, since
		// the render package has its own tests which cover this in more detail.
		dep := appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      entkubecontrollers.EsKubeController,
				Namespace: common.CalicoNamespace,
			},
		}
		Expect(test.GetResource(cli, &dep)).To(BeNil())

		// We also expect es-gateway to be created.
		dep = appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      esgateway.DeploymentName,
				Namespace: render.ElasticsearchNamespace,
			},
		}
		Expect(test.GetResource(cli, &dep)).To(BeNil())
	})

	It("should use images from ImageSet", func() {
		Expect(cli.Create(ctx, &operatorv1.ImageSet{
			ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
			Spec: operatorv1.ImageSetSpec{
				Images: []operatorv1.Image{
					{Image: "tigera/elasticsearch", Digest: "sha256:elasticsearchhash"},
					{Image: "tigera/calico", Digest: "sha256:kubecontrollershash"},
					{Image: "tigera/kibana", Digest: "sha256:kibanahash"},
					{Image: "tigera/eck-operator", Digest: "sha256:eckoperatorhash"},
				},
			},
		})).ToNot(HaveOccurred())

		// Run the reconciler.
		result, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(result).Should(Equal(successResult))

		// Check that kube-controllers was created as expected. We don't need to check every resource in detail, since
		// the render package has its own tests which cover this in more detail.
		dep := appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      entkubecontrollers.EsKubeController,
				Namespace: common.CalicoNamespace,
			},
		}
		Expect(test.GetResource(cli, &dep)).To(BeNil())
		kc := test.GetContainer(dep.Spec.Template.Spec.Containers, entkubecontrollers.EsKubeController)
		Expect(kc).ToNot(BeNil())
		Expect(kc.Image).To(Equal(fmt.Sprintf("some.registry.org/%s%s@%s", components.TigeraImagePath, components.ComponentTigeraCalico.Image, "sha256:kubecontrollershash")))
	})

	Context("External ES mode", func() {
		BeforeEach(func() {
			// Delete the Elasticsearch CR. This is created for ECK only.
			Expect(cli.Delete(ctx, &esv1.Elasticsearch{
				ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace},
			})).NotTo(HaveOccurred())

			// Create ESGW admin secret. For External ES, this is provisioned by the cluster admin into the
			// tigera-operator namespace.
			esAdminUserSecret := &corev1.Secret{}
			esAdminUserSecret.Name = render.ElasticsearchAdminUserSecret
			esAdminUserSecret.Namespace = common.OperatorNamespace()
			esAdminUserSecret.Data = map[string][]byte{"username": []byte("password")}
			Expect(cli.Create(ctx, esAdminUserSecret)).ShouldNot(HaveOccurred())

			// Create a dummy secret mocking the client certificates needed for mTLS.
			esClientSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: logstorage.ExternalCertsSecret, Namespace: common.OperatorNamespace()},
				Data:       map[string][]byte{"client.crt": []byte("cert"), "client.key": []byte("key")},
			}
			Expect(cli.Create(ctx, esClientSecret)).ShouldNot(HaveOccurred())

			// Update the reconciler to run in external ES mode for these tests.
			r.elasticExternal = true
		})

		It("should reconcile resources for a cluster", func() {
			// Run the reconciler.
			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).Should(Equal(successResult))

			// SetDegraded should not have been called.
			mockStatus.AssertNumberOfCalls(GinkgoT(), "SetDegraded", 0)

			// Check that kube-controllers was created as expected. We don't need to check every resource in detail, since
			// the render package has its own tests which cover this in more detail.
			dep := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      entkubecontrollers.EsKubeController,
					Namespace: common.CalicoNamespace,
				},
			}
			Expect(test.GetResource(cli, &dep)).To(BeNil())

			// We also expect es-gateway to be created.
			dep = appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      esgateway.DeploymentName,
					Namespace: render.ElasticsearchNamespace,
				},
			}
			Expect(test.GetResource(cli, &dep)).To(BeNil())
		})
	})
})
