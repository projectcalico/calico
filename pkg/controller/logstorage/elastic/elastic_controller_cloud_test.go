// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package elastic

import (
	"context"

	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/operator/pkg/render/logstorage"

	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/cloudconfig"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/render/logstorage/kibana"
	"github.com/tigera/operator/pkg/render/monitor"
)

var _ = Describe("External ES controller (Cloud))", func() {
	var (
		cli                client.Client
		mockStatus         *status.MockStatus
		scheme             *runtime.Scheme
		ctx                context.Context
		certificateManager certificatemanager.CertificateManager
		install            *operatorv1.Installation
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
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()
		var err error
		certificateManager, err = certificatemanager.Create(cli, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))) // Persist the root-ca in the operator namespace.

		// Create secrets necessary for reconcile to complete. These are typically created by the secrets controller.
		esKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, render.TigeraElasticsearchInternalCertSecret, common.OperatorNamespace(), []string{render.TigeraElasticsearchInternalCertSecret})
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, esKeyPair.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
		dnsNames := dns.GetServiceDNSNames(kibana.ServiceName, kibana.Namespace, dns.DefaultClusterDomain)
		kbKeyPair, err := certificateManager.GetOrCreateKeyPair(cli, kibana.TigeraKibanaCertSecret, common.OperatorNamespace(), dnsNames)
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, kbKeyPair.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		// Create the trusted bundle configmap. This is normally created out of band by the secret controller.
		bundle := certificateManager.CreateTrustedBundle(esKeyPair)
		Expect(cli.Create(ctx, bundle.ConfigMap(render.ElasticsearchNamespace))).NotTo(HaveOccurred())

		prometheusTLS, err := certificateManager.GetOrCreateKeyPair(cli, monitor.PrometheusClientTLSSecretName, common.OperatorNamespace(), []string{monitor.PrometheusServerTLSSecretName})
		Expect(err).NotTo(HaveOccurred())

		Expect(cli.Create(ctx, prometheusTLS.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		Expect(cli.Create(ctx, &operatorv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Status:     operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady},
		})).NotTo(HaveOccurred())

		Expect(cli.Create(ctx, &v3.Tier{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera"},
		})).NotTo(HaveOccurred())

		install = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Status: operatorv1.InstallationStatus{
				Variant:  operatorv1.CalicoEnterprise,
				Computed: &operatorv1.InstallationSpec{},
			},
			Spec: operatorv1.InstallationSpec{
				Variant:  operatorv1.CalicoEnterprise,
				Registry: "some.registry.org/",
			},
		}
		Expect(cli.Create(ctx, install)).ShouldNot(HaveOccurred())

		Expect(cli.Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: render.ElasticsearchNamespace},
		})).NotTo(HaveOccurred())
		// Create the public certs used to verify the Elasticsearch and Kibana.
		esPublicCert, err := secret.CreateTLSSecret(
			nil,
			"tigera-secure-es-http-certs-public",
			common.OperatorNamespace(),
			"tls.key",
			"tls.crt",
			rmeta.DefaultCertificateDuration,
			nil,
		)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cli.Create(ctx, esPublicCert)).ShouldNot(HaveOccurred())

		kbPublicCert, err := secret.CreateTLSSecret(
			nil,
			"tigera-secure-kb-http-certs-public",
			common.OperatorNamespace(),
			"tls.key",
			"tls.crt",
			rmeta.DefaultCertificateDuration,
			nil,
		)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cli.Create(ctx, kbPublicCert)).ShouldNot(HaveOccurred())

		// Create the ES admin username and password.
		esAdminUserSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ElasticsearchAdminUserSecret,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string][]byte{"tigera-mgmt": []byte("password")},
		}
		Expect(cli.Create(ctx, esAdminUserSecret)).ShouldNot(HaveOccurred())

		// Create the ExternalCertsSecret which contains the client certificate for connecting to the external ES cluster.
		externalCertsSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      logstorage.ExternalCertsSecret,
				Namespace: common.OperatorNamespace(),
			},
			Data: map[string][]byte{
				"tls.crt": {},
			},
		}
		Expect(cli.Create(ctx, externalCertsSecret)).ShouldNot(HaveOccurred())

		Expect(cli.Create(
			ctx,
			&operatorv1.ManagementCluster{
				ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name},
			})).NotTo(HaveOccurred())

		mockStatus = &status.MockStatus{}
		mockStatus.On("Run").Return()
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("ClearWarning", mock.Anything).Return().Maybe()
	})

	It("reconciles successfully", func() {
		CreateLogStorage(cli, &operatorv1.LogStorage{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec:       operatorv1.LogStorageSpec{},
			Status:     operatorv1.LogStorageStatus{State: operatorv1.TigeraStatusReady},
		})

		// Run the reconciler.
		r, err := NewExternalESReconcilerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())
		// Enable cloud mode so the cloud (tenant-from-CloudConfig) path is exercised.
		r.opts.Cloud = true

		// Cloud config doesn't exist, so we should be degraded.
		mockStatus.On("SetDegraded", operatorv1.ResourceReadError, "Failed to retrieve tigera-secure-cloud-config config map", mock.Anything, mock.Anything)
		result, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result).Should(Equal(reconcile.Result{}))
		mockStatus.AssertExpectations(GinkgoT())

		// Create the cloud config ConfigMap, which contains external ES information and tenant ID for this cluster.
		cloudConfig := cloudconfig.NewCloudConfig("tenantId", "tenantName", "externalES.com", "externalKb.com", true)
		Expect(cli.Create(ctx, cloudConfig.ConfigMap())).ShouldNot(HaveOccurred())

		mockStatus.On("ClearDegraded")
		mockStatus.On("ReadyToMonitor")
		result, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(result).Should(Equal(reconcile.Result{}))

		mockStatus.AssertExpectations(GinkgoT())

		// Verify that the tenantId has been added to the clusterName.
		clusterConfig := &corev1.ConfigMap{}
		Expect(cli.Get(ctx, client.ObjectKey{Name: relasticsearch.ClusterConfigConfigMapName, Namespace: common.OperatorNamespace()}, clusterConfig)).ToNot(HaveOccurred())
		Expect(clusterConfig.Data["clusterName"]).To(Equal("tenantId.cluster"))
	})
})
