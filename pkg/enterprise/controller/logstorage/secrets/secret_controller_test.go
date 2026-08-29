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

package secrets

import (
	"bytes"
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/stretchr/testify/mock"

	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	entcertificatemanager "github.com/tigera/operator/pkg/enterprise/certificatemanager"
	"github.com/tigera/operator/pkg/enterprise/controller/logstorage/initializer"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/logcollector"
	"github.com/tigera/operator/pkg/render/logstorage"
	"github.com/tigera/operator/pkg/render/logstorage/eck"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
	"github.com/tigera/operator/pkg/render/logstorage/esmetrics"
	"github.com/tigera/operator/pkg/render/logstorage/kibana"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/test"
)

var (
	esCertSecretKey     = client.ObjectKey{Name: render.TigeraElasticsearchGatewaySecret, Namespace: render.ElasticsearchNamespace}
	esCertSecretOperKey = client.ObjectKey{Name: render.TigeraElasticsearchGatewaySecret, Namespace: common.OperatorNamespace()}

	kbCertSecretKey     = client.ObjectKey{Name: kibana.TigeraKibanaCertSecret, Namespace: kibana.Namespace}
	kbCertSecretOperKey = client.ObjectKey{Name: kibana.TigeraKibanaCertSecret, Namespace: common.OperatorNamespace()}

	esDNSNames       = dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, dns.DefaultClusterDomain)
	esGatewayDNSNmes = dns.GetServiceDNSNames(esgateway.ServiceName, render.ElasticsearchNamespace, dns.DefaultClusterDomain)
	kbDNSNames       = dns.GetServiceDNSNames(kibana.ServiceName, kibana.Namespace, dns.DefaultClusterDomain)

	successResult = reconcile.Result{}
)

func NewSecretControllerWithShims(
	cli client.Client,
	scheme *runtime.Scheme,
	status status.StatusManager,
	provider operatorv1.Provider,
	clusterDomain string,
) (*SecretSubController, error) {
	opts := options.ControllerOptions{
		DetectedProvider: provider,
		ClusterDomain:    clusterDomain,
		ShutdownContext:  context.TODO(),
		Variant:          operatorv1.CalicoEnterprise,
	}

	r := &SecretSubController{
		client:        cli,
		scheme:        scheme,
		status:        status,
		clusterDomain: opts.ClusterDomain,
		multiTenant:   opts.MultiTenant,
	}
	r.status.Run(opts.ShutdownContext)
	return r, nil
}

func NewMultiTenantSecretControllerWithShims(
	cli client.Client,
	scheme *runtime.Scheme,
	status status.StatusManager,
	provider operatorv1.Provider,
	clusterDomain string,
) (*SecretSubController, error) {
	opts := options.ControllerOptions{
		DetectedProvider: provider,
		ClusterDomain:    clusterDomain,
		ShutdownContext:  context.TODO(),
		MultiTenant:      true,
		ElasticExternal:  true,
		Variant:          operatorv1.CalicoEnterprise,
	}

	r := &SecretSubController{
		client:          cli,
		scheme:          scheme,
		status:          status,
		clusterDomain:   opts.ClusterDomain,
		multiTenant:     opts.MultiTenant,
		elasticExternal: opts.ElasticExternal,
	}
	r.status.Run(opts.ShutdownContext)
	return r, nil
}

var _ = Describe("LogStorage Secrets controller", func() {
	var (
		cli                client.Client
		readyFlag          *utils.ReadyFlag
		scheme             *runtime.Scheme
		ctx                context.Context
		install            *operatorv1.Installation
		mockStatus         *status.MockStatus
		certificateManager certificatemanager.CertificateManager
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
			},
		}
		install.Status.Computed = &install.Spec
		Expect(cli.Create(ctx, install)).ShouldNot(HaveOccurred())

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
		var err error
		certificateManager, err = certificatemanager.Create(cli, &install.Spec, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cli.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))).ShouldNot(HaveOccurred())
	})

	It("should wait for the cluster CA to be provisioned", func() {
		// Create a LogStorage instance with a default configuration.
		ls := &operatorv1.LogStorage{}
		ls.Name = "tigera-secure"
		ls.Status.State = operatorv1.TigeraStatusReady
		CreateLogStorage(cli, ls)

		// Delete the CA secret for this test.
		caSecret := &corev1.Secret{}
		caSecret.Name = certificatemanagement.CASecretName
		caSecret.Namespace = common.OperatorNamespace()
		Expect(cli.Delete(ctx, caSecret)).ShouldNot(HaveOccurred())

		// Run the reconciler.
		r, err := NewSecretControllerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())
		_, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).Should(HaveOccurred())
		Expect(err.Error()).Should(ContainSubstring("CA secret"))
	})

	It("should render all necessary secrets for a standalone cluster", func() {
		// Create a LogStorage instance with a default configuration.
		ls := &operatorv1.LogStorage{}
		ls.Name = "tigera-secure"
		ls.Status.State = operatorv1.TigeraStatusReady
		CreateLogStorage(cli, ls)

		// Run the reconciler.
		r, err := NewSecretControllerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())
		_, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())

		// Expect secrets to have been created.
		expected := []types.NamespacedName{
			{Name: certificatemanagement.CASecretName, Namespace: common.OperatorNamespace()},

			{Name: render.TigeraElasticsearchInternalCertSecret, Namespace: common.OperatorNamespace()},
			{Name: render.TigeraElasticsearchInternalCertSecret, Namespace: render.ElasticsearchNamespace},

			{Name: kibana.TigeraKibanaCertSecret, Namespace: common.OperatorNamespace()},
			{Name: kibana.TigeraKibanaCertSecret, Namespace: kibana.Namespace},

			{Name: esmetrics.ElasticsearchMetricsServerTLSSecret, Namespace: common.OperatorNamespace()},
			{Name: esmetrics.ElasticsearchMetricsServerTLSSecret, Namespace: render.ElasticsearchNamespace},

			{Name: render.TigeraElasticsearchGatewaySecret, Namespace: common.OperatorNamespace()},
			{Name: render.TigeraElasticsearchGatewaySecret, Namespace: render.ElasticsearchNamespace},

			{Name: render.TigeraLinseedSecret, Namespace: common.OperatorNamespace()},
			{Name: render.TigeraLinseedSecret, Namespace: render.ElasticsearchNamespace},
		}
		ExpectSecrets(ctx, cli, expected)

		// Expect the trusted bundle to be provisioned in both the tigera-elasticsearch and tigera-kibana namespaces.
		// The bundle should include the tigera-operator CA.
		bundle := &corev1.ConfigMap{}
		bundleKey := types.NamespacedName{Name: certificatemanagement.TrustedCertConfigMapName, Namespace: render.ElasticsearchNamespace}
		Expect(cli.Get(ctx, bundleKey, bundle)).ShouldNot(HaveOccurred())

		// For this test, we only expect the tigera-operator CA to be included in the bundle as we haven't created any of the
		// other upstream certificates this controller monitors yet.
		rtest.ExpectBundleContents(bundle, types.NamespacedName{Name: certificatemanagement.CASecretName, Namespace: common.OperatorNamespace()})

		bundleKibana := &corev1.ConfigMap{}
		bundleKey = types.NamespacedName{Name: certificatemanagement.TrustedCertConfigMapName, Namespace: kibana.Namespace}
		Expect(cli.Get(ctx, bundleKey, bundleKibana)).ShouldNot(HaveOccurred())

		// For this test, we only expect the tigera-operator CA to be included in the bundle as we haven't created any of the
		// other upstream certificates this controller monitors yet.
		rtest.ExpectBundleContents(bundleKibana, types.NamespacedName{Name: certificatemanagement.CASecretName, Namespace: common.OperatorNamespace()})
	})

	It("should not trip up when a cert with missing key usages is configured for other components", func() {
		// Create a LogStorage instance with a default configuration.
		ls := &operatorv1.LogStorage{}
		ls.Name = "tigera-secure"
		ls.Status.State = operatorv1.TigeraStatusReady
		CreateLogStorage(cli, ls)

		By("Creating a fluent-bit certificate secret without all necessary usages")
		cryptoCA, err := tls.MakeCA(rmeta.TigeraOperatorCAIssuerPrefix)
		Expect(err).NotTo(HaveOccurred())
		tlsCfg, err := cryptoCA.MakeServerCertForDuration(sets.New[string]("test"), tls.DefaultCertificateDuration, tls.SetServerAuth)
		Expect(err).NotTo(HaveOccurred())
		keyContent, crtContent := &bytes.Buffer{}, &bytes.Buffer{}
		Expect(tlsCfg.WriteCertConfig(crtContent, keyContent)).NotTo(HaveOccurred())
		privateKeyPEM, certificatePEM := keyContent.Bytes(), crtContent.Bytes()
		fluentBitCert, err := certificateManager.GetOrCreateKeyPair(cli, logcollector.FluentBitTLSSecretName, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())
		fluentBitSecret := fluentBitCert.Secret(common.OperatorNamespace())
		fluentBitSecret.Data[corev1.TLSCertKey] = certificatePEM
		fluentBitSecret.Data[corev1.TLSPrivateKeyKey] = privateKeyPEM
		Expect(err).NotTo(HaveOccurred())
		r, err := NewSecretControllerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(r.client.Create(ctx, fluentBitSecret)).NotTo(HaveOccurred())

		By("reconciling the controller after a bad secret was created, we expect no problems, because bad secrets should be skipped")
		_, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("test that LogStorage reconciles if the user-supplied certs have any DNS names", func() {
		// This test currently just validates that user-provided certs will reconcile and not return an error and won't be
		// overwritten by the operator. This test will change once we add validation for user-provided certs.
		esDNSNames := []string{"es.example.com", "192.168.10.10"}
		testCA := test.MakeTestCA("logstorage-test")
		esSecret, err := secret.CreateTLSSecret(testCA,
			render.TigeraElasticsearchGatewaySecret, common.OperatorNamespace(), "tls.key", "tls.crt",
			tls.DefaultCertificateDuration, nil, esDNSNames...,
		)
		Expect(err).ShouldNot(HaveOccurred())

		Expect(cli.Create(ctx, esSecret)).ShouldNot(HaveOccurred())

		kbDNSNames = []string{"kb.example.com", "192.168.10.11"}
		kbSecret, err := secret.CreateTLSSecret(
			testCA,
			kibana.TigeraKibanaCertSecret,
			common.OperatorNamespace(),
			"tls.key",
			"tls.crt",
			tls.DefaultCertificateDuration,
			nil,
			kbDNSNames...,
		)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cli.Create(ctx, kbSecret)).ShouldNot(HaveOccurred())

		CreateLogStorage(cli, &operatorv1.LogStorage{
			ObjectMeta: metav1.ObjectMeta{
				Name: "tigera-secure",
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

		Expect(cli.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: eck.OperatorNamespace, Name: eck.LicenseConfigMapName},
			Data:       map[string]string{"eck_license_level": string(render.ElasticsearchLicenseTypeEnterprise)},
		})).ShouldNot(HaveOccurred())

		r, err := NewSecretControllerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())

		// Elasticsearch and kibana secrets are good.
		mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for Elasticsearch cluster to be operational", mock.Anything, mock.Anything).Return()
		_, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())

		Expect(cli.Get(ctx, esCertSecretOperKey, esSecret)).ShouldNot(HaveOccurred())
		test.VerifyCert(esSecret, esDNSNames...)

		Expect(cli.Get(ctx, kbCertSecretOperKey, kbSecret)).ShouldNot(HaveOccurred())
		test.VerifyCert(kbSecret, kbDNSNames...)

		// Verify the CA bundle.
		bundle := &corev1.ConfigMap{}
		bundleKey := types.NamespacedName{Name: certificatemanagement.TrustedCertConfigMapName, Namespace: render.ElasticsearchNamespace}
		Expect(cli.Get(ctx, bundleKey, bundle)).ShouldNot(HaveOccurred())

		// We expect both the tigera-operator CA and the user-provided certs to be included in the bundle.
		expectedCerts := []types.NamespacedName{
			{Name: certificatemanagement.CASecretName, Namespace: common.OperatorNamespace()},
			{Name: render.TigeraElasticsearchGatewaySecret, Namespace: common.OperatorNamespace()},
			{Name: kibana.TigeraKibanaCertSecret, Namespace: common.OperatorNamespace()},
		}
		rtest.ExpectBundleContents(bundle, expectedCerts...)
	})

	It("should regenerate operator managed certs that have invalid DNS names", func() {
		CreateLogStorage(cli, &operatorv1.LogStorage{
			ObjectMeta: metav1.ObjectMeta{
				Name: "tigera-secure",
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

		r, err := NewSecretControllerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())
		result, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(result).Should(Equal(successResult))

		By("deleting the existing ES and KB secrets")
		kbSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      kibana.TigeraKibanaCertSecret,
				Namespace: common.OperatorNamespace(),
			},
		}
		Expect(cli.Delete(ctx, kbSecret)).NotTo(HaveOccurred())

		By("creating new ES and KB secrets with an old invalid DNS name")
		_, err = secret.CreateTLSSecret(
			nil,
			kibana.TigeraKibanaCertSecret,
			common.OperatorNamespace(),
			"tls.key",
			"tls.crt",
			tls.DefaultCertificateDuration,
			nil,
			"tigera-secure-kb-http.tigera-elasticsearch.svc",
		)
		Expect(err).ShouldNot(HaveOccurred())

		// Reconcile should regenerate the certs
		_, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())

		By("confirming elasticsearch certs were updated and have the expected DNS names")
		combinedDNSNames := append(esGatewayDNSNmes, esDNSNames...)
		secret := &corev1.Secret{}

		Expect(cli.Get(ctx, esCertSecretKey, secret)).ShouldNot(HaveOccurred())
		test.VerifyCert(secret, combinedDNSNames...)

		Expect(cli.Get(ctx, esCertSecretOperKey, secret)).ShouldNot(HaveOccurred())
		test.VerifyCert(secret, combinedDNSNames...)

		kbDNSNames = dns.GetServiceDNSNames(kibana.ServiceName, kibana.Namespace, r.clusterDomain)
		By("confirming kibana certs were updated and have the expected DNS names")
		Expect(cli.Get(ctx, kbCertSecretKey, secret)).ShouldNot(HaveOccurred())
		test.VerifyCert(secret, kbDNSNames...)

		Expect(cli.Get(ctx, kbCertSecretOperKey, secret)).ShouldNot(HaveOccurred())
		test.VerifyCert(secret, kbDNSNames...)
	})

	It("test that LogStorage creates a kibana TLS cert secret if not provided and add an OwnerReference to it", func() {
		CreateLogStorage(cli, &operatorv1.LogStorage{
			ObjectMeta: metav1.ObjectMeta{
				Name: "tigera-secure",
			},
			Spec: operatorv1.LogStorageSpec{},
			Status: operatorv1.LogStorageStatus{
				State: operatorv1.TigeraStatusReady,
			},
		})

		r, err := NewSecretControllerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())

		result, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(result).Should(Equal(successResult))

		secret := &corev1.Secret{}
		Expect(cli.Get(ctx, kbCertSecretOperKey, secret)).ShouldNot(HaveOccurred())
		Expect(secret.GetOwnerReferences()).To(HaveLen(1))

		Expect(cli.Get(ctx, kbCertSecretKey, secret)).ShouldNot(HaveOccurred())
		Expect(secret.GetOwnerReferences()).To(HaveLen(1))
	})

	It("should not add OwnerReference to user supplied kibana TLS cert", func() {
		CreateLogStorage(cli, &operatorv1.LogStorage{
			ObjectMeta: metav1.ObjectMeta{
				Name: "tigera-secure",
			},
			Spec: operatorv1.LogStorageSpec{},
			Status: operatorv1.LogStorageStatus{
				State: operatorv1.TigeraStatusReady,
			},
		})

		// Create a user supplied kibana TLS cert secret.
		testCA := test.MakeTestCA("logstorage-test")
		kbSecret, err := secret.CreateTLSSecret(
			testCA,
			kibana.TigeraKibanaCertSecret,
			common.OperatorNamespace(),
			"tls.key",
			"tls.crt",
			tls.DefaultCertificateDuration,
			nil,
			"tigera-secure-kb-http.tigera-elasticsearch.svc",
		)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cli.Create(ctx, kbSecret)).ShouldNot(HaveOccurred())

		r, err := NewSecretControllerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())

		// Reconcile - the secret should be unchanged.
		result, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(result).Should(Equal(successResult))
		secret := &corev1.Secret{}
		Expect(cli.Get(ctx, kbCertSecretOperKey, secret)).ShouldNot(HaveOccurred())
		Expect(secret.GetOwnerReferences()).To(HaveLen(0))
		Expect(secret).To(Equal(kbSecret))
	})

	It("should not add OwnerReference to user supplied ES gateway TLS cert", func() {
		CreateLogStorage(cli, &operatorv1.LogStorage{
			ObjectMeta: metav1.ObjectMeta{
				Name: "tigera-secure",
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

		testCA := test.MakeTestCA("logstorage-test")
		dnsNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, dns.DefaultClusterDomain)
		gwSecret, err := secret.CreateTLSSecret(testCA,
			render.TigeraElasticsearchGatewaySecret,
			common.OperatorNamespace(),
			corev1.TLSPrivateKeyKey,
			corev1.TLSCertKey,
			tls.DefaultCertificateDuration,
			nil,
			dnsNames...,
		)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cli.Create(ctx, gwSecret)).ShouldNot(HaveOccurred())

		r, err := NewSecretControllerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())

		result, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(result).Should(Equal(successResult))

		secret := &corev1.Secret{}
		Expect(cli.Get(ctx, esCertSecretOperKey, secret)).ShouldNot(HaveOccurred())
		Expect(secret.GetOwnerReferences()).To(HaveLen(0))
	})

	It("should add OwnerReference to the public elasticsearch TLS cert secret", func() {
		CreateLogStorage(cli, &operatorv1.LogStorage{
			ObjectMeta: metav1.ObjectMeta{
				Name: "tigera-secure",
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

		Expect(cli.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: eck.OperatorNamespace, Name: eck.LicenseConfigMapName},
			Data:       map[string]string{"eck_license_level": string(render.ElasticsearchLicenseTypeEnterprise)},
		})).ShouldNot(HaveOccurred())

		r, err := NewSecretControllerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())

		result, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(result).Should(Equal(successResult))
	})

	It("should not take any action in managed cluster", func() {
		// Create a LogStorage instance with a default configuration.
		ls := &operatorv1.LogStorage{}
		ls.Name = "tigera-secure"
		ls.Status.State = operatorv1.TigeraStatusReady
		CreateLogStorage(cli, ls)

		// Create a ManagementClusterConnection object
		mcc := &operatorv1.ManagementClusterConnection{}
		mcc.Name = "tigera-secure"
		Expect(cli.Create(ctx, mcc)).ShouldNot(HaveOccurred())

		// Run the reconciler.
		r, err := NewSecretControllerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())
		_, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())

		// Query all secrets, the returned list should only contain the CA secret created in BeforeEach
		var secrets corev1.SecretList
		Expect(cli.List(ctx, &secrets)).ShouldNot(HaveOccurred())
		Expect(len(secrets.Items)).To(Equal(1))
	})

	Context("Multi-tenant secret rendering", func() {
		var tenant *operatorv1.Tenant
		tenantNS := "tenant-a-ns"

		BeforeEach(func() {
			// Create the tenant's namespace.
			Expect(cli.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: tenantNS}})).ShouldNot(HaveOccurred())

			// Create the tenant.
			tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: tenantNS},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a",
				},
			}
			Expect(cli.Create(ctx, tenant)).ShouldNot(HaveOccurred())

			// Create the external ES and Kibana public certificates, used for external ES.
			externalESSecret := rtest.CreateCertSecret(logstorage.ExternalESPublicCertName, common.OperatorNamespace(), "external.es.com")
			Expect(cli.Create(ctx, externalESSecret)).ShouldNot(HaveOccurred())
			externalKibanaSecret := rtest.CreateCertSecret(logstorage.ExternalKBPublicCertName, common.OperatorNamespace(), "external.kb.com")
			Expect(cli.Create(ctx, externalKibanaSecret)).ShouldNot(HaveOccurred())

			// Create a per-tenant CA secret for the test, and create its KeyPair.
			cm, err := entcertificatemanager.Create(cli,
				&install.Spec,
				dns.DefaultClusterDomain,
				tenantNS,
				tenant,
				certificatemanager.AllowCACreation())
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cli.Create(ctx, cm.KeyPair().Secret(tenantNS))).ShouldNot(HaveOccurred())
		})

		It("should render all necessary secrets for a multi-tenant management cluster", func() {
			// Create a LogStorage instance with a default configuration.
			ls := &operatorv1.LogStorage{}
			ls.Name = "tigera-secure"
			ls.Status.State = operatorv1.TigeraStatusReady
			CreateLogStorage(cli, ls)

			// Run the reconciler for a particular tenant.
			r, err := NewMultiTenantSecretControllerWithShims(cli, scheme, mockStatus, operatorv1.ProviderNone, dns.DefaultClusterDomain)
			Expect(err).ShouldNot(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: tenantNS}})
			Expect(err).ShouldNot(HaveOccurred())

			// Expect secrets to have been created.
			expected := []types.NamespacedName{
				// These are created in BeforeEach.
				{Name: certificatemanagement.CASecretName, Namespace: common.OperatorNamespace()},
				{Name: certificatemanagement.TenantCASecretName, Namespace: tenantNS},
				{Name: logstorage.ExternalESPublicCertName, Namespace: common.OperatorNamespace()},
				{Name: logstorage.ExternalKBPublicCertName, Namespace: common.OperatorNamespace()},

				// These are created by the controller.
				{Name: render.TigeraLinseedSecret, Namespace: tenantNS},
			}
			ExpectSecrets(ctx, cli, expected)

			// The trusted bundle shouldn't be created in multi-tenant mode. This is instead created by the secrets/tenant_controller.
			bundle := &corev1.ConfigMap{}
			bundleKey := types.NamespacedName{Name: certificatemanagement.TrustedCertConfigMapName, Namespace: tenantNS}
			Expect(cli.Get(ctx, bundleKey, bundle)).Should(HaveOccurred())
		})
	})
})

// CreateLogStorage creates a LogStorage object with the given parameters after filling in defaults,
// and asserts that the creation succeeds.
func CreateLogStorage(client client.Client, ls *operatorv1.LogStorage) {
	initializer.FillDefaults(ls)
	ExpectWithOffset(1, client.Create(context.Background(), ls)).ShouldNot(HaveOccurred())
}

// ExpectSecrets asserts that all of the given secrets exist in the cluster, and that no other secrets exist.
func ExpectSecrets(ctx context.Context, cli client.Client, expected []types.NamespacedName) {
	for _, expected := range expected {
		ExpectWithOffset(1, cli.Get(ctx, expected, &corev1.Secret{})).ShouldNot(HaveOccurred(), fmt.Sprintf("Error querying expected secret: %+v", expected))
	}

	// Query all secrets, iterate through them and make sure they are in the expected set from above.
	var secrets corev1.SecretList
	Expect(cli.List(ctx, &secrets)).ShouldNot(HaveOccurred())
	for _, secret := range secrets.Items {
		// Check if the expected list above contains this secret.
		var found bool
		for _, expected := range expected {
			if expected.Name == secret.Name && expected.Namespace == secret.Namespace {
				found = true
				break
			}
		}
		ExpectWithOffset(1, found).Should(BeTrue(), fmt.Sprintf("Unexpected secret was created: %s/%s", secret.Namespace, secret.Name))
	}
}
