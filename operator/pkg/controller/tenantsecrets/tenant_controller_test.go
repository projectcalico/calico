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

package tenantsecrets

import (
	"bytes"
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
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
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/dns"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	rtest "github.com/projectcalico/calico/operator/pkg/render/common/test"
	"github.com/projectcalico/calico/operator/pkg/render/logstorage"
	"github.com/projectcalico/calico/operator/pkg/tls"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

func NewTenantControllerWithShims(
	cli client.Client,
	scheme *runtime.Scheme,
	status status.StatusManager,
	clusterDomain string,
) (*TenantController, error) {
	r := &TenantController{
		client:          cli,
		scheme:          scheme,
		status:          status,
		clusterDomain:   clusterDomain,
		elasticExternal: true,
		log:             logf.Log.WithName("controller_tenant_secrets"),
	}
	r.status.Run(context.TODO())
	return r, nil
}

var _ = Describe("Tenant controller", func() {
	var (
		cli        client.Client
		scheme     *runtime.Scheme
		ctx        context.Context
		install    *operatorv1.Installation
		mockStatus *status.MockStatus
		r          *TenantController
		tenantNS   string
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
		install.Status.Computed = install.Spec.DeepCopy()
		install.Spec.Variant = ""
		Expect(cli.Create(ctx, install)).ShouldNot(HaveOccurred())

		// Create the cluster-scoped tigera-operator CA.
		cm, err := certificatemanager.Create(cli, install.Status.Computed, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cli.Create(ctx, cm.KeyPair().Secret(common.OperatorNamespace()))).ShouldNot(HaveOccurred())

		// Create the external ES and Kibana public certificates, used for external ES.

		cryptoCA, _ := tls.MakeCA(rmeta.TigeraOperatorCAIssuerPrefix + "@some-hash")
		dnsNames := []string{"external.ingress.elastic"}
		cfg, _ := cryptoCA.MakeServerCertForDuration(sets.New[string](dnsNames...), tls.DefaultCertificateDuration, tls.SetServerAuth, tls.SetClientAuth)
		keyContent, crtContent := &bytes.Buffer{}, &bytes.Buffer{}
		_ = cfg.WriteCertConfig(crtContent, keyContent)

		externalESSecret := rtest.CreateCertSecretWithContent(logstorage.ExternalESPublicCertName, common.OperatorNamespace(), keyContent.Bytes(), crtContent.Bytes())
		Expect(cli.Create(ctx, externalESSecret)).ShouldNot(HaveOccurred())
		externalKibanaSecret := rtest.CreateCertSecretWithContent(logstorage.ExternalKBPublicCertName, common.OperatorNamespace(), keyContent.Bytes(), crtContent.Bytes())
		Expect(cli.Create(ctx, externalKibanaSecret)).ShouldNot(HaveOccurred())

		// Create the tenant Namespace.
		tenantNS = "tenant-namespace"
		Expect(cli.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: tenantNS}})).ShouldNot(HaveOccurred())

		// Create the Tenant object.
		tenant := &operatorv1.Tenant{}
		tenant.Name = "default"
		tenant.Namespace = tenantNS
		tenant.Spec.ID = "test-tenant-id"
		tenant.Spec.Indices = []operatorv1.Index{
			{BaseIndexName: "calico_alerts", DataType: operatorv1.DataTypeAlerts},
			{BaseIndexName: "calico_auditlogs", DataType: operatorv1.DataTypeAuditLogs},
			{BaseIndexName: "calico_bgplogs", DataType: operatorv1.DataTypeBGPLogs},
			{BaseIndexName: "calico_compliance_benchmarks", DataType: operatorv1.DataTypeComplianceBenchmarks},
			{BaseIndexName: "calico_compliance_reports", DataType: operatorv1.DataTypeComplianceReports},
			{BaseIndexName: "calico_compliance_snapshots", DataType: operatorv1.DataTypeComplianceSnapshots},
			{BaseIndexName: "calico_dnslogs", DataType: operatorv1.DataTypeDNSLogs},
			{BaseIndexName: "calico_flowlogs", DataType: operatorv1.DataTypeFlowLogs},
			{BaseIndexName: "calico_L7logs", DataType: operatorv1.DataTypeL7Logs},
			{BaseIndexName: "calico_runtime_reports", DataType: operatorv1.DataTypeRuntimeReports},
			{BaseIndexName: "calico_threat_feeds_domain_name_set", DataType: operatorv1.DataTypeThreatFeedsDomainSet},
			{BaseIndexName: "calico_threat_feeds_ip_set", DataType: operatorv1.DataTypeThreatFeedsIPSet},
			{BaseIndexName: "calico_waf", DataType: operatorv1.DataTypeWAFLogs},
			{BaseIndexName: "calico_policy_activity", DataType: operatorv1.DataTypePolicyActivity},
		}
		Expect(cli.Create(ctx, tenant)).ShouldNot(HaveOccurred())

		// Create the reconciler for the test.
		mockStatus = &status.MockStatus{}
		mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("ClearWarning", mock.Anything).Return().Maybe()
		mockStatus.On("Run").Return()
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("ClearDegraded")
		mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
		r, err = NewTenantControllerWithShims(cli, scheme, mockStatus, dns.DefaultClusterDomain)
		Expect(err).ShouldNot(HaveOccurred())
	})

	It("should provision the tenant's CA", func() {
		// Run the reconciler.
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default", Namespace: tenantNS}})
		Expect(err).ShouldNot(HaveOccurred())

		// Query for the tenant's CA which should have been created.
		caSecret := &corev1.Secret{}
		Expect(cli.Get(ctx, types.NamespacedName{Name: certificatemanagement.TenantCASecretName, Namespace: tenantNS}, caSecret)).ShouldNot(HaveOccurred())
		Expect(caSecret.Data).Should(HaveKey("tls.crt"))

		// A trusted bundle without system roots should have been created.
		trustedBundle := &corev1.ConfigMap{}
		Expect(cli.Get(ctx, types.NamespacedName{Name: certificatemanagement.TrustedCertConfigMapName, Namespace: tenantNS}, trustedBundle)).ShouldNot(HaveOccurred())
		rtest.ExpectBundleContents(
			trustedBundle,

			// Should include both the per-tenant and cluster-scoped CA certs.
			types.NamespacedName{Name: certificatemanagement.CASecretName, Namespace: common.OperatorNamespace()},
			types.NamespacedName{Name: certificatemanagement.TenantCASecretName, Namespace: tenantNS},

			// Should include public certs for external ES.
			types.NamespacedName{Name: logstorage.ExternalESPublicCertName, Namespace: common.OperatorNamespace()},
		)

		// A trusted bundle ConfigMap with system roots should also have been created.
		Expect(cli.Get(ctx, types.NamespacedName{Name: certificatemanagement.TrustedCertConfigMapNamePublic, Namespace: tenantNS}, trustedBundle)).ShouldNot(HaveOccurred())
	})
})
