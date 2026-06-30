// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package compliance

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/test"
)

var _ = Describe("Cloud Compliance controller tests", func() {
	var c client.Client
	var ctx context.Context
	var cr *operatorv1.Compliance
	var r *ReconcileCompliance
	var mockStatus *status.MockStatus
	var scheme *runtime.Scheme
	var installation *operatorv1.Installation
	var licenseReadyFlag *utils.ReadyFlag
	var tierReadyFlag *utils.ReadyFlag

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())

		// Create a client that will have a crud interface of k8s objects.
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()

		mockStatus = &status.MockStatus{}
		mockStatus.On("AddDaemonsets", mock.Anything).Return()
		mockStatus.On("AddDeployments", mock.Anything).Return()
		mockStatus.On("RemoveDeployments", mock.Anything).Return()
		mockStatus.On("RemoveDaemonsets", mock.Anything).Return()
		mockStatus.On("AddStatefulSets", mock.Anything).Return()
		mockStatus.On("RemoveCertificateSigningRequests", mock.Anything).Return()
		mockStatus.On("AddCronJobs", mock.Anything)
		mockStatus.On("IsAvailable").Return(true)
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("AddCertificateSigningRequests", mock.Anything).Return()
		mockStatus.On("ClearDegraded")
		mockStatus.On("SetDegraded", "Waiting for LicenseKeyAPI to be ready", "").Return().Maybe()
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()
		mockStatus.On("ClearWarning", mock.Anything)
		mockStatus.On("Run").Return()

		// The compliance reconcile loop depends on a ton of objects that should be available in your client as
		// prerequisites. Without them, compliance will not even start creating objects. Let's create them now.
		installation = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operatorv1.InstallationSpec{
				Variant:  operatorv1.CalicoEnterprise,
				Registry: "some.registry.org/",
			},
			Status: operatorv1.InstallationStatus{
				Variant: operatorv1.CalicoEnterprise,
				Computed: &operatorv1.InstallationSpec{
					Registry: "my-reg",
					// The test is provider agnostic.
					KubernetesProvider: operatorv1.ProviderNone,
				},
			},
		}
		Expect(c.Create(
			ctx,
			installation)).NotTo(HaveOccurred())

		Expect(c.Create(ctx, &operatorv1.APIServer{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}, Status: operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ComplianceFeature}}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &operatorv1.Authentication{
			ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name},
			Spec: operatorv1.AuthenticationSpec{
				OIDC: &operatorv1.AuthenticationOIDC{
					IssuerURL: "https://auth.dev.calicocloud.io/",
					Type:      operatorv1.OIDCTypeTigera,
				},
			},
			Status: operatorv1.AuthenticationStatus{
				State: operatorv1.TigeraStatusReady,
			},
		})).ToNot(HaveOccurred())

		certificateManager, err := certificatemanager.Create(c, nil, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(context.Background(), certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		esDNSNames := dns.GetServiceDNSNames(render.TigeraElasticsearchGatewaySecret, render.ElasticsearchNamespace, dns.DefaultClusterDomain)
		linseedKeyPair, err := certificateManager.GetOrCreateKeyPair(c, render.TigeraLinseedSecret, render.ElasticsearchNamespace, esDNSNames)
		Expect(err).NotTo(HaveOccurred())

		// For managed clusters, we also need the public cert for Linseed.
		linseedPublicCert, err := certificateManager.GetOrCreateKeyPair(c, render.VoltronLinseedPublicCert, common.OperatorNamespace(), esDNSNames)
		Expect(err).NotTo(HaveOccurred())

		Expect(c.Create(ctx, linseedKeyPair.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
		Expect(c.Create(ctx, linseedPublicCert.Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())

		// Apply the compliance CR to the fake cluster.
		cr = &operatorv1.Compliance{ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name}}
		Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

		// Mark that watches were successful.
		licenseReadyFlag = &utils.ReadyFlag{}
		tierReadyFlag = &utils.ReadyFlag{}

		licenseReadyFlag.MarkAsReady()
		tierReadyFlag.MarkAsReady()
	})

	Context("Single tenant management cluster", func() {
		BeforeEach(func() {
			Expect(c.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: utils.CloudAuthConfig, Namespace: "tigera-operator"},
				Data: map[string]string{
					"tenantID": "anyTenant",
				},
			})).NotTo(HaveOccurred())
			Expect(c.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: render.OIDCSecretName, Namespace: "tigera-operator"},
				Data: map[string][]byte{
					"clientID":     []byte("anyID"),
					"clientSecret": []byte("anySecret"),
				},
			})).NotTo(HaveOccurred())

			Expect(c.Create(
				ctx,
				&operatorv1.ManagementCluster{
					ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name},
				})).NotTo(HaveOccurred())

			// Create an object we can use throughout the test to do the compliance reconcile loops.
			// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
			r = &ReconcileCompliance{
				client:          c,
				scheme:          scheme,
				status:          mockStatus,
				licenseAPIReady: licenseReadyFlag,
				tierWatchReady:  tierReadyFlag,
				opts: options.ControllerOptions{
					DetectedProvider: operatorv1.ProviderNone,
					ClusterDomain:    dns.DefaultClusterDomain,
					ShutdownContext:  context.TODO(),
					Cloud:            true,
				},
			}
			r.status.Run(r.opts.ShutdownContext)
		})

		It("should create a trusted bundle with external certificates", func() {
			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(0 * time.Second))

			trustedBundleConfigMap := corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tigera-ca-bundle",
					Namespace: render.ComplianceNamespace,
				},
			}
			err = test.GetResource(c, &trustedBundleConfigMap)
			Expect(err).ShouldNot(HaveOccurred())

			publicCerts, _ := pem.Decode([]byte(trustedBundleConfigMap.Data["ca-bundle.crt"]))
			Expect(publicCerts).NotTo(BeNil())
			_, err = x509.ParseCertificate(publicCerts.Bytes)
			Expect(err).To(BeNil(), "Error parsing bytes from ca-bundle.crt into certificate")

			tigeraCerts, _ := pem.Decode([]byte(trustedBundleConfigMap.Data["tigera-ca-bundle.crt"]))
			Expect(tigeraCerts).NotTo(BeNil())
			tigeraX509Certs, err := x509.ParseCertificate(tigeraCerts.Bytes)
			Expect(err).To(BeNil(), "Error parsing bytes from tigera-ca-bundle.crt into certificate")
			Expect(tigeraX509Certs.Subject.CommonName).To(Equal("tigera-operator-signer"))
		})
	})
})
