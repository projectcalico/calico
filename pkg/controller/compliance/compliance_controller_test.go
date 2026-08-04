// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compliance

import (
	"context"
	"fmt"
	"time"

	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/tls"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/test"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/render"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("Compliance controller tests", func() {
	var c client.Client
	var ctx context.Context
	var cr *operatorv1.Compliance
	var r ReconcileCompliance
	var mockStatus *status.MockStatus
	var scheme *runtime.Scheme
	var installation *operatorv1.Installation

	expectedDNSNames := dns.GetServiceDNSNames(render.ComplianceServiceName, render.ComplianceNamespace, dns.DefaultClusterDomain)
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
		mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return()
		mockStatus.On("ClearWarning", mock.Anything).Return()
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("SetMetaData", mock.Anything).Return()

		// Create an object we can use throughout the test to do the compliance reconcile loops.
		// As the parameters in the client changes, we expect the outcomes of the reconcile loops to change.
		r = ReconcileCompliance{
			client:          c,
			scheme:          scheme,
			status:          mockStatus,
			licenseAPIReady: &utils.ReadyFlag{},
			tierWatchReady:  &utils.ReadyFlag{},
			opts: options.ControllerOptions{
				DetectedProvider: operatorv1.ProviderNone,
				ClusterDomain:    dns.DefaultClusterDomain,
				Variant:          operatorv1.CalicoEnterprise,
			},
		}
		// We start off with a 'standard' installation, with nothing special
		installation = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operatorv1.InstallationSpec{
				Variant:  operatorv1.CalicoEnterprise,
				Registry: "some.registry.org/",
				ImagePullSecrets: []corev1.LocalObjectReference{{
					Name: "tigera-pull-secret",
				}},
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

		// The compliance reconcile loop depends on a ton of objects that should be available in your client as
		// prerequisites. Without them, compliance will not even start creating objects. Let's create them now.
		Expect(c.Create(ctx, &operatorv1.APIServer{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}, Status: operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &v3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "calico-system"}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ComplianceFeature}}})).NotTo(HaveOccurred())
		Expect(c.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tigera-pull-secret", Namespace: common.OperatorNamespace()}})).NotTo(HaveOccurred())

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
		cr = &operatorv1.Compliance{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}}
		Expect(c.Create(ctx, cr)).NotTo(HaveOccurred())

		// Mark that watches were successful.
		r.licenseAPIReady.MarkAsReady()
		r.tierWatchReady.MarkAsReady()
	})

	It("should create resources for standalone clusters", func() {
		By("reconciling when clustertype is Standalone")
		result, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter > 0).NotTo(BeTrue())

		dpl := appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{},
		}

		By("creating 3 deployments for compliance")
		Expect(c.Get(ctx, client.ObjectKey{
			Name:      render.ComplianceServerName,
			Namespace: render.ComplianceNamespace,
		}, &dpl)).NotTo(HaveOccurred())
		Expect(dpl.Spec.Template.ObjectMeta.Name).To(Equal(render.ComplianceServerName))

		dpl = appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{},
		}
		Expect(c.Get(ctx, client.ObjectKey{
			Name:      render.ComplianceSnapshotterName,
			Namespace: render.ComplianceNamespace,
		}, &dpl)).NotTo(HaveOccurred())
		Expect(dpl.Spec.Template.ObjectMeta.Name).To(Equal(render.ComplianceSnapshotterName))

		dpl = appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{},
		}
		Expect(c.Get(ctx, client.ObjectKey{
			Name:      render.ComplianceControllerName,
			Namespace: render.ComplianceNamespace,
		}, &dpl)).NotTo(HaveOccurred())
		Expect(dpl.Spec.Template.ObjectMeta.Name).To(Equal(render.ComplianceControllerName))
	})

	It("should reconcile if the compliance server cert is user-supplied", func() {
		// This test just validates that user-provided certs reconcile and do
		// not overwrite the certs.
		By("reconciling when clustertype is Standalone")
		result, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter > 0).NotTo(BeTrue())

		By("replacing the server certs with user-supplied certs")
		Expect(c.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name:      render.ComplianceServerCertSecret,
			Namespace: common.OperatorNamespace(),
		}})).NotTo(HaveOccurred())
		Expect(c.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name:      render.ComplianceServerCertSecret,
			Namespace: render.ComplianceNamespace,
		}})).NotTo(HaveOccurred())

		oldDNSNames := []string{"compliance.example.com", "compliance.tigera-compliance.svc"}
		testCA := test.MakeTestCA("compliance-test")
		newSecret, err := secret.CreateTLSSecret(testCA,
			render.ComplianceServerCertSecret, common.OperatorNamespace(), corev1.TLSPrivateKeyKey,
			corev1.TLSCertKey, tls.DefaultCertificateDuration, nil, oldDNSNames...,
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, newSecret)).NotTo(HaveOccurred())

		newSecret = secret.CopyToNamespace(render.ComplianceNamespace, newSecret)[0]
		Expect(c.Create(ctx, newSecret)).NotTo(HaveOccurred())

		assertExpectedCertDNSNames(c, oldDNSNames...)

		By("checking that an error occurred and the cert didn't change")
		result, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter > 0).NotTo(BeTrue())
		assertExpectedCertDNSNames(c, oldDNSNames...)
	})

	It("should reconcile if the compliance server cert is user-supplied and has the expected DNS names", func() {
		By("reconciling when clustertype is Standalone")
		result, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter > 0).NotTo(BeTrue())

		By("replacing the server certs with ones that include the expected DNS names")
		Expect(c.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name:      render.ComplianceServerCertSecret,
			Namespace: common.OperatorNamespace(),
		}})).NotTo(HaveOccurred())
		Expect(c.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name:      render.ComplianceServerCertSecret,
			Namespace: render.ComplianceNamespace,
		}})).NotTo(HaveOccurred())

		// Custom cert has the compliance svc DNS names as well as other DNS names
		dnsNames := append(expectedDNSNames, "compliance.example.com", "192.168.10.13")
		testCA := test.MakeTestCA("compliance-test")
		newSecret, err := secret.CreateTLSSecret(testCA,
			render.ComplianceServerCertSecret, common.OperatorNamespace(), corev1.TLSPrivateKeyKey,
			corev1.TLSCertKey, tls.DefaultCertificateDuration, nil, dnsNames...,
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, newSecret)).NotTo(HaveOccurred())

		newSecret = secret.CopyToNamespace(render.ComplianceNamespace, newSecret)[0]
		Expect(c.Create(ctx, newSecret)).NotTo(HaveOccurred())

		assertExpectedCertDNSNames(c, dnsNames...)

		By("checking that an error occurred and the cert didn't change")
		result, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter > 0).NotTo(BeTrue())
		assertExpectedCertDNSNames(c, dnsNames...)
	})

	It("test that Compliance creates a TLS cert secret if not provided and add an OwnerReference to it", func() {
		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())

		secret := &corev1.Secret{}

		err = c.Get(ctx, client.ObjectKey{Name: render.ComplianceServerCertSecret, Namespace: common.OperatorNamespace()}, secret)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(secret.GetOwnerReferences()).To(HaveLen(1))
	})

	It("should not add OwnerReference to an user supplied compliance TLS cert", func() {
		dnsNames := dns.GetServiceDNSNames(render.ComplianceServiceName, render.ComplianceNamespace, dns.DefaultClusterDomain)
		testCA := test.MakeTestCA("compliance-test")
		complianceSecret, err := secret.CreateTLSSecret(testCA,
			render.ComplianceServerCertSecret, common.OperatorNamespace(), corev1.TLSPrivateKeyKey, corev1.TLSCertKey,
			tls.DefaultCertificateDuration, nil, dnsNames...,
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Create(ctx, complianceSecret)).NotTo(HaveOccurred())

		_, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())

		err = c.Get(ctx, client.ObjectKey{Name: render.ComplianceServerCertSecret, Namespace: common.OperatorNamespace()}, complianceSecret)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(complianceSecret.GetOwnerReferences()).To(HaveLen(0))
	})

	It("should remove the compliance server in managed clusters", func() {
		By("reconciling when clustertype is Standalone")
		result, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter > 0).NotTo(BeTrue())

		By("creating a compliance-server deployment")
		dpl := appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{},
		}
		Expect(c.Get(ctx, client.ObjectKey{
			Name:      render.ComplianceServerName,
			Namespace: render.ComplianceNamespace,
		}, &dpl)).NotTo(HaveOccurred())
		Expect(dpl.Spec.Template.ObjectMeta.Name).To(Equal(render.ComplianceServerName))

		Expect(c.Create(
			ctx,
			&operatorv1.ManagementClusterConnection{
				ObjectMeta: metav1.ObjectMeta{Name: utils.DefaultEnterpriseInstanceKey.Name},
			})).NotTo(HaveOccurred())

		By("reconciling after the cluster type changes")
		_, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())

		By("removing one unnecessary deployment")

		// The server should be removed...
		err = c.Get(ctx, client.ObjectKey{
			Name:      render.ComplianceServerName,
			Namespace: render.ComplianceNamespace,
		}, &dpl)
		Expect(err).To(HaveOccurred())
		Expect(errors.IsNotFound(err)).To(BeTrue())

		// ... while the snapshotter and the controller are still there.
		Expect(c.Get(ctx, client.ObjectKey{
			Name:      render.ComplianceSnapshotterName,
			Namespace: render.ComplianceNamespace,
		}, &dpl)).NotTo(HaveOccurred())
		Expect(dpl.Spec.Template.ObjectMeta.Name).To(Equal(render.ComplianceSnapshotterName))

		Expect(c.Get(ctx, client.ObjectKey{
			Name:      render.ComplianceControllerName,
			Namespace: render.ComplianceNamespace,
		}, &dpl)).NotTo(HaveOccurred())
		Expect(dpl.Spec.Template.ObjectMeta.Name).To(Equal(render.ComplianceControllerName))
	})

	It("should add cluster role bindings when certificate management is enabled", func() {
		ca, err := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		Expect(err).NotTo(HaveOccurred())
		cert, _, _ := ca.Config.GetPEMBytes()
		installation.Spec.CertificateManagement = &operatorv1.CertificateManagement{
			CACert:     cert,
			SignerName: "a.b/c",
		}
		Expect(c.Update(ctx, installation)).NotTo(HaveOccurred())
		_, err = r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())

		crb := rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{},
		}
		Expect(c.Get(ctx, client.ObjectKey{
			Name: "tigera-compliance-benchmarker:csr-creator",
		}, &crb)).NotTo(HaveOccurred())
		Expect(crb.Subjects).To(HaveLen(1))
		Expect(c.Get(ctx, client.ObjectKey{
			Name: "tigera-compliance-controller:csr-creator",
		}, &crb)).NotTo(HaveOccurred())
		Expect(crb.Subjects).To(HaveLen(1))
		Expect(c.Get(ctx, client.ObjectKey{
			Name: "tigera-compliance-server:csr-creator",
		}, &crb)).NotTo(HaveOccurred())
		Expect(crb.Subjects).To(HaveLen(1))
		Expect(c.Get(ctx, client.ObjectKey{
			Name: "tigera-compliance-snapshotter:csr-creator",
		}, &crb)).NotTo(HaveOccurred())
		Expect(crb.Subjects).To(HaveLen(1))
		Expect(c.Get(ctx, client.ObjectKey{
			Name: "tigera-compliance-reporter:csr-creator",
		}, &crb)).NotTo(HaveOccurred())
		Expect(crb.Subjects).To(HaveLen(1))
	})

	It("create namespace, operator secrets role and pull secrets", func() {
		result, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(Equal(0 * time.Second))

		// Expect namespace to be created
		namespace := corev1.Namespace{
			TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		}
		Expect(c.Get(ctx, client.ObjectKey{
			Name: render.ComplianceNamespace,
		}, &namespace)).NotTo(HaveOccurred())
		Expect(namespace.Labels["pod-security.kubernetes.io/enforce"]).To(Equal("privileged"))
		Expect(namespace.Labels["pod-security.kubernetes.io/enforce-version"]).To(Equal("latest"))

		// Expect operator rolebinding to be created
		rb := rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{},
		}
		Expect(c.Get(ctx, client.ObjectKey{
			Name:      render.TigeraOperatorSecrets,
			Namespace: render.ComplianceNamespace,
		}, &rb)).NotTo(HaveOccurred())
		Expect(rb.OwnerReferences).To(HaveLen(1))
		Expect(rb.OwnerReferences[0].Kind).To(Equal("Compliance"))

		// Expect pull secrets to be created
		pullSecrets := corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		}
		Expect(c.Get(ctx, client.ObjectKey{
			Name:      "tigera-pull-secret",
			Namespace: render.ComplianceNamespace,
		}, &pullSecrets)).NotTo(HaveOccurred())
		Expect(pullSecrets.OwnerReferences).To(HaveLen(1))
		pullSecret := pullSecrets.OwnerReferences[0]
		Expect(pullSecret.Kind).To(Equal("Compliance"))
	})

	Context("image reconciliation", func() {
		It("should use builtin images", func() {
			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			// components.ComponentComplianceBenchmarker
			// components.ComponentComplianceSnapshotter
			// components.ComponentComplianceServer
			// components.ComponentComplianceController
			// components.ComponentComplianceReporter
			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceControllerName,
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			controller := test.GetContainer(d.Spec.Template.Spec.Containers, render.ComplianceControllerName)
			Expect(controller).ToNot(BeNil())
			Expect(controller.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s:%s",
					components.TigeraImagePath,
					components.ComponentTigeraCalico.Image,
					components.ComponentTigeraCalico.Version)))

			pt := corev1.PodTemplate{
				TypeMeta: metav1.TypeMeta{Kind: "PodTemplate", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tigera.io.report",
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &pt)).To(BeNil())
			Expect(pt.Template.Spec.Containers).To(HaveLen(1))
			reporter := test.GetContainer(pt.Template.Spec.Containers, "reporter")
			Expect(reporter).ToNot(BeNil())
			Expect(reporter.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s:%s",
					components.TigeraImagePath,
					components.ComponentTigeraCalico.Image,
					components.ComponentTigeraCalico.Version)))

			d = appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceSnapshotterName,
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			snap := test.GetContainer(d.Spec.Template.Spec.Containers, render.ComplianceSnapshotterName)
			Expect(snap).ToNot(BeNil())
			Expect(snap.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s:%s",
					components.TigeraImagePath,
					components.ComponentTigeraCalico.Image,
					components.ComponentTigeraCalico.Version)))

			ds := appsv1.DaemonSet{
				TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "compliance-benchmarker",
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &ds)).To(BeNil())
			Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
			bench := test.GetContainer(ds.Spec.Template.Spec.Containers, "compliance-benchmarker")
			Expect(bench).ToNot(BeNil())
			Expect(bench.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s:%s",
					components.TigeraImagePath,
					components.ComponentComplianceBenchmarker.Image,
					components.ComponentComplianceBenchmarker.Version)))

			d = appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceServerName,
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			server := test.GetContainer(d.Spec.Template.Spec.Containers, render.ComplianceServerName)
			Expect(server).ToNot(BeNil())
			Expect(server.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s:%s",
					components.TigeraImagePath,
					components.ComponentTigeraCalico.Image,
					components.ComponentTigeraCalico.Version)))
		})
		It("should use images from imageset", func() {
			Expect(c.Create(ctx, &operatorv1.ImageSet{
				ObjectMeta: metav1.ObjectMeta{Name: "enterprise-" + components.EnterpriseRelease},
				Spec: operatorv1.ImageSetSpec{
					Images: []operatorv1.Image{
						{Image: "tigera/compliance-benchmarker", Digest: "sha256:benchmarkerhash"},
						{Image: "tigera/calico", Digest: "sha256:deadbeef0123456789"},
					},
				},
			})).ToNot(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceControllerName,
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			controller := test.GetContainer(d.Spec.Template.Spec.Containers, render.ComplianceControllerName)
			Expect(controller).ToNot(BeNil())
			Expect(controller.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s@%s",
					components.TigeraImagePath,
					components.ComponentTigeraCalico.Image,
					"sha256:deadbeef0123456789")))

			pt := corev1.PodTemplate{
				TypeMeta: metav1.TypeMeta{Kind: "PodTemplate", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tigera.io.report",
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &pt)).To(BeNil())
			Expect(pt.Template.Spec.Containers).To(HaveLen(1))
			reporter := test.GetContainer(pt.Template.Spec.Containers, "reporter")
			Expect(reporter).ToNot(BeNil())
			Expect(reporter.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s@%s",
					components.TigeraImagePath,
					components.ComponentTigeraCalico.Image,
					"sha256:deadbeef0123456789")))

			d = appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceSnapshotterName,
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			snap := test.GetContainer(d.Spec.Template.Spec.Containers, render.ComplianceSnapshotterName)
			Expect(snap).ToNot(BeNil())
			Expect(snap.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s@%s",
					components.TigeraImagePath,
					components.ComponentTigeraCalico.Image,
					"sha256:deadbeef0123456789")))

			ds := appsv1.DaemonSet{
				TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "compliance-benchmarker",
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &ds)).To(BeNil())
			Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
			bench := test.GetContainer(ds.Spec.Template.Spec.Containers, "compliance-benchmarker")
			Expect(bench).ToNot(BeNil())
			Expect(bench.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s@%s",
					components.TigeraImagePath,
					components.ComponentComplianceBenchmarker.Image,
					"sha256:benchmarkerhash")))

			d = appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceServerName,
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).To(BeNil())
			Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
			server := test.GetContainer(d.Spec.Template.Spec.Containers, render.ComplianceServerName)
			Expect(server).ToNot(BeNil())
			Expect(server.Image).To(Equal(
				fmt.Sprintf("some.registry.org/%s%s@%s",
					components.TigeraImagePath,
					components.ComponentTigeraCalico.Image,
					"sha256:deadbeef0123456789")))
		})
	})

	Context("calico-system reconciliation", func() {
		var readyFlag *utils.ReadyFlag

		BeforeEach(func() {
			mockStatus = &status.MockStatus{}
			mockStatus.On("OnCRFound").Return()
			mockStatus.On("SetMetaData", mock.Anything).Return()

			readyFlag = &utils.ReadyFlag{}
			readyFlag.MarkAsReady()
			r = ReconcileCompliance{
				client:          c,
				scheme:          scheme,
				status:          mockStatus,
				licenseAPIReady: readyFlag,
				tierWatchReady:  readyFlag,
				opts: options.ControllerOptions{
					DetectedProvider: operatorv1.ProviderNone,
					ClusterDomain:    dns.DefaultClusterDomain,
					Variant:          operatorv1.CalicoEnterprise,
				},
			}
		})

		It("should wait if calico-system tier is unavailable", func() {
			test.DeleteCalicoSystemTierAndExpectWait(ctx, c, &r, mockStatus)
		})

		It("should wait if tier watch is not ready", func() {
			r.tierWatchReady = &utils.ReadyFlag{}
			test.ExpectWaitForTierWatch(ctx, &r, mockStatus)
		})
	})

	Context("Feature compliance not active", func() {
		BeforeEach(func() {
			By("Deleting the previous license")
			Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{common.ComplianceFeature}}})).NotTo(HaveOccurred())
			By("Creating a new license that does not contain compliance as a feature")
			Expect(c.Create(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
		})

		It("should not create resources", func() {
			mockStatus.On("SetDegraded", operatorv1.ResourceValidationError, "Feature is not active - License does not support this feature", mock.Anything, mock.Anything).Return()

			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(0 * time.Second))

			d := appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceControllerName,
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).NotTo(BeNil())

			controller := test.GetContainer(d.Spec.Template.Spec.Containers, render.ComplianceControllerName)
			Expect(controller).To(BeNil())

			pt := corev1.PodTemplate{
				TypeMeta: metav1.TypeMeta{Kind: "PodTemplate", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tigera.io.report",
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &pt)).NotTo(BeNil())

			reporter := test.GetContainer(pt.Template.Spec.Containers, "reporter")
			Expect(reporter).To(BeNil())

			d = appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceSnapshotterName,
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).NotTo(BeNil())

			snap := test.GetContainer(d.Spec.Template.Spec.Containers, render.ComplianceSnapshotterName)
			Expect(snap).To(BeNil())

			ds := appsv1.DaemonSet{
				TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "compliance-benchmarker",
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &ds)).NotTo(BeNil())
			bench := test.GetContainer(ds.Spec.Template.Spec.Containers, "compliance-benchmarker")

			Expect(bench).To(BeNil())
			d = appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      render.ComplianceServerName,
					Namespace: render.ComplianceNamespace,
				},
			}
			Expect(test.GetResource(c, &d)).NotTo(BeNil())

			server := test.GetContainer(d.Spec.Template.Spec.Containers, render.ComplianceServerName)
			Expect(server).To(BeNil())
		})

		AfterEach(func() {
			By("Deleting the previous license")
			Expect(c.Delete(ctx, &v3.LicenseKey{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: v3.LicenseKeyStatus{Features: []string{}}})).NotTo(HaveOccurred())
		})
	})

	Context("Reconcile for Condition status", func() {
		generation := int64(2)

		It("should reconcile with creating new status condition with one item", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "compliance"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status: operatorv1.TigeraStatusStatus{
					Conditions: []operatorv1.TigeraStatusCondition{
						{
							Type:               operatorv1.ComponentAvailable,
							Status:             operatorv1.ConditionTrue,
							Reason:             string(operatorv1.AllObjectsAvailable),
							Message:            "All Objects are available",
							ObservedGeneration: generation,
						},
					},
				},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "compliance",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := GetCompliance(ctx, r.client, false, "notused")
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Status.Conditions).To(HaveLen(1))
			Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
			Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))
		})

		It("should reconcile with empty tigerastatus conditions ", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "compliance"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status:     operatorv1.TigeraStatusStatus{},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "compliance",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := GetCompliance(ctx, r.client, false, "notused")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(instance.Status.Conditions).To(HaveLen(0))
		})

		It("should reconcile with creating new status condition  with multiple conditions as true", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "compliance"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status: operatorv1.TigeraStatusStatus{
					Conditions: []operatorv1.TigeraStatusCondition{
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
					},
				},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "compliance",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := GetCompliance(ctx, r.client, false, "notused")
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Status.Conditions).To(HaveLen(3))
			Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
			Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))

			Expect(instance.Status.Conditions[1].Type).To(Equal("Progressing"))
			Expect(string(instance.Status.Conditions[1].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[1].Reason).To(Equal(string(operatorv1.ResourceNotReady)))
			Expect(instance.Status.Conditions[1].Message).To(Equal("Progressing Installation.operatorv1.tigera.io"))
			Expect(instance.Status.Conditions[1].ObservedGeneration).To(Equal(generation))

			Expect(instance.Status.Conditions[2].Type).To(Equal("Degraded"))
			Expect(string(instance.Status.Conditions[2].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[2].Reason).To(Equal(string(operatorv1.ResourceUpdateError)))
			Expect(instance.Status.Conditions[2].Message).To(Equal("Error resolving ImageSet for components"))
			Expect(instance.Status.Conditions[2].ObservedGeneration).To(Equal(generation))
		})

		It("should reconcile with creating new status condition and toggle Available to true & others to false", func() {
			ts := &operatorv1.TigeraStatus{
				ObjectMeta: metav1.ObjectMeta{Name: "compliance"},
				Spec:       operatorv1.TigeraStatusSpec{},
				Status: operatorv1.TigeraStatusStatus{
					Conditions: []operatorv1.TigeraStatusCondition{
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
							Reason:             string(operatorv1.NotApplicable),
							Message:            "Not Applicable",
							ObservedGeneration: generation,
						},
						{
							Type:               operatorv1.ComponentDegraded,
							Status:             operatorv1.ConditionFalse,
							Reason:             string(operatorv1.NotApplicable),
							Message:            "Not Applicable",
							ObservedGeneration: generation,
						},
					},
				},
			}
			Expect(c.Create(ctx, ts)).NotTo(HaveOccurred())

			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{
				Name:      "compliance",
				Namespace: "",
			}})
			Expect(err).ShouldNot(HaveOccurred())
			instance, err := GetCompliance(ctx, r.client, false, "notused")
			Expect(err).ShouldNot(HaveOccurred())

			Expect(instance.Status.Conditions).To(HaveLen(3))
			Expect(instance.Status.Conditions[0].Type).To(Equal("Ready"))
			Expect(string(instance.Status.Conditions[0].Status)).To(Equal(string(operatorv1.ConditionTrue)))
			Expect(instance.Status.Conditions[0].Reason).To(Equal(string(operatorv1.AllObjectsAvailable)))
			Expect(instance.Status.Conditions[0].Message).To(Equal("All Objects are available"))
			Expect(instance.Status.Conditions[0].ObservedGeneration).To(Equal(generation))

			Expect(instance.Status.Conditions[1].Type).To(Equal("Progressing"))
			Expect(string(instance.Status.Conditions[1].Status)).To(Equal(string(operatorv1.ConditionFalse)))
			Expect(instance.Status.Conditions[1].Reason).To(Equal(string(operatorv1.NotApplicable)))
			Expect(instance.Status.Conditions[1].Message).To(Equal("Not Applicable"))
			Expect(instance.Status.Conditions[1].ObservedGeneration).To(Equal(generation))

			Expect(instance.Status.Conditions[2].Type).To(Equal("Degraded"))
			Expect(string(instance.Status.Conditions[2].Status)).To(Equal(string(operatorv1.ConditionFalse)))
			Expect(instance.Status.Conditions[2].Reason).To(Equal(string(operatorv1.NotApplicable)))
			Expect(instance.Status.Conditions[2].Message).To(Equal("Not Applicable"))
			Expect(instance.Status.Conditions[2].ObservedGeneration).To(Equal(generation))
		})
	})

	Context("Multi-tenant/namespaced reconciliation", func() {
		tenantANamespace := "tenant-a"
		tenantBNamespace := "tenant-b"

		BeforeEach(func() {
			r.opts.MultiTenant = true
		})

		It("should reconcile both with and without namespace provided while namespaced compliance instances exist", func() {
			// Create the Tenant resources for tenant-a and tenant-b.
			tenantA := &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "default",
					Namespace: tenantANamespace,
				},
				Spec: operatorv1.TenantSpec{ID: "tenant-a"},
			}
			Expect(c.Create(ctx, tenantA)).NotTo(HaveOccurred())
			tenantB := &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "default",
					Namespace: tenantBNamespace,
				},
				Spec: operatorv1.TenantSpec{ID: "tenant-b"},
			}
			Expect(c.Create(ctx, tenantB)).NotTo(HaveOccurred())

			certificateManagerTenantA, err := certificatemanager.Create(c, nil, dns.DefaultClusterDomain, tenantANamespace, certificatemanager.AllowCACreation(), certificatemanager.WithTenant(tenantA))
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, certificateManagerTenantA.KeyPair().Secret(tenantANamespace)))
			trustedBundleWithSystemCAsTenantA, err := certificateManagerTenantA.CreateMultiTenantTrustedBundleWithSystemRootCertificates()
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, trustedBundleWithSystemCAsTenantA.ConfigMap(tenantANamespace))).NotTo(HaveOccurred())

			linseedTLSTenantA, err := certificateManagerTenantA.GetOrCreateKeyPair(c, render.TigeraLinseedSecret, tenantANamespace, []string{render.TigeraLinseedSecret})
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, linseedTLSTenantA.Secret(tenantANamespace))).NotTo(HaveOccurred())

			certificateManagerTenantB, err := certificatemanager.Create(c, nil, "", tenantBNamespace, certificatemanager.AllowCACreation(), certificatemanager.WithTenant(tenantB))
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, certificateManagerTenantB.KeyPair().Secret(tenantBNamespace)))
			trustedBundleWithSystemCAsTenantB, err := certificateManagerTenantB.CreateMultiTenantTrustedBundleWithSystemRootCertificates()
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, trustedBundleWithSystemCAsTenantB.ConfigMap(tenantBNamespace))).NotTo(HaveOccurred())

			linseedTLSTenantB, err := certificateManagerTenantB.GetOrCreateKeyPair(c, render.TigeraLinseedSecret, tenantBNamespace, []string{render.TigeraLinseedSecret})
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, linseedTLSTenantB.Secret(tenantBNamespace))).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &operatorv1.Compliance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tigera-secure",
					Namespace: tenantANamespace,
				},
			})).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &operatorv1.Compliance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tigera-secure",
					Namespace: tenantBNamespace,
				},
			})).NotTo(HaveOccurred())

			result, err := r.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(0 * time.Second))

			// We check for correct rendering of all resources in compliance_test.go, so use the SA
			// merely as a proxy here that the creation of our Compliance went smoothly
			tenantAServiceAccount := corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
				Name:      render.ComplianceServerServiceAccount,
				Namespace: tenantANamespace,
			}}

			tenantBServiceAccount := corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
				Name:      render.ComplianceServerServiceAccount,
				Namespace: tenantBNamespace,
			}}

			// We called Reconcile without specifying a namespace, so neither of these namespaced objects should
			// exist yet
			err = test.GetResource(c, &tenantAServiceAccount)
			Expect(err).Should(HaveOccurred())

			err = test.GetResource(c, &tenantBServiceAccount)
			Expect(err).Should(HaveOccurred())

			// Now reconcile only tenant A's namespace and check that its Compliance object exists, but tenant B's
			// Compliance object still hasn't been reconciled so it should still not exist
			_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: tenantANamespace}})
			Expect(err).ShouldNot(HaveOccurred())

			err = test.GetResource(c, &tenantAServiceAccount)
			Expect(err).ShouldNot(HaveOccurred())

			err = test.GetResource(c, &tenantBServiceAccount)
			Expect(err).Should(HaveOccurred())

			// Now reconcile tenant B's namespace and check that its Compliance object exists now alongside tenant A's
			_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: tenantBNamespace}})
			Expect(err).ShouldNot(HaveOccurred())

			err = test.GetResource(c, &tenantAServiceAccount)
			Expect(err).ShouldNot(HaveOccurred())

			err = test.GetResource(c, &tenantBServiceAccount)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("create operator secrets role and pull secrets", func() {
			// Create the Tenant resources for tenant-a
			tenantA := &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "default",
					Namespace: tenantANamespace,
				},
				Spec: operatorv1.TenantSpec{ID: "tenant-a"},
			}
			Expect(c.Create(ctx, tenantA)).NotTo(HaveOccurred())

			certificateManagerTenantA, err := certificatemanager.Create(c, nil, dns.DefaultClusterDomain, tenantANamespace, certificatemanager.AllowCACreation(), certificatemanager.WithTenant(tenantA))
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, certificateManagerTenantA.KeyPair().Secret(tenantANamespace)))
			trustedBundleWithSystemCAsTenantA, err := certificateManagerTenantA.CreateMultiTenantTrustedBundleWithSystemRootCertificates()
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, trustedBundleWithSystemCAsTenantA.ConfigMap(tenantANamespace))).NotTo(HaveOccurred())

			linseedTLSTenantA, err := certificateManagerTenantA.GetOrCreateKeyPair(c, render.TigeraLinseedSecret, tenantANamespace, []string{render.TigeraLinseedSecret})
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Create(ctx, linseedTLSTenantA.Secret(tenantANamespace))).NotTo(HaveOccurred())

			Expect(c.Create(ctx, &operatorv1.Compliance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tigera-secure",
					Namespace: tenantANamespace,
				},
			})).NotTo(HaveOccurred())

			result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: tenantANamespace}})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(0 * time.Second))

			// Expect operator role binding to be created
			rb := rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{},
			}
			Expect(c.Get(ctx, client.ObjectKey{
				Name:      render.TigeraOperatorSecrets,
				Namespace: tenantANamespace,
			}, &rb)).NotTo(HaveOccurred())
			Expect(rb.OwnerReferences).To(HaveLen(1))
			ownerRoleBinding := rb.OwnerReferences[0]
			Expect(ownerRoleBinding.Kind).To(Equal("Tenant"))

			// Expect pull secrets to be created
			pullSecrets := corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			}
			Expect(c.Get(ctx, client.ObjectKey{
				Name:      "tigera-pull-secret",
				Namespace: tenantANamespace,
			}, &pullSecrets)).NotTo(HaveOccurred())
			Expect(pullSecrets.OwnerReferences).To(HaveLen(1))
			ownerPullSecrets := pullSecrets.OwnerReferences[0]
			Expect(ownerPullSecrets.Kind).To(Equal("Tenant"))
		})
	})
})

func assertExpectedCertDNSNames(c client.Client, expectedDNSNames ...string) {
	ctx := context.Background()
	secret := &corev1.Secret{}

	Expect(c.Get(ctx, client.ObjectKey{
		Name:      render.ComplianceServerCertSecret,
		Namespace: common.OperatorNamespace(),
	}, secret)).NotTo(HaveOccurred())
	test.VerifyCertSANs(secret.Data[corev1.TLSCertKey], expectedDNSNames...)

	Expect(c.Get(ctx, client.ObjectKey{
		Name:      render.ComplianceServerCertSecret,
		Namespace: render.ComplianceNamespace,
	}, secret)).NotTo(HaveOccurred())
	test.VerifyCertSANs(secret.Data[corev1.TLSCertKey], expectedDNSNames...)
}
