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

package istio

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/stretchr/testify/mock"
	admregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	"github.com/projectcalico/calico/operator/pkg/render/istio"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

// testCert is a certificate made for a test, with the PEM forms a Secret holds.
type testCert struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	keyPEM  []byte
}

// newTestCert signs a certificate for cn with parent, or self-signs it when
// parent is nil.
func newTestCert(cn string, parent *testCert, isCA bool) *testCert {
	return newTestCertWith(cn, parent, isCA, nil)
}

// newTestCertWith is newTestCert with edit applied to the template first.
func newTestCertWith(cn string, parent *testCert, isCA bool, edit func(*x509.Certificate)) *testCert {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	Expect(err).NotTo(HaveOccurred())
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if edit != nil {
		edit(template)
	}
	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	keyDER, err := x509.MarshalECPrivateKey(key)
	Expect(err).NotTo(HaveOccurred())
	return &testCert{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

var _ = Describe("Istio controller certificate authority", func() {
	var (
		cli          client.Client
		scheme       *runtime.Scheme
		ctx          context.Context
		mockStatus   *status.MockStatus
		installation *operatorv1.Installation
		istioCR      *operatorv1.Istio
		r            *ReconcileIstio
		// now is the reconciler's clock; tests move it.
		now time.Time
	)

	operatorNS := common.OperatorNamespace()
	cacertsKey := types.NamespacedName{Name: istio.CACertsSecretName, Namespace: istio.IstioNamespace}
	operatorCAKey := types.NamespacedName{Name: istio.OperatorCASecretName, Namespace: operatorNS}
	anchorsKey := types.NamespacedName{Name: istio.TrustExportConfigMapName, Namespace: istio.IstioNamespace}

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).ShouldNot(HaveOccurred())
		Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(admregv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
		Expect(autoscalingv2.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

		ctx = context.Background()
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		mockStatus = &status.MockStatus{}
		mockStatus.On("SetWarning", mock.Anything, mock.Anything).Return().Maybe()
		mockStatus.On("ClearWarning", mock.Anything).Return().Maybe()
		mockStatus.On("AddDaemonsets", mock.Anything).Maybe().Return()
		mockStatus.On("AddDeployments", mock.Anything).Maybe().Return()
		mockStatus.On("AddStatefulSets", mock.Anything).Maybe().Return()
		mockStatus.On("AddCronJobs", mock.Anything).Maybe()
		mockStatus.On("IsAvailable").Maybe().Return(true)
		mockStatus.On("OnCRFound").Maybe().Return()
		mockStatus.On("ClearDegraded").Maybe()
		mockStatus.On("SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Maybe().Return()
		mockStatus.On("ReadyToMonitor").Maybe()
		mockStatus.On("OnCRNotFound").Maybe().Return()
		mockStatus.On("SetMetaData", mock.Anything).Maybe().Return()

		installation = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       operatorv1.InstallationSpec{Variant: operatorv1.Calico},
			Status: operatorv1.InstallationStatus{
				Variant:    operatorv1.Calico,
				Conditions: []metav1.Condition{{Type: string(operatorv1.ComponentAvailable), Status: metav1.ConditionTrue}},
			},
		}
		installation.Status.Computed = &installation.Spec
		istioCR = &operatorv1.Istio{ObjectMeta: metav1.ObjectMeta{Name: "default"}}

		now = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
		r = &ReconcileIstio{Client: cli, scheme: scheme, provider: operatorv1.ProviderNone, status: mockStatus, now: func() time.Time { return now }}
	})

	createResources := func() {
		Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, istioCR)).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, &v3.ClusterInformation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       v3.ClusterInformationSpec{ClusterGUID: "0123456789abcdef0123456789abcdef"},
		})).NotTo(HaveOccurred())
	}

	reconcileResult := func() reconcile.Result {
		result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "default"}})
		Expect(err).ShouldNot(HaveOccurred())
		return result
	}

	reconcileIstio := func() {
		reconcileResult()
	}

	getSecret := func(key types.NamespacedName) *corev1.Secret {
		s := &corev1.Secret{}
		Expect(cli.Get(ctx, key, s)).NotTo(HaveOccurred())
		return s
	}

	secretAbsent := func(key types.NamespacedName) {
		Expect(errors.IsNotFound(cli.Get(ctx, key, &corev1.Secret{}))).To(BeTrue(), "expected Secret %s to be absent", key)
	}

	getConfigMap := func(key types.NamespacedName) *corev1.ConfigMap {
		cm := &corev1.ConfigMap{}
		Expect(cli.Get(ctx, key, cm)).NotTo(HaveOccurred())
		return cm
	}

	getIstiod := func() *appsv1.Deployment {
		d := &appsv1.Deployment{}
		Expect(cli.Get(ctx, types.NamespacedName{Name: istio.IstioIstiodDeploymentName, Namespace: istio.IstioNamespace}, d)).NotTo(HaveOccurred())
		return d
	}

	createOperatorSecret := func(name string, data map[string][]byte) {
		Expect(cli.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: operatorNS},
			Data:       data,
		})).NotTo(HaveOccurred())
	}
	createCASecret := func(name string, data map[string][]byte) {
		Expect(cli.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: operatorNS, Labels: map[string]string{istio.CASecretLabel: "true"}},
			Data:       data,
		})).NotTo(HaveOccurred())
	}

	expectDegradedMentioning := func(parts ...string) {
		mockStatus.AssertCalled(GinkgoT(), "SetDegraded", operatorv1.ResourceValidationError, mock.MatchedBy(func(msg string) bool {
			for _, p := range parts {
				if !strings.Contains(msg, p) {
					return false
				}
			}
			return true
		}), mock.Anything, mock.Anything)
	}

	expectNotDegraded := func() {
		mockStatus.AssertNotCalled(GinkgoT(), "SetDegraded", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		mockStatus.AssertCalled(GinkgoT(), "ClearDegraded")
	}

	Context("operator-managed CA", func() {
		BeforeEach(createResources)

		It("generates the CA once, persists it in the operator namespace and renders cacerts from it", func() {
			reconcileIstio()

			caSecret := getSecret(operatorCAKey)
			Expect(caSecret.Data).To(HaveLen(4))
			Expect(caSecret.OwnerReferences).To(BeEmpty())
			ca, err := istio.LoadCA(caSecret.Data)
			Expect(err).NotTo(HaveOccurred())
			Expect(ca.Roots).To(HaveLen(1))
			Expect(ca.Roots[0].Subject.Organization).To(Equal([]string{"cluster.local"}))
			Expect(caSecret.Data[istio.CertChainKey]).To(Equal(caSecret.Data[istio.CACertKey]))
			Expect(caSecret.Data[istio.RootCertKey]).To(Equal(caSecret.Data[istio.CACertKey]))
			Expect(caSecret.Labels).To(HaveKey(certificatemanagement.SignerLabel))
			Expect(caSecret.Annotations).To(HaveKeyWithValue(certificatemanagement.ExpiryAnnotation,
				ca.Roots[0].NotAfter.UTC().Format(certificatemanagement.ExpiryFormat)))

			cacerts := getSecret(cacertsKey)
			Expect(cacerts.Labels).To(HaveKeyWithValue(istio.CACertsLabel, "operatorManaged"))
			Expect(cacerts.Data).To(Equal(caSecret.Data))
			Expect(cacerts.OwnerReferences).NotTo(BeEmpty())

			cm := getConfigMap(anchorsKey)
			Expect(cm.Data[istio.RootCertKey]).To(Equal(string(caSecret.Data[istio.CACertKey])))
			Expect(cm.Data[istio.TrustDomainKey]).To(Equal("cluster.local"))

			istiod := getIstiod()
			Expect(istiod.Spec.Template.Annotations).To(HaveKey(istio.CACertsHashAnnotation))
			Expect(istiod.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "ISTIO_MULTIROOT_MESH", Value: "true"}))
			expectNotDegraded()
			mockStatus.AssertCalled(GinkgoT(), "ClearWarning", caWarningKey)

			reconcileIstio()
			Expect(getSecret(operatorCAKey).Data).To(Equal(caSecret.Data))
			Expect(getSecret(cacertsKey).Data).To(Equal(cacerts.Data))
		})

		It("goes Degraded and leaves the CA alone while certificate management is set", func() {
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, installation)).To(Succeed())
			installation.Spec.CertificateManagement = &operatorv1.CertificateManagement{CACert: []byte("ca"), SignerName: "example.com/signer"}
			Expect(cli.Update(ctx, installation)).To(Succeed())
			installation.Status.Computed = installation.Spec.DeepCopy()
			Expect(cli.Status().Update(ctx, installation)).To(Succeed())
			reconcileIstio()

			secretAbsent(operatorCAKey)
			secretAbsent(cacertsKey)
			Expect(errors.IsNotFound(cli.Get(ctx, anchorsKey, &corev1.ConfigMap{}))).To(BeTrue())
			Expect(getIstiod().Spec.Template.Annotations).NotTo(HaveKey(istio.CACertsHashAnnotation))
			expectDegradedMentioning("certificateManagement")
		})

		It("treats an explicit operatorManaged the same as unset", func() {
			istioCR.Spec.CertificateAuthority = &operatorv1.IstioCertificateAuthority{OperatorManaged: &operatorv1.IstioOperatorManagedCA{}}
			Expect(cli.Update(ctx, istioCR)).NotTo(HaveOccurred())
			reconcileIstio()
			Expect(getSecret(cacertsKey).Data).To(Equal(getSecret(operatorCAKey).Data))
			expectNotDegraded()
		})

		It("keeps the CA Secret when the Istio CR is deleted", func() {
			reconcileIstio()

			current := &operatorv1.Istio{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, current)).NotTo(HaveOccurred())
			Expect(cli.Delete(ctx, current)).NotTo(HaveOccurred())
			reconcileIstio()

			Expect(errors.IsNotFound(cli.Get(ctx, types.NamespacedName{Name: "default"}, &operatorv1.Istio{}))).To(BeTrue())
			getSecret(operatorCAKey)
		})

		It("reports a persisted CA that no longer validates instead of replacing it", func() {
			reconcileIstio()
			cacerts := getSecret(cacertsKey)

			caSecret := getSecret(operatorCAKey)
			caSecret.Data[istio.CAKeyKey] = newTestCert("other", nil, true).keyPEM
			Expect(cli.Update(ctx, caSecret)).NotTo(HaveOccurred())
			reconcileIstio()

			Expect(getSecret(operatorCAKey).Data[istio.CAKeyKey]).To(Equal(caSecret.Data[istio.CAKeyKey]))
			Expect(getSecret(cacertsKey).Data).To(Equal(cacerts.Data))
			expectDegradedMentioning(operatorNS+"/"+istio.OperatorCASecretName, "does not match")
		})

		It("reports a CA Secret with no data instead of generating a CA over it", func() {
			Expect(cli.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: istio.OperatorCASecretName, Namespace: operatorNS},
			})).NotTo(HaveOccurred())
			reconcileIstio()

			Expect(getSecret(operatorCAKey).Data).To(BeEmpty())
			expectDegradedMentioning(operatorNS+"/"+istio.OperatorCASecretName, "expected keys")
		})
	})

	Context("customer CA", func() {
		var root, intermediate *testCert

		BeforeEach(func() {
			root = newTestCert("root", nil, true)
			intermediate = newTestCert("intermediate", root, true)
			istioCR.Spec.CertificateAuthority = &operatorv1.IstioCertificateAuthority{Secret: &operatorv1.IstioCASecret{Name: "istio-mesh-ca"}}
			createResources()
		})

		expectIntermediateCA := func() {
			cacerts := getSecret(cacertsKey)
			Expect(cacerts.Labels).To(HaveKeyWithValue(istio.CACertsLabel, "secret"))
			Expect(cacerts.Data[istio.CACertKey]).To(Equal(intermediate.certPEM))
			Expect(cacerts.Data[istio.CAKeyKey]).To(Equal(intermediate.keyPEM))
			Expect(cacerts.Data[istio.CertChainKey]).To(Equal(concatPEM(intermediate.certPEM, root.certPEM)))
			Expect(cacerts.Data[istio.RootCertKey]).To(Equal(root.certPEM))
			Expect(getConfigMap(anchorsKey).Data[istio.RootCertKey]).To(Equal(string(root.certPEM)))
			secretAbsent(operatorCAKey)
			expectNotDegraded()
		}

		It("renders cacerts from a Secret in Istio's plug-in layout", func() {
			createCASecret("istio-mesh-ca", map[string][]byte{
				istio.CACertKey:    intermediate.certPEM,
				istio.CAKeyKey:     intermediate.keyPEM,
				istio.CertChainKey: concatPEM(intermediate.certPEM, root.certPEM),
				istio.RootCertKey:  root.certPEM,
			})
			reconcileIstio()
			expectIntermediateCA()
		})

		It("renders cacerts from a Secret in the kubernetes.io/tls layout", func() {
			createCASecret("istio-mesh-ca", map[string][]byte{
				corev1.TLSCertKey:       intermediate.certPEM,
				corev1.TLSPrivateKeyKey: intermediate.keyPEM,
				"ca.crt":                root.certPEM,
			})
			reconcileIstio()
			expectIntermediateCA()
		})

		It("goes Degraded and renders no cacerts when the Secret does not exist", func() {
			reconcileIstio()
			secretAbsent(cacertsKey)
			secretAbsent(operatorCAKey)
			expectDegradedMentioning(operatorNS+"/istio-mesh-ca", "does not exist")
			Expect(getIstiod().Spec.Template.Annotations).NotTo(HaveKey(istio.CACertsHashAnnotation))
		})

		It("copies nothing from a Secret without the opt-in label, and uses it once the label is set", func() {
			createOperatorSecret("istio-mesh-ca", map[string][]byte{
				corev1.TLSCertKey:       intermediate.certPEM,
				corev1.TLSPrivateKeyKey: intermediate.keyPEM,
				"ca.crt":                root.certPEM,
			})
			reconcileIstio()
			secretAbsent(cacertsKey)
			secretAbsent(operatorCAKey)
			expectDegradedMentioning(operatorNS+"/istio-mesh-ca", istio.CASecretLabel+"=true")

			byo := getSecret(types.NamespacedName{Name: "istio-mesh-ca", Namespace: operatorNS})
			byo.Labels = map[string]string{istio.CASecretLabel: "true"}
			Expect(cli.Update(ctx, byo)).NotTo(HaveOccurred())
			mockStatus.Calls = nil
			reconcileIstio()
			expectIntermediateCA()
		})

		It("copies nothing from a CA whose name constraints rule out the trust domain, and uses it once the trust domain fits", func() {
			constrained := newTestCertWith("corp-root", nil, true, func(c *x509.Certificate) {
				c.PermittedURIDomains = []string{"corp.example"}
			})
			createCASecret("istio-mesh-ca", map[string][]byte{
				istio.CACertKey:   constrained.certPEM,
				istio.CAKeyKey:    constrained.keyPEM,
				istio.RootCertKey: constrained.certPEM,
			})
			reconcileIstio()
			secretAbsent(cacertsKey)
			secretAbsent(operatorCAKey)
			expectDegradedMentioning(operatorNS+"/istio-mesh-ca", "spiffe://cluster.local/")

			Expect(cli.Get(ctx, client.ObjectKeyFromObject(istioCR), istioCR)).NotTo(HaveOccurred())
			istioCR.Spec.TrustDomain = ptr.To("corp.example")
			Expect(cli.Update(ctx, istioCR)).NotTo(HaveOccurred())
			mockStatus.Calls = nil
			reconcileIstio()
			Expect(getSecret(cacertsKey).Data[istio.CACertKey]).To(Equal(constrained.certPEM))
			expectNotDegraded()
		})

		It("keeps the last cacerts and goes Degraded when the Secret turns invalid", func() {
			createCASecret("istio-mesh-ca", map[string][]byte{
				istio.CACertKey:   root.certPEM,
				istio.CAKeyKey:    root.keyPEM,
				istio.RootCertKey: root.certPEM,
			})
			reconcileIstio()
			cacerts := getSecret(cacertsKey)
			hash := getIstiod().Spec.Template.Annotations[istio.CACertsHashAnnotation]

			byo := getSecret(types.NamespacedName{Name: "istio-mesh-ca", Namespace: operatorNS})
			byo.Data[istio.CAKeyKey] = intermediate.keyPEM
			Expect(cli.Update(ctx, byo)).NotTo(HaveOccurred())
			reconcileIstio()

			Expect(getSecret(cacertsKey).Data).To(Equal(cacerts.Data))
			Expect(getIstiod().Spec.Template.Annotations[istio.CACertsHashAnnotation]).To(Equal(hash))
			Expect(getConfigMap(anchorsKey).Data[istio.RootCertKey]).To(Equal(string(root.certPEM)))
			expectDegradedMentioning(operatorNS+"/istio-mesh-ca", "ca-key.pem does not match")
		})

		It("reconciles when the named Secret changes and not for other Secrets", func() {
			istioCR.Spec.TrustAnchors = &operatorv1.IstioTrustAnchors{Additional: []operatorv1.IstioTrustAnchor{{Secret: &operatorv1.IstioCASecret{Name: "partner-root"}}}}
			Expect(cli.Update(ctx, istioCR)).NotTo(HaveOccurred())

			requests := func(name, namespace string) []reconcile.Request {
				return r.enqueueForReferencedSecret(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}})
			}
			Expect(requests("istio-mesh-ca", operatorNS)).To(HaveLen(1))
			Expect(requests("partner-root", operatorNS)).To(HaveLen(1))
			Expect(requests(istio.OperatorCASecretName, operatorNS)).To(HaveLen(1))
			Expect(requests("tigera-pull-secret", operatorNS)).To(BeEmpty())
			Expect(requests("istio-mesh-ca", istio.IstioNamespace)).To(BeEmpty())
		})
	})

	Context("additional trust anchors", func() {
		It("merges valid anchors deduplicated and sorted, and names the invalid ones", func() {
			a, b := newTestCert("a", nil, true), newTestCert("b", nil, true)
			leaf := newTestCert("leaf", a, false)
			istioCR.Spec.TrustAnchors = &operatorv1.IstioTrustAnchors{Additional: []operatorv1.IstioTrustAnchor{
				{Secret: &operatorv1.IstioCASecret{Name: "partner-root"}},
				{PEM: string(b.certPEM)},
				{PEM: string(a.certPEM)},
				{PEM: string(leaf.certPEM)},
				{Secret: &operatorv1.IstioCASecret{Name: "missing-root"}},
				{Secret: &operatorv1.IstioCASecret{Name: "wrong-key"}},
			}}
			createResources()
			createOperatorSecret("partner-root", map[string][]byte{istio.RootCertKey: a.certPEM})
			createOperatorSecret("wrong-key", map[string][]byte{"tls.crt": a.certPEM})
			reconcileIstio()

			own, err := istio.LoadCA(getSecret(operatorCAKey).Data)
			Expect(err).NotTo(HaveOccurred())
			bundle := getSecret(cacertsKey).Data[istio.RootCertKey]
			Expect(bundle).To(Equal(istio.ComposeRootBundle(own.Roots, []*x509.Certificate{a.cert, b.cert})))

			cm := getConfigMap(anchorsKey)
			Expect(cm.Data[istio.RootCertKey]).To(Equal(string(own.CertPEM)))

			expectDegradedMentioning(
				"spec.trustAnchors.additional[3]: certificate 1 is not a CA",
				"spec.trustAnchors.additional[4]: Secret "+operatorNS+"/missing-root does not exist",
				"spec.trustAnchors.additional[5] (Secret "+operatorNS+"/wrong-key): key root-cert.pem is missing",
			)
		})

		It("changes the istiod hash when an anchor is added", func() {
			createResources()
			reconcileIstio()
			hash := getIstiod().Spec.Template.Annotations[istio.CACertsHashAnnotation]

			current := &operatorv1.Istio{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, current)).NotTo(HaveOccurred())
			current.Spec.TrustAnchors = &operatorv1.IstioTrustAnchors{Additional: []operatorv1.IstioTrustAnchor{{PEM: string(newTestCert("a", nil, true).certPEM)}}}
			Expect(cli.Update(ctx, current)).NotTo(HaveOccurred())
			reconcileIstio()

			Expect(getIstiod().Spec.Template.Annotations[istio.CACertsHashAnnotation]).NotTo(Equal(hash))
			expectNotDegraded()
		})
	})

	Context("trust domain", func() {
		It("renders the trust domain to istiod, ztunnel and the published ConfigMap", func() {
			istioCR.Spec.TrustDomain = ptr.To("mesh.example")
			createResources()
			reconcileIstio()

			meshCM := getConfigMap(types.NamespacedName{Name: "istio", Namespace: istio.IstioNamespace})
			Expect(meshCM.Data["mesh"]).To(ContainSubstring("trustDomain: mesh.example"))

			ztunnel := &appsv1.DaemonSet{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: istio.IstioZTunnelDaemonSetName, Namespace: istio.IstioNamespace}, ztunnel)).NotTo(HaveOccurred())
			Expect(ztunnel.Spec.Template.Spec.Containers[0].Env).To(ContainElement(corev1.EnvVar{Name: "TRUST_DOMAIN", Value: "mesh.example"}))

			Expect(getConfigMap(anchorsKey).Data[istio.TrustDomainKey]).To(Equal("mesh.example"))
			ca, err := istio.LoadCA(getSecret(operatorCAKey).Data)
			Expect(err).NotTo(HaveOccurred())
			Expect(ca.Roots[0].Subject.Organization).To(Equal([]string{"mesh.example"}))
		})
	})

	Context("signer transitions", func() {
		var selfSigned *testCert
		wait := istio.SignerTransitionWait()
		istioCAKey := types.NamespacedName{Name: istio.IstioSelfSignedCASecretName, Namespace: istio.IstioNamespace}

		BeforeEach(func() {
			selfSigned = newTestCert("self-signed", nil, true)
			createResources()
		})

		// createIstioCASecret persists the self-signed CA the way istiod 1.31 does.
		createIstioCASecret := func() {
			Expect(cli.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: istio.IstioSelfSignedCASecretName, Namespace: istio.IstioNamespace},
				Type:       "istio.io/ca-root",
				Data: map[string][]byte{
					istio.CACertKey:    selfSigned.certPEM,
					istio.CAKeyKey:     selfSigned.keyPEM,
					istio.CertChainKey: nil,
					"key.pem":          nil,
					istio.RootCertKey:  selfSigned.certPEM,
				},
			})).NotTo(HaveOccurred())
		}

		// markIstiodRolled makes the Deployment report a complete rollout of the
		// template the last reconcile rendered.
		markIstiodRolled := func() {
			d := getIstiod()
			replicas := int32(1)
			if d.Spec.Replicas != nil {
				replicas = *d.Spec.Replicas
			}
			d.Status = appsv1.DeploymentStatus{ObservedGeneration: d.Generation, Replicas: replicas, UpdatedReplicas: replicas, ReadyReplicas: replicas, AvailableReplicas: replicas}
			Expect(cli.Status().Update(ctx, d)).NotTo(HaveOccurred())
		}

		transitionOf := func() istio.TransitionState { return istio.ReadTransition(getSecret(cacertsKey)) }
		istiodHash := func() string { return getIstiod().Spec.Template.Annotations[istio.CACertsHashAnnotation] }
		operatorCA := func() *istio.CA {
			ca, err := istio.LoadCA(getSecret(operatorCAKey).Data)
			Expect(err).NotTo(HaveOccurred())
			return ca
		}
		// replaceOperatorCA puts a new root in the operator-managed CA Secret, the
		// way a user rotates it.
		replaceOperatorCA := func(root *testCert) {
			caSecret := getSecret(operatorCAKey)
			caSecret.Data = map[string][]byte{
				istio.CACertKey:    root.certPEM,
				istio.CAKeyKey:     root.keyPEM,
				istio.CertChainKey: root.certPEM,
				istio.RootCertKey:  root.certPEM,
			}
			Expect(cli.Update(ctx, caSecret)).NotTo(HaveOccurred())
		}
		useCustomerCA := func(name string) {
			current := &operatorv1.Istio{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, current)).NotTo(HaveOccurred())
			current.Spec.CertificateAuthority = nil
			if name != "" {
				current.Spec.CertificateAuthority = &operatorv1.IstioCertificateAuthority{Secret: &operatorv1.IstioCASecret{Name: name}}
			}
			Expect(cli.Update(ctx, current)).NotTo(HaveOccurred())
		}
		createCustomerCA := func(name string, root, intermediate *testCert) {
			createCASecret(name, map[string][]byte{
				istio.CACertKey:    intermediate.certPEM,
				istio.CAKeyKey:     intermediate.keyPEM,
				istio.CertChainKey: concatPEM(intermediate.certPEM, root.certPEM),
				istio.RootCertKey:  root.certPEM,
			})
		}

		expectSigner := func(c *testCert) {
			cacerts := getSecret(cacertsKey)
			Expect(cacerts.Data[istio.CACertKey]).To(Equal(c.certPEM))
			Expect(cacerts.Data[istio.CAKeyKey]).To(Equal(c.keyPEM))
		}
		expectBundle := func(roots ...*x509.Certificate) {
			Expect(getSecret(cacertsKey).Data[istio.RootCertKey]).To(Equal(istio.ComposeRootBundle(roots)))
		}
		expectPublished := func(roots ...*x509.Certificate) {
			Expect(getConfigMap(anchorsKey).Data[istio.RootCertKey]).To(Equal(string(istio.ComposeRootBundle(roots))))
		}
		expectPhase := func(phase istio.TransitionPhase, deadline time.Time) istio.TransitionState {
			state := transitionOf()
			Expect(state.Phase).To(Equal(phase))
			Expect(state.Deadline.Equal(deadline)).To(BeTrue(), "deadline %s, expected %s", state.Deadline, deadline)
			return state
		}
		expectWarningMentioning := func(parts ...string) {
			mockStatus.AssertCalled(GinkgoT(), "SetWarning", caWarningKey, mock.MatchedBy(func(msg string) bool {
				for _, p := range parts {
					if !strings.Contains(msg, p) {
						return false
					}
				}
				return true
			}))
		}

		// markIstiodRolling makes the Deployment report the template the last
		// reconcile rendered as still rolling out, with the old replica not yet
		// gone. The fake client never bumps the generation, so without this a
		// template change looks observed and complete at once.
		markIstiodRolling := func() {
			d := getIstiod()
			d.Status = appsv1.DeploymentStatus{ObservedGeneration: d.Generation, Replicas: 2, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}
			Expect(cli.Status().Update(ctx, d)).NotTo(HaveOccurred())
		}

		// advanceTo drives a transition from the phase cacerts records up to the
		// given phase, rolling istiod or moving the clock as each phase needs.
		advanceTo := func(phase istio.TransitionPhase) {
			for state := transitionOf(); state.Phase != istio.TransitionNone && state.Phase < phase; state = transitionOf() {
				switch state.Phase {
				case istio.TransitionDistributeRoot, istio.TransitionSwitchSigner:
					markIstiodRolled()
				default:
					now = state.Deadline
				}
				reconcileIstio()
			}
			expectPhase(phase, transitionOf().Deadline)
		}

		It("migrates a self-signed install through the four phases, never dropping a root a ztunnel may still need", func() {
			createIstioCASecret()
			result := reconcileResult()
			op := operatorCA()
			opRoot := op.Roots[0]

			// Phase 1: the self-signed CA keeps signing, both roots are served.
			cacerts := getSecret(cacertsKey)
			Expect(cacerts.Labels).To(HaveKeyWithValue(istio.CACertsLabel, "selfSigned"))
			expectSigner(selfSigned)
			Expect(cacerts.Data[istio.CertChainKey]).To(Equal(selfSigned.certPEM))
			expectBundle(selfSigned.cert, opRoot)
			Expect(transitionRecord(cacerts)).To(Equal(map[string]string{
				istio.TransitionPhaseAnnotation: "1",
				istio.TransitionFromAnnotation:  istio.Fingerprint(selfSigned.cert),
				istio.TransitionToAnnotation:    istio.Fingerprint(opRoot),
			}))
			expectPublished(selfSigned.cert, opRoot)
			hash := istiodHash()
			Expect(hash).To(Equal(rmeta.SecretsAnnotationHash(cacerts)))
			Expect(result.RequeueAfter).To(Equal(utils.StandardRetry))
			expectNotDegraded()
			expectWarningMentioning("phase 1/4", istio.IstioNamespace+"/"+istio.IstioSelfSignedCASecretName)

			// No clock runs until istiod has rolled, however long that takes.
			now = now.Add(time.Hour)
			Expect(reconcileResult().RequeueAfter).To(Equal(utils.StandardRetry))
			expectPhase(istio.TransitionDistributeRoot, time.Time{})
			Expect(getSecret(cacertsKey).Data).To(Equal(cacerts.Data))

			// Phase 2: the roll starts the clock; the data, and so istiod, stay put.
			markIstiodRolled()
			result = reconcileResult()
			deadline := now.Add(wait)
			state := expectPhase(istio.TransitionAwaitDistribution, deadline)
			Expect(result.RequeueAfter).To(Equal(wait))
			Expect(getSecret(cacertsKey).Data).To(Equal(cacerts.Data))
			Expect(istiodHash()).To(Equal(hash))
			expectWarningMentioning("phase 2/4", state.Deadline.UTC().Format(time.RFC3339))

			now = now.Add(wait / 2)
			Expect(reconcileResult().RequeueAfter).To(Equal(wait / 2))
			expectPhase(istio.TransitionAwaitDistribution, deadline)

			// Phase 3: the operator-managed CA signs; the old root is still trusted.
			now = now.Add(wait / 2)
			result = reconcileResult()
			Expect(result.RequeueAfter).To(Equal(utils.StandardRetry))
			expectPhase(istio.TransitionSwitchSigner, time.Time{})
			cacerts = getSecret(cacertsKey)
			Expect(cacerts.Labels).To(HaveKeyWithValue(istio.CACertsLabel, "operatorManaged"))
			Expect(cacerts.Data[istio.CACertKey]).To(Equal(op.CertPEM))
			Expect(cacerts.Data[istio.CAKeyKey]).To(Equal(op.KeyPEM))
			expectBundle(selfSigned.cert, opRoot)
			Expect(transitionRecord(cacerts)).To(Equal(map[string]string{
				istio.TransitionPhaseAnnotation: "3",
				istio.TransitionFromAnnotation:  istio.Fingerprint(selfSigned.cert),
				istio.TransitionToAnnotation:    istio.Fingerprint(opRoot),
			}))
			expectPublished(selfSigned.cert, opRoot)
			Expect(istiodHash()).NotTo(Equal(hash))
			hash = istiodHash()
			expectWarningMentioning("rotation, phase 3/4")

			// The request to roll is not the roll: a template still rolling out starts no clock.
			markIstiodRolling()
			reconcileIstio()
			expectPhase(istio.TransitionSwitchSigner, time.Time{})

			// Phase 4: one more TTL from that roll.
			markIstiodRolled()
			result = reconcileResult()
			deadline = now.Add(wait)
			expectPhase(istio.TransitionAwaitExpiry, deadline)
			Expect(result.RequeueAfter).To(Equal(wait))
			Expect(istiodHash()).To(Equal(hash))
			expectWarningMentioning("phase 4/4", deadline.UTC().Format(time.RFC3339))

			// Done: the old root goes, the record is cleared, istiod rolls once more.
			now = now.Add(wait)
			mockStatus.Calls = nil
			result = reconcileResult()
			Expect(result.RequeueAfter).To(BeZero())
			cacerts = getSecret(cacertsKey)
			Expect(transitionRecord(cacerts)).To(BeEmpty())
			Expect(cacerts.Data).To(Equal(getSecret(operatorCAKey).Data))
			expectPublished(opRoot)
			Expect(istiodHash()).NotTo(Equal(hash))
			mockStatus.AssertCalled(GinkgoT(), "ClearWarning", caWarningKey)
			mockStatus.AssertNotCalled(GinkgoT(), "SetWarning", caWarningKey, mock.Anything)
			expectNotDegraded()

			// istio-ca-secret is still there and no longer matters.
			getSecret(istioCAKey)
			reconcileIstio()
			Expect(getSecret(cacertsKey).Data).To(Equal(cacerts.Data))
		})

		It("resumes from the record on cacerts alone after a restart", func() {
			createIstioCASecret()
			reconcileIstio()

			// A restart in phase 1 does not start the clock: the roll has to be seen.
			r = &ReconcileIstio{Client: cli, scheme: scheme, provider: operatorv1.ProviderNone, status: mockStatus, now: func() time.Time { return now }}
			now = now.Add(time.Hour)
			reconcileIstio()
			expectPhase(istio.TransitionDistributeRoot, time.Time{})

			markIstiodRolled()
			reconcileIstio()
			deadline := expectPhase(istio.TransitionAwaitDistribution, now.Add(wait)).Deadline

			// A restart in phase 2 keeps the deadline and requeues for what is left.
			r = &ReconcileIstio{Client: cli, scheme: scheme, provider: operatorv1.ProviderNone, status: mockStatus, now: func() time.Time { return now }}
			now = now.Add(time.Hour)
			Expect(reconcileResult().RequeueAfter).To(Equal(wait - time.Hour))
			expectPhase(istio.TransitionAwaitDistribution, deadline)

			now = deadline
			reconcileIstio()
			expectPhase(istio.TransitionSwitchSigner, time.Time{})
			Expect(getSecret(cacertsKey).Data[istio.CACertKey]).To(Equal(operatorCA().CertPEM))
		})

		It("restarts from phase 1 for a desired signer that changes before the switch", func() {
			createIstioCASecret()
			reconcileIstio()
			advanceTo(istio.TransitionAwaitDistribution)
			root := newTestCert("root", nil, true)
			intermediate := newTestCert("intermediate", root, true)
			createCustomerCA("istio-mesh-ca", root, intermediate)
			useCustomerCA("istio-mesh-ca")

			reconcileIstio()

			state := expectPhase(istio.TransitionDistributeRoot, time.Time{})
			Expect(state.Retiring).To(HaveLen(1))
			Expect(state.Retiring[0].Raw).To(Equal(selfSigned.cert.Raw))
			Expect(state.Incoming).To(HaveLen(1))
			Expect(state.Incoming[0].Raw).To(Equal(root.cert.Raw))
			expectSigner(selfSigned)
			expectBundle(selfSigned.cert, root.cert)
			expectPublished(selfSigned.cert, root.cert)
			expectWarningMentioning("phase 1/4", operatorNS+"/istio-mesh-ca")
			expectNotDegraded()
		})

		It("finishes retiring the old root before it starts the transition a later change asks for", func() {
			createIstioCASecret()
			reconcileIstio()
			advanceTo(istio.TransitionAwaitExpiry)
			op := operatorCA()
			deadline := transitionOf().Deadline
			root := newTestCert("root", nil, true)
			intermediate := newTestCert("intermediate", root, true)
			createCustomerCA("istio-mesh-ca", root, intermediate)
			useCustomerCA("istio-mesh-ca")

			now = now.Add(time.Hour)
			Expect(reconcileResult().RequeueAfter).To(Equal(wait - time.Hour))
			expectPhase(istio.TransitionAwaitExpiry, deadline)
			Expect(getSecret(cacertsKey).Data[istio.CACertKey]).To(Equal(op.CertPEM))
			expectBundle(selfSigned.cert, op.Roots[0])
			expectPublished(selfSigned.cert, op.Roots[0])

			now = deadline
			reconcileIstio()
			state := expectPhase(istio.TransitionDistributeRoot, time.Time{})
			Expect(state.Retiring[0].Raw).To(Equal(op.Roots[0].Raw))
			Expect(state.Incoming[0].Raw).To(Equal(root.cert.Raw))
			Expect(getSecret(cacertsKey).Data[istio.CACertKey]).To(Equal(op.CertPEM))
			Expect(getSecret(cacertsKey).Labels).To(HaveKeyWithValue(istio.CACertsLabel, "operatorManaged"))
			expectBundle(op.Roots[0], root.cert)
			expectPublished(op.Roots[0], root.cert)
		})

		It("holds the phase and goes Degraded while the desired CA is not usable", func() {
			createIstioCASecret()
			reconcileIstio()
			advanceTo(istio.TransitionAwaitDistribution)
			cacerts := getSecret(cacertsKey)
			op := operatorCA()
			caSecret := getSecret(operatorCAKey)
			goodKey := caSecret.Data[istio.CAKeyKey]
			caSecret.Data[istio.CAKeyKey] = newTestCert("other", nil, true).keyPEM
			Expect(cli.Update(ctx, caSecret)).NotTo(HaveOccurred())

			now = now.Add(wait)
			result := reconcileResult()

			Expect(result.RequeueAfter).To(BeZero())
			held := getSecret(cacertsKey)
			Expect(held.Data).To(Equal(cacerts.Data))
			Expect(held.Annotations).To(Equal(cacerts.Annotations))
			expectPublished(selfSigned.cert, op.Roots[0])
			expectDegradedMentioning(operatorNS+"/"+istio.OperatorCASecretName, "does not match")
			expectWarningMentioning("paused at phase 2/4")

			caSecret = getSecret(operatorCAKey)
			caSecret.Data[istio.CAKeyKey] = goodKey
			Expect(cli.Update(ctx, caSecret)).NotTo(HaveOccurred())
			mockStatus.Calls = nil
			reconcileIstio()
			expectPhase(istio.TransitionSwitchSigner, time.Time{})
			Expect(getSecret(cacertsKey).Data[istio.CACertKey]).To(Equal(op.CertPEM))
			expectNotDegraded()
		})

		It("goes Degraded, renders nothing and keeps the self-signed root published when istio-ca-secret is not a usable CA", func() {
			Expect(cli.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: istio.IstioSelfSignedCASecretName, Namespace: istio.IstioNamespace},
				Data: map[string][]byte{
					istio.CACertKey:   selfSigned.certPEM,
					istio.CAKeyKey:    newTestCert("other", nil, true).keyPEM,
					istio.RootCertKey: selfSigned.certPEM,
				},
			})).NotTo(HaveOccurred())
			reconcileIstio()

			secretAbsent(cacertsKey)
			cm := getConfigMap(anchorsKey)
			Expect(cm.Data[istio.RootCertKey]).To(Equal(string(selfSigned.certPEM)))
			Expect(cm.Data[istio.TrustDomainKey]).To(Equal("cluster.local"))
			Expect(getIstiod().Spec.Template.Annotations).NotTo(HaveKey(istio.CACertsHashAnnotation))
			expectDegradedMentioning(istio.IstioNamespace+"/"+istio.IstioSelfSignedCASecretName, "does not match")
		})

		It("goes Degraded and publishes nothing when the self-signed root does not parse", func() {
			Expect(cli.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: istio.IstioSelfSignedCASecretName, Namespace: istio.IstioNamespace},
				Data:       map[string][]byte{istio.RootCertKey: []byte("garbage")},
			})).NotTo(HaveOccurred())
			reconcileIstio()

			secretAbsent(cacertsKey)
			Expect(errors.IsNotFound(cli.Get(ctx, anchorsKey, &corev1.ConfigMap{}))).To(BeTrue())
			expectDegradedMentioning(istio.IstioNamespace+"/"+istio.IstioSelfSignedCASecretName, "not a usable CA")
		})

		It("rotates the operator-managed root through the same phases when its Secret is deleted", func() {
			reconcileIstio()
			old := operatorCA()
			Expect(transitionRecord(getSecret(cacertsKey))).To(BeEmpty())
			Expect(cli.Delete(ctx, getSecret(operatorCAKey))).NotTo(HaveOccurred())

			reconcileIstio()
			op := operatorCA()
			Expect(op.Roots[0].Raw).NotTo(Equal(old.Roots[0].Raw))
			expectPhase(istio.TransitionDistributeRoot, time.Time{})
			Expect(getSecret(cacertsKey).Data[istio.CACertKey]).To(Equal(old.CertPEM))
			expectBundle(old.Roots[0], op.Roots[0])
			expectPublished(old.Roots[0], op.Roots[0])
			expectWarningMentioning("rotation, phase 1/4")

			advanceTo(istio.TransitionSwitchSigner)
			cacerts := getSecret(cacertsKey)
			Expect(cacerts.Labels).To(HaveKeyWithValue(istio.CACertsLabel, "operatorManaged"))
			Expect(cacerts.Data[istio.CACertKey]).To(Equal(op.CertPEM))
			expectBundle(old.Roots[0], op.Roots[0])
			expectPublished(old.Roots[0], op.Roots[0])

			markIstiodRolled()
			reconcileIstio()
			expectPhase(istio.TransitionAwaitExpiry, now.Add(wait))

			now = now.Add(wait)
			reconcileIstio()
			cacerts = getSecret(cacertsKey)
			Expect(transitionRecord(cacerts)).To(BeEmpty())
			Expect(cacerts.Data[istio.RootCertKey]).To(Equal(op.CertPEM))
			expectPublished(op.Roots[0])
			expectNotDegraded()
		})

		It("moves an operator-managed install to a customer CA through the same phases", func() {
			reconcileIstio()
			op := operatorCA()
			Expect(transitionRecord(getSecret(cacertsKey))).To(BeEmpty())
			root := newTestCert("root", nil, true)
			intermediate := newTestCert("intermediate", root, true)
			createCustomerCA("istio-mesh-ca", root, intermediate)
			useCustomerCA("istio-mesh-ca")

			reconcileIstio()
			expectPhase(istio.TransitionDistributeRoot, time.Time{})
			Expect(getSecret(cacertsKey).Labels).To(HaveKeyWithValue(istio.CACertsLabel, "operatorManaged"))
			Expect(getSecret(cacertsKey).Data[istio.CACertKey]).To(Equal(op.CertPEM))
			expectBundle(op.Roots[0], root.cert)
			expectPublished(op.Roots[0], root.cert)
			expectWarningMentioning("phase 1/4", "operator-managed CA", operatorNS+"/istio-mesh-ca")

			advanceTo(istio.TransitionSwitchSigner)
			cacerts := getSecret(cacertsKey)
			Expect(cacerts.Labels).To(HaveKeyWithValue(istio.CACertsLabel, "secret"))
			expectSigner(intermediate)
			Expect(cacerts.Data[istio.CertChainKey]).To(Equal(concatPEM(intermediate.certPEM, root.certPEM)))
			expectBundle(op.Roots[0], root.cert)
			expectPublished(op.Roots[0], root.cert)

			markIstiodRolled()
			reconcileIstio()
			expectPhase(istio.TransitionAwaitExpiry, now.Add(wait))

			now = now.Add(wait)
			reconcileIstio()
			cacerts = getSecret(cacertsKey)
			Expect(transitionRecord(cacerts)).To(BeEmpty())
			Expect(cacerts.Data[istio.RootCertKey]).To(Equal(root.certPEM))
			expectPublished(root.cert)
			expectNotDegraded()
		})

		It("ends a transition whose destination turns back into the CA already signing", func() {
			reconcileIstio()
			op := operatorCA()
			root := newTestCert("root", nil, true)
			createCustomerCA("istio-mesh-ca", root, newTestCert("intermediate", root, true))
			useCustomerCA("istio-mesh-ca")
			reconcileIstio()
			expectPhase(istio.TransitionDistributeRoot, time.Time{})

			useCustomerCA("")
			reconcileIstio()

			Expect(transitionRecord(getSecret(cacertsKey))).To(BeEmpty())
			expectBundle(op.Roots[0])
			expectPublished(op.Roots[0])
		})

		It("needs no transition for a new intermediate under the root istiod already signs with", func() {
			root := newTestCert("root", nil, true)
			first := newTestCert("first", root, true)
			createCustomerCA("istio-mesh-ca", root, first)
			useCustomerCA("istio-mesh-ca")
			reconcileIstio()
			expectSigner(first)

			second := newTestCert("second", root, true)
			byo := getSecret(types.NamespacedName{Name: "istio-mesh-ca", Namespace: operatorNS})
			byo.Data[istio.CACertKey], byo.Data[istio.CAKeyKey] = second.certPEM, second.keyPEM
			byo.Data[istio.CertChainKey] = concatPEM(second.certPEM, root.certPEM)
			Expect(cli.Update(ctx, byo)).NotTo(HaveOccurred())
			reconcileIstio()

			expectSigner(second)
			Expect(transitionRecord(getSecret(cacertsKey))).To(BeEmpty())
			expectBundle(root.cert)
		})

		It("keeps a customer Secret's extra roots in the bundle, and out of the published roots, while it moves to another customer CA", func() {
			extra := newTestCert("extra", nil, true)
			createCustomerCAWithExtra := func(name string, root, intermediate *testCert) {
				createCASecret(name, map[string][]byte{
					istio.CACertKey:    intermediate.certPEM,
					istio.CAKeyKey:     intermediate.keyPEM,
					istio.CertChainKey: concatPEM(intermediate.certPEM, root.certPEM),
					istio.RootCertKey:  concatPEM(root.certPEM, extra.certPEM),
				})
			}
			rootA := newTestCert("root-a", nil, true)
			createCustomerCAWithExtra("ca-a", rootA, newTestCert("intermediate-a", rootA, true))
			useCustomerCA("ca-a")
			reconcileIstio()
			expectBundle(rootA.cert, extra.cert)
			expectPublished(rootA.cert)

			rootB := newTestCert("root-b", nil, true)
			createCustomerCAWithExtra("ca-b", rootB, newTestCert("intermediate-b", rootB, true))
			useCustomerCA("ca-b")
			reconcileIstio()
			expectPhase(istio.TransitionDistributeRoot, time.Time{})
			expectBundle(rootA.cert, rootB.cert, extra.cert)
			expectPublished(rootA.cert, rootB.cert)
			for _, phase := range []istio.TransitionPhase{istio.TransitionAwaitDistribution, istio.TransitionSwitchSigner, istio.TransitionAwaitExpiry} {
				advanceTo(phase)
				expectBundle(rootA.cert, rootB.cert, extra.cert)
				expectPublished(rootA.cert, rootB.cert)
			}

			now = now.Add(wait)
			reconcileIstio()
			Expect(transitionRecord(getSecret(cacertsKey))).To(BeEmpty())
			expectBundle(rootB.cert, extra.cert)
			expectPublished(rootB.cert)
			expectNotDegraded()
		})

		It("starts no transition and publishes nothing for a trust anchor with the same subject and key as the signer's root", func() {
			root := newTestCert("root", nil, true)
			intermediate := newTestCert("intermediate", root, true)
			createCASecret("istio-mesh-ca", map[string][]byte{
				istio.CACertKey:    intermediate.certPEM,
				istio.CAKeyKey:     intermediate.keyPEM,
				istio.CertChainKey: concatPEM(intermediate.certPEM, root.certPEM),
				istio.RootCertKey:  root.certPEM,
			})
			template := *root.cert
			template.SerialNumber = big.NewInt(2)
			der, err := x509.CreateCertificate(rand.Reader, &template, &template, &root.key.PublicKey, root.key)
			Expect(err).NotTo(HaveOccurred())
			twin, err := x509.ParseCertificate(der)
			Expect(err).NotTo(HaveOccurred())
			current := &operatorv1.Istio{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, current)).NotTo(HaveOccurred())
			current.Spec.CertificateAuthority = &operatorv1.IstioCertificateAuthority{Secret: &operatorv1.IstioCASecret{Name: "istio-mesh-ca"}}
			current.Spec.TrustAnchors = &operatorv1.IstioTrustAnchors{Additional: []operatorv1.IstioTrustAnchor{{PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}}}
			Expect(cli.Update(ctx, current)).NotTo(HaveOccurred())

			for range 3 {
				reconcileIstio()
				markIstiodRolled()
				Expect(transitionRecord(getSecret(cacertsKey))).To(BeEmpty())
				Expect(getSecret(cacertsKey).Annotations).To(HaveKeyWithValue(istio.SignerRootsAnnotation, istio.Fingerprint(root.cert)))
				expectSigner(intermediate)
				expectBundle(root.cert, twin)
				expectPublished(root.cert)
			}
			expectNotDegraded()
		})

		It("retires the old root of a customer CA renewed with the same subject and key, and stops there", func() {
			old := newTestCert("root", nil, true)
			intermediate := newTestCert("intermediate", old, true)
			createCustomerCA("istio-mesh-ca", old, intermediate)
			useCustomerCA("istio-mesh-ca")
			reconcileIstio()
			expectBundle(old.cert)

			// The intermediate verifies under either root, so both are on its chain
			// once the bundle holds both.
			template := *old.cert
			template.SerialNumber = big.NewInt(2)
			template.NotAfter = old.cert.NotAfter.Add(time.Hour)
			der, err := x509.CreateCertificate(rand.Reader, &template, &template, &old.key.PublicKey, old.key)
			Expect(err).NotTo(HaveOccurred())
			renewedCert, err := x509.ParseCertificate(der)
			Expect(err).NotTo(HaveOccurred())
			renewed := &testCert{cert: renewedCert, key: old.key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM: old.keyPEM}
			byo := getSecret(types.NamespacedName{Name: "istio-mesh-ca", Namespace: operatorNS})
			byo.Data[istio.CertChainKey] = concatPEM(intermediate.certPEM, renewed.certPEM)
			byo.Data[istio.RootCertKey] = renewed.certPEM
			Expect(cli.Update(ctx, byo)).NotTo(HaveOccurred())
			reconcileIstio()
			expectPhase(istio.TransitionDistributeRoot, time.Time{})
			expectBundle(old.cert, renewed.cert)

			advanceTo(istio.TransitionAwaitExpiry)
			Expect(transitionOf().Retiring).To(ConsistOf(old.cert))
			now = now.Add(wait)
			reconcileIstio()
			Expect(transitionRecord(getSecret(cacertsKey))).To(BeEmpty())
			expectBundle(renewed.cert)
			expectPublished(renewed.cert)

			reconcileIstio()
			Expect(transitionRecord(getSecret(cacertsKey))).To(BeEmpty())
			expectNotDegraded()
		})

		It("keeps additional roots in the bundle, and out of the published roots, through every phase", func() {
			extra := newTestCert("extra", nil, true)
			current := &operatorv1.Istio{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, current)).NotTo(HaveOccurred())
			current.Spec.TrustAnchors = &operatorv1.IstioTrustAnchors{Additional: []operatorv1.IstioTrustAnchor{{PEM: string(extra.certPEM)}}}
			Expect(cli.Update(ctx, current)).NotTo(HaveOccurred())
			createIstioCASecret()
			reconcileIstio()
			op := operatorCA()
			others := []*x509.Certificate{extra.cert}

			expectEveryRoot := func(own ...*x509.Certificate) {
				Expect(getSecret(cacertsKey).Data[istio.RootCertKey]).To(Equal(istio.ComposeRootBundle(own, others)))
				expectPublished(own...)
			}
			expectEveryRoot(selfSigned.cert, op.Roots[0])
			for _, phase := range []istio.TransitionPhase{istio.TransitionAwaitDistribution, istio.TransitionSwitchSigner, istio.TransitionAwaitExpiry} {
				advanceTo(phase)
				expectEveryRoot(selfSigned.cert, op.Roots[0])
			}
			now = now.Add(wait)
			reconcileIstio()
			Expect(transitionRecord(getSecret(cacertsKey))).To(BeEmpty())
			expectEveryRoot(op.Roots[0])
			expectNotDegraded()
		})

		It("leaves a cacerts the operator did not create alone, and publishes only the roots it signs with", func() {
			root := newTestCert("hand-made-root", nil, true)
			handMade := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: istio.CACertsSecretName, Namespace: istio.IstioNamespace},
				Data: map[string][]byte{
					istio.CACertKey:    root.certPEM,
					istio.CAKeyKey:     root.keyPEM,
					istio.CertChainKey: root.certPEM,
					istio.RootCertKey:  concatPEM(root.certPEM, selfSigned.certPEM),
				},
			}
			Expect(cli.Create(ctx, handMade)).NotTo(HaveOccurred())
			reconcileIstio()
			reconcileIstio()

			cacerts := getSecret(cacertsKey)
			Expect(cacerts.Data).To(Equal(handMade.Data))
			Expect(cacerts.Labels).NotTo(HaveKey(istio.CACertsLabel))
			Expect(cacerts.Annotations).To(BeEmpty())
			Expect(cacerts.OwnerReferences).To(BeEmpty())
			secretAbsent(operatorCAKey)
			expectPublished(root.cert)
			mockStatus.AssertNotCalled(GinkgoT(), "SetWarning", caWarningKey, mock.Anything)
			expectNotDegraded()
		})

		It("leaves a kubernetes.io/tls cacerts the operator did not create alone, and publishes its roots", func() {
			root := newTestCert("hand-made-root", nil, true)
			intermediate := newTestCert("hand-made-intermediate", root, true)
			handMade := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: istio.CACertsSecretName, Namespace: istio.IstioNamespace},
				Type:       corev1.SecretTypeTLS,
				Data: map[string][]byte{
					corev1.TLSCertKey:       intermediate.certPEM,
					corev1.TLSPrivateKeyKey: intermediate.keyPEM,
					"ca.crt":                root.certPEM,
				},
			}
			Expect(cli.Create(ctx, handMade)).NotTo(HaveOccurred())
			reconcileIstio()
			reconcileIstio()

			cacerts := getSecret(cacertsKey)
			Expect(cacerts.Data).To(Equal(handMade.Data))
			Expect(cacerts.Labels).NotTo(HaveKey(istio.CACertsLabel))
			Expect(cacerts.OwnerReferences).To(BeEmpty())
			expectPublished(root.cert)
			expectNotDegraded()
		})

		It("leaves a cacerts the operator did not create alone, and warns, when the CR asks for a customer CA and extra anchors", func() {
			root := newTestCert("hand-made-root", nil, true)
			handMade := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: istio.CACertsSecretName, Namespace: istio.IstioNamespace},
				Data: map[string][]byte{
					istio.CACertKey:    root.certPEM,
					istio.CAKeyKey:     root.keyPEM,
					istio.CertChainKey: root.certPEM,
					istio.RootCertKey:  root.certPEM,
				},
			}
			Expect(cli.Create(ctx, handMade)).NotTo(HaveOccurred())
			customerRoot := newTestCert("root", nil, true)
			customerIntermediate := newTestCert("intermediate", customerRoot, true)
			createCustomerCA("istio-mesh-ca", customerRoot, customerIntermediate)
			useCustomerCA("istio-mesh-ca")
			extra := newTestCert("extra", nil, true)
			current := &operatorv1.Istio{}
			Expect(cli.Get(ctx, types.NamespacedName{Name: "default"}, current)).NotTo(HaveOccurred())
			current.Spec.TrustAnchors = &operatorv1.IstioTrustAnchors{Additional: []operatorv1.IstioTrustAnchor{{PEM: string(extra.certPEM)}}}
			Expect(cli.Update(ctx, current)).NotTo(HaveOccurred())
			reconcileIstio()
			reconcileIstio()

			cacerts := getSecret(cacertsKey)
			Expect(cacerts.Data).To(Equal(handMade.Data))
			Expect(cacerts.Labels).NotTo(HaveKey(istio.CACertsLabel))
			Expect(cacerts.OwnerReferences).To(BeEmpty())
			secretAbsent(operatorCAKey)
			expectPublished(root.cert)
			expectWarningMentioning(istio.IstioNamespace+"/"+istio.CACertsSecretName, "spec.certificateAuthority", "spec.trustAnchors")
			expectNotDegraded()
		})

		It("goes Degraded and keeps a cacerts the operator did not create when it is not a usable CA", func() {
			root := newTestCert("hand-made-root", nil, true)
			handMade := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: istio.CACertsSecretName, Namespace: istio.IstioNamespace},
				Data:       map[string][]byte{istio.CACertKey: root.certPEM, istio.CAKeyKey: root.keyPEM},
			}
			Expect(cli.Create(ctx, handMade)).NotTo(HaveOccurred())
			reconcileIstio()

			Expect(getSecret(cacertsKey).Data).To(Equal(handMade.Data))
			Expect(errors.IsNotFound(cli.Get(ctx, anchorsKey, &corev1.ConfigMap{}))).To(BeTrue())
			expectDegradedMentioning(istio.IstioNamespace+"/"+istio.CACertsSecretName, "not a usable CA")
		})

		It("does not roll istiod onto a cacerts that stops validating", func() {
			reconcileIstio()
			markIstiodRolled()
			hash := istiodHash()

			cacerts := getSecret(cacertsKey)
			cacerts.Data[istio.CAKeyKey] = newTestCert("other", nil, true).keyPEM
			Expect(cli.Update(ctx, cacerts)).NotTo(HaveOccurred())
			reconcileIstio()

			Expect(istiodHash()).To(Equal(hash))
			expectDegradedMentioning(istio.IstioNamespace+"/"+istio.CACertsSecretName, "does not match")
		})

		It("retires istio-ca-secret after the migration, so a deleted cacerts comes back with the operator-managed CA", func() {
			createIstioCASecret()
			reconcileIstio()
			advanceTo(istio.TransitionAwaitExpiry)
			Expect(getSecret(istioCAKey).Annotations).NotTo(HaveKey(istio.SelfSignedCARetiredAnnotation))
			now = transitionOf().Deadline
			reconcileIstio()
			Expect(transitionOf().Phase).To(Equal(istio.TransitionNone))
			Expect(getSecret(istioCAKey).Annotations).To(HaveKeyWithValue(istio.SelfSignedCARetiredAnnotation, istio.Fingerprint(selfSigned.cert)))

			Expect(cli.Delete(ctx, getSecret(cacertsKey))).NotTo(HaveOccurred())
			reconcileIstio()

			cacerts := getSecret(cacertsKey)
			Expect(transitionRecord(cacerts)).To(BeEmpty())
			Expect(cacerts.Data).To(Equal(getSecret(operatorCAKey).Data))
			expectPublished(operatorCA().Roots[0])
			expectNotDegraded()
		})

		It("falls back to istio-ca-secret for a cacerts deleted before the migration ends, while its root is still trusted", func() {
			createIstioCASecret()
			reconcileIstio()
			advanceTo(istio.TransitionSwitchSigner)

			Expect(cli.Delete(ctx, getSecret(cacertsKey))).NotTo(HaveOccurred())
			reconcileIstio()

			expectPhase(istio.TransitionDistributeRoot, time.Time{})
			expectSigner(selfSigned)
			Expect(getSecret(istioCAKey).Annotations).NotTo(HaveKey(istio.SelfSignedCARetiredAnnotation))
		})

		It("holds and goes Degraded when cacerts is deleted during a rotation, until the published roots are let go", func() {
			reconcileIstio()
			oldRoot := operatorCA().Roots[0]
			markIstiodRolled()
			newRoot := newTestCert("new-root", nil, true)
			intermediate := newTestCert("intermediate", newRoot, true)
			createCustomerCA("istio-mesh-ca", newRoot, intermediate)
			useCustomerCA("istio-mesh-ca")
			reconcileIstio()
			expectPhase(istio.TransitionDistributeRoot, time.Time{})
			hash := istiodHash()

			Expect(cli.Delete(ctx, getSecret(cacertsKey))).NotTo(HaveOccurred())
			reconcileIstio()

			secretAbsent(cacertsKey)
			Expect(istiodHash()).To(Equal(hash))
			Expect(getConfigMap(anchorsKey).Data[istio.RootCertKey]).To(ContainSubstring(string(istio.EncodeCertificates(oldRoot))))
			expectDegradedMentioning(istio.IstioNamespace+"/"+istio.CACertsSecretName+" is missing", istio.TrustExportConfigMapName)

			Expect(cli.Delete(ctx, getConfigMap(anchorsKey))).NotTo(HaveOccurred())
			mockStatus.Calls = nil
			reconcileIstio()

			expectSigner(intermediate)
			expectPublished(newRoot.cert)
			expectNotDegraded()
		})

		It("holds and goes Degraded when a new istiod creates a self-signed CA after cacerts is deleted during a rotation", func() {
			reconcileIstio()
			oldRoot := operatorCA().Roots[0]
			markIstiodRolled()
			replaceOperatorCA(newTestCert("new-root", nil, true))
			reconcileIstio()
			expectPhase(istio.TransitionDistributeRoot, time.Time{})
			hash := istiodHash()

			Expect(cli.Delete(ctx, getSecret(cacertsKey))).NotTo(HaveOccurred())
			createIstioCASecret()
			reconcileIstio()

			secretAbsent(cacertsKey)
			Expect(istiodHash()).To(Equal(hash))
			Expect(getConfigMap(anchorsKey).Data[istio.RootCertKey]).To(ContainSubstring(string(istio.EncodeCertificates(oldRoot))))
			expectDegradedMentioning(istio.IstioNamespace+"/"+istio.CACertsSecretName+" is missing", istio.TrustExportConfigMapName)
		})

		It("holds and goes Degraded, leaving the ConfigMap as it is, when the published roots do not parse", func() {
			corrupt := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: istio.TrustExportConfigMapName, Namespace: istio.IstioNamespace},
				Data:       map[string]string{istio.RootCertKey: "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"},
			}
			Expect(cli.Create(ctx, corrupt)).NotTo(HaveOccurred())
			createIstioCASecret()
			reconcileIstio()

			secretAbsent(cacertsKey)
			Expect(getConfigMap(anchorsKey).Data).To(Equal(corrupt.Data))
			expectDegradedMentioning(istio.IstioNamespace+"/"+istio.CACertsSecretName+" is missing", istio.TrustExportConfigMapName, "does not parse")

			Expect(cli.Delete(ctx, getConfigMap(anchorsKey))).NotTo(HaveOccurred())
			mockStatus.Calls = nil
			reconcileIstio()

			Expect(getSecret(cacertsKey).Labels).To(HaveKeyWithValue(istio.CACertsLabel, string(istio.CASourceSelfSigned)))
			expectPhase(istio.TransitionDistributeRoot, time.Time{})
			expectNotDegraded()
		})

		It("ignores istio-ca-secret once an operator-rendered cacerts exists", func() {
			reconcileIstio()
			cacerts := getSecret(cacertsKey)
			createIstioCASecret()
			reconcileIstio()

			Expect(getSecret(cacertsKey).Data).To(Equal(cacerts.Data))
			Expect(transitionRecord(getSecret(cacertsKey))).To(BeEmpty())
			Expect(getConfigMap(anchorsKey).Data[istio.RootCertKey]).To(Equal(string(cacerts.Data[istio.CACertKey])))
			mockStatus.AssertNotCalled(GinkgoT(), "SetWarning", mock.Anything, mock.Anything)
			expectNotDegraded()
		})
	})
})

func concatPEM(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// transitionRecord is the part of a cacerts' annotations that records a signer
// transition, without the certificate metadata that sits beside it.
func transitionRecord(s *corev1.Secret) map[string]string {
	out := map[string]string{}
	for k, v := range s.Annotations {
		if strings.HasPrefix(k, "operator.tigera.io/istio-ca-transition-") {
			out[k] = v
		}
	}
	return out
}
