// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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
	anchorsKey := types.NamespacedName{Name: istio.TrustAnchorsConfigMapName, Namespace: istio.IstioNamespace}

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
			Expect(cacerts.Annotations).To(Equal(map[string]string{
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
			Expect(cacerts.Annotations).To(Equal(map[string]string{
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
			Expect(cacerts.Annotations).To(BeEmpty())
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
			replaceOperatorCA(root)

			reconcileIstio()

			state := expectPhase(istio.TransitionDistributeRoot, time.Time{})
			Expect(state.Retiring).To(HaveLen(1))
			Expect(state.Retiring[0].Raw).To(Equal(selfSigned.cert.Raw))
			Expect(state.Incoming).To(HaveLen(1))
			Expect(state.Incoming[0].Raw).To(Equal(root.cert.Raw))
			expectSigner(selfSigned)
			expectBundle(selfSigned.cert, root.cert)
			expectPublished(selfSigned.cert, root.cert)
			expectWarningMentioning("phase 1/4", "self-signed CA")
			expectNotDegraded()
		})

		It("finishes retiring the old root before it starts the transition a later change asks for", func() {
			createIstioCASecret()
			reconcileIstio()
			advanceTo(istio.TransitionAwaitExpiry)
			op := operatorCA()
			deadline := transitionOf().Deadline
			root := newTestCert("root", nil, true)
			replaceOperatorCA(root)

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
			Expect(getSecret(cacertsKey).Annotations).To(BeEmpty())
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
			Expect(cacerts.Annotations).To(BeEmpty())
			Expect(cacerts.Data[istio.RootCertKey]).To(Equal(op.CertPEM))
			expectPublished(op.Roots[0])
			expectNotDegraded()
		})

		It("migrates a cacerts the operator did not create, from the CA it holds, keeping its other roots until the end", func() {
			root := newTestCert("hand-made-root", nil, true)
			Expect(cli.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: istio.CACertsSecretName, Namespace: istio.IstioNamespace},
				Data: map[string][]byte{
					istio.CACertKey:    root.certPEM,
					istio.CAKeyKey:     root.keyPEM,
					istio.CertChainKey: root.certPEM,
					istio.RootCertKey:  concatPEM(root.certPEM, selfSigned.certPEM),
				},
			})).NotTo(HaveOccurred())
			reconcileIstio()

			cacerts := getSecret(cacertsKey)
			Expect(cacerts.Labels).To(HaveKeyWithValue(istio.CACertsLabel, "unmanaged"))
			expectSigner(root)
			state := expectPhase(istio.TransitionDistributeRoot, time.Time{})
			Expect(state.Retiring[0].Raw).To(Equal(root.cert.Raw))
			Expect(state.Kept).To(HaveLen(1))
			Expect(state.Kept[0].Raw).To(Equal(selfSigned.cert.Raw))
			opRoot := operatorCA().Roots[0]
			expectBundle(root.cert, opRoot, selfSigned.cert)
			expectPublished(root.cert, opRoot)
			expectNotDegraded()
			expectWarningMentioning("phase 1/4", istio.IstioNamespace+"/"+istio.CACertsSecretName, "user-provided")

			advanceTo(istio.TransitionAwaitExpiry)
			expectBundle(root.cert, opRoot, selfSigned.cert)
			expectPublished(root.cert, opRoot)

			now = transitionOf().Deadline
			reconcileIstio()
			Expect(transitionOf().Phase).To(Equal(istio.TransitionNone))
			expectBundle(opRoot)
			expectPublished(opRoot)
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

		It("ignores istio-ca-secret once an operator-rendered cacerts exists", func() {
			reconcileIstio()
			cacerts := getSecret(cacertsKey)
			createIstioCASecret()
			reconcileIstio()

			Expect(getSecret(cacertsKey).Data).To(Equal(cacerts.Data))
			Expect(getSecret(cacertsKey).Annotations).To(BeEmpty())
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
