// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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

package csr

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller"
	"github.com/projectcalico/calico/operator/pkg/controller/certificatemanager"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/ctrlruntime"
	ctrlrclient "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/dns"
	"github.com/projectcalico/calico/operator/pkg/extensions"
	"github.com/projectcalico/calico/operator/pkg/render"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
	fakecalicoclient "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
)

// stubExtension contributes the signable assets, standing in for whatever a variant adds.
type stubExtension struct {
	extensions.CSRExtension
	needsRole bool
}

func (s stubExtension) ExtendInputs(_ context.Context, ci controller.Inputs) (controller.Inputs, []certificatemanagement.KeyPairInterface, error) {
	ci.RenderInputs.Extension = render.CSRData{
		AllowedAssets:       stubAssets(),
		RequiresSigningRole: s.needsRole,
		ResolveSubject:      stubSubjectResolver,
	}
	return ci, nil, nil
}

func (s stubExtension) Watches(ctrlruntime.Controller) error {
	return nil
}

func stubAssets() map[string]render.TLSAsset {
	return map[string]render.TLSAsset{
		stubSecretName: {
			ServiceAccountName:      stubServiceAccount,
			ServiceAccountNamespace: stubNamespace,
			ValidDNSNames:           stubDNSNames,
		},
		stubAuthorizedSecretName: {
			ValidDNSNames: []string{stubAuthorizedDNSName},
			Authorize: func(context.Context, *certificatesv1.CertificateSigningRequest) (bool, error) {
				return stubAuthorizeAllowed, nil
			},
		},
	}
}

// stubSubjectResolver stands in for a variant that recognizes requests no pod issued.
func stubSubjectResolver(_ context.Context, csr *certificatesv1.CertificateSigningRequest) (*render.CSRSubject, error) {
	name, ok := csr.Labels[stubSubjectLabel]
	if !ok {
		return nil, nil
	}
	if name == "" {
		return nil, errors.New("subject can not be empty")
	}
	return &render.CSRSubject{Name: name}, nil
}

func stubExtensions(needsRole bool) extensions.Extensions {
	return extensions.New(extensions.Set{CSR: stubExtension{needsRole: needsRole}})
}

const (
	stubSecretName     = "stub-server-tls"
	stubServiceAccount = "stub-server"
	stubNamespace      = "stub-ns"
	stubPodName        = "stub-server-0"

	// The stub-authorized asset stands in for one that any of several service
	// accounts may request, so the variant authorizes it instead.
	stubAuthorizedSecretName = "stub-authorized-tls"
	stubAuthorizedDNSName    = "stub-authorized"
	stubSubjectLabel         = "stub.tigera.io/subject"
	stubSubjectName          = "stub-subject"
)

// stubAuthorizeAllowed is the verdict the stub asset's authorizer returns.
var stubAuthorizeAllowed = true

var stubDNSNames = []string{"stub-server", "stub-server.stub-ns", "stub-server.stub-ns.svc", "stub-server.stub-ns.svc.cluster.local"}

var _ = Describe("CSR controller tests", func() {
	var (
		cli                client.Client
		clientset          *fake.Clientset
		calicoClientset    *fakecalicoclient.Clientset
		ctx                context.Context
		r                  reconcileCSR
		scheme             *runtime.Scheme
		mockStatus         *status.MockStatus
		installation       *operatorv1.Installation
		certificateManager certificatemanager.CertificateManager
		err                error
	)

	BeforeEach(func() {
		ctx = context.TODO()
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		Expect(certificatesv1.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		// Create a client that will have a crud interface of k8s objects.
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).WithStatusSubresource(ctrlrclient.TypesWithStatuses(scheme, certificatesv1.SchemeGroupVersion)...).Build()
		clientset = fake.NewClientset()
		calicoClientset = fakecalicoclient.NewSimpleClientset()
		installation = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operatorv1.InstallationSpec{
				Variant:  operatorv1.CalicoEnterprise,
				Registry: "some.registry.org/",
			},
		}
		Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())
		certificateManager, err = certificatemanager.Create(cli, &installation.Spec, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
		mockStatus = &status.MockStatus{}
		mockStatus.On("OnCRFound").Return()
		r = reconcileCSR{
			client:        cli,
			clientset:     clientset,
			calicoClient:  calicoClientset,
			scheme:        scheme,
			provider:      operatorv1.ProviderNone,
			clusterDomain: dns.DefaultClusterDomain,
			extensions:    stubExtensions(true),
		}
	})

	Context("csr reconciliation", func() {
		It("should reconcile the CSR controller", func() {
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should reconcile a submitted CSR", func() {
			Expect(cli.Create(ctx, validPod())).NotTo(HaveOccurred())
			csr := validPodCSR(validPodX509CR(), validPod())
			Expect(cli.Create(ctx, csr)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(r.client.Get(ctx, client.ObjectKey{Name: csr.Name}, csr)).NotTo(HaveOccurred())
			Expect(csr.Status.Conditions).To(HaveLen(1))
			Expect(csr.Status.Conditions[0].Type).To(Equal(certificatesv1.CertificateApproved))
			Expect(csr.Status.Conditions[0].Status).To(Equal(corev1.ConditionTrue))
			Expect(csr.Status.Certificate).ToNot(BeEmpty())
			Expect(cli.Get(ctx, types.NamespacedName{Name: certificatemanagement.CSRClusterRoleName}, &rbacv1.ClusterRole{})).NotTo(HaveOccurred())
		})

		It("should reconcile 2 submitted CSRs", func() {
			validPod2 := validPod()
			validPod2.Name = validPod2.Name + "2"
			Expect(cli.Create(ctx, validPod2)).NotTo(HaveOccurred())
			csr2 := validPodCSR(validPodX509CR(), validPod2)
			csr2.Name = csr2.Name + "2"
			Expect(cli.Create(ctx, csr2)).NotTo(HaveOccurred())

			Expect(cli.Create(ctx, validPod())).NotTo(HaveOccurred())
			csr := validPodCSR(validPodX509CR(), validPod())
			Expect(cli.Create(ctx, csr)).NotTo(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(r.client.Get(ctx, client.ObjectKey{Name: csr.Name}, csr)).NotTo(HaveOccurred())
			Expect(csr.Status.Conditions).To(HaveLen(1))
			Expect(csr.Status.Conditions[0].Type).To(Equal(certificatesv1.CertificateApproved))
			Expect(csr.Status.Conditions[0].Status).To(Equal(corev1.ConditionTrue))
			Expect(csr.Status.Certificate).ToNot(BeEmpty())

			Expect(r.client.Get(ctx, client.ObjectKey{Name: csr2.Name}, csr2)).NotTo(HaveOccurred())
			Expect(csr2.Status.Conditions).To(HaveLen(1))
			Expect(csr2.Status.Conditions[0].Type).To(Equal(certificatesv1.CertificateApproved))
			Expect(csr2.Status.Conditions[0].Status).To(Equal(corev1.ConditionTrue))
			Expect(csr2.Status.Certificate).ToNot(BeEmpty())
		})

		It("should reject a submitted CSR that does not pass validation", func() {
			csr := validPodCSR(validPodX509CR(), validPod())
			csr.Spec.Username = "attacker"
			Expect(cli.Create(ctx, csr)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(r.client.Get(ctx, client.ObjectKey{Name: csr.Name}, csr)).NotTo(HaveOccurred())
			Expect(csr.Status.Conditions).To(HaveLen(1))
			Expect(csr.Status.Conditions[0].Type).To(Equal(certificatesv1.CertificateDenied))
			Expect(csr.Status.Conditions[0].Status).To(Equal(corev1.ConditionTrue))
			Expect(csr.Status.Certificate).To(BeEmpty())
		})
	})

	DescribeTable("csr validation for pods", func(csr *certificatesv1.CertificateSigningRequest, pod *corev1.Pod, expectError, expectRelevant bool) {
		var subject *render.CSRSubject
		if pod != nil {
			subject = &render.CSRSubject{Name: pod.Name, IP: pod.Status.PodIP}
		}
		certificate, err := validate(ctx, csr, subject, stubAssets())
		if expectError {
			Expect(err).To(HaveOccurred())
		} else if expectRelevant {
			Expect(relevantCSR(csr)).To(BeTrue())
			Expect(err).ToNot(HaveOccurred())
			Expect(certificate.ExtKeyUsage).To(Equal(extKeyUsage))
			Expect(certificate.DNSNames).To(Equal(stubDNSNames))
			Expect(certificate.Subject.CommonName).To(Equal(stubDNSNames[0]))
			Expect(certificate.IPAddresses).To(Equal([]net.IP{net.ParseIP(pod.Status.PodIP).To4()}))
			Expect(certificate.IsCA).To(BeFalse())
		} else {
			Expect(relevantCSR(csr)).To(BeFalse())
		}
	},
		Entry("valid CSR / happy flow", validPodCSR(validPodX509CR(), validPod()), validPod(), false, true),
		Entry("valid CSR / no pod", validPodCSR(validPodX509CR(), validPod()), nil, true, true),
		Entry("unrecognized csr name", invalidPodCSR(validPodX509CR(), validPod(), invalidName), validPod(), true, true),
		Entry("invalid username", invalidPodCSR(validPodX509CR(), validPod(), invalidUserName), validPod(), true, true),
		Entry("invalid certificate request", invalidPodCSR(validPodX509CR(), validPod(), invalidRequest), validPod(), true, true),
		Entry("previously denied csr", invalidPodCSR(validPodX509CR(), validPod(), invalidDenied), validPod(), false, false),
		Entry("previously failed csr", invalidPodCSR(validPodX509CR(), validPod(), invalidFailed), validPod(), false, false),
		Entry("bad DNS names in x509 certificate request", invalidPodCSR(invalidX509CR(invalidDNSNames), validPod()), validPod(), true, true),
		Entry("bad CN in x509 certificate request", invalidPodCSR(invalidX509CR(invalidCN), validPod()), validPod(), true, true),
		Entry("bad IP in x509 certificate request", invalidPodCSR(invalidX509CR(invalidIP), validPod()), validPod(), true, true),
		Entry("irrelevant signer name", invalidPodCSR(invalidX509CR(), validPod(), invalidSignername), validPod(), false, false),
	)

	DescribeTable("csr validation for subjects the variant authorizes", func(csr *certificatesv1.CertificateSigningRequest, subject *render.CSRSubject, expectError, expectRelevant, authorized bool) {
		stubAuthorizeAllowed = authorized
		certificate, err := validate(ctx, csr, subject, stubAssets())
		if expectError {
			Expect(err).To(HaveOccurred())
		} else if expectRelevant {
			Expect(relevantCSR(csr)).To(BeTrue())
			Expect(err).NotTo(HaveOccurred())
			Expect(certificate.ExtKeyUsage).To(Equal(extKeyUsage))
			Expect(certificate.DNSNames).To(Equal([]string{stubAuthorizedDNSName}))
			Expect(certificate.Subject.CommonName).To(Equal(stubAuthorizedDNSName))
			Expect(certificate.IsCA).To(BeFalse())
		} else {
			Expect(relevantCSR(csr)).To(BeFalse())
		}
	},
		Entry("valid CSR / happy flow", validAuthorizedCSR(validAuthorizedX509CR()), stubSubject(), false, true, true),
		Entry("valid CSR / no subject", validAuthorizedCSR(validAuthorizedX509CR()), nil, true, true, true),
		Entry("valid CSR / requestor not authorized", validAuthorizedCSR(validAuthorizedX509CR()), stubSubject(), true, true, false),
		Entry("unrecognized csr name", invalidAuthorizedCSR(validAuthorizedX509CR(), invalidName), stubSubject(), true, true, true),
		Entry("invalid certificate request", invalidAuthorizedCSR(validAuthorizedX509CR(), invalidRequest), stubSubject(), true, true, true),
		Entry("previously denied csr", invalidAuthorizedCSR(validAuthorizedX509CR(), invalidDenied), stubSubject(), false, false, true),
		Entry("previously failed csr", invalidAuthorizedCSR(validAuthorizedX509CR(), invalidFailed), stubSubject(), false, false, true),
		Entry("bad DNS names in x509 certificate request", invalidAuthorizedCSR(invalidX509CR(invalidDNSNames)), stubSubject(), true, true, true),
		Entry("bad CN in x509 certificate request", invalidAuthorizedCSR(invalidX509CR(invalidCN)), stubSubject(), true, true, true),
		Entry("bad IP in x509 certificate request", invalidAuthorizedCSR(invalidX509CR(invalidIP)), stubSubject(), true, true, true),
		Entry("irrelevant signer name", invalidAuthorizedCSR(invalidX509CR(), invalidSignername), stubSubject(), false, false, true),
	)

	DescribeTable("getPod", func(csr *certificatesv1.CertificateSigningRequest, pod *corev1.Pod, expectPodNil bool) {
		if pod != nil {
			Expect(cli.Create(ctx, pod)).NotTo(HaveOccurred())
		}
		foundPod, err := r.getPod(ctx, csr)
		Expect(err).NotTo(HaveOccurred())
		if expectPodNil {
			Expect(foundPod).To(BeNil())
		} else {
			Expect(foundPod).NotTo(BeNil())
		}
	},
		Entry("Valid CSR, pod found", validPodCSR(validPodX509CR(), validPod()), validPod(), false),
		Entry("Valid CSR, no pod found", validPodCSR(validPodX509CR(), validPod()), nil, true),
		Entry("Valid CSR, no matching pod found due to different uid", validPodCSR(validPodX509CR(), validPod()), invalidPod(invalidUID), true),
		Entry("Valid CSR, no matching pod found due to different pod name", validPodCSR(validPodX509CR(), validPod()), invalidPod(invalidName), true),
		Entry("Valid CSR, no matching pod found due to different csr username", invalidPodCSR(validPodX509CR(), validPod(), invalidUserName), validPod(), true),
		Entry("Invalid CSR, irrelevant pod names", invalidPodCSR(invalidX509CR(), validPod(), invalidExtraPodNames), validPod(), true),
		Entry("Invalid CSR, irrelevant pod names len", invalidPodCSR(invalidX509CR(), validPod(), invalidExtraPodNamesLen), validPod(), true),
		Entry("Invalid CSR, irrelevant pod UIDs", invalidPodCSR(invalidX509CR(), validPod(), invalidExtraPodUIDs), validPod(), true),
		Entry("Invalid CSR, irrelevant pod UIDs len", invalidPodCSR(invalidX509CR(), validPod(), invalidExtraPodUIDsLen), validPod(), true),
	)

	DescribeTable("subject resolution", func(csr *certificatesv1.CertificateSigningRequest, pod *corev1.Pod, expectedName string) {
		if pod != nil {
			Expect(cli.Create(ctx, pod)).NotTo(HaveOccurred())
		}
		subject, err := r.subject(ctx, csr, stubSubjectResolver)
		Expect(err).NotTo(HaveOccurred())
		if expectedName == "" {
			Expect(subject).To(BeNil())
		} else {
			Expect(subject.Name).To(Equal(expectedName))
		}
	},
		Entry("a pod issued the request", validPodCSR(validPodX509CR(), validPod()), validPod(), stubPodName),
		Entry("the variant recognizes the request", validAuthorizedCSR(validAuthorizedX509CR()), nil, stubSubjectName),
		Entry("nobody recognizes the request", invalidPodCSR(validPodX509CR(), validPod(), invalidExtraPodNames), nil, ""),
	)
})

func validPodX509CR() *x509.CertificateRequest {
	subj := pkix.Name{
		CommonName: "stub-server",
	}
	extKeyUsages := []asn1.ObjectIdentifier{
		// ExtKeyUsageServerAuth
		{1, 3, 6, 1, 5, 5, 7, 3, 1},
		// ExtKeyUsageClientAuth
		{1, 3, 6, 1, 5, 5, 7, 3, 2},
	}

	extKeyUsagesVal, err := asn1.Marshal(extKeyUsages)
	Expect(err).NotTo(HaveOccurred())
	return &x509.CertificateRequest{
		Subject:            subj,
		DNSNames:           stubDNSNames,
		IPAddresses:        []net.IP{net.ParseIP("1.2.3.4")},
		SignatureAlgorithm: x509.SHA256WithRSA,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 37},
				Value: extKeyUsagesVal,
			},
		},
	}
}

func validAuthorizedX509CR() *x509.CertificateRequest {
	subj := pkix.Name{
		CommonName: stubAuthorizedDNSName,
	}
	extKeyUsages := []asn1.ObjectIdentifier{
		// ExtKeyUsageServerAuth
		{1, 3, 6, 1, 5, 5, 7, 3, 1},
		// ExtKeyUsageClientAuth
		{1, 3, 6, 1, 5, 5, 7, 3, 2},
	}

	extKeyUsagesVal, err := asn1.Marshal(extKeyUsages)
	Expect(err).NotTo(HaveOccurred())
	return &x509.CertificateRequest{
		Subject:            subj,
		DNSNames:           []string{stubAuthorizedDNSName},
		SignatureAlgorithm: x509.SHA256WithRSA,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 37},
				Value: extKeyUsagesVal,
			},
		},
	}
}

func validPodCSR(cr *x509.CertificateRequest, pod *corev1.Pod) *certificatesv1.CertificateSigningRequest {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())
	buf := bytes.NewBuffer([]byte{})
	err = pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	Expect(err).NotTo(HaveOccurred())
	certificateRequest, err := x509.CreateCertificateRequest(rand.Reader, cr, key)
	Expect(err).NotTo(HaveOccurred())
	return &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: stubSecretName + ":" + stubPodName,
			Labels: map[string]string{
				"k8s-app":                stubServiceAccount,
				"operator.tigera.io/csr": stubServiceAccount,
			},
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request: pem.EncodeToMemory(&pem.Block{
				Type: "CERTIFICATE REQUEST", Bytes: certificateRequest,
			}),
			SignerName: "tigera.io/operator-signer",
			Username:   "system:serviceaccount:" + stubNamespace + ":" + stubServiceAccount,
			Extra: map[string]certificatesv1.ExtraValue{
				"authentication.kubernetes.io/pod-name": []string{pod.Name},
				"authentication.kubernetes.io/pod-uid":  []string{string(pod.UID)},
			},
		},
		Status: certificatesv1.CertificateSigningRequestStatus{},
	}
}

func validAuthorizedCSR(cr *x509.CertificateRequest) *certificatesv1.CertificateSigningRequest {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())
	buf := bytes.NewBuffer([]byte{})
	err = pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	Expect(err).NotTo(HaveOccurred())
	certificateRequest, err := x509.CreateCertificateRequest(rand.Reader, cr, key)
	Expect(err).NotTo(HaveOccurred())
	return &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: stubAuthorizedSecretName + ":" + stubSubjectName,
			Labels: map[string]string{
				"k8s-app":                stubServiceAccount,
				stubSubjectLabel:         stubSubjectName,
				"operator.tigera.io/csr": stubServiceAccount,
			},
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request: pem.EncodeToMemory(&pem.Block{
				Type: "CERTIFICATE REQUEST", Bytes: certificateRequest,
			}),
			SignerName: "tigera.io/operator-signer",
			Username:   "system:serviceaccount:" + stubNamespace + ":some-other-account",
		},
		Status: certificatesv1.CertificateSigningRequestStatus{},
	}
}

type invalidation int

func stubSubject() *render.CSRSubject {
	return &render.CSRSubject{Name: stubSubjectName}
}

func validPod() *corev1.Pod {
	return &corev1.Pod{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      stubPodName,
			Namespace: stubNamespace,
			Labels: map[string]string{
				"k8s-app": stubServiceAccount,
			},
			UID: "uid",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: stubServiceAccount,
		},
		Status: corev1.PodStatus{
			PodIP: "1.2.3.4",
		},
	}
}

const (
	invalidUID invalidation = iota
	invalidName
	invalidUserName
	invalidRequest
	invalidDenied
	invalidFailed
	invalidDNSNames
	invalidCN
	invalidIP
	invalidSignername
	invalidExtraPodNames
	invalidExtraPodNamesLen
	invalidExtraPodUIDs
	invalidExtraPodUIDsLen
)

func invalidPodCSR(cr *x509.CertificateRequest, pod *corev1.Pod, invalidations ...invalidation) *certificatesv1.CertificateSigningRequest {
	csr := validPodCSR(cr, pod)
	for _, i := range invalidations {
		switch i {
		case invalidUserName:
			csr.Spec.Username = "invalid"
		case invalidName:
			csr.Name = "invalid"
		case invalidRequest:
			csr.Spec.Request = []byte("invalid")
		case invalidDenied:
			csr.Status.Conditions = []certificatesv1.CertificateSigningRequestCondition{
				{
					Type:   certificatesv1.CertificateDenied,
					Status: corev1.ConditionTrue,
				},
			}
		case invalidFailed:
			csr.Status.Conditions = []certificatesv1.CertificateSigningRequestCondition{
				{
					Type:   certificatesv1.CertificateFailed,
					Status: corev1.ConditionTrue,
				},
			}
		case invalidSignername:
			csr.Spec.SignerName = "not.relevant/signerName"
		case invalidExtraPodNames:
			csr.Spec.Extra["authentication.kubernetes.io/pod-name"] = []string{"a"}
		case invalidExtraPodNamesLen:
			csr.Spec.Extra["authentication.kubernetes.io/pod-name"] = []string{stubPodName, "b"}
		case invalidExtraPodUIDs:
			csr.Spec.Extra["authentication.kubernetes.io/pod-uid"] = []string{"a"}
		case invalidExtraPodUIDsLen:
			csr.Spec.Extra["authentication.kubernetes.io/pod-uid"] = []string{"uid", "b"}
		}
	}
	return csr
}

func invalidAuthorizedCSR(cr *x509.CertificateRequest, invalidations ...invalidation) *certificatesv1.CertificateSigningRequest {
	csr := validAuthorizedCSR(cr)
	for _, i := range invalidations {
		switch i {
		case invalidName:
			csr.Name = "invalid"
		case invalidRequest:
			csr.Spec.Request = []byte("invalid")
		case invalidDenied:
			csr.Status.Conditions = []certificatesv1.CertificateSigningRequestCondition{
				{
					Type:   certificatesv1.CertificateDenied,
					Status: corev1.ConditionTrue,
				},
			}
		case invalidFailed:
			csr.Status.Conditions = []certificatesv1.CertificateSigningRequestCondition{
				{
					Type:   certificatesv1.CertificateFailed,
					Status: corev1.ConditionTrue,
				},
			}
		case invalidSignername:
			csr.Spec.SignerName = "not.relevant/signerName"
		}
	}
	return csr
}

func invalidPod(invalidations ...invalidation) *corev1.Pod {
	pod := validPod()

	for _, i := range invalidations {
		switch i {
		case invalidUID:
			pod.UID = "invalid"
		case invalidName:
			pod.Name = "invalid"
		}
	}
	return pod
}

func invalidX509CR(invalidations ...invalidation) *x509.CertificateRequest {
	cr := validPodX509CR()
	for _, i := range invalidations {
		switch i {
		case invalidDNSNames:
			cr.DNSNames = []string{"google.com"}
		case invalidCN:
			cr.Subject.CommonName = "google.com"
		case invalidIP:
			cr.IPAddresses = []net.IP{net.ParseIP("8.8.8.8")}
		}
	}
	return cr
}
