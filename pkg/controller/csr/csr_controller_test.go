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
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	authv1 "k8s.io/api/authorization/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	fakecalicoclient "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/monitor"
	"github.com/tigera/operator/pkg/controller/status"
	ctrlrclient "github.com/tigera/operator/pkg/ctrlruntime/client"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

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
		Expect(cli.Create(ctx, &operatorv1.Monitor{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec:       operatorv1.MonitorSpec{ExternalPrometheus: &operatorv1.ExternalPrometheus{Namespace: "default"}},
		})).NotTo(HaveOccurred())
		certificateManager, err = certificatemanager.Create(cli, &installation.Spec, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
		mockStatus = &status.MockStatus{}
		mockStatus.On("OnCRFound").Return()
		r = reconcileCSR{
			client:           cli,
			clientset:        clientset,
			calicoClient:     calicoClientset,
			scheme:           scheme,
			provider:         operatorv1.ProviderNone,
			clusterDomain:    dns.DefaultClusterDomain,
			allowedTLSAssets: allowedAssets(dns.DefaultClusterDomain),
			variant:          operatorv1.CalicoEnterprise,
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
		certificate, err := validate(clientset, csr, pod, allowedAssets(dns.DefaultClusterDomain))
		if expectError {
			Expect(err).To(HaveOccurred())
		} else if expectRelevant {
			Expect(relevantCSR(csr)).To(BeTrue())
			Expect(err).ToNot(HaveOccurred())
			Expect(certificate.ExtKeyUsage).To(Equal(extKeyUsage))
			Expect(certificate.DNSNames).To(Equal(monitor.PrometheusTLSServerDNSNames(dns.DefaultClusterDomain)))
			Expect(certificate.Subject.CommonName).To(Equal(monitor.PrometheusTLSServerDNSNames(dns.DefaultClusterDomain)[0]))
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

	DescribeTable("csr validation for non-cluster hosts", func(csr *certificatesv1.CertificateSigningRequest, hep *v3.HostEndpoint, expectError, expectRelevant, subjectAccessReviewAllowed bool) {
		clientset.PrependReactor("create", "subjectaccessreviews", func(action testing.Action) (handled bool, ret runtime.Object, err error) {
			return true, &authv1.SubjectAccessReview{
				Status: authv1.SubjectAccessReviewStatus{
					Allowed: subjectAccessReviewAllowed,
				},
			}, nil
		})
		certificate, err := validate(clientset, csr, hep, allowedAssets(dns.DefaultClusterDomain))
		if expectError {
			Expect(err).To(HaveOccurred())
		} else if expectRelevant {
			Expect(relevantCSR(csr)).To(BeTrue())
			Expect(err).NotTo(HaveOccurred())
			Expect(certificate.ExtKeyUsage).To(Equal(extKeyUsage))
			Expect(certificate.DNSNames).To(Equal([]string{"typha-client-noncluster-host"}))
			Expect(certificate.Subject.CommonName).To(Equal("typha-client-noncluster-host"))
			Expect(certificate.IsCA).To(BeFalse())
		} else {
			Expect(relevantCSR(csr)).To(BeFalse())
		}
	},
		Entry("valid CSR / happy flow", validNonClusterHostCSR(validNonClusterHostX509CR(), validHostEndpoint()), validHostEndpoint(), false, true, true),
		Entry("valid CSR / no hep", validNonClusterHostCSR(validNonClusterHostX509CR(), validHostEndpoint()), nil, true, true, true),
		Entry("valid CSR / subject access review denied", validNonClusterHostCSR(validNonClusterHostX509CR(), validHostEndpoint()), validHostEndpoint(), true, true, false),
		Entry("unrecognized csr name", invalidNonClusterHostCSR(validNonClusterHostX509CR(), validHostEndpoint(), invalidName), validHostEndpoint(), true, true, true),
		Entry("invalid certificate request", invalidNonClusterHostCSR(validNonClusterHostX509CR(), validHostEndpoint(), invalidRequest), validHostEndpoint(), true, true, true),
		Entry("previously denied csr", invalidNonClusterHostCSR(validNonClusterHostX509CR(), validHostEndpoint(), invalidDenied), validHostEndpoint(), false, false, true),
		Entry("previously failed csr", invalidNonClusterHostCSR(validNonClusterHostX509CR(), validHostEndpoint(), invalidFailed), validHostEndpoint(), false, false, true),
		Entry("bad DNS names in x509 certificate request", invalidNonClusterHostCSR(invalidX509CR(invalidDNSNames), validHostEndpoint()), validHostEndpoint(), true, true, true),
		Entry("bad CN in x509 certificate request", invalidNonClusterHostCSR(invalidX509CR(invalidCN), validHostEndpoint()), validHostEndpoint(), true, true, true),
		Entry("bad IP in x509 certificate request", invalidNonClusterHostCSR(invalidX509CR(invalidIP), validHostEndpoint()), validHostEndpoint(), true, true, true),
		Entry("irrelevant signer name", invalidNonClusterHostCSR(invalidX509CR(), validHostEndpoint(), invalidSignername), validHostEndpoint(), false, false, true),
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

	DescribeTable("getHostEndpoint", func(csr *certificatesv1.CertificateSigningRequest, hep *v3.HostEndpoint, expectHepNil bool) {
		if hep != nil {
			Expect(cli.Create(ctx, hep)).NotTo(HaveOccurred())
			// When we list HostEndpoints, we use a field selector to filter host endpoint by their spec.node.
			// The default fake client's List method does not support filed selectors, so we need to add a reactor to handle this.
			calicoClientset.PrependReactor("list", "hostendpoints", func(action testing.Action) (handled bool, ret runtime.Object, err error) {
				listAction, ok := action.(testing.ListAction)
				Expect(ok).To(BeTrue())
				fieldSelector := listAction.GetListRestrictions().Fields
				value, found := fieldSelector.RequiresExactMatch("spec.node")
				Expect(found).To(BeTrue())
				if value == hep.Spec.Node {
					return true, &v3.HostEndpointList{
						Items: []v3.HostEndpoint{*hep},
					}, nil
				}
				return true, &v3.HostEndpointList{}, nil
			})
		}
		v, ok := csr.Labels["nonclusterhost.tigera.io/hostname"]
		Expect(ok).To(BeTrue())
		foundHep, err := r.getHostEndpoint(ctx, v)
		Expect(err).NotTo(HaveOccurred())
		if expectHepNil {
			Expect(foundHep).To(BeNil())
		} else {
			Expect(foundHep).NotTo(BeNil())
		}
	},
		Entry("Valid CSR, hep found", validNonClusterHostCSR(validNonClusterHostX509CR(), validHostEndpoint()), validHostEndpoint(), false),
		Entry("Valid CSR, no hep found", validNonClusterHostCSR(validNonClusterHostX509CR(), validHostEndpoint()), nil, true),
		Entry("Valid CSR, no matching hep found due to different hostname", validNonClusterHostCSR(validNonClusterHostX509CR(), validHostEndpoint()), invalidHostEndpoint(invalidName), true),
		Entry("Invalid CSR label, irrelevant hep", invalidNonClusterHostCSR(invalidX509CR(), validHostEndpoint(), invalidLabel), validHostEndpoint(), true),
	)
})

func validPodX509CR() *x509.CertificateRequest {
	subj := pkix.Name{
		CommonName: "prometheus-http-api",
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
		DNSNames:           []string{"prometheus-http-api", "prometheus-http-api.tigera-prometheus", "prometheus-http-api.tigera-prometheus.svc", "prometheus-http-api.tigera-prometheus.svc.cluster.local"},
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

func validNonClusterHostX509CR() *x509.CertificateRequest {
	subj := pkix.Name{
		CommonName: "typha-client-noncluster-host",
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
		DNSNames:           []string{"typha-client-noncluster-host"},
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
			Name: "calico-node-prometheus-tls:prometheus-calico-node-prometheus-0",
			Labels: map[string]string{
				"k8s-app":                "tigera-prometheus",
				"operator.tigera.io/csr": "tigera-prometheus",
			},
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request: pem.EncodeToMemory(&pem.Block{
				Type: "CERTIFICATE REQUEST", Bytes: certificateRequest,
			}),
			SignerName: "tigera.io/operator-signer",
			Username:   "system:serviceaccount:tigera-prometheus:prometheus",
			Extra: map[string]certificatesv1.ExtraValue{
				"authentication.kubernetes.io/pod-name": []string{pod.Name},
				"authentication.kubernetes.io/pod-uid":  []string{string(pod.UID)},
			},
		},
		Status: certificatesv1.CertificateSigningRequestStatus{},
	}
}

func validNonClusterHostCSR(cr *x509.CertificateRequest, hep *v3.HostEndpoint) *certificatesv1.CertificateSigningRequest {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())
	buf := bytes.NewBuffer([]byte{})
	err = pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	Expect(err).NotTo(HaveOccurred())
	certificateRequest, err := x509.CreateCertificateRequest(rand.Reader, cr, key)
	Expect(err).NotTo(HaveOccurred())
	return &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-certs-noncluster-host:" + hep.Spec.Node,
			Labels: map[string]string{
				"k8s-app":                           "calico-node",
				"nonclusterhost.tigera.io/hostname": hep.Spec.Node,
				"operator.tigera.io/csr":            "calico-node",
			},
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request: pem.EncodeToMemory(&pem.Block{
				Type: "CERTIFICATE REQUEST", Bytes: certificateRequest,
			}),
			SignerName: "tigera.io/operator-signer",
			Username:   "system:serviceaccount:calico-system:tigera-noncluster-host",
		},
		Status: certificatesv1.CertificateSigningRequestStatus{},
	}
}

type invalidation int

func validPod() *corev1.Pod {
	return &corev1.Pod{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prometheus-calico-node-prometheus-0",
			Namespace: "tigera-prometheus",
			Labels: map[string]string{
				"k8s-app": "tigera-prometheus",
			},
			UID: "uid",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "prometheus",
		},
		Status: corev1.PodStatus{
			PodIP: "1.2.3.4",
		},
	}
}

func validHostEndpoint() *v3.HostEndpoint {
	return &v3.HostEndpoint{
		TypeMeta: metav1.TypeMeta{Kind: "HostEndpoint", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "some-hep",
		},
		Spec: v3.HostEndpointSpec{
			ExpectedIPs:   []string{"1.2.3.4", "5.6.7.8"},
			InterfaceName: "eth0",
			Node:          "some-node",
			Profiles:      []string{"some-profile"},
		},
	}
}

const (
	invalidUID invalidation = iota
	invalidName
	invalidLabel
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
			csr.Spec.Extra["authentication.kubernetes.io/pod-name"] = []string{"prometheus-calico-node-prometheus-0", "b"}
		case invalidExtraPodUIDs:
			csr.Spec.Extra["authentication.kubernetes.io/pod-uid"] = []string{"a"}
		case invalidExtraPodUIDsLen:
			csr.Spec.Extra["authentication.kubernetes.io/pod-uid"] = []string{"uid", "b"}
		}
	}
	return csr
}

func invalidNonClusterHostCSR(cr *x509.CertificateRequest, hep *v3.HostEndpoint, invalidations ...invalidation) *certificatesv1.CertificateSigningRequest {
	csr := validNonClusterHostCSR(cr, hep)
	for _, i := range invalidations {
		switch i {
		case invalidName:
			csr.Name = "invalid"
		case invalidLabel:
			csr.Labels["nonclusterhost.tigera.io/hostname"] = "invalid"
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

func invalidHostEndpoint(invalidation ...invalidation) *v3.HostEndpoint {
	hep := validHostEndpoint()
	for _, i := range invalidation {
		switch i {
		case invalidName:
			hep.Spec.Node = "invalid"
		}
	}
	return hep
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
