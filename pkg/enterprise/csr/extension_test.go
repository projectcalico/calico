// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package csr_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	authv1 "k8s.io/api/authorization/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	fakecalicoclient "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/ctrlruntime"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/enterprise/controller/monitor"
	"github.com/tigera/operator/pkg/render"
	rmonitor "github.com/tigera/operator/pkg/render/monitor"
)

var _ = Describe("CSR extension", func() {
	var (
		cli             client.Client
		clientset       *fake.Clientset
		calicoClientset *fakecalicoclient.Clientset
	)

	// csrData runs ExtendInputs against cli and returns what the extension stashed.
	csrData := func() render.CSRData {
		ci, keyPairs, err := ext.CSR().ExtendInputs(ctx, controller.Inputs{
			RenderInputs: render.Inputs{ClusterDomain: dns.DefaultClusterDomain},
			Client:       cli,
			K8sClientset: clientset,
			CalicoClient: calicoClientset,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(keyPairs).To(BeEmpty())
		return render.CSRDataFromInputs(ci.RenderInputs)
	}

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		clientset = fake.NewClientset()
		calicoClientset = fakecalicoclient.NewSimpleClientset()
	})

	It("makes the Prometheus server certificate signable", func() {
		assets := csrData().AllowedAssets
		asset, ok := assets[rmonitor.PrometheusServerTLSSecretName]
		Expect(ok).To(BeTrue())
		Expect(asset.ServiceAccountName).To(Equal(rmonitor.PrometheusServiceAccountName))
		Expect(asset.ServiceAccountNamespace).To(Equal(rmonitor.TigeraPrometheusObjectName))
		Expect(asset.ValidDNSNames).To(Equal(monitor.PrometheusTLSServerDNSNames(dns.DefaultClusterDomain)))
	})

	It("makes the non-cluster host node certificate signable", func() {
		asset, ok := csrData().AllowedAssets[render.NodeTLSSecretNameNonClusterHost]
		Expect(ok).To(BeTrue())
		Expect(asset.ServiceAccountName).To(BeEmpty())
		Expect(asset.ValidDNSNames).To(ConsistOf(render.FelixCommonName + render.TyphaNonClusterHostSuffix))
	})

	DescribeTable("resolving the subject of a non-cluster host request", func(csr *certificatesv1.CertificateSigningRequest, hep *v3.HostEndpoint, expectedName string) {
		if hep != nil {
			// The fake clientset ignores field selectors, so match on spec.node here.
			calicoClientset.PrependReactor("list", "hostendpoints", func(action testing.Action) (bool, runtime.Object, error) {
				listAction, ok := action.(testing.ListAction)
				Expect(ok).To(BeTrue())
				value, found := listAction.GetListRestrictions().Fields.RequiresExactMatch("spec.node")
				Expect(found).To(BeTrue())
				if value == hep.Spec.Node {
					return true, &v3.HostEndpointList{Items: []v3.HostEndpoint{*hep}}, nil
				}
				return true, &v3.HostEndpointList{}, nil
			})
		}

		subject, err := csrData().ResolveSubject(ctx, csr)
		Expect(err).NotTo(HaveOccurred())
		if expectedName == "" {
			Expect(subject).To(BeNil())
		} else {
			Expect(subject.Name).To(Equal(expectedName))
		}
	},
		Entry("host endpoint found", nonClusterHostCSR("some-node"), hostEndpoint("some-node"), "some-node"),
		Entry("no host endpoint at all", nonClusterHostCSR("some-node"), nil, ""),
		Entry("host endpoint for another node", nonClusterHostCSR("some-node"), hostEndpoint("other-node"), ""),
		Entry("not a non-cluster host request", &certificatesv1.CertificateSigningRequest{}, nil, ""),
	)

	It("rejects a non-cluster host request with an empty hostname", func() {
		_, err := csrData().ResolveSubject(ctx, nonClusterHostCSR(""))
		Expect(err).To(HaveOccurred())
	})

	DescribeTable("authorizing the non-cluster host node certificate", func(allowed bool) {
		clientset.PrependReactor("create", "subjectaccessreviews", func(action testing.Action) (bool, runtime.Object, error) {
			review, ok := action.(testing.CreateAction).GetObject().(*authv1.SubjectAccessReview)
			Expect(ok).To(BeTrue())
			Expect(review.Spec.ResourceAttributes.Name).To(Equal(render.TyphaCommonName + render.TyphaNonClusterHostSuffix))
			return true, &authv1.SubjectAccessReview{Status: authv1.SubjectAccessReviewStatus{Allowed: allowed}}, nil
		})

		asset := csrData().AllowedAssets[render.NodeTLSSecretNameNonClusterHost]
		Expect(asset.Authorize).NotTo(BeNil())
		Expect(asset.Authorize(ctx, nonClusterHostCSR("some-node"))).To(Equal(allowed))
	},
		Entry("the requestor holds the permission", true),
		Entry("the requestor does not", false),
	)

	It("needs the CSR role when external Prometheus is configured", func() {
		Expect(cli.Create(ctx, &operatorv1.Monitor{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec:       operatorv1.MonitorSpec{ExternalPrometheus: &operatorv1.ExternalPrometheus{Namespace: "default"}},
		})).NotTo(HaveOccurred())
		Expect(csrData().RequiresSigningRole).To(BeTrue())
	})

	It("needs the CSR role when a NonClusterHost exists", func() {
		Expect(cli.Create(ctx, &operatorv1.NonClusterHost{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		})).NotTo(HaveOccurred())
		Expect(csrData().RequiresSigningRole).To(BeTrue())
	})

	It("still checks for a NonClusterHost when no Monitor exists", func() {
		Expect(csrData().RequiresSigningRole).To(BeFalse())

		Expect(cli.Create(ctx, &operatorv1.NonClusterHost{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		})).NotTo(HaveOccurred())
		Expect(csrData().RequiresSigningRole).To(BeTrue())
	})

	It("watches every CR the signing-role decision reads", func() {
		rec := &watchRecorder{}
		Expect(ext.CSR().Watches(rec)).NotTo(HaveOccurred())
		Expect(rec.watched).To(ConsistOf("*v1.Monitor", "*v1.NonClusterHost"))
	})

	It("does not need the CSR role when Prometheus is internal", func() {
		Expect(cli.Create(ctx, &operatorv1.Monitor{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		})).NotTo(HaveOccurred())
		Expect(csrData().RequiresSigningRole).To(BeFalse())
	})
})

// watchRecorder collects the objects an extension asks to watch. Only WatchObject is
// called, so the embedded interface stays nil.
type watchRecorder struct {
	ctrlruntime.Controller

	watched []string
}

func (w *watchRecorder) WatchObject(obj client.Object, _ handler.EventHandler, _ ...predicate.Predicate) error {
	w.watched = append(w.watched, fmt.Sprintf("%T", obj))
	return nil
}

func nonClusterHostCSR(hostname string) *certificatesv1.CertificateSigningRequest {
	return &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:   render.NodeTLSSecretNameNonClusterHost + ":" + hostname,
			Labels: map[string]string{"nonclusterhost.tigera.io/hostname": hostname},
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Username: "system:serviceaccount:calico-system:tigera-noncluster-host",
		},
	}
}

func hostEndpoint(node string) *v3.HostEndpoint {
	return &v3.HostEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "some-hep"},
		Spec:       v3.HostEndpointSpec{InterfaceName: "eth0", Node: node},
	}
}
