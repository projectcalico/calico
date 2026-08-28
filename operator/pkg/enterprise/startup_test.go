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

package enterprise_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/enterprise"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/logstorage"
)

var _ = Describe("VerifyAPIsExist", func() {
	enterpriseAPIs := &metav1.APIResourceList{
		GroupVersion: "operator.tigera.io/v1",
		APIResources: []metav1.APIResource{
			{Kind: "LogStorage"},
		},
	}
	calicoAPIs := &metav1.APIResourceList{
		GroupVersion: "operator.tigera.io/v1",
		APIResources: []metav1.APIResource{
			{Kind: "Installation"},
		},
	}

	It("accepts an Enterprise install whose CRDs are served", func() {
		cs := fake.NewSimpleClientset()
		cs.Resources = []*metav1.APIResourceList{enterpriseAPIs}

		Expect(enterprise.VerifyAPIsExist(operatorv1.CalicoEnterprise, cs)).To(Succeed())
	})

	It("rejects an Enterprise install whose CRDs are absent", func() {
		cs := fake.NewSimpleClientset()
		cs.Resources = []*metav1.APIResourceList{calicoAPIs}

		Expect(enterprise.VerifyAPIsExist(operatorv1.CalicoEnterprise, cs)).To(MatchError(ContainSubstring("CRDs are not installed")))
	})

	It("accepts the deprecated Enterprise variant", func() {
		cs := fake.NewSimpleClientset()
		cs.Resources = []*metav1.APIResourceList{enterpriseAPIs}

		//nolint:staticcheck // SA1019: the deprecated spelling is what this covers
		Expect(enterprise.VerifyAPIsExist(operatorv1.TigeraSecureEnterprise, cs)).To(Succeed())
	})

	It("leaves Calico alone when the Enterprise CRDs are absent", func() {
		cs := fake.NewSimpleClientset()
		cs.Resources = []*metav1.APIResourceList{calicoAPIs}

		Expect(enterprise.VerifyAPIsExist(operatorv1.Calico, cs)).To(Succeed())
	})
})

var _ = Describe("VerifyElasticsearch", func() {
	internalCert := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.TigeraElasticsearchInternalCertSecret,
			Namespace: render.ElasticsearchNamespace,
		},
	}
	externalCert := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      logstorage.ExternalCertsSecret,
			Namespace: render.ElasticsearchNamespace,
		},
	}

	It("rejects an external configuration that still has the internal certificate", func() {
		cs := fake.NewSimpleClientset(internalCert)

		err := enterprise.VerifyElasticsearch(ctx, cs, operatorv1.CalicoEnterprise, false, true)
		Expect(err).To(MatchError(ContainSubstring("configured as external ES")))
	})

	It("rejects an internal configuration that still has the external certificate", func() {
		cs := fake.NewSimpleClientset(externalCert)

		err := enterprise.VerifyElasticsearch(ctx, cs, operatorv1.CalicoEnterprise, false, false)
		Expect(err).To(MatchError(ContainSubstring("configured as internal ES")))
	})

	It("accepts an external configuration with only the external certificate", func() {
		cs := fake.NewSimpleClientset(externalCert)

		Expect(enterprise.VerifyElasticsearch(ctx, cs, operatorv1.CalicoEnterprise, false, true)).To(Succeed())
	})

	It("accepts an internal configuration with only the internal certificate", func() {
		cs := fake.NewSimpleClientset(internalCert)

		Expect(enterprise.VerifyElasticsearch(ctx, cs, operatorv1.CalicoEnterprise, false, false)).To(Succeed())
	})

	It("accepts both certificates while a migration is in flight", func() {
		cs := fake.NewSimpleClientset(internalCert, externalCert)

		Expect(enterprise.VerifyElasticsearch(ctx, cs, operatorv1.CalicoEnterprise, true, true)).To(Succeed())
	})

	It("leaves Calico alone when a contradictory certificate exists", func() {
		cs := fake.NewSimpleClientset(externalCert)

		Expect(enterprise.VerifyElasticsearch(ctx, cs, operatorv1.Calico, false, false)).To(Succeed())
	})
})

var _ = Describe("ProtectedNamespaces", func() {
	It("covers the Enterprise namespaces the operator manages", func() {
		Expect(enterprise.ProtectedNamespaces()).To(ContainElements(
			render.ElasticsearchNamespace,
			render.ManagerNamespace,
			render.LogCollectorNamespace,
		))
	})

	It("claims no namespace the operator does not manage", func() {
		Expect(enterprise.ProtectedNamespaces()).NotTo(ContainElements("kube-system", "default"))
	})
})
