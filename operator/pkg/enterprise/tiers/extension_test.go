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

package tiers_test

import (
	"context"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/enterprise"
	eoptions "github.com/projectcalico/calico/operator/pkg/enterprise/options"
	"github.com/projectcalico/calico/operator/pkg/extensions"
	"github.com/projectcalico/calico/operator/pkg/render"
)

func TestTiers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "pkg/enterprise/tiers Suite")
}

var _ = Describe("DNSClientNamespaces", func() {
	var scheme *runtime.Scheme
	var ctx context.Context

	BeforeEach(func() {
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		ctx = context.Background()
	})

	tiersExt := func(multiTenant bool) extensions.TiersExtension {
		return enterprise.New(operatorv1.CalicoEnterprise, eoptions.Options{MultiTenant: multiTenant}).Tiers()
	}

	It("returns the Enterprise namespaces on a single-tenant cluster", func() {
		cli := fake.NewClientBuilder().WithScheme(scheme).Build()
		ns, err := tiersExt(false).DNSClientNamespaces(ctx, cli)
		Expect(err).NotTo(HaveOccurred())
		Expect(ns).To(ContainElement(render.ElasticsearchNamespace))
		Expect(ns).NotTo(ContainElement("tenant-a"))
	})

	It("adds the tenant namespaces on a multi-tenant cluster", func() {
		cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
			&operatorv1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "tenant-a"}},
			&operatorv1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "tenant-b"}},
		).Build()
		ns, err := tiersExt(true).DNSClientNamespaces(ctx, cli)
		Expect(err).NotTo(HaveOccurred())
		Expect(ns).To(ContainElement(render.ElasticsearchNamespace))
		Expect(ns).To(ContainElements("tenant-a", "tenant-b"))
	})

	It("returns nothing when the variant is Calico", func() {
		cli := fake.NewClientBuilder().WithScheme(scheme).Build()
		ns, err := enterprise.New(operatorv1.Calico, eoptions.Options{}).Tiers().DNSClientNamespaces(ctx, cli)
		Expect(err).NotTo(HaveOccurred())
		Expect(ns).To(BeEmpty())
	})
})
