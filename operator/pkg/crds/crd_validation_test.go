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

package crds

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	opv1 "github.com/projectcalico/calico/operator/api/v1"
)

var _ = Describe("CRD schema validation", Ordered, func() {
	var (
		testEnv *envtest.Environment
		c       client.Client
		ctx     context.Context
	)

	BeforeAll(func() {
		ctx = context.Background()

		_, thisFile, _, ok := runtime.Caller(0)
		Expect(ok).To(BeTrue())

		testEnv = &envtest.Environment{
			CRDDirectoryPaths:     []string{filepath.Join(filepath.Dir(thisFile), "operator")},
			ErrorIfCRDPathMissing: true,
		}
		cfg, err := testEnv.Start()
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = testEnv.Stop() })

		Expect(opv1.AddToScheme(scheme.Scheme)).To(Succeed())
		c, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		istio := &opv1.Istio{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
		Expect(client.IgnoreNotFound(c.Delete(ctx, istio))).To(Succeed())
	})

	Describe("Istio", func() {
		create := func(spec opv1.IstioSpec) error {
			return c.Create(ctx, &opv1.Istio{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: spec})
		}
		expectValid := func(err error, valid bool) {
			if valid {
				ExpectWithOffset(1, err).NotTo(HaveOccurred())
			} else {
				ExpectWithOffset(1, apierrors.IsInvalid(err)).To(BeTrue(), "expected an Invalid error, got %v", err)
			}
		}

		DescribeTable("certificateAuthority is a union",
			func(ca *opv1.IstioCertificateAuthority, valid bool) {
				expectValid(create(opv1.IstioSpec{CertificateAuthority: ca}), valid)
			},
			Entry("accepts an empty union", &opv1.IstioCertificateAuthority{}, true),
			Entry("accepts operatorManaged",
				&opv1.IstioCertificateAuthority{OperatorManaged: &opv1.IstioOperatorManagedCA{}}, true),
			Entry("accepts secret",
				&opv1.IstioCertificateAuthority{Secret: &opv1.IstioCASecret{Name: "istio-mesh-ca"}}, true),
			Entry("rejects both members",
				&opv1.IstioCertificateAuthority{
					OperatorManaged: &opv1.IstioOperatorManagedCA{},
					Secret:          &opv1.IstioCASecret{Name: "istio-mesh-ca"},
				}, false),
			Entry("rejects an empty secret name",
				&opv1.IstioCertificateAuthority{Secret: &opv1.IstioCASecret{}}, false),
		)

		DescribeTable("trustAnchors.additional entries are a union",
			func(anchor opv1.IstioTrustAnchor, valid bool) {
				expectValid(create(opv1.IstioSpec{
					TrustAnchors: &opv1.IstioTrustAnchors{Additional: []opv1.IstioTrustAnchor{anchor}},
				}), valid)
			},
			Entry("accepts secret", opv1.IstioTrustAnchor{Secret: &opv1.IstioCASecret{Name: "partner-root"}}, true),
			Entry("accepts pem", opv1.IstioTrustAnchor{PEM: "-----BEGIN CERTIFICATE-----"}, true),
			Entry("rejects an empty entry", opv1.IstioTrustAnchor{}, false),
			Entry("rejects both members",
				opv1.IstioTrustAnchor{
					Secret: &opv1.IstioCASecret{Name: "partner-root"},
					PEM:    "-----BEGIN CERTIFICATE-----",
				}, false),
		)

		DescribeTable("trustDomain is one or more DNS-1123 labels",
			func(domain string, valid bool) {
				expectValid(create(opv1.IstioSpec{TrustDomain: ptr.To(domain)}), valid)
			},
			Entry("accepts the Istio default", "cluster.local", true),
			Entry("accepts a single label", "mesh", true),
			Entry("accepts a fully qualified name", "mesh.example.com.", true),
			Entry("accepts mixed case", "Mesh.Example", true),
			Entry("accepts a 63 character label", strings.Repeat("a", 63)+".local", true),
			Entry("rejects an empty value", "", false),
			Entry("rejects an empty label", "mesh..local", false),
			Entry("rejects a leading dot", ".mesh.local", false),
			Entry("rejects a leading hyphen", "-mesh.local", false),
			Entry("rejects a trailing hyphen", "mesh-.local", false),
			Entry("rejects an underscore", "mesh_a.local", false),
			Entry("rejects a 64 character label", strings.Repeat("a", 64)+".local", false),
			Entry("rejects a value over 253 characters", strings.Repeat("a.", 127)+"a", false),
		)
	})
})
