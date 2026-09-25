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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/projectcalico/api/pkg/lib/numorstring"

	opv1 "github.com/projectcalico/calico/operator/api/v1"
)

var _ = Describe("CRD schema defaults", Ordered, func() {
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
		defaultName := metav1.ObjectMeta{Name: "default"}
		for _, obj := range []client.Object{
			&opv1.Whisker{ObjectMeta: defaultName},
			&opv1.Istio{ObjectMeta: defaultName},
			&opv1.ManagementClusterConnection{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}},
		} {
			Expect(client.IgnoreNotFound(c.Delete(ctx, obj))).To(Succeed())
		}
	})

	Describe("Whisker", func() {
		It("defaults an empty spec", func() {
			w := &opv1.Whisker{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
			Expect(c.Create(ctx, w)).To(Succeed())

			Expect(w.Spec.Notifications).To(HaveValue(Equal(opv1.Enabled)))
		})

		It("leaves a configured value alone", func() {
			w := &opv1.Whisker{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       opv1.WhiskerSpec{Notifications: ptr.To(opv1.Disabled)},
			}
			Expect(c.Create(ctx, w)).To(Succeed())

			Expect(w.Spec.Notifications).To(HaveValue(Equal(opv1.Disabled)))
		})
	})

	Describe("Istio", func() {
		It("defaults an empty spec", func() {
			i := &opv1.Istio{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
			Expect(c.Create(ctx, i)).To(Succeed())

			Expect(i.Spec.DSCPMark).To(HaveValue(Equal(numorstring.DSCPFromInt(23))))
		})

		It("leaves a configured value alone", func() {
			mark := numorstring.DSCPFromInt(42)
			i := &opv1.Istio{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       opv1.IstioSpec{DSCPMark: &mark},
			}
			Expect(c.Create(ctx, i)).To(Succeed())

			Expect(i.Spec.DSCPMark).To(HaveValue(Equal(numorstring.DSCPFromInt(42))))
		})
	})

	Describe("ManagementClusterConnection", func() {
		It("defaults an empty spec", func() {
			mcc := &opv1.ManagementClusterConnection{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}}
			Expect(c.Create(ctx, mcc)).To(Succeed())

			Expect(mcc.Spec.TLS).To(Equal(&opv1.ManagementClusterTLS{CA: opv1.CATypeTigera}))
		})

		It("leaves a configured CA alone", func() {
			mcc := &opv1.ManagementClusterConnection{
				ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
				Spec:       opv1.ManagementClusterConnectionSpec{TLS: &opv1.ManagementClusterTLS{CA: opv1.CATypePublic}},
			}
			Expect(c.Create(ctx, mcc)).To(Succeed())

			Expect(mcc.Spec.TLS.CA).To(Equal(opv1.CATypePublic))
		})
	})
})
