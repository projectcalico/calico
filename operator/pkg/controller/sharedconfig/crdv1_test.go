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

package sharedconfig_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/controller/sharedconfig"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
)

var _ = Describe("crd.projectcalico.org/v1 writer", func() {
	var c client.Client
	var ctx context.Context
	var w sharedconfig.Writer

	getFelixConfig := func() *v3.FelixConfiguration {
		fc := &v3.FelixConfiguration{}
		Expect(c.Get(ctx, types.NamespacedName{Name: "default"}, fc)).NotTo(HaveOccurred())
		return fc
	}

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()
		w = sharedconfig.NewWriter(c, false)
	})

	It("should create the default FelixConfiguration when it doesn't exist", func() {
		_, err := w.UpdateFelixConfiguration(ctx, func(fc *v3.FelixConfiguration) (bool, error) {
			fc.Spec.HealthPort = ptr.To(9099)
			return true, nil
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(getFelixConfig().Spec.HealthPort).To(Equal(ptr.To(9099)))
	})

	It("should patch an existing FelixConfiguration", func() {
		Expect(c.Create(ctx, &v3.FelixConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       v3.FelixConfigurationSpec{HealthPort: ptr.To(9099)},
		})).NotTo(HaveOccurred())

		_, err := w.UpdateFelixConfiguration(ctx, func(fc *v3.FelixConfiguration) (bool, error) {
			fc.Spec.BPFEnabled = ptr.To(true)
			return true, nil
		})
		Expect(err).NotTo(HaveOccurred())

		fc := getFelixConfig()
		Expect(fc.Spec.BPFEnabled).To(Equal(ptr.To(true)))
		Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9099)))
	})

	It("should not write when the update function reports no change", func() {
		Expect(c.Create(ctx, &v3.FelixConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).NotTo(HaveOccurred())
		before := getFelixConfig().ResourceVersion

		_, err := w.UpdateFelixConfiguration(ctx, func(fc *v3.FelixConfiguration) (bool, error) {
			fc.Spec.BPFEnabled = ptr.To(true)
			return false, nil
		})
		Expect(err).NotTo(HaveOccurred())

		fc := getFelixConfig()
		Expect(fc.ResourceVersion).To(Equal(before))
		Expect(fc.Spec.BPFEnabled).To(BeNil())
	})

	It("should return the update function's error without writing", func() {
		_, err := w.UpdateFelixConfiguration(ctx, func(fc *v3.FelixConfiguration) (bool, error) {
			fc.Spec.BPFEnabled = ptr.To(true)
			return true, errors.New("user modified bpfEnabled")
		})
		Expect(err).To(MatchError("user modified bpfEnabled"))
		Expect(c.Get(ctx, types.NamespacedName{Name: "default"}, &v3.FelixConfiguration{})).To(HaveOccurred())
	})

	Context("a declaration that stops declaring a field", func() {
		declare := func(port *int) sharedconfig.DeclareFelixConfiguration {
			return func(_ *v3.FelixConfiguration) (*sharedconfig.FelixConfigurationDeclaration, error) {
				return &sharedconfig.FelixConfigurationDeclaration{
					Manager: "test",
					Owned:   &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{HealthPort: port}},
					Policies: map[string]sharedconfig.ConflictPolicy{
						"spec.healthPort": sharedconfig.ConflictDefer,
					},
				}, nil
			}
		}

		It("should delete a field it wrote itself", func() {
			_, err := w.ApplyFelixConfiguration(ctx, declare(ptr.To(9099)))
			Expect(err).NotTo(HaveOccurred())
			Expect(getFelixConfig().Spec.HealthPort).To(Equal(ptr.To(9099)))

			_, err = w.ApplyFelixConfiguration(ctx, declare(nil))
			Expect(err).NotTo(HaveOccurred())
			Expect(getFelixConfig().Spec.HealthPort).To(BeNil())
		})

		It("should leave a value it never wrote", func() {
			Expect(c.Create(ctx, &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       v3.FelixConfigurationSpec{HealthPort: ptr.To(9199)},
			})).NotTo(HaveOccurred())

			_, err := w.ApplyFelixConfiguration(ctx, declare(nil))
			Expect(err).NotTo(HaveOccurred())
			Expect(getFelixConfig().Spec.HealthPort).To(Equal(ptr.To(9199)))
		})

		It("should leave a value someone else changed", func() {
			_, err := w.ApplyFelixConfiguration(ctx, declare(ptr.To(9099)))
			Expect(err).NotTo(HaveOccurred())

			fc := getFelixConfig()
			fc.Spec.HealthPort = ptr.To(9199)
			Expect(c.Update(ctx, fc)).NotTo(HaveOccurred())

			_, err = w.ApplyFelixConfiguration(ctx, declare(nil))
			Expect(err).NotTo(HaveOccurred())
			Expect(getFelixConfig().Spec.HealthPort).To(Equal(ptr.To(9199)))
		})
	})
})
