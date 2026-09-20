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

package managedfields_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/controller/managedfields"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
)

var _ = Describe("crd.projectcalico.org/v1 writer", func() {
	var c client.Client
	var ctx context.Context
	var w *managedfields.FieldManager

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
		w = managedfields.New(c, false)
	})

	Context("a declaration that stops declaring a field", func() {
		declare := func(port *int) managedfields.Declare[*v3.FelixConfiguration] {
			return func(_ *v3.FelixConfiguration) (*managedfields.Declaration[*v3.FelixConfiguration], error) {
				return &managedfields.Declaration[*v3.FelixConfiguration]{
					Manager: "test",
					Owned:   &v3.FelixConfiguration{Spec: v3.FelixConfigurationSpec{HealthPort: port}},
					Policies: map[string]managedfields.ConflictPolicy{
						"spec.healthPort": managedfields.ConflictDefer,
					},
				}, nil
			}
		}

		It("should delete a field it wrote itself", func() {
			_, err := managedfields.Apply(ctx, w, declare(ptr.To(9099)))
			Expect(err).NotTo(HaveOccurred())
			Expect(getFelixConfig().Spec.HealthPort).To(Equal(ptr.To(9099)))

			_, err = managedfields.Apply(ctx, w, declare(nil))
			Expect(err).NotTo(HaveOccurred())
			Expect(getFelixConfig().Spec.HealthPort).To(BeNil())
		})

		It("should leave a value it never wrote", func() {
			Expect(c.Create(ctx, &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec:       v3.FelixConfigurationSpec{HealthPort: ptr.To(9199)},
			})).NotTo(HaveOccurred())

			_, err := managedfields.Apply(ctx, w, declare(nil))
			Expect(err).NotTo(HaveOccurred())
			Expect(getFelixConfig().Spec.HealthPort).To(Equal(ptr.To(9199)))
		})

		// libcalico-go stashes the v3 metadata on every v3 write, and RestoreV3Metadata pulls it
		// back out. The operator's own record has to survive that round trip.
		Context("with a projectcalico.org/metadata stash present", func() {
			BeforeEach(func() {
				Expect(c.Create(ctx, &v3.FelixConfiguration{ObjectMeta: metav1.ObjectMeta{
					Name:        "default",
					Annotations: map[string]string{"projectcalico.org/metadata": `{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{}"}}`},
				}})).NotTo(HaveOccurred())
			})

			It("should read back the record it wrote", func() {
				_, err := managedfields.Apply(ctx, w, declare(ptr.To(9099)))
				Expect(err).NotTo(HaveOccurred())

				var seen map[string]string
				_, err = managedfields.Apply(ctx, w, func(current *v3.FelixConfiguration) (*managedfields.Declaration[*v3.FelixConfiguration], error) {
					seen = current.Annotations
					return declare(ptr.To(9099))(current)
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(seen).To(HaveKey("operator.tigera.io/owned-fields"))
			})

			It("should stop writing once the declared values are in place", func() {
				_, err := managedfields.Apply(ctx, w, declare(ptr.To(9099)))
				Expect(err).NotTo(HaveOccurred())
				settled := getFelixConfig().ResourceVersion

				for range 2 {
					_, err = managedfields.Apply(ctx, w, declare(ptr.To(9099)))
					Expect(err).NotTo(HaveOccurred())
				}
				Expect(getFelixConfig().ResourceVersion).To(Equal(settled))
			})

			It("should leave the stash alone", func() {
				for range 3 {
					_, err := managedfields.Apply(ctx, w, declare(ptr.To(9099)))
					Expect(err).NotTo(HaveOccurred())
				}
				Expect(getFelixConfig().Annotations).To(HaveKey("projectcalico.org/metadata"))
			})
		})

		It("should leave a value someone else changed", func() {
			_, err := managedfields.Apply(ctx, w, declare(ptr.To(9099)))
			Expect(err).NotTo(HaveOccurred())

			fc := getFelixConfig()
			fc.Spec.HealthPort = ptr.To(9199)
			Expect(c.Update(ctx, fc)).NotTo(HaveOccurred())

			_, err = managedfields.Apply(ctx, w, declare(nil))
			Expect(err).NotTo(HaveOccurred())
			Expect(getFelixConfig().Spec.HealthPort).To(Equal(ptr.To(9199)))
		})
	})
})
