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

// declareClusterRoutes governs spec.programClusterRoutes, declaring a value only when mode is set.
func declareClusterRoutes(mode string) managedfields.Declare[*v3.BGPConfiguration] {
	return func(_ *v3.BGPConfiguration) (*managedfields.Declaration, error) {
		bgpConfig := &v3.BGPConfiguration{}
		d := &managedfields.Declaration{
			Manager:  "installation",
			Owned:    bgpConfig,
			Policies: map[string]managedfields.ConflictPolicy{"spec.programClusterRoutes": managedfields.ConflictOverride},
		}
		if mode != "" {
			bgpConfig.Spec.ProgramClusterRoutes = ptr.To(mode)
		}
		return d, nil
	}
}

var _ = Describe("Applying declared BGPConfiguration fields", func() {
	var c client.Client
	var ctx context.Context

	getBGPConfig := func() *v3.BGPConfiguration {
		bgpConfig := &v3.BGPConfiguration{}
		Expect(c.Get(ctx, types.NamespacedName{Name: "default"}, bgpConfig)).NotTo(HaveOccurred())
		return bgpConfig
	}

	// Both API groups have to retract, because Felix gives its half of cluster route programming
	// up as soon as the Installation stops asking for a mode.
	for _, useV3CRDs := range []bool{true, false} {
		group := "crd.projectcalico.org/v1"
		if useV3CRDs {
			group = "projectcalico.org/v3"
		}

		Context(group, func() {
			var w *managedfields.FieldManager

			BeforeEach(func() {
				scheme := runtime.NewScheme()
				Expect(apis.AddToScheme(scheme, useV3CRDs)).NotTo(HaveOccurred())
				c = ctrlrfake.DefaultFakeClientBuilder(scheme).WithReturnManagedFields().Build()
				ctx = context.Background()
				w = managedfields.New(c)
			})

			It("should write the declared value", func() {
				bgpConfig, err := declareClusterRoutes("EnabledNoEncapOnly").Apply(ctx, w)
				Expect(err).NotTo(HaveOccurred())
				Expect(bgpConfig.Spec.ProgramClusterRoutes).To(Equal(ptr.To("EnabledNoEncapOnly")))
				Expect(getBGPConfig().Spec.ProgramClusterRoutes).To(Equal(ptr.To("EnabledNoEncapOnly")))
			})

			It("should take the field back when the declaration stops setting it", func() {
				_, err := declareClusterRoutes("EnabledNoEncapOnly").Apply(ctx, w)
				Expect(err).NotTo(HaveOccurred())

				bgpConfig, err := declareClusterRoutes("").Apply(ctx, w)
				Expect(err).NotTo(HaveOccurred())
				Expect(bgpConfig.Spec.ProgramClusterRoutes).To(BeNil())
				Expect(getBGPConfig().Spec.ProgramClusterRoutes).To(BeNil())
			})

			It("should not create a BGPConfiguration for a declaration with nothing to write", func() {
				_, err := declareClusterRoutes("").Apply(ctx, w)
				Expect(err).NotTo(HaveOccurred())

				bgpConfig := &v3.BGPConfiguration{}
				err = c.Get(ctx, types.NamespacedName{Name: "default"}, bgpConfig)
				Expect(err).To(HaveOccurred())
			})

			It("should leave a field it never wrote alone", func() {
				Expect(c.Create(ctx, &v3.BGPConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: "default"},
					Spec:       v3.BGPConfigurationSpec{ProgramClusterRoutes: ptr.To("Enabled")},
				})).NotTo(HaveOccurred())

				_, err := declareClusterRoutes("").Apply(ctx, w)
				Expect(err).NotTo(HaveOccurred())
				Expect(getBGPConfig().Spec.ProgramClusterRoutes).To(Equal(ptr.To("Enabled")))
			})
		})
	}
})
