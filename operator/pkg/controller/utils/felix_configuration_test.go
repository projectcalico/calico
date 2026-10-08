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

package utils_test

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
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
)

var _ = Describe("PatchFelixConfiguration", func() {
	var c client.Client
	var ctx context.Context

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
	})

	It("should create the default FelixConfiguration when it doesn't exist", func() {
		_, err := utils.PatchFelixConfiguration(ctx, c, func(fc *v3.FelixConfiguration) (bool, error) {
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

		_, err := utils.PatchFelixConfiguration(ctx, c, func(fc *v3.FelixConfiguration) (bool, error) {
			fc.Spec.BPFEnabled = ptr.To(true)
			return true, nil
		})
		Expect(err).NotTo(HaveOccurred())

		fc := getFelixConfig()
		Expect(fc.Spec.BPFEnabled).To(Equal(ptr.To(true)))
		Expect(fc.Spec.HealthPort).To(Equal(ptr.To(9099)))
	})

	It("should not write when the patch function reports no change", func() {
		Expect(c.Create(ctx, &v3.FelixConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "default"}})).NotTo(HaveOccurred())
		before := getFelixConfig().ResourceVersion

		_, err := utils.PatchFelixConfiguration(ctx, c, func(fc *v3.FelixConfiguration) (bool, error) {
			fc.Spec.BPFEnabled = ptr.To(true)
			return false, nil
		})
		Expect(err).NotTo(HaveOccurred())

		fc := getFelixConfig()
		Expect(fc.ResourceVersion).To(Equal(before))
		Expect(fc.Spec.BPFEnabled).To(BeNil())
	})

	It("should return the patch function's error without writing", func() {
		_, err := utils.PatchFelixConfiguration(ctx, c, func(fc *v3.FelixConfiguration) (bool, error) {
			fc.Spec.BPFEnabled = ptr.To(true)
			return true, errors.New("user modified bpfEnabled")
		})
		Expect(err).To(MatchError("user modified bpfEnabled"))
		Expect(c.Get(ctx, types.NamespacedName{Name: "default"}, &v3.FelixConfiguration{})).To(HaveOccurred())
	})

	It("should leave the v3 metadata stash in place", func() {
		Expect(c.Create(ctx, &v3.FelixConfiguration{ObjectMeta: metav1.ObjectMeta{
			Name:        "default",
			Annotations: map[string]string{"projectcalico.org/metadata": `{"annotations":{"team":"networking"}}`},
		}})).NotTo(HaveOccurred())

		_, err := utils.PatchFelixConfiguration(ctx, c, func(fc *v3.FelixConfiguration) (bool, error) {
			fc.Spec.BPFEnabled = ptr.To(true)
			return true, nil
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(getFelixConfig().Annotations).To(HaveKey("projectcalico.org/metadata"))
	})
})
