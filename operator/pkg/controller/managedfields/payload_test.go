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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/controller/managedfields"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
)

// spec.bpfLogLevel is the one FelixConfigurationSpec field with no omitempty, so it is what a
// payload built from the whole struct claims without meaning to.
var _ = Describe("Fields outside the declaration", func() {
	var c client.Client
	var ctx context.Context

	getFelixConfig := func() *v3.FelixConfiguration {
		fc := &v3.FelixConfiguration{}
		Expect(c.Get(ctx, types.NamespacedName{Name: "default"}, fc)).NotTo(HaveOccurred())
		return fc
	}

	// The fake's deduced type converter takes the field set from the typed object, so an applier
	// picks up fields with no omitempty that its payload never carried.  A real server does not.
	Context("with the API server tracking ownership", func() {
		var w *managedfields.FieldManager

		BeforeEach(func() {
			scheme := runtime.NewScheme()
			Expect(apis.AddToScheme(scheme, true)).NotTo(HaveOccurred())
			c = ctrlrfake.DefaultFakeClientBuilder(scheme).WithReturnManagedFields().Build()
			ctx = context.Background()
			w = managedfields.New(c)
		})

		It("should not take ownership of an undeclared field", func() {
			_, err := declare(managedfields.ConflictDefer, managedfields.ConflictDefer).Apply(ctx, w)
			Expect(err).NotTo(HaveOccurred())

			fc := getFelixConfig()
			Expect(fc.ManagedFields).To(HaveLen(1))
			Expect(fc.ManagedFields[0].Manager).To(Equal("operator.tigera.io/installation"))
			Expect(fc.ManagedFields[0].FieldsV1.GetRawString()).NotTo(ContainSubstring("bpfLogLevel"))
		})
	})
})
