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

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/enterprise"
)

var _ = Describe("Controllers", func() {
	DescribeTable("contributes the Enterprise-only controllers",
		func(variant operatorv1.ProductVariant) {
			names := []string{}
			for _, c := range enterprise.Controllers(variant) {
				Expect(c.Add).NotTo(BeNil())
				names = append(names, c.Name)
			}
			Expect(names).To(ContainElement("Monitor"))
		},
		Entry("CalicoEnterprise", operatorv1.CalicoEnterprise),
		//nolint:staticcheck // SA1019: the deprecated spelling is what this covers
		Entry("TigeraSecureEnterprise", operatorv1.TigeraSecureEnterprise),
	)

	It("contributes nothing for Calico", func() {
		Expect(enterprise.Controllers(operatorv1.Calico)).To(BeEmpty())
	})
})
