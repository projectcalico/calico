// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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

package tenancy

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/pkg/common"
)

var _ = Describe("Tenancy utility function tests", func() {
	Context("GetWatchNamespace", func() {
		It("should return expected values in single-tenant mode", func() {
			expectedInstallNS := "defaultNS"
			expectedTruthNS := common.OperatorNamespace()
			expectedWatchNamespaces := []string{expectedInstallNS, expectedTruthNS}
			installNS, truthNS, watchNamespaces := GetWatchNamespaces(false, expectedInstallNS)
			Expect(installNS).To(Equal(expectedInstallNS))
			Expect(truthNS).To(Equal(expectedTruthNS))
			Expect(watchNamespaces).To(Equal(expectedWatchNamespaces))
		})

		It("should return expected values in multi-tenant mode", func() {
			expectedInstallNS := ""
			expectedTruthNS := ""
			expectedWatchNamespaces := []string{""}
			installNS, truthNS, watchNamespaces := GetWatchNamespaces(false, "dontcare")
			Expect(installNS).To(Equal(expectedInstallNS))
			Expect(truthNS).To(Equal(expectedTruthNS))
			Expect(watchNamespaces).To(Equal(expectedWatchNamespaces))
		})
	})
})
