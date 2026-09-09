// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

package common

import (
	"os"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("Operator ServiceAccount name tests", func() {
	ginkgo.It("should read service account name from the environment variable once", func() {
		gomega.Expect(os.Setenv("OPERATOR_SERVICEACCOUNT", "tigera-operator-env-var")).NotTo(gomega.HaveOccurred())
		gomega.Expect(OperatorServiceAccount()).To(gomega.Equal("tigera-operator-env-var"))
		gomega.Expect(os.Unsetenv("OPERATOR_SERVICEACCOUNT")).NotTo(gomega.HaveOccurred())
		gomega.Expect(os.Setenv("OPERATOR_SERVICEACCOUNT", "other-value")).NotTo(gomega.HaveOccurred())
		gomega.Expect(OperatorServiceAccount()).To(gomega.Equal("tigera-operator-env-var"))
	})
})
