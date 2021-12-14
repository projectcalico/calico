// Copyright (c) 2016-2020 Tigera, Inc. All rights reserved.

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

package k8s

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"k8s.io/client-go/tools/clientcmd"
)

var _ = Describe("CreateKubernetesClientset fillLoadingRulesFromKubeConfigSpec", func() {

	When("There are multiple Kubeconfig files specified", func() {
		It("Should fill Precedence instead of ExplicitPath", func() {
			loadingRules := clientcmd.ClientConfigLoadingRules{}
			fillLoadingRulesFromKubeConfigSpec(&loadingRules, "filename1:filename2")

			Expect(loadingRules.ExplicitPath).To(BeEmpty())
			Expect(loadingRules.Precedence).To(BeEquivalentTo([]string{"filename1", "filename2"}))
		})
	})

	When("Only a single Kubeconfig file specified", func() {
		It("Should keep filling ExplicitPath field only", func() {
			loadingRules := clientcmd.ClientConfigLoadingRules{}
			fillLoadingRulesFromKubeConfigSpec(&loadingRules, "filename1")

			Expect(loadingRules.ExplicitPath).To(BeEquivalentTo("filename1"))
			Expect(loadingRules.Precedence).To(BeEmpty())
		})
	})

})
