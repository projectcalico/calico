// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package render_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/render"
	rtest "github.com/projectcalico/calico/operator/pkg/render/common/test"
)

var _ = Describe("Setup rendering tests", func() {
	var cfg *render.SetUpConfiguration
	BeforeEach(func() {
		cfg = &render.SetUpConfiguration{
			Installation:    &operatorv1.InstallationSpec{KubernetesProvider: operatorv1.ProviderNone},
			Namespace:       "test-namespace",
			PSS:             render.PSSRestricted,
			CreateNamespace: true,
		}
	})

	renderNamespace := func() *corev1.Namespace {
		resources, _ := render.NewSetup(cfg).Objects()
		return rtest.GetResource(resources, "test-namespace", "", "", "v1", "Namespace").(*corev1.Namespace)
	}

	It("should label the namespace with the configured pod security standard", func() {
		namespace := renderNamespace()

		Expect(namespace.Labels).To(HaveKeyWithValue("pod-security.kubernetes.io/enforce", "restricted"))
		Expect(namespace.Labels).To(HaveKeyWithValue("pod-security.kubernetes.io/enforce-version", "latest"))
	})

	It("should not set pod security labels when PodSecurityLabels is Disabled", func() {
		cfg.Installation.PodSecurityLabels = ptr.To(operatorv1.PodSecurityLabelsDisabled)
		namespace := renderNamespace()

		Expect(namespace.Labels).To(HaveKeyWithValue("name", "test-namespace"))
		Expect(namespace.Labels).NotTo(HaveKey("pod-security.kubernetes.io/enforce"))
		Expect(namespace.Labels).NotTo(HaveKey("pod-security.kubernetes.io/enforce-version"))
	})
})
