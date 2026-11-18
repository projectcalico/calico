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

package policy

import (
	"context"
	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
)

// DESCRIPTION: Temporary canary that always fails.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithCategory(describe.Policy),
	"Sandcat canary",
	func() {
		f := utils.NewDefaultFramework("sandcat-canary")

		framework.ConformanceIt("reads the canary config map value", func() {
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "canary"},
				Data:       map[string]string{"value": "actual"},
			}
			_, err := f.ClientSet.CoreV1().ConfigMaps(f.Namespace.Name).Create(context.Background(), cm, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			got, err := f.ClientSet.CoreV1().ConfigMaps(f.Namespace.Name).Get(context.Background(), "canary", metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(got.Data["value"]).To(Equal("expected"))
		})
	},
)
