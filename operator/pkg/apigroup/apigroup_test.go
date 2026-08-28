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

package apigroup

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("apigroup", func() {
	It("should default to Unknown with nil env vars", func() {
		Set(Unknown)
		Expect(Get()).To(Equal(Unknown))
		Expect(EnvVars()).To(BeNil())
	})

	It("should return CALICO_API_GROUP env var when set to V3", func() {
		Set(V3)
		Expect(Get()).To(Equal(V3))
		Expect(EnvVars()).To(Equal([]corev1.EnvVar{
			{Name: "CALICO_API_GROUP", Value: "projectcalico.org/v3"},
		}))
	})

	It("should return nil env vars when set to V1", func() {
		Set(V1)
		Expect(Get()).To(Equal(V1))
		Expect(EnvVars()).To(BeNil())
	})

	It("should clear env vars when set back to Unknown", func() {
		Set(V3)
		Set(Unknown)
		Expect(Get()).To(Equal(Unknown))
		Expect(EnvVars()).To(BeNil())
	})
})
