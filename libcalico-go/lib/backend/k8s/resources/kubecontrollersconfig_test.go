// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package resources

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

var _ = Describe("k8s sync label validation tests", func() {
	client := NewKubeControllersConfigClient(nil, nil).(*customK8sResourceClient)
	It("should accept enabled sync labels", func() {
		res := &apiv3.KubeControllersConfiguration{
			Spec: apiv3.KubeControllersConfigurationSpec{
				Controllers: apiv3.ControllersConfig{
					Node: &apiv3.NodeControllerConfig{
						SyncLabels: apiv3.Enabled,
					},
				},
			},
		}
		err := client.validator.Validate(res)
		Expect(err).To(BeNil())
	})

	It("should not accept disabled sync labels", func() {
		res := &apiv3.KubeControllersConfiguration{
			Spec: apiv3.KubeControllersConfigurationSpec{
				Controllers: apiv3.ControllersConfig{
					Node: &apiv3.NodeControllerConfig{
						SyncLabels: apiv3.Disabled,
					},
				},
			},
		}
		err := client.validator.Validate(res)
		Expect(err).To(HaveOccurred())
	})
})
