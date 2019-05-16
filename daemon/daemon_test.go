// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package daemon

import (
	"k8s.io/api/core/v1"

	"github.com/projectcalico/felix/config"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Typha address discovery", func() {

	getKubernetesService := func(namespace, name string) (*v1.Service, error) {
		return &v1.Service{
			Spec: v1.ServiceSpec{
				ClusterIP: "fd5f:65af::2",
				Ports: []v1.ServicePort{
					v1.ServicePort{
						Name: "calico-typha",
						Port: 8156,
					},
				},
			},
		}, nil
	}

	It("should bracket an IPv6 Typha address", func() {
		configParams := config.New()
		configParams.UpdateFrom(map[string]string{
			"TyphaK8sServiceName": "calico-typha",
		}, config.EnvironmentVariable)
		typhaAddr, err := discoverTyphaAddr(configParams, getKubernetesService)
		Expect(err).NotTo(HaveOccurred())
		Expect(typhaAddr).To(Equal("[fd5f:65af::2]:8156"))
	})
})
