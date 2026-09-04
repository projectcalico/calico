// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package ippool

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("kubeadm pod-network-cidr detection", func() {
	It("should parse podSubnet if it exists", func() {
		data := `
networking:
  dnsDomain: cluster.local
  podSubnet: 192.168.0.0/16
  serviceSubnet: 10.96.0.0/12`
		cidr, err := extractKubeadmCIDRs(&corev1.ConfigMap{
			Data: map[string]string{
				"ClusterConfiguration": data,
			},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(cidr).To(Equal([]string{"192.168.0.0/16"}))
	})

	It("should error if podSubnet is missing", func() {
		data := `
networking:
  dnsDomain: cluster.local
  serviceSubnet: 10.96.0.0/12`
		_, err := extractKubeadmCIDRs(&corev1.ConfigMap{
			Data: map[string]string{
				"ClusterConfiguration": data,
			},
		})
		Expect(err).To(HaveOccurred())
	})
})
