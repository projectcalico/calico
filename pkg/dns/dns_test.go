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

package dns_test

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/tigera/operator/pkg/dns"
)

var _ = Describe("Common Tests", func() {
	Context("Get cluster domain", func() {

		It("Should have the right value for the alternative resolv.conf", func() {
			dir, err := os.Getwd()
			if err != nil {
				panic(err)
			}
			resolvConfPath := dir + "/testdata/resolv.conf"
			clusterDomain, err := dns.GetClusterDomain(resolvConfPath)
			Expect(clusterDomain).To(Equal("othername.local"))
			Expect(err).ToNot(HaveOccurred())
		})

		It("Should throw an error for a nonexisting file", func() {
			_, err := dns.GetClusterDomain("does-not.exist")
			Expect(err).To(HaveOccurred())
		})
	})

	Context("Get all DNS names for a service", func() {
		DescribeTable("Should return the correct services names", func(service, namespace, clusterDomain string, expectedDNSNames []string) {
			names := dns.GetServiceDNSNames(service, namespace, clusterDomain)
			Expect(names).To(ConsistOf(expectedDNSNames))
		},
			Entry("default", "a", "b", dns.DefaultClusterDomain, []string{"a", "a.b", "a.b.svc", "a.b.svc.cluster.local"}),
			Entry("default", "a", "b", "somedomain", []string{"a", "a.b", "a.b.svc", "a.b.svc.somedomain"}),
		)
	})
})
