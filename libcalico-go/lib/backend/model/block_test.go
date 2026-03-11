// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package model_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

func mustParseCIDR(s string) net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return *ipNet
}

var _ = Describe("AllocationBlock tests", func() {
	It("should calculate non-affine allocations correctly", func() {
		affinity := "host:myhost"
		block := model.AllocationBlock{
			CIDR: mustParseCIDR("10.0.1.0/29"),
			Allocations: []*int{
				intPtr(1), /* other host */
				intPtr(0), /* same host should be skipped */
				intPtr(2), /* another host */
				intPtr(3), /* missing attrs should be skipped */
				nil,
				nil,
				nil,
				intPtr(2), /* alias of another host */
			},
			Affinity: &affinity,
			Attributes: []model.AllocationAttribute{
				{ActiveOwnerAttrs: map[string]string{"node": "myhost"}},
				{ActiveOwnerAttrs: map[string]string{"node": "otherhost"}},
				{ActiveOwnerAttrs: map[string]string{"node": "anotherhost"}},
			},
		}

		Expect(block.NonAffineAllocations()).To(ConsistOf(
			model.Allocation{Host: "otherhost", Addr: *net.ParseIP("10.0.1.0")},
			model.Allocation{Host: "anotherhost", Addr: *net.ParseIP("10.0.1.2")},
			model.Allocation{Host: "anotherhost", Addr: *net.ParseIP("10.0.1.7")},
		))
	})

	DescribeTable("CIDR table tests",
		func(cidr string, expectedNumIPs int) {
			block := model.AllocationBlock{
				CIDR: mustParseCIDR(cidr),
			}
			Expect(block.NumAddresses()).To(Equal(expectedNumIPs))
		},
		Entry("10.0.0.0/16", "10.0.0.0/16", 65536),
		Entry("10.0.0.0/32", "10.0.0.0/32", 1),
	)

	DescribeTable("ordinal arithmetic tests",
		func(cidr string, ordinal int, expectedAddr string) {
			block := model.AllocationBlock{
				CIDR: mustParseCIDR(cidr),
			}
			ip := block.OrdinalToIP(ordinal)
			Expect(ip.String()).To(Equal(expectedAddr))
			Expect(block.IPToOrdinal(ip)).To(Equal(ordinal))
		},
		Entry("10.0.0.0/30 0", "10.0.0.0/30", 0, "10.0.0.0"),
		Entry("10.0.0.0/30 1", "10.0.0.0/30", 1, "10.0.0.1"),
		Entry("10.0.0.0/30 2", "10.0.0.0/30", 2, "10.0.0.2"),
		Entry("10.0.0.0/30 3", "10.0.0.0/30", 3, "10.0.0.3"),

		Entry("10.0.0.64/30 0", "10.0.0.64/30", 0, "10.0.0.64"),
		Entry("10.0.0.64/30 1", "10.0.0.64/30", 1, "10.0.0.65"),
		Entry("10.0.0.64/30 2", "10.0.0.64/30", 2, "10.0.0.66"),
		Entry("10.0.0.64/30 3", "10.0.0.64/30", 3, "10.0.0.67"),

		Entry("10.0.0.64/32 3", "10.0.0.64/32", 0, "10.0.0.64"),

		Entry("10.0.128.0/17 0", "10.0.128.0/17", 0, "10.0.128.0"),
		Entry("10.0.128.0/17 256", "10.0.128.0/17", 256, "10.0.129.0"),
		Entry("10.0.128.0/17 257", "10.0.128.0/17", 257, "10.0.129.1"),
	)
})

func intPtr(i int) *int {
	return &i
}
