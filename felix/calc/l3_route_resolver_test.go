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

package calc

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/ip"
)

var _ = Describe("L3RouteResolver", func() {
	Describe("l3rrNodeInfo", func() {
		It("should not return empty IP addresses in AddressesAsCIDRs()", func() {
			var (
				emptyV4Addr ip.V4Addr
				emptyV6Addr ip.V6Addr
			)
			info := l3rrNodeInfo{
				V4Addr: emptyV4Addr,
				V6Addr: emptyV6Addr,
			}
			Expect(info.AddressesAsCIDRs()).To(Equal([]ip.CIDR{}))
		})
	})
})
