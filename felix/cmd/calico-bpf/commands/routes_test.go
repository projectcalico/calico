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

package commands

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/ip"
)

// 10.65.0.1/32: local host
// 127.0.0.1/32: local host
// 172.17.0.6/32: local host
// 10.65.1.0/26: remote workload, host IP 172.17.0.7
// 10.65.0.2/32: local host
// 10.65.0.3/32: local host
// 172.17.0.7/32: local host

func TestSortCIDRs(t *testing.T) {
	RegisterTestingT(t)
	cidrs := []ip.CIDR{
		ip.MustParseCIDROrIP("100.65.0.1/32"),
		ip.MustParseCIDROrIP("10.65.0.1/32"),
		ip.MustParseCIDROrIP("127.0.0.1/32"),
		ip.MustParseCIDROrIP("172.17.0.6/32"),
		ip.MustParseCIDROrIP("10.65.1.0/26"),
		ip.MustParseCIDROrIP("10.65.0.2/32"),
		ip.MustParseCIDROrIP("10.65.0.3/32"),
		ip.MustParseCIDROrIP("172.17.0.7/32"),
	}
	sortCIDRs(cidrs)
	expectedResult := []ip.CIDR{
		ip.MustParseCIDROrIP("10.65.0.1/32"),
		ip.MustParseCIDROrIP("10.65.0.2/32"),
		ip.MustParseCIDROrIP("10.65.0.3/32"),
		ip.MustParseCIDROrIP("10.65.1.0/26"),
		ip.MustParseCIDROrIP("100.65.0.1/32"),
		ip.MustParseCIDROrIP("127.0.0.1/32"),
		ip.MustParseCIDROrIP("172.17.0.6/32"),
		ip.MustParseCIDROrIP("172.17.0.7/32"),
	}
	Expect(cidrs).To(Equal(expectedResult))
}

func TestSortCIDRsAlreadySorted(t *testing.T) {
	RegisterTestingT(t)
	cidrs := []ip.CIDR{
		ip.MustParseCIDROrIP("10.65.0.1/32"),
		ip.MustParseCIDROrIP("10.65.0.2/32"),
		ip.MustParseCIDROrIP("10.65.0.3/32"),
		ip.MustParseCIDROrIP("10.65.1.0/26"),
		ip.MustParseCIDROrIP("127.0.0.1/32"),
		ip.MustParseCIDROrIP("172.17.0.6/32"),
		ip.MustParseCIDROrIP("172.17.0.7/32"),
	}
	sortCIDRs(cidrs)
	expectedResult := []ip.CIDR{
		ip.MustParseCIDROrIP("10.65.0.1/32"),
		ip.MustParseCIDROrIP("10.65.0.2/32"),
		ip.MustParseCIDROrIP("10.65.0.3/32"),
		ip.MustParseCIDROrIP("10.65.1.0/26"),
		ip.MustParseCIDROrIP("127.0.0.1/32"),
		ip.MustParseCIDROrIP("172.17.0.6/32"),
		ip.MustParseCIDROrIP("172.17.0.7/32"),
	}
	Expect(cidrs).To(Equal(expectedResult))
}
