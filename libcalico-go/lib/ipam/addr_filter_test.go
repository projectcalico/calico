// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package ipam

import (
	"fmt"
	"strings"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

var cidrFilterTests = []struct {
	FilterCIDRs  []string
	IPsMatch     []string
	CIDRsMatch   []string
	IPsNoMatch   []string
	CIDRsNoMatch []string
}{
	{
		FilterCIDRs: []string{"0.0.0.0/0"},
		IPsMatch:    []string{"0.0.0.0", "255.255.255.255", "10.0.0.1"},
		CIDRsMatch:  []string{"0.0.0.0/0", "255.255.255.255/32", "10.0.0.0/8"},
	},
	{
		FilterCIDRs: []string{"::/0"},
		IPsMatch:    []string{"::", "ffff::", "cafe:f00d::"},
		CIDRsMatch:  []string{"::/0", "ffff::/32", "cafe:f00d::/96"},
	},
	{
		FilterCIDRs:  []string{"192.168.1.64/26", "192.168.1.0/26"},
		IPsMatch:     []string{"192.168.1.0", "192.168.1.63", "192.168.1.64", "192.168.1.127"},
		CIDRsMatch:   []string{"192.168.1.64/26", "192.168.1.0/26", "192.168.1.0/25", "192.168.1.64/27", "192.168.1.96/27"},
		IPsNoMatch:   []string{"10.0.0.1", "0.0.0.0"},
		CIDRsNoMatch: []string{"10.0.0.0/8", "0.0.0.0/32", "192.168.2.64/26", "192.168.1.0/24"},
	},
}

func TestCIDRSliceFilter_Matches(t *testing.T) {
	for _, test := range cidrFilterTests {
		test := test
		t.Run(fmt.Sprintf("filter_%s", strings.Join(test.FilterCIDRs, ",")), func(t *testing.T) {
			var filter cidrSliceFilter
			for _, cidr := range test.FilterCIDRs {
				filter = append(filter, net.MustParseCIDR(cidr))
			}
			for _, ip := range test.IPsMatch {
				t.Run(fmt.Sprintf("should match IP %s", ip), func(t *testing.T) {
					RegisterTestingT(t)
					Expect(filter.MatchesIP(net.MustParseIP(ip))).To(BeTrue())
				})
			}
			for _, ip := range test.IPsNoMatch {
				t.Run(fmt.Sprintf("should not match IP %s", ip), func(t *testing.T) {
					RegisterTestingT(t)
					Expect(filter.MatchesIP(net.MustParseIP(ip))).To(BeFalse())
				})
			}
			for _, cidrStr := range test.CIDRsMatch {
				t.Run(fmt.Sprintf("should match CIDR %s", cidrStr), func(t *testing.T) {
					RegisterTestingT(t)
					cidr := net.MustParseCIDR(cidrStr)
					Expect(filter.MatchesWholeCIDR(&cidr)).To(BeTrue())
				})
			}
			for _, cidrStr := range test.CIDRsNoMatch {
				t.Run(fmt.Sprintf("should not match CIDR %s", cidrStr), func(t *testing.T) {
					RegisterTestingT(t)
					cidr := net.MustParseCIDR(cidrStr)
					Expect(filter.MatchesWholeCIDR(&cidr)).To(BeFalse())
				})
			}
		})
	}
}

func TestCIDRSliceFilter_filterOutDuplicates(t *testing.T) {
	for _, test := range []struct {
		CIDRs    []string
		Expected []string
	}{
		{
			CIDRs:    nil,
			Expected: nil,
		},
		{
			CIDRs:    []string{"0.0.0.0/0", "10.0.0.0/8"},
			Expected: []string{"0.0.0.0/0"},
		},
		{
			CIDRs:    []string{"::/0", "f0f0::/16"},
			Expected: []string{"::/0"},
		},
		{
			CIDRs:    []string{"10.0.0.0/24", "10.0.0.0/25", "10.0.0.128/25", "11.0.0.0/8"},
			Expected: []string{"10.0.0.0/24", "11.0.0.0/8"},
		},
		{
			CIDRs:    []string{"10.0.0.0/24", "10.0.0.0/25", "10.0.0.128/25", "11.0.0.0/24"},
			Expected: []string{"10.0.0.0/24", "11.0.0.0/24"},
		},
		{
			CIDRs:    []string{"10.0.0.0/24", "10.0.0.0/25", "11.0.0.0/25", "10.0.0.0/25", "10.0.0.128/25", "11.0.0.0/8"},
			Expected: []string{"10.0.0.0/24", "11.0.0.0/8"},
		},
	} {
		test := test
		t.Run(fmt.Sprintf("filterOutDuplicates_%s", strings.Join(test.CIDRs, ",")), func(t *testing.T) {
			RegisterTestingT(t)
			var filter cidrSliceFilter
			for _, cidr := range test.CIDRs {
				filter = append(filter, net.MustParseCIDR(cidr))
			}
			output := filter.filterOutDuplicates()
			var expected cidrSliceFilter
			for _, cidrStr := range test.Expected {
				expected = append(expected, net.MustParseCIDR(cidrStr))
			}
			Expect(output).To(Equal(expected))
			output = output.filterOutDuplicates()
			Expect(output).To(Equal(expected), "expected idempotency")
		})
	}
}
