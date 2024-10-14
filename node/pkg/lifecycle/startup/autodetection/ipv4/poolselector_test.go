//go:build linux

// Copyright (c) 2020 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package ipv4

import (
	"errors"
	"fmt"
	"net"
	"testing"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func init() {
	testutils.HookLogrusForGinkgo()
}

func TestCommands(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../../../report/autodetection_ipv4_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "IPv4 pool selector Suite", []Reporter{junitReporter})
}

var _ = Describe("IPv4 pool selector tests", func() {
	Describe("Pool selector tests", func() {
		It("select default because not overlapping", func() {
			actualNet := parseCIDR("192.168.0.0/16")
			hostAddresses := []net.IPNet{parseCIDR("192.169.64.2/24")}

			selected := findAvailableCIDR(&actualNet, hostAddresses)

			Expect(*selected).To(Equal(parseCIDR("192.168.0.0/16")))
		})

		It("select first from range because it is overlapping", func() {
			actualNet := parseCIDR("192.168.0.0/16")
			hostAddresses := []net.IPNet{parseCIDR("192.168.64.2/24")}

			selected := findAvailableCIDR(&actualNet, hostAddresses)

			Expect(*selected).To(Equal(parseCIDR("172.16.0.0/16")))
		})

		It("select second from range because it is overlapping", func() {
			actualNet := parseCIDR("192.168.0.0/16")
			hostAddresses := []net.IPNet{parseCIDR("192.168.64.2/24"), parseCIDR("172.16.0.1/16")}

			selected := findAvailableCIDR(&actualNet, hostAddresses)

			Expect(*selected).To(Equal(parseCIDR("172.17.0.0/16")))
		})

		It("should fail because all are overlapping", func() {
			actualNet := parseCIDR("192.168.0.0/16")
			hostAddresses := []net.IPNet{parseCIDR("192.168.64.2/24")}
			for i := FALLBACK_IPPOOL_MIN; i <= FALLBACK_IPPOOL_MAX; i++ {
				hostAddresses = append(hostAddresses, parseCIDR(fmt.Sprintf(FALLBACK_IPPOOL_TEMPLATE, i)))
			}

			selected := findAvailableCIDR(&actualNet, hostAddresses)

			Expect(*selected).To(Equal(actualNet))
		})
	})

	Describe("Get default IPv4 pool tests", func() {
		var originalRetriever func(netlink.Link, int) ([]netlink.Addr, error)

		BeforeEach(func() {
			originalRetriever = hostIPAddressRetriever
		})

		AfterEach(func() {
			hostIPAddressRetriever = originalRetriever
		})

		It("unable to retrieve host addresses", func() {
			hostIPAddressRetriever = func(netlink.Link, int) ([]netlink.Addr, error) {
				return []netlink.Addr{}, errors.New("fatal error")
			}
			_, preferredPool, _ := net.ParseCIDR("192.168.0.0/16")

			_, err := GetDefaultIPv4Pool(preferredPool)

			Expect(err).NotTo(BeNil())
		})

		It("select first from range because it is overlapping", func() {
			hostIPAddressRetriever = func(netlink.Link, int) ([]netlink.Addr, error) {
				net := parseCIDR("192.168.64.2/24")
				return []netlink.Addr{netlink.Addr{IPNet: &net}}, nil
			}
			_, preferredPool, _ := net.ParseCIDR("192.168.0.0/16")

			selected, _ := GetDefaultIPv4Pool(preferredPool)

			Expect(*selected).To(Equal(parseCIDR("172.16.0.0/16")))
		})
	})
})

func parseCIDR(s string) net.IPNet {
	_, n, _ := net.ParseCIDR(s)
	return *n
}
