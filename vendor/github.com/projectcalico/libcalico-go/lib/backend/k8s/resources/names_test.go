// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package resources_test

import (
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/libcalico-go/lib/net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Name conversion methods", func() {
	It("should convert an IPv4 address to a resource compatible name", func() {
		Expect(resources.IPToResourceName(net.MustParseIP("11.223.3.41"))).To(Equal("11-223-3-41"))
	})
	It("should convert a compressed IPv6 address to a resource compatible name", func() {
		Expect(resources.IPToResourceName(net.MustParseIP("AA:1234:BBee::"))).To(Equal("00aa-1234-bbee-0000-0000-0000-0000-0000"))
	})
	It("should convert a compressed IPv6 address to a resource compatible name", func() {
		Expect(resources.IPToResourceName(net.MustParseIP("::1234:BBee:CC"))).To(Equal("0000-0000-0000-0000-0000-1234-bbee-00cc"))
	})
	It("should convert a compressed IPv6 address to a resource compatible name", func() {
		Expect(resources.IPToResourceName(net.MustParseIP("AA:1234::BBee:CC"))).To(Equal("00aa-1234-0000-0000-0000-0000-bbee-00cc"))
	})
	It("should convert an IPv4 Network to a resource compatible name", func() {
		Expect(resources.IPNetToResourceName(net.MustParseNetwork("11.223.3.0/24"))).To(Equal("11-223-3-0-24"))
	})
	It("should convert an IPv4 Network to a resource compatible name", func() {
		Expect(resources.IPNetToResourceName(net.MustParseNetwork("11.223.3.41/32"))).To(Equal("11-223-3-41-32"))
	})
	It("should convert an IPv6 Network to a resource compatible name", func() {
		Expect(resources.IPNetToResourceName(net.MustParseNetwork("AA:1234::BBee:CC00/120"))).To(Equal("aa-1234--bbee-cc00-120"))
	})
	It("should convert an IPv6 Network to a resource compatible name", func() {
		Expect(resources.IPNetToResourceName(net.MustParseNetwork("AA:1234:BBee::/120"))).To(Equal("aa-1234-bbee---120"))
	})
	It("should convert an IPv6 Network to a resource compatible name", func() {
		Expect(resources.IPNetToResourceName(net.MustParseNetwork("aa:1234:bbee::/128"))).To(Equal("aa-1234-bbee---128"))
	})

	It("should convert a resource name to the equivalent IPv4 address", func() {
		i, err := resources.ResourceNameToIP("11-223-3-41")
		Expect(err).NotTo(HaveOccurred())
		Expect(*i).To(Equal(net.MustParseIP("11.223.3.41")))
	})
	It("should convert a resource name to the equivalent IPv6 address", func() {
		i, err := resources.ResourceNameToIP("aa-1234-0-0-0-0-bbee-cc")
		Expect(err).NotTo(HaveOccurred())
		Expect(*i).To(Equal(net.MustParseIP("AA:1234:0:0:0:0:BBee:CC")))
	})
	It("should not convert an invalid resource name to an IP address", func() {
		_, err := resources.ResourceNameToIP("aa-1234-0-0-0-0-bbee-cc-0-0")
		Expect(err).To(HaveOccurred())
	})
	It("should not convert an invalid resource name to an IP address", func() {
		_, err := resources.ResourceNameToIP("11-223-3-4a")
		Expect(err).To(HaveOccurred())
	})
	It("should convert a resource name to the equivalent IPv4 Network", func() {
		n, err := resources.ResourceNameToIPNet("11-223-3-128-25")
		Expect(err).NotTo(HaveOccurred())
		Expect(*n).To(Equal(net.MustParseNetwork("11.223.3.128/25")))
	})
	It("should convert a resource name to the equivalent IPv4 Network", func() {
		n, err := resources.ResourceNameToIPNet("11-223-3-41-32")
		Expect(err).NotTo(HaveOccurred())
		Expect(*n).To(Equal(net.MustParseNetwork("11.223.3.41/32")))
	})
	It("should convert a resource name to the equivalent IPv6 Network", func() {
		n, err := resources.ResourceNameToIPNet("aa-1234--bbee-cc-2")
		Expect(err).NotTo(HaveOccurred())
		Expect(*n).To(Equal(net.MustParseNetwork("AA:1234::BBee:CC/2")))
	})
	It("should convert a resource name to the equivalent IPv6 Network", func() {
		n, err := resources.ResourceNameToIPNet("aa-1234-bbee---120")
		Expect(err).NotTo(HaveOccurred())
		Expect(*n).To(Equal(net.MustParseNetwork("AA:1234:BBee::/120")))
	})
	It("should convert a resource name to the equivalent IPv6 Network", func() {
		n, err := resources.ResourceNameToIPNet("aa-1234-bbee---128")
		Expect(err).NotTo(HaveOccurred())
		Expect(*n).To(Equal(net.MustParseNetwork("AA:1234:BBee::/128")))
	})
	It("should not convert an invalid resource name to an IP network", func() {
		_, err := resources.ResourceNameToIPNet("11--223--3-41")
		Expect(err).To(HaveOccurred())
	})
})
