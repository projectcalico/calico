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
		Expect(resources.IPToResourceName(net.MustParseIP("11.223.3.41"))).To(Equal("11-223-3-441"))
	})
	It("should convert an IPv6 address to a resource compatible name", func() {
		Expect(resources.IPToResourceName(net.MustParseIP("AA:1234::BBee:CC"))).To(Equal("aa-1234--bbee-cc"))
	})
	It("should convert an IPv4 Network to a resource compatible name", func() {
		Expect(resources.IPNetToResourceName(net.MustParseNetwork("11.223.3.41/43"))).To(Equal("11-223-3-41-43"))
	})
	It("should convert an IPv4 Network to a resource compatible name", func() {
		Expect(resources.IPNetToResourceName(net.MustParseNetwork("11.223.3.41"))).To(Equal("11-223-3-41-32"))
	})
	It("should convert an IPv6 Network to a resource compatible name", func() {
		Expect(resources.IPNetToResourceName(net.MustParseNetwork("AA:1234::BBee:CC/2"))).To(Equal("aa-1234--bbee-cc-2"))
	})
	It("should convert an IPv6 Network to a resource compatible name", func() {
		Expect(resources.IPNetToResourceName(net.MustParseNetwork("AA:1234:BBee::/120"))).To(Equal("aa-1234-bbee---120"))
	})
	It("should convert an IPv6 Network to a resource compatible name", func() {
		Expect(resources.IPNetToResourceName(net.MustParseNetwork("AA:1234:BBee::0000"))).To(Equal("aa-1234-bbee--0000-128"))
	})

	It("should convert a resource name to the equivalent IPv4 address", func() {
		Expect(resources.ResourceNameToIP("11-223-3-441")).To(Equal(net.MustParseIP("11.223.3.41")))
	})
	It("should convert a resource name to the equivalent IPv6 address", func() {
		Expect(resources.ResourceNameToIP("aa-1234--bbee-cc")).To(Equal(net.MustParseIP("AA:1234::BBee:CC")))
	})
	It("should convert a resource name to the equivalent IPv4 Network", func() {
		Expect(resources.ResourceNameToIPNet("11-223-3-41-43")).To(Equal(net.MustParseNetwork("11.223.3.41/43")))
	})
	It("should convert a resource name to the equivalent IPv4 Network", func() {
		Expect(resources.ResourceNameToIPNet("11-223-3-41-32")).To(Equal(net.MustParseNetwork("11.223.3.41")))
	})
	It("should convert a resource name to the equivalent IPv6 Network", func() {
		Expect(resources.ResourceNameToIPNet("aa-1234--bbee-cc-2")).To(Equal(net.MustParseNetwork("AA:1234::BBee:CC/2")))
	})
	It("should convert a resource name to the equivalent IPv6 Network", func() {
		Expect(resources.ResourceNameToIPNet("aa-1234-bbee---120")).To(Equal(net.MustParseNetwork("AA:1234:BBee::/120")))
	})
	It("should convert a resource name to the equivalent IPv6 Network", func() {
		Expect(resources.ResourceNameToIPNet("aa-1234-bbee--0000-128")).To(Equal(net.MustParseNetwork("AA:1234:BBee::0000")))
	})
})
