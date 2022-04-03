// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

package config_test

import (
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/calico/felix/config"
	"net"
)

var _ = DescribeTable("Endpoint list parameter parsing",
	func(raw string, expected interface{}) {
		p := config.EndpointListParam{config.Metadata{
			Name: "Endpoints",
		}}
		actual, err := p.Parse(raw)
		Expect(err).To(BeNil())
		Expect(actual).To(Equal(expected))
	},
	Entry("Empty", "", []string{}),
	Entry("Single URL", "http://10.0.0.1:1234/", []string{"http://10.0.0.1:1234/"}),
	Entry("No slash", "http://10.0.0.1:1234", []string{"http://10.0.0.1:1234/"}),
	Entry("Two URLs", "http://etcd:1234,http://etcd2:2345",
		[]string{"http://etcd:1234/", "http://etcd2:2345/"}),
	Entry("Two URLs extra commas", ",http://etcd:1234,,http://etcd2:2345,",
		[]string{"http://etcd:1234/", "http://etcd2:2345/"}),
)

var _ = DescribeTable("CIDR list parameter parsing",
	func(raw string, expected interface{}, expectSuccess bool) {
		p := config.CIDRListParam{config.Metadata{
			Name: "CIDRs",
		}}
		actual, err := p.Parse(raw)
		if expectSuccess {
			Expect(err).To(BeNil())
			Expect(actual).To(Equal(expected))
		} else {
			Expect(err).NotTo(BeNil())
		}
	},
	Entry("Empty", "", []string{}, true),
	Entry("Single IPv4", "1.1.1.1", []string{"1.1.1.1/32"}, true),
	Entry("Single CIDR", "1.1.1.1/32", []string{"1.1.1.1/32"}, true),
	Entry("Single CIDR subnet", "1.1.1.1/24", []string{"1.1.1.0/24"}, true),
	Entry("Mix of IP and CIDRs", "1.1.1.1/24, 2.2.2.2", []string{"1.1.1.0/24", "2.2.2.2/32"}, true),
	Entry("Reject IPv6", "aabc::1111/32", []string{}, false),
)

var _ = DescribeTable("KeyValue list parameter parsing",
	func(raw string, expected map[string]string) {
		p := config.KeyValueListParam{config.Metadata{
			Name: "FeatureOverride",
		}}
		actual, err := p.Parse(raw)
		if expected == nil {
			Expect(err).NotTo(BeNil())
		} else {
			Expect(err).To(BeNil())
			Expect(actual).To(Equal(expected))
		}
	},
	Entry("Empty", "  ", map[string]string{}),
	Entry("Single value", "key=value", map[string]string{
		"key": "value",
	}),
	Entry("Malformed", "key=value,malformed", nil),
	Entry("Spaces", "  key=value,  v2= x ,,,,", map[string]string{
		"key": "value",
		"v2":  " x ",
	}),
)

var _ = DescribeTable("IPv4 list parameter parsing",
	func(raw string, expected string, expectSuccess bool) {
		p := config.Ipv4Param{config.Metadata{
			Name: "IPv4",
		}}
		actual, err := p.Parse(raw)
		if expectSuccess {
			Expect(err).To(BeNil())
			ipStr := actual.(net.IP)
			Expect(ipStr.String()).To(Equal(expected))
		} else {
			Expect(err).NotTo(BeNil())
		}
	},

	Entry("Empty", " ", "", false),
	Entry("IPv4 address", "10.1.1.2", "10.1.1.2", true),
	Entry("IPv6 address", "aabc::1111", "", false),
)

var _ = DescribeTable("IPv6 list parameter parsing",
	func(raw string, expected string, expectSuccess bool) {
		p := config.Ipv6Param{config.Metadata{
			Name: "IPv6",
		}}
		actual, err := p.Parse(raw)
		if expectSuccess {
			Expect(err).To(BeNil())
			ipStr := actual.(net.IP)
			Expect(ipStr.String()).To(Equal(expected))
		} else {
			Expect(err).NotTo(BeNil())
		}
	},

	Entry("Empty", " ", "", false),
	Entry("IPv4 address", "10.1.1.2", "", false),
	Entry("IPv6 address", "aabc::1111", "aabc::1111", true),
)
