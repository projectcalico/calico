// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package nodeinit

import (
	"net"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("Parse comma-separated IP:port addresses",
	func(addr string, expectedIPPorts []IPPort, errorExpected bool) {
		ipPorts, err := parseCommaSeparatedIPPorts(addr)
		Expect(err != nil).To(Equal(errorExpected))
		Expect(ipPorts).To(Equal(expectedIPPorts))
	},
	Entry("Parsing empty string", "", nil, true),
	Entry("Parsing a single IPv4:Port string", "1.1.1.1:443", []IPPort{{net.ParseIP("1.1.1.1"), 443, true}}, false),
	Entry("Parsing a single IPv6:Port string", "[2001:db8::1]:6443", []IPPort{{net.ParseIP("2001:db8::1"), 6443, false}}, false),
	Entry("Parsing multiple IP:Port strings",
		"192.168.0.1:6443,[2001:db8::1]:6443",
		[]IPPort{
			{net.ParseIP("192.168.0.1"), 6443, true},
			{net.ParseIP("2001:db8::1"), 6443, false},
		},
		false),
	Entry("Parsing invalid port", "1.1.1.1:port", nil, true),
	Entry("Parsing invalid IP", "1.1.1:80", nil, true),
	Entry("Parsing invalid address", "made-up-addr", nil, true),
	Entry("Parsing invalid string - ending with comma", "[2001:db8::1]:443,", nil, true),
	Entry("Parsing invalid string - starting with comma", ",[2001:db8::1]:443", nil, true),
)
