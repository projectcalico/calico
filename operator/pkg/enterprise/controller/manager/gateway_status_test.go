// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package manager

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("managerDomainHost",
	func(input, expected string) {
		Expect(managerDomainHost(input)).To(Equal(expected))
	},
	Entry("bare host", "manager.example.com", "manager.example.com"),
	Entry("https scheme", "https://manager.example.com", "manager.example.com"),
	Entry("http scheme", "http://manager.example.com", "manager.example.com"),
	Entry("explicit default port", "https://manager.example.com:443", "manager.example.com"),
	Entry("non-default port", "manager.example.com:9443", "manager.example.com"),
	Entry("scheme and port", "https://manager.example.com:9443", "manager.example.com"),
	Entry("bare IPv6 without port", "2001:db8::1", "2001:db8::1"),
	Entry("bracketed IPv6 with port", "[2001:db8::1]:443", "2001:db8::1"),
)
