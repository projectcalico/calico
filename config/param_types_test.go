// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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
	. "github.com/projectcalico/felix/go/felix/config"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("Endpoint list parameter parsing",
	func(raw string, expected interface{}) {
		p := EndpointListParam{Metadata{
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
