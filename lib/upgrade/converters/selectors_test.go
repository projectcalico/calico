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

package converters

import (
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var selectorTable = []TableEntry{
	Entry("foo == 'bar'", "foo == 'bar'", "foo == 'bar'"),
	Entry("calico/k8s_ns == 'default'", "calico/k8s_ns == 'default'", "projectcalico.org/namespace == 'default'"),
	Entry("calico/k8s_ns in {'default'}", "calico/k8s_ns in {'default'}", "projectcalico.org/namespace in {'default'}"),
	Entry("has(calico/k8s_ns)", "has(calico/k8s_ns)", "has(projectcalico.org/namespace)"),
	Entry("has(calico/k8s_ns) || foo == 'bar'", "has(calico/k8s_ns) || foo == 'bar'", "has(projectcalico.org/namespace) || foo == 'bar'"),
}

var _ = DescribeTable("v1->v3 selector conversion tests",
	func(v1, v3 string) {
		Expect(convertSelector(v1)).To(Equal(v3), v1)
	},
	selectorTable...,
)
