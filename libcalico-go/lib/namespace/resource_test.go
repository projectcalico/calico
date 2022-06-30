// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package namespace_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/namespace"
)

var _ = Describe("lib/namespace tests", func() {
	DescribeTable("Namespaced resources",
		func(kind string, isNamespaced bool) {
			Expect(namespace.IsNamespaced(kind)).To(Equal(isNamespaced))
		},

		Entry(namespace.KindKubernetesNetworkPolicy, namespace.KindKubernetesNetworkPolicy, true),
		Entry(namespace.KindKubernetesService, namespace.KindKubernetesService, true),
		Entry(namespace.KindKubernetesEndpointSlice, namespace.KindKubernetesEndpointSlice, true),
		Entry("BGPConfiguration", "BGPConfiguration", false),
	)
})
