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

package model_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var _ = Describe("BGP Filter key parsing", func() {
	key := (BGPFilterListOptions{}).KeyFromDefaultPath("/calico/bgp/v1/filters/filter-1")

	Expect(key).To(Equal(BGPFilterKey{Name: "filter-1"}))
	serialized, err := KeyToDefaultPath(BGPFilterKey{Name: "filter-1"})
	Expect(err).ToNot(HaveOccurred())
	Expect(serialized).To(Equal("/calico/bgp/v1/filters/filter-1"))
})
