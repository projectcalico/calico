// Copyright (c) 2017,2021 Tigera, Inc. All rights reserved.

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

package v3_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

var _ = Describe("RouteTableRanges", func() {
	It("should report the correct number of designated tables", func() {
		routeTableRanges := v3.RouteTableRanges{{Min: 1, Max: 100}}
		Expect(routeTableRanges.NumDesignatedTables()).To(BeEquivalentTo(100))
	})
})
