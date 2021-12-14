// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
//
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

package calc_test

import (
	. "github.com/projectcalico/calico/felix/calc"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var (
	tenPointFive = 10.5
)

var _ = DescribeTable("PolKV should stringify correctly",
	func(kv PolKV, expected string) {
		Expect(kv.String()).To(Equal(expected))
	},
	Entry("zero", PolKV{}, "(nil policy)"),
	Entry("nil policy", PolKV{Key: model.PolicyKey{Name: "name"}}, "name(nil policy)"),
	Entry("nil order",
		PolKV{Key: model.PolicyKey{Name: "name"}, Value: &model.Policy{}}, "name(default)"),
	Entry("order set",
		PolKV{Key: model.PolicyKey{Name: "name"}, Value: &model.Policy{Order: &tenPointFive}},
		"name(10.5)"),
)
