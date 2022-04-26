// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package stringutils_test

import (
	. "github.com/projectcalico/calico/felix/stringutils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("ParseKeyValueList tests",
	func(input string, expected map[string]string) {
		values, err := ParseKeyValueList(input)
		if expected == nil {
			// An error is expected
			Expect(err).NotTo(BeNil())
			Expect(values).To(BeNil())
		} else {
			Expect(err).To(BeNil())
			Expect(values).To(Equal(expected))
		}
	},
	Entry("Empty", "   ", map[string]string{}),
	Entry("Single value", "key=value", map[string]string{
		"key": "value",
	}),
	Entry("A faulty entry", "key=value, none", nil),
	Entry("An empty entry", "key=value, none=", map[string]string{
		"key":  "value",
		"none": "",
	}),
	Entry("Values with spaces", "key=   ,  v2= x ", map[string]string{
		"key": "   ",
		"v2":  " x ",
	}),
	Entry("Value with an equal sign (=)", "key=key = value,v2=7", map[string]string{
		"key": "key = value",
		"v2":  "7",
	}),
	Entry("Empty item, tailing ','", ",  key=value,", map[string]string{
		"key": "value",
	}),
)
