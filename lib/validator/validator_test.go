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

package validator_test

import (
	. "github.com/tigera/libcalico-go/lib/validator"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/tigera/libcalico-go/lib/backend/model"
)

var _ = DescribeTable("Validator",
	func(input interface{}, valid bool) {
		if valid {
			Expect(Validate(input)).To(BeNil(),
				"expected value to be valid")
		} else {
			Expect(Validate(input)).ToNot(BeNil(),
				"expected value to be invalid")
		}
	},
	// Empty rule is valid, it means "allow all".
	Entry("empty rule", model.Rule{}, true),

	// Actions.
	Entry("should accept allow action", model.Rule{Action: "allow"}, true),
	Entry("should accept deny action", model.Rule{Action: "deny"}, true),
	Entry("should accept next-tier action", model.Rule{Action: "next-tier"}, true),
	Entry("should accept log action", model.Rule{Action: "log"}, true),
	Entry("should reject unknown action", model.Rule{Action: "unknown"}, false),
	Entry("should reject unknown action", model.Rule{Action: "allowfoo"}, false),
)
