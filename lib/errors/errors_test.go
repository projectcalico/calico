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

package errors_test

import (
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/errors"
)

var _ = DescribeTable(
	"error types",
	func(err error, expected string) {
		Expect(err.Error()).To(Equal(expected))
	},
	Entry(
		"Operation not supported without reason",
		errors.ErrorOperationNotSupported{
			Operation: "create",
			Identifier: model.ResourceKey{
				Kind:      v3.KindNetworkPolicy,
				Namespace: "namespace1",
				Name:      "knp.default.k8spolicy",
			},
		},
		"operation create is not supported on NetworkPolicy(namespace1/knp.default.k8spolicy)",
	),
	Entry(
		"Operation not supported with reason",
		errors.ErrorOperationNotSupported{
			Operation:  "apply",
			Identifier: "foo.bar.baz",
			Reason:     "cannot mix foobar with baz",
		},
		"operation apply is not supported on foo.bar.baz: cannot mix foobar with baz",
	),
)
