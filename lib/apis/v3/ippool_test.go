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

package v3_test

import (
	. "github.com/projectcalico/libcalico-go/lib/apis/v3"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// These tests verify that the IPPool nodeSelector works as expected
var _ = Describe("IPPoolSpec nodeSelector", func() {
	var (
		node Node
		pool IPPool
	)
	BeforeEach(func() {
		node = Node{}
		pool = IPPool{}
	})
	It("should return true, nil for empty nodeSelector", func() {
		pool.Spec = IPPoolSpec{NodeSelector: ""}

		matches, err := pool.SelectsNode(node)
		Expect(err).ToNot(HaveOccurred())
		Expect(matches).To(Equal(true))
	})
	It("should return false, err for invalid selector syntax", func() {
		pool.Spec = IPPoolSpec{NodeSelector: "this is invalid selector syntax"}

		matches, err := pool.SelectsNode(node)
		Expect(err).To(HaveOccurred())
		Expect(matches).To(Equal(false))
	})
	It("should return false, nil for mismatching labels", func() {
		pool.Spec = IPPoolSpec{NodeSelector: `foo == "bar"`}

		matches, err := pool.SelectsNode(node)
		Expect(err).ToNot(HaveOccurred())
		Expect(matches).To(Equal(false))
	})
	It("should return true, nil for mismatching labels", func() {
		node.Labels = map[string]string{"foo": "bar"}
		pool.Spec = IPPoolSpec{NodeSelector: `foo == "bar"`}

		matches, err := pool.SelectsNode(node)
		Expect(err).ToNot(HaveOccurred())
		Expect(matches).To(Equal(true))
	})
})
