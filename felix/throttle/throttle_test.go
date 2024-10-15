// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package throttle_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/felix/throttle"
)

var _ = Describe("Throttle with bucket size 3", func() {
	var throttle *Throttle
	BeforeEach(func() {
		throttle = New(3)
	})
	It("should not admit at start of day", func() {
		Expect(throttle.Admit()).To(BeFalse())
		Expect(throttle.WouldAdmit()).To(BeFalse())
	})
	It("should leak", func() {
		for i := 0; i < 5; i++ {
			throttle.Refill()
		}
		Expect(throttle.Admit()).To(BeTrue())
		Expect(throttle.Admit()).To(BeTrue())
		Expect(throttle.Admit()).To(BeTrue())

		Expect(throttle.Admit()).To(BeFalse())
	})
	It("should not go negative", func() {
		for i := 0; i < 5; i++ {
			Expect(throttle.Admit()).To(BeFalse())
		}
		throttle.Refill()
		Expect(throttle.Admit()).To(BeTrue())
		Expect(throttle.Admit()).To(BeFalse())
	})
	It("should not change count due to WouldAdmit", func() {
		throttle.Refill() // count = 1
		Expect(throttle.WouldAdmit()).To(BeTrue())
		Expect(throttle.WouldAdmit()).To(BeTrue())
		Expect(throttle.WouldAdmit()).To(BeTrue())
		Expect(throttle.Admit()).To(BeTrue())
		Expect(throttle.WouldAdmit()).To(BeFalse())
	})
})
