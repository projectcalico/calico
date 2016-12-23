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

package set_test

import (
	"github.com/projectcalico/felix/go/felix/set"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Set", func() {
	It("can copy a Set", func() {
		var s set.Set = set.New()
		s.Add(1)
		s.Add(2)
		c := s.Copy()
		Expect(c.Len()).To(Equal(s.Len()))
		c.Iter(func(item interface{}) error {
			Expect(s.Contains(item)).To(BeTrue())
			return nil
		})
	})
})
