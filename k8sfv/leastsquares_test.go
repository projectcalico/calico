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

package main

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/k8sfv/leastsquares"
)

var _ = Context("least squares", func() {

	It("should fit a straight line", func() {
		p := []leastsquares.Point{
			{1, 1},
			{2, 2},
			{3, 3},
			{4, 4},
		}
		gradient, constant := leastsquares.LeastSquaresMethod(p)
		Expect(gradient).To(BeNumerically("==", 1))
		Expect(constant).To(BeNumerically("==", 0))
	})
})
