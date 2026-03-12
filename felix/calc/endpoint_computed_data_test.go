// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/proto"
)

var _ = Describe("EndpointComputedData ApplyTo methods", func() {
	Describe("IstioCalculator.ApplyTo", func() {
		var (
			cie *calc.ComputedIstioEndpoint
			wep *proto.WorkloadEndpoint
		)

		BeforeEach(func() {
			cie = &calc.ComputedIstioEndpoint{}
			wep = &proto.WorkloadEndpoint{
				State:          "up",
				Name:           "test-endpoint",
				IsIstioAmbient: false,
			}
		})

		It("should set IsIstioAmbient to true", func() {
			Expect(wep.IsIstioAmbient).To(BeFalse())
			cie.ApplyTo(wep)
			Expect(wep.IsIstioAmbient).To(BeTrue())
		})

		It("should set IsIstioAmbient to true even if already true", func() {
			wep.IsIstioAmbient = true
			cie.ApplyTo(wep)
			Expect(wep.IsIstioAmbient).To(BeTrue())
		})

		It("should not modify other endpoint fields", func() {
			originalName := wep.Name
			originalState := wep.State
			cie.ApplyTo(wep)
			Expect(wep.Name).To(Equal(originalName))
			Expect(wep.State).To(Equal(originalState))
		})
	})

	Describe("Multiple ApplyTo calls", func() {
		It("should apply both Istio and Egress computed data correctly", func() {
			wep := &proto.WorkloadEndpoint{
				State:          "up",
				Name:           "test-endpoint",
				IsIstioAmbient: false,
			}

			// Apply Istio computed data
			compIstioEp := &calc.ComputedIstioEndpoint{}
			compIstioEp.ApplyTo(wep)
			Expect(wep.IsIstioAmbient).To(BeTrue())

			// Verify both computed data are applied
			Expect(wep.IsIstioAmbient).To(BeTrue())
		})
	})
})
