// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package utils_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/utils"
)

var _ = Describe("policySyncPathPrefix coordination predicates", func() {
	Describe("IstioRequiresPolicySync", func() {
		It("returns false when the Istio CR is absent", func() {
			Expect(utils.IstioRequiresPolicySync(nil, operatorv1.CalicoEnterprise)).To(BeFalse())
		})

		It("returns false on a non-Enterprise variant", func() {
			Expect(utils.IstioRequiresPolicySync(&operatorv1.Istio{}, operatorv1.Calico)).To(BeFalse())
		})

		It("returns true when an Istio CR is present on Enterprise with WaypointLogging unset (default)", func() {
			Expect(utils.IstioRequiresPolicySync(&operatorv1.Istio{}, operatorv1.CalicoEnterprise)).To(BeTrue())
		})

		It("returns true when WaypointLogging is explicitly Enabled", func() {
			enabled := operatorv1.L7LogCollectionEnabled
			Expect(utils.IstioRequiresPolicySync(&operatorv1.Istio{
				Spec: operatorv1.IstioSpec{WaypointLogging: &enabled},
			}, operatorv1.CalicoEnterprise)).To(BeTrue())
		})

		It("returns false when WaypointLogging is explicitly Disabled", func() {
			disabled := operatorv1.L7LogCollectionDisabled
			Expect(utils.IstioRequiresPolicySync(&operatorv1.Istio{
				Spec: operatorv1.IstioSpec{WaypointLogging: &disabled},
			}, operatorv1.CalicoEnterprise)).To(BeFalse())
		})
	})

	Describe("DesiredPolicySyncPathPrefix", func() {
		It("preserves a customer override regardless of need flags", func() {
			Expect(utils.DesiredPolicySyncPathPrefix("/var/run/customer", false, false)).To(Equal("/var/run/customer"))
			Expect(utils.DesiredPolicySyncPathPrefix("/var/run/customer", true, true)).To(Equal("/var/run/customer"))
		})

		It("returns the operator default when either side needs it", func() {
			Expect(utils.DesiredPolicySyncPathPrefix("", true, false)).To(Equal("/var/run/nodeagent"))
			Expect(utils.DesiredPolicySyncPathPrefix("", false, true)).To(Equal("/var/run/nodeagent"))
		})

		It("leaves the field empty when nothing is set and neither side needs it", func() {
			Expect(utils.DesiredPolicySyncPathPrefix("", false, false)).To(Equal(""))
		})

		It("preserves the operator default even when neither side needs it", func() {
			// egressgateway and Gateway API set the same default and never clear
			// it, so the applicationlayer/istio path must not clear a value it
			// may not own.
			Expect(utils.DesiredPolicySyncPathPrefix("/var/run/nodeagent", false, false)).To(Equal("/var/run/nodeagent"))
		})
	})
})
