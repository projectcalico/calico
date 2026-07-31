// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !windows

package intdataplane

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

var _ = Describe("useNftables", func() {
	var hostSupportConsulted bool
	hostSupport := func(supported bool) func() bool {
		return func() bool {
			hostSupportConsulted = true
			return supported
		}
	}

	BeforeEach(func() {
		hostSupportConsulted = false
	})

	It("should be disabled in Disabled mode regardless of detection", func() {
		Expect(useNftables(string(v3.NFTablesModeDisabled), true, hostSupport(true))).To(BeFalse())
		Expect(hostSupportConsulted).To(BeFalse())
	})

	It("should be enabled in Enabled mode regardless of detection", func() {
		// hostSupport says false so a consult, if it happened, would also
		// flip the result.
		Expect(useNftables(string(v3.NFTablesModeEnabled), false, hostSupport(false))).To(BeTrue())
		Expect(hostSupportConsulted).To(BeFalse())
	})

	It("Auto: should follow kube-proxy when no host capability check is supplied", func() {
		Expect(useNftables(string(v3.NFTablesModeAuto), true, nil)).To(BeTrue())
		Expect(useNftables(string(v3.NFTablesModeAuto), false, nil)).To(BeFalse())
	})

	It("Auto: should use the host capability check when kube-proxy is not detected", func() {
		Expect(useNftables(string(v3.NFTablesModeAuto), false, hostSupport(true))).To(BeTrue())
		Expect(hostSupportConsulted).To(BeTrue())
	})

	It("Auto: should fall back to iptables on an unsupported host", func() {
		Expect(useNftables(string(v3.NFTablesModeAuto), false, hostSupport(false))).To(BeFalse())
		Expect(hostSupportConsulted).To(BeTrue())
	})

	It("Auto: should prefer the kube-proxy signal over the host capability check", func() {
		Expect(useNftables(string(v3.NFTablesModeAuto), true, hostSupport(false))).To(BeTrue())
		Expect(hostSupportConsulted).To(BeFalse())
	})
})
