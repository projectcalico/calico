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

package nftables_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/nftables"
)

var _ = Describe("Enabled", func() {
	var hostSupportConsulted bool
	hostSupport := func(supported bool) func() bool {
		return func() bool {
			hostSupportConsulted = true
			return supported
		}
	}
	kubeProxy := func(enabled bool) func() (bool, error) {
		return func() (bool, error) {
			return enabled, nil
		}
	}
	kubeProxyErr := func() (bool, error) {
		return false, fmt.Errorf("no nft binary")
	}

	BeforeEach(func() {
		hostSupportConsulted = false
	})

	It("should be disabled in Disabled mode regardless of detection", func() {
		Expect(nftables.Enabled(string(v3.NFTablesModeDisabled), kubeProxy(true), hostSupport(true))).To(BeFalse())
		Expect(hostSupportConsulted).To(BeFalse())
	})

	It("should be enabled in Enabled mode regardless of detection", func() {
		// hostSupport says false so a consult, if it happened, would also
		// flip the result.
		Expect(nftables.Enabled(string(v3.NFTablesModeEnabled), kubeProxy(false), hostSupport(false))).To(BeTrue())
		Expect(hostSupportConsulted).To(BeFalse())
	})

	It("should not consult kube-proxy outside Auto mode", func() {
		Expect(nftables.Enabled(string(v3.NFTablesModeEnabled), kubeProxyErr, nil)).To(BeTrue())
		Expect(nftables.Enabled(string(v3.NFTablesModeDisabled), kubeProxyErr, nil)).To(BeFalse())
	})

	It("Auto: should follow kube-proxy when no host capability check is supplied", func() {
		Expect(nftables.Enabled(string(v3.NFTablesModeAuto), kubeProxy(true), nil)).To(BeTrue())
		Expect(nftables.Enabled(string(v3.NFTablesModeAuto), kubeProxy(false), nil)).To(BeFalse())
	})

	It("Auto: should use the host capability check when kube-proxy is not detected", func() {
		Expect(nftables.Enabled(string(v3.NFTablesModeAuto), kubeProxy(false), hostSupport(true))).To(BeTrue())
		Expect(hostSupportConsulted).To(BeTrue())
	})

	It("Auto: should fall back to iptables on an unsupported host", func() {
		Expect(nftables.Enabled(string(v3.NFTablesModeAuto), kubeProxy(false), hostSupport(false))).To(BeFalse())
		Expect(hostSupportConsulted).To(BeTrue())
	})

	It("Auto: should prefer the kube-proxy signal over the host capability check", func() {
		Expect(nftables.Enabled(string(v3.NFTablesModeAuto), kubeProxy(true), hostSupport(false))).To(BeTrue())
		Expect(hostSupportConsulted).To(BeFalse())
	})

	It("Auto: should report a failed kube-proxy detection", func() {
		enabled, err := nftables.Enabled(string(v3.NFTablesModeAuto), kubeProxyErr, hostSupport(true))
		Expect(err).To(HaveOccurred())
		Expect(enabled).To(BeFalse())
		Expect(hostSupportConsulted).To(BeFalse())
	})
})
