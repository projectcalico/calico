// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

// Regression tests for the LoadBalancer controller's allocationTracker.
//
// The allocationTracker maintains three cross-indexed maps:
//
//	servicesByIP  — IP  → serviceKey
//	ipsByService  — serviceKey → set of IPs
//	ipsByBlock    — blockCIDR  → set of IPs
//
// These must be kept in sync. The tests below verify that every removal code
// path correctly cleans all three maps.

package loadbalancer

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("allocationTracker leak investigation", func() {
	const (
		blockCIDR = "10.0.0.0/26"
		ip1       = "10.0.0.1"
		ip2       = "10.0.0.2"
	)

	var (
		svcKey serviceKey
		t      allocationTracker
	)

	BeforeEach(func() {
		svcKey = serviceKey{
			handle:    "lb-test-handle",
			name:      "test-svc",
			namespace: "test-ns",
		}
		t = allocationTracker{
			servicesByIP: make(map[string]serviceKey),
			ipsByService: make(map[serviceKey]map[string]bool),
			ipsByBlock:   make(map[string]map[string]bool),
		}
	})

	// ── Positive tests: correct code paths ─────────────────────────────────

	Describe("correct cleanup via deleteBlock", func() {
		It("cleans servicesByIP, ipsByService, and ipsByBlock when block is removed", func() {
			t.assignAddressToBlock(blockCIDR, ip1, svcKey)
			t.assignAddressToBlock(blockCIDR, ip2, svcKey)

			t.deleteBlock(blockCIDR)

			Expect(t.ipsByBlock).ToNot(HaveKey(blockCIDR),
				"ipsByBlock should not contain the block key after deleteBlock")
			Expect(t.servicesByIP).ToNot(HaveKey(ip1),
				"servicesByIP should not contain ip1 after deleteBlock")
			Expect(t.servicesByIP).ToNot(HaveKey(ip2),
				"servicesByIP should not contain ip2 after deleteBlock")
			Expect(t.ipsByService[svcKey]).To(BeEmpty(),
				"ipsByService for svcKey should be empty after deleteBlock")
		})
	})

	Describe("correct cleanup via releaseAddressFromBlock", func() {
		It("cleans all three maps when a single IP is removed from the block", func() {
			t.assignAddressToBlock(blockCIDR, ip1, svcKey)

			t.releaseAddressFromBlock(blockCIDR, ip1)

			Expect(t.servicesByIP).ToNot(HaveKey(ip1),
				"servicesByIP should not contain ip1 after releaseAddressFromBlock")
			Expect(t.ipsByService[svcKey]).ToNot(HaveKey(ip1),
				"ipsByService[svcKey] should not contain ip1 after releaseAddressFromBlock")
			Expect(t.ipsByBlock[blockCIDR]).ToNot(HaveKey(ip1),
				"ipsByBlock[blockCIDR] should not contain ip1 after releaseAddressFromBlock")
		})

		// Regression: after the last IP in a block is removed via releaseAddressFromBlock,
		// the outer block key must also be pruned from ipsByBlock. Previously, empty inner
		// maps accumulated for every block that had ever hosted a LB IP.
		It("removes the block key from ipsByBlock when its last IP is released", func() {
			t.assignAddressToBlock(blockCIDR, ip1, svcKey)
			t.releaseAddressFromBlock(blockCIDR, ip1)

			Expect(t.ipsByBlock).ToNot(HaveKey(blockCIDR),
				"ipsByBlock should not keep an empty inner map for a fully-released block")
		})
	})

	// ── deleteService cleans all three maps ────────────────────────────────

	Describe("deleteService cleans all three maps", func() {
		// Regression: deleteService previously only cleaned servicesByIP and ipsByService,
		// leaving stale IP entries in ipsByBlock until the next datastore syncer
		// block-update (which might never arrive for a disrupted or quiet block).
		// Fixed by delegating to releaseAddressFromService for each IP.
		It("cleans ipsByBlock when a service is deleted", func() {
			t.assignAddressToBlock(blockCIDR, ip1, svcKey)
			t.assignAddressToBlock(blockCIDR, ip2, svcKey)

			t.deleteService(svcKey)

			Expect(t.ipsByBlock[blockCIDR]).ToNot(HaveKey(ip1),
				"ipsByBlock should not contain ip1 after deleteService")
			Expect(t.ipsByBlock[blockCIDR]).ToNot(HaveKey(ip2),
				"ipsByBlock should not contain ip2 after deleteService")
		})

		It("correctly cleans servicesByIP and ipsByService (these are fine)", func() {
			t.assignAddressToBlock(blockCIDR, ip1, svcKey)

			t.deleteService(svcKey)

			Expect(t.servicesByIP).ToNot(HaveKey(ip1),
				"servicesByIP should be cleaned by deleteService")
			Expect(t.ipsByService).ToNot(HaveKey(svcKey),
				"ipsByService should not contain svcKey after deleteService")
		})
	})

	// ── releaseAddressFromService cleans all three maps ────────────────────

	Describe("releaseAddressFromService cleans all three maps", func() {
		// Regression: releaseAddressFromService (used by releaseIP for annotation-change
		// IP swaps) previously only cleaned servicesByIP and ipsByService, leaving stale
		// entries in ipsByBlock. Fixed by scanning ipsByBlock for the IP and removing it.
		It("cleans ipsByBlock when an IP is released from a service", func() {
			t.assignAddressToBlock(blockCIDR, ip1, svcKey)

			t.releaseAddressFromService(svcKey, ip1)

			Expect(t.ipsByBlock[blockCIDR]).ToNot(HaveKey(ip1),
				"ipsByBlock should not contain ip1 after releaseAddressFromService")
		})

		It("correctly cleans servicesByIP and ipsByService (these are fine)", func() {
			t.assignAddressToBlock(blockCIDR, ip1, svcKey)

			t.releaseAddressFromService(svcKey, ip1)

			Expect(t.servicesByIP).ToNot(HaveKey(ip1),
				"servicesByIP should be cleaned by releaseAddressFromService")
			Expect(t.ipsByService[svcKey]).ToNot(HaveKey(ip1),
				"ipsByService[svcKey] should not contain ip1 after releaseAddressFromService")
		})
	})

	// ── Re-assignment safety ────────────────────────────────────────────────

	Describe("re-assignment after deleteService", func() {
		It("correctly reflects the new service in all three maps after an IP is re-assigned", func() {
			svcKey2 := serviceKey{handle: "lb-other-handle", name: "other-svc", namespace: "test-ns"}

			// Service 1 gets ip1 from blockCIDR.
			t.assignAddressToBlock(blockCIDR, ip1, svcKey)

			// Service 1 is deleted; all maps should be clean.
			t.deleteService(svcKey)

			// Service 2 is now assigned ip1 from the same block.
			t.assignAddressToBlock(blockCIDR, ip1, svcKey2)

			// servicesByIP and ipsByService should now reflect service 2.
			Expect(t.servicesByIP[ip1]).To(Equal(svcKey2),
				"servicesByIP should point to svcKey2 after re-assignment")
			Expect(t.ipsByService[svcKey2]).To(HaveKey(ip1),
				"ipsByService[svcKey2] should contain ip1")
			Expect(t.ipsByService[svcKey]).ToNot(HaveKey(ip1),
				"ipsByService[svcKey] (old service) should not contain ip1")
			// ipsByBlock should still reflect the re-assignment correctly.
			Expect(t.ipsByBlock[blockCIDR]).To(HaveKey(ip1),
				"ipsByBlock should contain ip1 after re-assignment")
		})
	})
})
