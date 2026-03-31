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

// Memory leak investigation tests for the LoadBalancer controller's allocationTracker.
//
// The allocationTracker maintains three cross-indexed maps:
//
//	servicesByIP  — IP  → serviceKey
//	ipsByService  — serviceKey → set of IPs
//	ipsByBlock    — blockCIDR  → set of IPs
//
// These must be kept in sync. The tests below probe whether every removal code
// path correctly cleans all three maps, and whether stale entries can accumulate
// when only a subset of maps is cleaned.

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

		// This test currently FAILS — it documents a confirmed bug:
		// After the last IP in a block is removed via releaseAddressFromBlock, the outer
		// block key is never deleted from ipsByBlock. Empty inner maps accumulate for
		// every block that has ever hosted a LB IP, growing proportionally to pool churn.
		// Fix: deleteBlock (or a new helper) should be called when the inner map becomes empty.
		It("removes the block key from ipsByBlock when its last IP is released (documents accumulation bug)", func() {
			t.assignAddressToBlock(blockCIDR, ip1, svcKey)
			t.releaseAddressFromBlock(blockCIDR, ip1)

			Expect(t.ipsByBlock).ToNot(HaveKey(blockCIDR),
				"ipsByBlock should not keep an empty inner map for a fully-released block; "+
					"stale block keys accumulate indefinitely")
		})
	})

	// ── Inconsistency tests: deleteService skips ipsByBlock ────────────────

	Describe("deleteService and ipsByBlock inconsistency", func() {
		// This test currently FAILS — it documents a confirmed bug:
		// deleteService cleans servicesByIP and ipsByService but NOT ipsByBlock.
		// After a service is deleted the block-index retains stale IP entries until
		// the next block-update notification arrives from the datastore syncer.
		// In the absence of a syncer notification (disrupted connection, quiet block)
		// the stale entries can persist indefinitely.
		// Fix: deleteService should also remove IPs from ipsByBlock, or the caller
		// (releaseIPsByHandle) should call deleteBlock/releaseAddressFromBlock first.
		It("cleans ipsByBlock when a service is deleted (documents stale-block bug)", func() {
			t.assignAddressToBlock(blockCIDR, ip1, svcKey)
			t.assignAddressToBlock(blockCIDR, ip2, svcKey)

			t.deleteService(svcKey)

			Expect(t.ipsByBlock[blockCIDR]).ToNot(HaveKey(ip1),
				"ipsByBlock should not contain ip1 after deleteService; "+
					"currently stale until next syncer block-update")
			Expect(t.ipsByBlock[blockCIDR]).ToNot(HaveKey(ip2),
				"ipsByBlock should not contain ip2 after deleteService; "+
					"currently stale until next syncer block-update")
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

	// ── Inconsistency tests: releaseAddressFromService skips ipsByBlock ────

	Describe("releaseAddressFromService and ipsByBlock inconsistency", func() {
		// This test currently FAILS — it documents a confirmed bug:
		// releaseAddressFromService (used by releaseIP for annotation-change IP swaps)
		// cleans servicesByIP and ipsByService but NOT ipsByBlock.
		// The fix is the same as for deleteService: the caller (releaseIP) should also
		// call releaseAddressFromBlock, or releaseAddressFromService should be extended.
		It("cleans ipsByBlock when an IP is released from a service (documents stale-block bug)", func() {
			t.assignAddressToBlock(blockCIDR, ip1, svcKey)

			t.releaseAddressFromService(svcKey, ip1)

			Expect(t.ipsByBlock[blockCIDR]).ToNot(HaveKey(ip1),
				"ipsByBlock should not contain ip1 after releaseAddressFromService; "+
					"currently stale until next syncer block-update")
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

	// ── Safety test: stale ipsByBlock doesn't corrupt state on next block update ──

	Describe("stale ipsByBlock is safe to overwrite on re-assignment", func() {
		It("can re-assign an IP to a different service after deleteService leaves it stale in ipsByBlock", func() {
			svcKey2 := serviceKey{handle: "lb-other-handle", name: "other-svc", namespace: "test-ns"}

			// Service 1 gets ip1 from blockCIDR.
			t.assignAddressToBlock(blockCIDR, ip1, svcKey)

			// Service 1 is deleted — ipsByBlock retains the stale entry.
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
