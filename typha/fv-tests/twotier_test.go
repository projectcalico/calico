// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fvtests_test

import (
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/typha/pkg/rolemanager"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

// buildThreeLevelChain wires a full datastore → leader → tier1 → tier2 → client
// chain in-process, with snapshot-integrity checksums enabled on every hop
// (checksums are on by default in production now, so the chain must show zero
// false mismatches end to end):
//
//   - leader: a promotableHarness promoted to Leader; sourced from its
//     fakeDatastore (the canonical source of truth).
//   - tier1: a promotableHarness whose upstream is the leader's address; promoted
//     to Tier1 so it sources from the leader.
//   - tier2: a promotableHarness whose upstream is the tier1's address; left in
//     Tier2 so it sources from tier1.
//   - client: an ordinary syncclient connected to tier2.
//
// All three Typhas use checksum-enabled upstream sources, so a checksum mismatch
// anywhere in the chain would trip the verifier (and, with the default reconnect
// action, manifest as instability the assertions would catch).
func buildThreeLevelChain(t *testing.T, st syncproto.SyncerType) (leader, tier1, tier2 *promotableHarness, cc *chainClient) {
	t.Helper()

	// Leader: promote it so it runs the datastore source.  Its bootstrap (Tier2)
	// upstream is an unreachable placeholder — harmless because we promote it to
	// Leader immediately, swapping the source to the datastore before it matters.
	leader = newPromotableHarnessOpts("127.0.0.1:1", st, true)
	leader.Start()
	t.Cleanup(leader.Stop)
	leader.elector.promote()
	Eventually(leader.manager.Role, 5*time.Second, 20*time.Millisecond).Should(Equal(rolemanager.Leader))

	// Tier1: upstream = leader; promote to Tier1.
	tier1 = newPromotableHarnessOpts(leader.Addr(), st, true)
	tier1.Start()
	t.Cleanup(tier1.Stop)
	tier1.elector.promoteTier1()
	Eventually(tier1.manager.Role, 5*time.Second, 20*time.Millisecond).Should(Equal(rolemanager.Tier1))

	// Tier2: upstream = tier1; leave in Tier2 (bootstrap role).
	tier2 = newPromotableHarnessOpts(tier1.Addr(), st, true)
	tier2.Start()
	t.Cleanup(tier2.Stop)
	Eventually(tier2.manager.Role, 5*time.Second, 20*time.Millisecond).Should(Equal(rolemanager.Tier2))

	// Client connects to tier2.
	cc = newChainClient(t, tier2.Addr(), st)
	return
}

// TestTwoTier_FullChainParity verifies that data written at the datastore (the
// leader's fakeDatastore) propagates all the way down the three-level chain to a
// client of tier-2, with full parity, and that live mutations also flow through.
func TestTwoTier_FullChainParity(t *testing.T) {
	RegisterTestingT(t)
	logutils.RedirectLogrusToTestingT(t)

	st := syncproto.SyncerTypeFelix
	leader, _, _, cc := buildThreeLevelChain(t, st)

	// Seed the datastore at the top of the chain.
	leader.ds.Set("a", "a-v1")
	leader.ds.Set("b", "b-v1")

	expected := map[string]string{
		configPath("a"): "a-v1",
		configPath("b"): "b-v1",
	}
	Eventually(func() map[string]string { return recorderValues(cc.recorder) },
		15*time.Second, 100*time.Millisecond).Should(Equal(expected),
		"datastore data should reach the tier-2 client through the full chain")
	Eventually(cc.recorder.Status, 15*time.Second, 100*time.Millisecond).Should(Equal(api.InSync))

	// Live mutations at the datastore should flow down the whole chain.
	leader.ds.Set("c", "c-v1")
	leader.ds.Set("a", "a-v2")
	leader.ds.Delete("b")
	expectedAfter := map[string]string{
		configPath("a"): "a-v2",
		configPath("c"): "c-v1",
	}
	Eventually(func() map[string]string { return recorderValues(cc.recorder) },
		15*time.Second, 100*time.Millisecond).Should(Equal(expectedAfter),
		"live datastore mutations should propagate through the full chain")

	// The chain must stay stable — no checksum-mismatch-induced reconnect storms
	// emptying the cache.
	Consistently(func() map[string]string { return recorderValues(cc.recorder) },
		"2s", "100ms").Should(Equal(expectedAfter),
		"chain should be stable with checksums enabled (no false mismatches)")
}

// TestTwoTier_Tier1Death verifies the fail-safe / serve-stale property (binding
// decision 5) when the middle of the chain dies: killing the tier-1 must not
// cause the tier-2's client to see an empty or torn snapshot.  The tier-2 keeps
// serving its last-known-good cache (marked not-in-sync) while it has no
// upstream.  Real re-pointing to a replacement tier-1 is a discovery concern
// exercised by the Felix FV multi-typha topology; here we prove the data-path
// resilience.
func TestTwoTier_Tier1Death(t *testing.T) {
	RegisterTestingT(t)
	logutils.RedirectLogrusToTestingT(t)

	st := syncproto.SyncerTypeFelix
	leader, tier1, _, cc := buildThreeLevelChain(t, st)

	leader.ds.Set("k", "v1")
	Eventually(func() map[string]string { return recorderValues(cc.recorder) },
		15*time.Second, 100*time.Millisecond).Should(Equal(map[string]string{
		configPath("k"): "v1",
	}))

	// Kill the tier-1: the tier-2 loses its upstream.
	tier1.Stop()

	// The tier-2 must keep serving its last-known-good cache to the client — no
	// empty/torn snapshot during the outage.
	Consistently(func() map[string]string { return recorderValues(cc.recorder) },
		"2s", "100ms").Should(Equal(map[string]string{
		configPath("k"): "v1",
	}), "tier-2 should keep serving last-known-good data while tier-1 is down")
}

// TestTwoTier_Tier2WinsLeaderLease verifies the worst-case failure: any Typha
// (including a tier-2) may win the leader lease.  Here a tier-2 is promoted
// directly to Leader (skipping tier-1), stands up the datastore source, and its
// client reconciles to datastore truth — proving the role manager handles a
// tier-2 → leader jump (not just the tier-1 → leader ladder step).
func TestTwoTier_Tier2WinsLeaderLease(t *testing.T) {
	RegisterTestingT(t)
	logutils.RedirectLogrusToTestingT(t)

	st := syncproto.SyncerTypeFelix

	// A tier-2 typha with its own fakeDatastore (so when it wins the leader lease
	// it has a datastore to serve from).  Its configured upstream is unused once
	// it becomes leader.
	upstream := newUpstreamHarness(st)
	upstream.Start()
	t.Cleanup(upstream.Stop)

	tier2 := newPromotableHarnessOpts(upstream.Addr(), st, true)
	tier2.Start()
	t.Cleanup(tier2.Stop)

	// Seed the upstream so the tier-2 has data while a leaf.
	upstream.SendStatus(st, api.ResyncInProgress)
	upstream.SendConfigUpdate(st, "up", "up-v1")
	upstream.SendStatus(st, api.InSync)
	tier2.ds.Set("ds", "ds-v1")

	cc := newChainClient(t, tier2.Addr(), st)
	Eventually(tier2.manager.Role, 5*time.Second, 20*time.Millisecond).Should(Equal(rolemanager.Tier2))
	Eventually(func() map[string]string { return recorderValues(cc.recorder) },
		10*time.Second, 100*time.Millisecond).Should(Equal(map[string]string{
		configPath("up"): "up-v1",
	}))

	// The tier-2 wins the leader lease (worst case): promote it straight to Leader.
	tier2.elector.promote()
	Eventually(tier2.manager.Role, 5*time.Second, 20*time.Millisecond).Should(Equal(rolemanager.Leader))
	Eventually(func() map[string]string { return recorderValues(cc.recorder) },
		10*time.Second, 100*time.Millisecond).Should(Equal(map[string]string{
		configPath("ds"): "ds-v1",
	}), "a tier-2 that wins the leader lease serves datastore truth, client reconciles")
}
