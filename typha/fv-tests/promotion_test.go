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
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/typha/pkg/rolemanager"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

func configPath(name string) string {
	p, err := model.KeyToDefaultPath(model.GlobalConfigKey{Name: name})
	if err != nil {
		panic(err)
	}
	return p
}

// TestPromotion_FollowerToLeaderAndBack drives the full WS-C promotion/demotion
// path in-process:
//
//   - A follower (promotableHarness) starts sourcing from an upstream harness.
//   - Its client sees the upstream's data.
//   - We promote it (fake elector emits Leader); it tears down the upstream
//     source and stands up a real datastore source fed by a fakeDatastore.  The
//     client reconciles to the datastore's truth (including keys that exist only
//     in the datastore and deletions of keys that were only upstream).
//   - We demote it back; it reconciles to the upstream's truth again.
//
// This exercises the dedupe-buffer reconciliation under a real source swap (not
// just a reconnect): the property is that the client ends with exactly the
// new source's KV set after each transition.
func TestPromotion_FollowerToLeaderAndBack(t *testing.T) {
	RegisterTestingT(t)
	logutils.RedirectLogrusToTestingT(t)

	st := syncproto.SyncerTypeFelix

	// Upstream "leader-of-record" the follower initially sources from.
	upstream := newUpstreamHarness(st)
	upstream.Start()
	t.Cleanup(upstream.Stop)

	// Follower whose source the role manager swaps.
	follower := newPromotableHarness(upstream.Addr(), st)
	follower.Start()
	t.Cleanup(follower.Stop)

	// Seed the upstream: keys "u-keep" and "u-only".
	upstream.SendStatus(st, api.ResyncInProgress)
	upstream.SendConfigUpdate(st, "u-keep", "u-keep-v1")
	upstream.SendConfigUpdate(st, "u-only", "u-only-v1")
	upstream.SendStatus(st, api.InSync)

	// Seed the fakeDatastore (used once promoted): "u-keep" (same key, different
	// value) and "ds-only".  When promoted, the client should converge to the
	// datastore set: u-keep=ds value, ds-only present, u-only gone.
	follower.ds.Set("u-keep", "u-keep-ds")
	follower.ds.Set("ds-only", "ds-only-v1")

	// Client of the follower.
	cc := newChainClient(t, follower.Addr(), st)

	// Wait for the manager to converge to Follower and the client to see the
	// upstream's data.
	Eventually(follower.manager.Role, 3*time.Second, 20*time.Millisecond).Should(Equal(rolemanager.Tier2))
	upstreamExpected := map[string]string{
		configPath("u-keep"): "u-keep-v1",
		configPath("u-only"): "u-only-v1",
	}
	Eventually(func() map[string]string { return recorderValues(cc.recorder) },
		10*time.Second, 100*time.Millisecond).Should(Equal(upstreamExpected),
		"client should see upstream data while follower")
	Eventually(cc.recorder.Status, 10*time.Second, 100*time.Millisecond).Should(Equal(api.InSync))

	// Promote the follower.
	follower.elector.promote()
	Eventually(follower.manager.Role, 5*time.Second, 20*time.Millisecond).Should(Equal(rolemanager.Leader))

	datastoreExpected := map[string]string{
		configPath("u-keep"):  "u-keep-ds",
		configPath("ds-only"): "ds-only-v1",
		// u-only must be reconciled away (synthesized delete at InSync).
	}
	Eventually(func() map[string]string { return recorderValues(cc.recorder) },
		10*time.Second, 100*time.Millisecond).Should(Equal(datastoreExpected),
		"client should reconcile to datastore truth after promotion")
	Eventually(cc.recorder.Status, 10*time.Second, 100*time.Millisecond).Should(Equal(api.InSync))

	// Mutate the datastore while leader: add, update, delete.  These flow live.
	follower.ds.Set("ds-added", "ds-added-v1")
	follower.ds.Set("u-keep", "u-keep-ds2")
	follower.ds.Delete("ds-only")
	leaderAfterMutations := map[string]string{
		configPath("u-keep"):   "u-keep-ds2",
		configPath("ds-added"): "ds-added-v1",
	}
	Eventually(func() map[string]string { return recorderValues(cc.recorder) },
		10*time.Second, 100*time.Millisecond).Should(Equal(leaderAfterMutations),
		"live datastore mutations should reach the client while leader")

	// Demote back to follower; converge to upstream truth again.  The upstream
	// still holds u-keep=v1 and u-only=v1; ds-only/ds-added must be reconciled
	// away.
	follower.elector.demote()
	Eventually(follower.manager.Role, 5*time.Second, 20*time.Millisecond).Should(Equal(rolemanager.Tier2))
	Eventually(func() map[string]string { return recorderValues(cc.recorder) },
		10*time.Second, 100*time.Millisecond).Should(Equal(upstreamExpected),
		"client should reconcile back to upstream truth after demotion")
	Eventually(cc.recorder.Status, 10*time.Second, 100*time.Millisecond).Should(Equal(api.InSync))
}

// TestPromotion_KeyDeletedDuringTransition verifies that a key present in the
// follower's cache but absent from the new source's snapshot is deleted at the
// new source's InSync (the dedupe buffer synthesizes the deletion), even though
// the key was never explicitly deleted by either source.
func TestPromotion_KeyDeletedDuringTransition(t *testing.T) {
	RegisterTestingT(t)
	logutils.RedirectLogrusToTestingT(t)

	st := syncproto.SyncerTypeFelix
	upstream := newUpstreamHarness(st)
	upstream.Start()
	t.Cleanup(upstream.Stop)

	follower := newPromotableHarness(upstream.Addr(), st)
	follower.Start()
	t.Cleanup(follower.Stop)

	// Upstream holds "doomed"; datastore does not.
	upstream.SendStatus(st, api.ResyncInProgress)
	upstream.SendConfigUpdate(st, "doomed", "doomed-v1")
	upstream.SendStatus(st, api.InSync)
	follower.ds.Set("survivor", "survivor-v1")

	cc := newChainClient(t, follower.Addr(), st)
	Eventually(func() map[string]string { return recorderValues(cc.recorder) },
		10*time.Second, 100*time.Millisecond).Should(Equal(map[string]string{
		configPath("doomed"): "doomed-v1",
	}))

	// Promote: "doomed" should vanish, "survivor" should appear.
	follower.elector.promote()
	Eventually(func() map[string]string { return recorderValues(cc.recorder) },
		10*time.Second, 100*time.Millisecond).Should(Equal(map[string]string{
		configPath("survivor"): "survivor-v1",
	}), "doomed key should be synthesized-deleted on promotion")
}

// TestPromotion_WithChecksumsEnabled is the end-to-end checksum-over-promotion
// proof: the follower runs with snapshot-integrity checking enabled on its
// upstream source.  Across a promote/demote cycle the data still reconciles
// correctly and the verifier does not spuriously fire (the follower's
// reconstructed checksum matches the upstream's while it is a follower, and the
// verifier is torn down with the upstream source on promotion).  This guards
// against the checksum machinery destabilising the source-swap path.
func TestPromotion_WithChecksumsEnabled(t *testing.T) {
	RegisterTestingT(t)
	logutils.RedirectLogrusToTestingT(t)

	st := syncproto.SyncerTypeFelix
	upstream := newUpstreamHarness(st)
	upstream.Start()
	t.Cleanup(upstream.Stop)

	follower := newPromotableHarnessOpts(upstream.Addr(), st, true /* checksums */)
	follower.Start()
	t.Cleanup(follower.Stop)

	upstream.SendStatus(st, api.ResyncInProgress)
	upstream.SendConfigUpdate(st, "a", "a-v1")
	upstream.SendConfigUpdate(st, "b", "b-v1")
	upstream.SendStatus(st, api.InSync)
	follower.ds.Set("a", "a-ds")
	follower.ds.Set("c", "c-ds")

	cc := newChainClient(t, follower.Addr(), st)

	// As a follower with checksums on, the client should see the upstream data
	// and stay stable (no spurious reconnect storms emptying the cache).
	upstreamExpected := map[string]string{
		configPath("a"): "a-v1",
		configPath("b"): "b-v1",
	}
	Eventually(func() map[string]string { return recorderValues(cc.recorder) },
		10*time.Second, 100*time.Millisecond).Should(Equal(upstreamExpected))
	Consistently(func() map[string]string { return recorderValues(cc.recorder) },
		"2s", "100ms").Should(Equal(upstreamExpected),
		"checksum verifier should not destabilise a correctly-synced follower")

	// Promote, then demote, and confirm reconciliation still works end to end.
	follower.elector.promote()
	Eventually(func() map[string]string { return recorderValues(cc.recorder) },
		10*time.Second, 100*time.Millisecond).Should(Equal(map[string]string{
		configPath("a"): "a-ds",
		configPath("c"): "c-ds",
	}), "promotion reconciles to datastore truth with checksums enabled")

	follower.elector.demote()
	Eventually(func() map[string]string { return recorderValues(cc.recorder) },
		10*time.Second, 100*time.Millisecond).Should(Equal(upstreamExpected),
		"demotion reconciles back to upstream truth with checksums enabled")
}
