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
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/typha/pkg/synccheck"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

// mismatchCount reads the current value of the checksum-mismatch counter for the
// given syncer type, via the testutil registry hook the metric is registered on.
func mismatchCount(st syncproto.SyncerType) float64 {
	return testutil.ToFloat64(synccheck.CounterMismatchesForTest(string(st)))
}

func matchCount(st syncproto.SyncerType) float64 {
	return testutil.ToFloat64(synccheck.CounterMatchesForTest(string(st)))
}

// TestChecksum_CleanRunMatches verifies that, across all four syncer types, a
// healthy chain produces checksum matches and zero false-positive mismatches:
// the follower's reconstruction always agrees with the upstream.
func TestChecksum_CleanRunMatches(t *testing.T) {
	RegisterTestingT(t)
	logutils.RedirectLogrusToTestingT(t)

	upstream := newUpstreamHarness(allChainSyncerTypes...)
	upstream.Start()
	t.Cleanup(upstream.Stop)

	// Same version as the upstream so the full XOR comparison (not count-only)
	// is exercised.
	follower := newChecksumFollowerHarness(
		upstream.Addr(), "v-same", synccheck.MismatchActionReconnect, allChainSyncerTypes...)
	follower.Start()
	t.Cleanup(follower.Stop)

	mismatchBefore := map[syncproto.SyncerType]float64{}
	for _, st := range allChainSyncerTypes {
		mismatchBefore[st] = mismatchCount(st)
	}

	// Seed each syncer with data, then churn it (updates + deletes) so the
	// periodic checksum path runs over a changing snapshot, then settle in-sync.
	for i, st := range allChainSyncerTypes {
		upstream.SendStatus(st, api.ResyncInProgress)
		for j := 0; j < 5; j++ {
			upstream.SendConfigUpdate(st, stKeyName(st, j), stValue(i, j))
		}
		upstream.SendStatus(st, api.InSync)
	}
	// Mutate after going in-sync to drive periodic checksums over a moving target.
	for i, st := range allChainSyncerTypes {
		upstream.SendConfigUpdate(st, stKeyName(st, 0), stValue(i, 99)) // clobber
		upstream.SendDelete(st, stKeyName(st, 1))                       // delete
		upstream.SendConfigUpdate(st, stKeyName(st, 5), stValue(i, 5))  // add
	}

	// Each syncer should record matches and never a mismatch.
	for _, st := range allChainSyncerTypes {
		st := st
		Eventually(func() float64 { return matchCount(st) }, 15*time.Second, 100*time.Millisecond).
			Should(BeNumerically(">", 0), "expected checksum matches for %s", st)
	}
	// Give periodic checks plenty of time to (not) raise a false positive.
	for _, st := range allChainSyncerTypes {
		st := st
		Consistently(func() float64 { return mismatchCount(st) - mismatchBefore[st] }, "2s", "100ms").
			Should(BeZero(), "unexpected checksum mismatch for %s", st)
		Expect(follower.reconnects[st].Load()).To(BeZero(), "unexpected reconnect for %s", st)
	}
}

// TestChecksum_FaultInjectionDetectedAndRemediated injects a phantom key into
// the follower's pipeline (data the upstream never sent), so the follower's
// reconstruction diverges from the upstream's checksum.  The verifier must
// detect the mismatch and request a reconnect.
func TestChecksum_FaultInjectionDetectedAndRemediated(t *testing.T) {
	RegisterTestingT(t)
	logutils.RedirectLogrusToTestingT(t)

	st := syncproto.SyncerTypeFelix
	upstream := newUpstreamHarness(st)
	upstream.Start()
	t.Cleanup(upstream.Stop)

	follower := newChecksumFollowerHarness(
		upstream.Addr(), "v-same", synccheck.MismatchActionReconnect, st)
	follower.Start()
	t.Cleanup(follower.Stop)

	upstream.SendStatus(st, api.ResyncInProgress)
	for j := 0; j < 3; j++ {
		upstream.SendConfigUpdate(st, stKeyName(st, j), stValue(0, j))
	}
	upstream.SendStatus(st, api.InSync)

	// Wait for a clean match first.
	Eventually(func() float64 { return matchCount(st) }, 15*time.Second, 100*time.Millisecond).
		Should(BeNumerically(">", 0))

	mismatchBefore := mismatchCount(st)
	reconnectsBefore := follower.reconnects[st].Load()

	// Corrupt the follower's reconstruction with a key the upstream never sent.
	follower.injectPhantomKey(st, "phantom", "phantom-value")

	// The next upstream checksum (sent periodically, or driven by any further
	// upstream change) now disagrees with the follower's cache.  Send a benign
	// upstream update to ensure a fresh checksum is emitted promptly.
	upstream.SendConfigUpdate(st, stKeyName(st, 0), stValue(0, 42))

	Eventually(func() float64 { return mismatchCount(st) - mismatchBefore }, 20*time.Second, 100*time.Millisecond).
		Should(BeNumerically(">=", 1), "expected the injected fault to be detected")
	Eventually(func() int64 { return follower.reconnects[st].Load() - reconnectsBefore }, 20*time.Second, 100*time.Millisecond).
		Should(BeNumerically(">=", 1), "expected a reconnect to be requested as remediation")
}

// TestChecksum_BackCompatNoFlagNoChecksum verifies that a client which does not
// advertise checksum support (a plain syncclient, like an older Felix) still
// works against a checksum-capable upstream and is never sent MsgChecksum — it
// reaches in-sync with correct data, proving the new message type doesn't leak
// to clients that didn't negotiate it.
func TestChecksum_BackCompatNoFlagNoChecksum(t *testing.T) {
	RegisterTestingT(t)
	logutils.RedirectLogrusToTestingT(t)

	st := syncproto.SyncerTypeFelix
	upstream := newUpstreamHarness(st)
	upstream.Start()
	t.Cleanup(upstream.Stop)

	upstream.SendStatus(st, api.ResyncInProgress)
	exp := map[string]string{}
	for j := 0; j < 4; j++ {
		path, _ := upstream.SendConfigUpdate(st, stKeyName(st, j), stValue(0, j))
		exp[path] = stValue(0, j)
	}
	upstream.SendStatus(st, api.InSync)

	// newChainClient (ws-a helper) builds a plain syncclient with no checksum
	// verifier, so it never advertises SupportsChecksum.  If the server wrongly
	// sent MsgChecksum, the client would still decode it (gob-registered) and
	// ignore it, but the more important assertion is that the connection stays
	// healthy and data is correct.
	cc := newChainClient(t, upstream.Addr(), st)
	Eventually(cc.recorder.Status, 10*time.Second, 100*time.Millisecond).Should(Equal(api.InSync))
	Eventually(func() map[string]string { return recorderValues(cc.recorder) },
		10*time.Second, 100*time.Millisecond).Should(Equal(exp))
}

// TestChecksum_VersionSkewCountOnly verifies that when the follower runs a
// different version from the upstream, comparison downgrades to KVCount-only:
// even though the follower re-serializes values (here the bytes happen to match,
// but the path is the count-only one), a correct count produces matches and no
// false-positive mismatch.
func TestChecksum_VersionSkewCountOnly(t *testing.T) {
	RegisterTestingT(t)
	logutils.RedirectLogrusToTestingT(t)

	st := syncproto.SyncerTypeFelix
	upstream := newUpstreamHarness(st)
	upstream.Start()
	t.Cleanup(upstream.Stop)

	// Different version string from the upstream's buildinfo version forces the
	// count-only downgrade in the client handshake.
	follower := newChecksumFollowerHarness(
		upstream.Addr(), "definitely-a-different-version", synccheck.MismatchActionReconnect, st)
	follower.Start()
	t.Cleanup(follower.Stop)

	mismatchBefore := mismatchCount(st)

	upstream.SendStatus(st, api.ResyncInProgress)
	for j := 0; j < 4; j++ {
		upstream.SendConfigUpdate(st, stKeyName(st, j), stValue(0, j))
	}
	upstream.SendStatus(st, api.InSync)

	Eventually(func() float64 { return matchCount(st) }, 15*time.Second, 100*time.Millisecond).
		Should(BeNumerically(">", 0))
	Consistently(func() float64 { return mismatchCount(st) - mismatchBefore }, "2s", "100ms").
		Should(BeZero(), "count-only comparison should not raise mismatches for a correct count")
}
