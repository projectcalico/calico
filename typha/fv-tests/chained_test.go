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
	"context"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/dedupebuffer"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	fvtests "github.com/projectcalico/calico/typha/fv-tests"
	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

var allChainSyncerTypes = []syncproto.SyncerType{
	syncproto.SyncerTypeFelix,
	syncproto.SyncerTypeBGP,
	syncproto.SyncerTypeTunnelIPAllocation,
	syncproto.SyncerTypeNodeStatus,
}

// chainClient connects a real syncclient (with a dedupe buffer + recorder) to
// the given address for the given syncer type.
type chainClient struct {
	recorder *fvtests.StateRecorder
	client   *syncclient.SyncerClient
	cancel   context.CancelFunc
	finished chan struct{}
}

func newChainClient(t *testing.T, addr string, st syncproto.SyncerType) *chainClient {
	t.Helper()
	recorder := fvtests.NewRecorder()
	buf := dedupebuffer.New()
	client := syncclient.New(
		discovery.New(discovery.WithAddrOverride(addr)),
		"client-version", "client-host", "client-info",
		buf,
		&syncclient.Options{SyncerType: st},
	)
	ctx, cancel := context.WithCancel(context.Background())
	go buf.SendToSinkForever(recorder)
	go recorder.Loop(ctx)
	if err := client.Start(ctx); err != nil {
		t.Fatalf("failed to start chain client: %v", err)
	}
	finished := make(chan struct{})
	go func() {
		client.Finished.Wait()
		close(finished)
	}()
	cc := &chainClient{recorder: recorder, client: client, cancel: cancel, finished: finished}
	t.Cleanup(func() {
		cancel()
		buf.Stop()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("chain client did not finish")
		}
	})
	return cc
}

// TestChainedTypha_Parity asserts that, for all four syncer types, the follower
// Typha serves byte-identical data (keys, values, in-sync status) to what the
// upstream holds, and that a downstream client of the follower sees the same.
func TestChainedTypha_Parity(t *testing.T) {
	RegisterTestingT(t)
	logutils.RedirectLogrusToTestingT(t)

	upstream := newUpstreamHarness(allChainSyncerTypes...)
	upstream.Start()
	t.Cleanup(upstream.Stop)

	follower := newFollowerHarness(upstream.Addr(), allChainSyncerTypes...)
	follower.Start()
	t.Cleanup(follower.Stop)

	// Seed each syncer type with distinct data and mark in sync.
	expected := map[syncproto.SyncerType]map[string]string{}
	for i, st := range allChainSyncerTypes {
		upstream.SendStatus(st, api.ResyncInProgress)
		exp := map[string]string{}
		for j := 0; j < 3; j++ {
			name := stKeyName(st, j)
			value := stValue(i, j)
			path, _ := upstream.SendConfigUpdate(st, name, value)
			exp[path] = value
		}
		upstream.SendStatus(st, api.InSync)
		expected[st] = exp
	}

	// Connect a client of the follower per syncer type and check full parity.
	for _, st := range allChainSyncerTypes {
		st := st
		exp := expected[st]
		cc := newChainClient(t, follower.Addr(), st)

		// Follower's own cache should match the upstream data.
		Eventually(func() map[string]string {
			vals, _ := breadcrumbContents(t, follower.caches[st])
			return vals
		}, 10*time.Second, 100*time.Millisecond).Should(Equal(exp), "follower cache for %s", st)

		Eventually(func() api.SyncStatus {
			_, status := breadcrumbContents(t, follower.caches[st])
			return status
		}, 10*time.Second, 100*time.Millisecond).Should(Equal(api.InSync), "follower in-sync for %s", st)

		// Downstream client should match too.
		Eventually(cc.recorder.Status, 10*time.Second, 100*time.Millisecond).Should(Equal(api.InSync))
		Eventually(func() map[string]string {
			return recorderValues(cc.recorder)
		}, 10*time.Second, 100*time.Millisecond).Should(Equal(exp), "client of follower for %s", st)
	}
}

// TestChainedTypha_UpstreamRestartReconciliation is the most important WS-A
// test: while the upstream server is down, the follower keeps serving stale
// data; after the upstream comes back (with adds, updates and deletes applied
// during the outage), the follower reconciles and the changes propagate all the
// way to a client of the follower.
func TestChainedTypha_UpstreamRestartReconciliation(t *testing.T) {
	RegisterTestingT(t)
	logutils.RedirectLogrusToTestingT(t)

	st := syncproto.SyncerTypeFelix
	upstream := newUpstreamHarness(st)
	upstream.Start()
	t.Cleanup(upstream.Stop)

	follower := newFollowerHarness(upstream.Addr(), st)
	follower.Start()
	t.Cleanup(follower.Stop)

	// Initial snapshot: keep, update, drop.
	upstream.SendStatus(st, api.ResyncInProgress)
	keepPath, _ := upstream.SendConfigUpdate(st, "keep", "keep-v1")
	updatePath, _ := upstream.SendConfigUpdate(st, "update", "update-v1")
	dropPath, _ := upstream.SendConfigUpdate(st, "drop", "drop-v1")
	upstream.SendStatus(st, api.InSync)

	cc := newChainClient(t, follower.Addr(), st)

	initial := map[string]string{
		keepPath:   "keep-v1",
		updatePath: "update-v1",
		dropPath:   "drop-v1",
	}
	Eventually(func() map[string]string { return recorderValues(cc.recorder) },
		10*time.Second, 100*time.Millisecond).Should(Equal(initial))
	Eventually(cc.recorder.Status, 10*time.Second, 100*time.Millisecond).Should(Equal(api.InSync))

	// Take the upstream server down.  The follower should keep serving the
	// stale data it already has.
	t.Log("Stopping upstream server")
	upstream.StopServerOnly()

	// Client should still see the old data (served stale) for a while.
	Consistently(func() map[string]string { return recorderValues(cc.recorder) },
		"1s", "100ms").Should(Equal(initial))

	// Apply changes to the upstream caches while the server is down:
	//   - add a new key
	//   - update an existing key
	//   - delete a key
	t.Log("Mutating upstream while server is down")
	addPath, _ := upstream.SendConfigUpdate(st, "added", "added-v1")
	upstream.SendConfigUpdate(st, "update", "update-v2")
	upstream.SendDelete(st, "drop")

	// Bring the upstream server back up; the follower's syncclient reconnects
	// and the dedupe buffer reconciles (synthesizing the delete for "drop").
	t.Log("Restarting upstream server")
	upstream.RestartServer()

	expectedAfter := map[string]string{
		keepPath:   "keep-v1",
		updatePath: "update-v2",
		addPath:    "added-v1",
		// dropPath deleted
	}
	Eventually(func() map[string]string { return recorderValues(cc.recorder) },
		20*time.Second, 100*time.Millisecond).Should(Equal(expectedAfter),
		"client should reconcile adds/updates/deletes after upstream restart")
	Eventually(cc.recorder.Status, 10*time.Second, 100*time.Millisecond).Should(Equal(api.InSync))
}

// TestChainedTypha_CompressionAcrossChain verifies the follower negotiates
// snappy compression / decoder restart with the upstream (i.e. the chain works
// with decoder restart enabled, which is the default).  We simply assert data
// flows; the follower's source uses default options (decoder restart on).
func TestChainedTypha_CompressionAcrossChain(t *testing.T) {
	RegisterTestingT(t)
	logutils.RedirectLogrusToTestingT(t)

	st := syncproto.SyncerTypeFelix
	upstream := newUpstreamHarness(st)
	upstream.Start()
	t.Cleanup(upstream.Stop)

	follower := newFollowerHarness(upstream.Addr(), st)
	follower.Start()
	t.Cleanup(follower.Stop)

	upstream.SendStatus(st, api.ResyncInProgress)
	// Enough data to make compression meaningful and to force several
	// breadcrumbs (cache batch size is 10).
	exp := map[string]string{}
	for i := 0; i < 50; i++ {
		path, _ := upstream.SendConfigUpdate(st, stKeyName(st, i), stValue(0, i))
		exp[path] = stValue(0, i)
	}
	upstream.SendStatus(st, api.InSync)

	cc := newChainClient(t, follower.Addr(), st)
	Eventually(func() map[string]string { return recorderValues(cc.recorder) },
		15*time.Second, 100*time.Millisecond).Should(Equal(exp))
	Eventually(cc.recorder.Status, 10*time.Second, 100*time.Millisecond).Should(Equal(api.InSync))
}

func stKeyName(st syncproto.SyncerType, j int) string {
	return string(st) + "-key-" + itoa(j)
}

func stValue(i, j int) string {
	return "value-" + itoa(i) + "-" + itoa(j)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func recorderValues(r *fvtests.StateRecorder) map[string]string {
	out := map[string]string{}
	for path, upd := range r.KVs() {
		if s, ok := upd.Value.(string); ok {
			out[path] = s
		}
	}
	return out
}
