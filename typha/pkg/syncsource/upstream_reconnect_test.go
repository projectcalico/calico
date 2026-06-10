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

package syncsource

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/snapcache"
	"github.com/projectcalico/calico/typha/pkg/synccheck"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
	"github.com/projectcalico/calico/typha/pkg/syncserver"
)

// restartCountingSink wraps the syncer callbacks and counts how many times
// OnTyphaConnectionRestarted fires, so a test can observe that a reconnect
// actually happened.  It is restart-aware so the syncclient keeps reconnecting.
type restartCountingSink struct {
	restarts atomic.Int64

	mu       sync.Mutex
	inSync   bool
	statuses []api.SyncStatus
}

func (s *restartCountingSink) OnTyphaConnectionRestarted() {
	s.restarts.Add(1)
}

func (s *restartCountingSink) OnStatusUpdated(status api.SyncStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statuses = append(s.statuses, status)
	if status == api.InSync {
		s.inSync = true
	}
}

func (s *restartCountingSink) OnUpdates([]api.Update) {}

func (s *restartCountingSink) inSyncSeen() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inSync
}

// startTestServer brings up a minimal syncserver with one in-sync felix cache on
// a random port and returns its address plus a stop func.
func startTestServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	cache := snapcache.New(snapcache.Config{
		MaxBatchSize:   10,
		WakeUpInterval: 50 * time.Millisecond,
		Name:           "felix",
	})
	cacheCtx, cacheCancel := context.WithCancel(context.Background())
	cache.Start(cacheCtx)
	cache.OnStatusUpdated(api.InSync)

	srv := syncserver.New(
		map[syncproto.SyncerType]syncserver.BreadcrumbProvider{syncproto.SyncerTypeFelix: cache},
		syncserver.Config{
			PingInterval:     10 * time.Second,
			Port:             syncserver.PortRandom,
			DropInterval:     50 * time.Millisecond,
			ChecksumInterval: 50 * time.Millisecond,
		},
	)
	srvCtx, srvCancel := context.WithCancel(context.Background())
	srv.Start(srvCtx)

	addr = "127.0.0.1:" + itoaPort(srv.Port())
	stop = func() {
		srvCancel()
		srv.Finished.Wait()
		cacheCancel()
		<-cache.Done
	}
	return addr, stop
}

func itoaPort(p int) string {
	if p == 0 {
		return "0"
	}
	var b []byte
	for p > 0 {
		b = append([]byte{byte('0' + p%10)}, b...)
		p /= 10
	}
	return string(b)
}

// TestUpstreamTyphaSource_ReconnectForcesRestart verifies that calling
// Reconnect() on a connected source drops the current connection and the
// syncclient's restart-aware loop reconnects (firing OnTyphaConnectionRestarted
// on the sink).  This is the path the checksum verifier's RequestReconnect
// drives on a confirmed mismatch.
func TestUpstreamTyphaSource_ReconnectForcesRestart(t *testing.T) {
	addr, stop := startTestServer(t)
	defer stop()

	sink := &restartCountingSink{}
	src := NewUpstreamTyphaSource(
		discovery.New(discovery.WithAddrOverride(addr)),
		UpstreamConfig{
			MyVersion:  "test",
			MyHostname: "test-host",
			SyncerType: syncproto.SyncerTypeFelix,
		},
		sink,
	)
	if err := src.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer src.Stop()

	// Wait until the initial sync completes.
	waitFor(t, sink.inSyncSeen, 5*time.Second, "initial InSync")
	before := sink.restarts.Load()

	// Force a reconnect.
	ups, ok := src.(UpstreamTyphaSource)
	if !ok {
		t.Fatal("source is not an UpstreamTyphaSource")
	}
	ups.Reconnect()

	// The restart-aware loop should reconnect, firing OnTyphaConnectionRestarted.
	waitFor(t, func() bool { return sink.restarts.Load() > before }, 5*time.Second,
		"OnTyphaConnectionRestarted after Reconnect")
}

// TestUpstreamTyphaSource_VerifierMismatchTriggersReconnect wires a real
// synccheck.Verifier whose RequestReconnect is the source's Reconnect, then
// drives a confirmed checksum mismatch and asserts the source reconnects.  This
// is exactly the daemon's follower wiring (minus the snapcache plumbing), proving
// a mismatch reaches the reconnect path end to end.
func TestUpstreamTyphaSource_VerifierMismatchTriggersReconnect(t *testing.T) {
	addr, stop := startTestServer(t)
	defer stop()

	sink := &restartCountingSink{}
	src := NewUpstreamTyphaSource(
		discovery.New(discovery.WithAddrOverride(addr)),
		UpstreamConfig{
			MyVersion:  "test",
			MyHostname: "test-host",
			SyncerType: syncproto.SyncerTypeFelix,
			ClientOptions: syncclient.Options{
				ChecksumCheckInterval: 50 * time.Millisecond,
			},
		},
		sink,
	)
	ups := src.(UpstreamTyphaSource)

	// Local checksum is deliberately wrong (KVCount 999) so the comparison
	// against the server's empty snapshot always mismatches.  The syncclient's
	// own checksum-checker loop drives the comparison; once the mismatch has
	// persisted it calls RequestReconnect = the source's Reconnect, which forces
	// a reconnect (firing OnTyphaConnectionRestarted).  We assert at least two
	// restarts so we know it was the verifier (not just the initial connect).
	verifier := synccheck.NewVerifier(synccheck.VerifierConfig{
		SyncerType:     string(syncproto.SyncerTypeFelix),
		MismatchAction: synccheck.MismatchActionReconnect,
		Local: synccheck.LocalChecksumFunc(func() synccheck.Checksum {
			return synccheck.Checksum{XOR: 0xdeadbeef, KVCount: 999}
		}),
		RequestReconnect:     ups.Reconnect,
		PersistChecks:        1,
		ReconnectMinInterval: time.Millisecond,
	})
	ups.SetChecksumVerifier(verifier)

	if err := src.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer src.Stop()

	// The verifier should drive repeated reconnects (each reconnect re-syncs,
	// the checksum still mismatches, so it reconnects again).  Seeing several
	// restarts proves the mismatch→reconnect path fires.
	waitFor(t, func() bool { return sink.restarts.Load() >= 2 }, 10*time.Second,
		"repeated reconnects driven by confirmed checksum mismatch")
}

func waitFor(t *testing.T, cond func() bool, timeout time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
