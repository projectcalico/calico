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
	"net"
	"testing"
	"time"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/dedupebuffer"
	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

// deadAddr returns an address that nothing is listening on (we bind a listener
// to grab a free port, then close it).
func deadAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// TestUpstreamTyphaSource_StopWhileConnecting verifies that Stop() returns
// promptly (closing Done) even when the source is stuck retrying the initial
// connection to an upstream that isn't there.  This exercises the
// "no more callbacks after Stop" contract during the connecting phase.
func TestUpstreamTyphaSource_StopWhileConnecting(t *testing.T) {
	buf := dedupebuffer.New()
	src := NewUpstreamTyphaSource(
		discovery.New(discovery.WithAddrOverride(deadAddr(t))),
		UpstreamConfig{
			MyVersion:  "test",
			MyHostname: "test-host",
			SyncerType: syncproto.SyncerTypeFelix,
		},
		buf,
	)

	if err := src.Start(context.Background()); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	// Give it a moment to enter its retry loop.
	time.Sleep(50 * time.Millisecond)

	stopReturned := make(chan struct{})
	go func() {
		src.Stop()
		close(stopReturned)
	}()

	select {
	case <-stopReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return while source was connecting")
	}

	select {
	case <-src.Done():
	case <-time.After(time.Second):
		t.Fatal("Done not closed after Stop")
	}
}

// blackHoleAddr returns an address whose dial hangs rather than failing fast.
// We use a TEST-NET-1 address (RFC 5737, 192.0.2.0/24, guaranteed not routed on
// the public internet) so a TCP SYN gets no response and the dial blocks until
// its timeout.  This models a dead upstream leader whose IP no longer answers,
// as opposed to deadAddr() (a closed local port) which is refused instantly.
func blackHoleAddr() string {
	return "192.0.2.1:5473"
}

// TestUpstreamTyphaSource_StopWhileDialBlackHole is the regression test for the
// promotion stall: when the upstream leader dies, a follower promoting to leader
// must tear down its upstream source promptly even if the source is stuck in an
// in-flight TCP/TLS dial to the now-unreachable leader.  Previously the dial used
// a fixed 10s timeout that ignored context cancellation, so Stop() blocked for up
// to that timeout (observed as a >9s role-transition stall in the felix FV).  The
// dial now honours the connection context, so Stop() must return well under the
// dial timeout.
func TestUpstreamTyphaSource_StopWhileDialBlackHole(t *testing.T) {
	buf := dedupebuffer.New()
	src := NewUpstreamTyphaSource(
		discovery.New(discovery.WithAddrOverride(blackHoleAddr())),
		UpstreamConfig{
			MyVersion:  "test",
			MyHostname: "test-host",
			SyncerType: syncproto.SyncerTypeFelix,
		},
		buf,
	)

	if err := src.Start(context.Background()); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	// Give the loop time to enter the (hanging) dial.
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	stopReturned := make(chan struct{})
	go func() {
		src.Stop()
		close(stopReturned)
	}()

	// The dial timeout is 10s; with context-aware dialing Stop must abort the
	// in-flight dial near-instantly.  Allow generous slack for slow CI but well
	// below the dial timeout so a regression (reverting to a ctx-ignoring dial)
	// fails this test.
	select {
	case <-stopReturned:
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("Stop took %v, expected it to abort the in-flight dial promptly", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not return while source was stuck dialling a black-hole address")
	}

	select {
	case <-src.Done():
	case <-time.After(time.Second):
		t.Fatal("Done not closed after Stop")
	}
}

// TestUpstreamTyphaSource_StopBeforeAndAfter verifies Stop is idempotent and
// safe to call multiple times.
func TestUpstreamTyphaSource_StopIdempotent(t *testing.T) {
	buf := dedupebuffer.New()
	src := NewUpstreamTyphaSource(
		discovery.New(discovery.WithAddrOverride(deadAddr(t))),
		UpstreamConfig{SyncerType: syncproto.SyncerTypeFelix},
		buf,
	)
	_ = src.Start(context.Background())
	time.Sleep(20 * time.Millisecond)
	src.Stop()
	src.Stop() // Should not panic or block.

	select {
	case <-src.Done():
	case <-time.After(time.Second):
		t.Fatal("Done not closed after Stop")
	}
}

// TestUpstreamTyphaSource_ContextCancelStops verifies that cancelling the
// context passed to Start terminates the source.
func TestUpstreamTyphaSource_ContextCancelStops(t *testing.T) {
	buf := dedupebuffer.New()
	src := NewUpstreamTyphaSource(
		discovery.New(discovery.WithAddrOverride(deadAddr(t))),
		UpstreamConfig{SyncerType: syncproto.SyncerTypeFelix},
		buf,
	)
	ctx, cancel := context.WithCancel(context.Background())
	_ = src.Start(ctx)
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-src.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done not closed after context cancel")
	}
}

// Compile-time assertion that dedupebuffer satisfies the sink type.
var _ api.SyncerCallbacks = (*dedupebuffer.DedupeBuffer)(nil)
