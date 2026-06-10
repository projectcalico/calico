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
