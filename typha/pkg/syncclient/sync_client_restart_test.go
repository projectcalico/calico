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

package syncclient_test

import (
	"context"
	"encoding/gob"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

// handshakeServer accepts connections, completes the Typha handshake on each,
// sends an InSync status, then reads until the client disconnects.  It counts
// how many connections it has accepted so a test can observe a reconnect.
func handshakeServer(t *testing.T, l net.Listener, accepted *atomic.Int64) {
	t.Helper()
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		accepted.Add(1)
		go func(conn net.Conn) {
			defer conn.Close()
			enc := gob.NewEncoder(conn)
			dec := gob.NewDecoder(conn)
			var env syncproto.Envelope
			if err := dec.Decode(&env); err != nil {
				return
			}
			hello, ok := env.Message.(syncproto.MsgClientHello)
			if !ok {
				return
			}
			_ = enc.Encode(syncproto.Envelope{Message: syncproto.MsgServerHello{
				Version:                     "test",
				SyncerType:                  hello.SyncerType,
				SupportsNodeResourceUpdates: true,
				ServerConnID:                hello.ClientConnID,
			}})
			_ = enc.Encode(syncproto.Envelope{Message: syncproto.MsgSyncStatus{SyncStatus: api.InSync}})
			for {
				if err := dec.Decode(&env); err != nil {
					return
				}
			}
		}(conn)
	}
}

// TestRestartConnection_ReconnectsWithoutTearingDownClient verifies that
// RestartConnection() drops the current connection and the client reconnects
// (firing OnTyphaConnectionRestarted) while staying alive, and that Stop() still
// cleanly shuts it down afterwards.
func TestRestartConnection_ReconnectsWithoutTearingDownClient(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	var accepted atomic.Int64
	go handshakeServer(t, l, &accepted)

	rec := &restartAwareRecorder{}
	c := syncclient.New(
		discovery.New(discovery.WithAddrOverride(l.Addr().String())),
		"v", "h", "i",
		rec,
		&syncclient.Options{SyncerType: syncproto.SyncerTypeFelix, DisableDecoderRestart: true},
	)
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Wait for the first connection to be established.
	waitFor(t, 5*time.Second, func() bool { return accepted.Load() >= 1 })

	restartsBefore := func() int {
		rec.lock.Lock()
		defer rec.lock.Unlock()
		return rec.restarts
	}()

	// Force a reconnect.
	c.RestartConnection()

	// A second connection should be accepted and OnTyphaConnectionRestarted
	// should fire, without the client exiting.
	waitFor(t, 5*time.Second, func() bool { return accepted.Load() >= 2 })
	waitFor(t, 5*time.Second, func() bool {
		rec.lock.Lock()
		defer rec.lock.Unlock()
		return rec.restarts > restartsBefore
	})

	// The client is still alive: Stop() cleanly shuts it down.
	done := make(chan struct{})
	go func() { c.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop blocked after RestartConnection")
	}
}

// TestRestartConnection_BeforeConnectIsNoOp verifies RestartConnection is a safe
// no-op when no connection has been established.
func TestRestartConnection_BeforeConnectIsNoOp(t *testing.T) {
	c := syncclient.New(
		discovery.New(discovery.WithAddrOverride(deadAddr(t))),
		"v", "h", "i",
		&restartAwareRecorder{},
		&syncclient.Options{SyncerType: syncproto.SyncerTypeFelix},
	)
	// Must not panic or block.
	c.RestartConnection()
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		if cond() {
			return
		}
		select {
		case <-deadline:
			t.Fatal("condition not met within timeout")
		case <-time.After(10 * time.Millisecond):
		}
	}
}
