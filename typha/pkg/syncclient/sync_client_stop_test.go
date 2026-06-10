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
	"sync"
	"testing"
	"time"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

// restartAwareRecorder is a minimal RestartAwareCallbacks implementation so the
// client treats it as restart-aware (and thus retries internally rather than
// exiting on disconnect).
type restartAwareRecorder struct {
	lock     sync.Mutex
	statuses []api.SyncStatus
	restarts int
}

func (r *restartAwareRecorder) OnStatusUpdated(status api.SyncStatus) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.statuses = append(r.statuses, status)
}

func (r *restartAwareRecorder) OnUpdates(_ []api.Update) {}

func (r *restartAwareRecorder) OnTyphaConnectionRestarted() {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.restarts++
}

func deadAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// TestStop_BeforeStart verifies Stop is a no-op (doesn't block/panic) if Start
// was never called.
func TestStop_BeforeStart(t *testing.T) {
	c := syncclient.New(
		discovery.New(discovery.WithAddrOverride(deadAddr(t))),
		"v", "h", "i",
		&restartAwareRecorder{},
		&syncclient.Options{SyncerType: syncproto.SyncerTypeFelix},
	)
	done := make(chan struct{})
	go func() { c.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop before Start blocked")
	}
}

// TestStop_WhileConnecting verifies Stop returns once the client is running and
// retrying its connection to an unavailable server.  The client connects
// synchronously in Start (and fails since nothing is listening), so we point it
// at a listener that accepts but never replies, leaving the client blocked in
// the handshake read; then Stop must unblock it.
func TestStop_WhileHandshaking(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	// Accept connections but never send the ServerHello, so the client blocks
	// reading the handshake response.
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			// Hold the connection open without replying.
			_ = conn
		}
	}()

	c := syncclient.New(
		discovery.New(discovery.WithAddrOverride(l.Addr().String())),
		"v", "h", "i",
		&restartAwareRecorder{},
		&syncclient.Options{SyncerType: syncproto.SyncerTypeFelix},
	)
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	done := make(chan struct{})
	go func() { c.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop blocked while handshaking")
	}
}

// TestStop_WhileStreaming verifies Stop cleanly shuts the client down after a
// successful handshake while it is streaming.  We run a tiny gob server that
// completes the handshake and then sends a status + pings.
func TestStop_WhileStreaming(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		enc := gob.NewEncoder(conn)
		dec := gob.NewDecoder(conn)

		// Read ClientHello.
		var env syncproto.Envelope
		if err := dec.Decode(&env); err != nil {
			return
		}
		hello, ok := env.Message.(syncproto.MsgClientHello)
		if !ok {
			return
		}
		// Send ServerHello (no decoder restart to keep things simple).
		_ = enc.Encode(syncproto.Envelope{Message: syncproto.MsgServerHello{
			Version:                     "test",
			SyncerType:                  hello.SyncerType,
			SupportsNodeResourceUpdates: true,
			ServerConnID:                hello.ClientConnID,
		}})
		// Send an InSync status.
		_ = enc.Encode(syncproto.Envelope{Message: syncproto.MsgSyncStatus{SyncStatus: api.InSync}})
		// Then just sit reading until the client goes away.
		for {
			if err := dec.Decode(&env); err != nil {
				return
			}
		}
	}()

	rec := &restartAwareRecorder{}
	c := syncclient.New(
		discovery.New(discovery.WithAddrOverride(l.Addr().String())),
		"v", "h", "i",
		rec,
		// Disable decoder restart so the simple server above doesn't need to
		// implement compression negotiation.
		&syncclient.Options{SyncerType: syncproto.SyncerTypeFelix, DisableDecoderRestart: true},
	)
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Wait until the InSync status propagates, i.e. we're streaming.
	deadline := time.After(5 * time.Second)
	for {
		rec.lock.Lock()
		gotInSync := false
		for _, s := range rec.statuses {
			if s == api.InSync {
				gotInSync = true
			}
		}
		rec.lock.Unlock()
		if gotInSync {
			break
		}
		select {
		case <-deadline:
			t.Fatal("never reached InSync (streaming) phase")
		case <-time.After(10 * time.Millisecond):
		}
	}

	done := make(chan struct{})
	go func() { c.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop blocked while streaming")
	}

	// After Stop returns, Finished must be complete (no more callbacks).
	finishedDone := make(chan struct{})
	go func() { c.Finished.Wait(); close(finishedDone) }()
	select {
	case <-finishedDone:
	case <-time.After(time.Second):
		t.Fatal("Finished not complete after Stop returned")
	}
}
