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

// Package syncsource defines the SyncerSource abstraction used at the head of
// each of Typha's syncer pipelines.  A SyncerSource produces syncer callbacks
// (status updates and KV updates) into a sink.  There are two implementations:
//
//   - datastoreSource wraps a real bapi.Syncer connected to the datastore.
//     This is the source used by a "leader" Typha (or any Typha in the
//     non-hierarchical, default configuration).
//
//   - upstreamTyphaSource wraps a syncclient.SyncerClient connected to an
//     upstream Typha.  This is the source used by a "follower" Typha when
//     hierarchical mode is enabled.
//
// Both implementations satisfy the SyncerSource interface so that the daemon
// can swap one for the other without the rest of the pipeline (dedupe buffer,
// validation filter, snapshot cache) needing to know which is in use.  See
// typha/DESIGN.md, "Hierarchical mode", for the design rationale.
package syncsource

import (
	"context"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
)

// SyncerSource produces syncer callbacks into a fixed sink (supplied at
// construction time).  Implementations either wrap a real datastore Syncer or
// a syncclient connection to an upstream Typha.
//
// The lifecycle contract is:
//
//   - Start(ctx) begins delivering callbacks to the sink.  It may block briefly
//     (e.g. to make an initial connection) but should not block for the
//     lifetime of the source.  Returns an error if it cannot start at all.
//   - Stop() halts the source.  It is idempotent and MUST block until no
//     further callbacks can be delivered to the sink.  WS-C relies on this
//     guarantee: after Stop() returns it is safe to attach a new source to the
//     same sink (and call OnTyphaConnectionRestarted on it) without racing with
//     callbacks from the old source.
//   - Done() returns a channel that is closed when the source has terminated,
//     either because of a fatal error or because Stop() was called.  The daemon
//     watches this so it can react to a source dying (mirrors Felix watching
//     typhaConnection.Finished).
type SyncerSource interface {
	Start(ctx context.Context) error
	Stop()
	Done() <-chan struct{}
}

// Callbacks is the sink that a SyncerSource delivers into.  It is exactly the
// syncer callbacks API; in Typha this is always a dedupebuffer.DedupeBuffer
// (which additionally implements syncclient.RestartAwareCallbacks).
type Callbacks = api.SyncerCallbacks
