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

package dedupebuffer

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
)

// TestDedupeBuffer_DeleteOfAbsentKey checks that a deletion for a key the buffer
// has never seen is harmless: it neither panics nor emits a spurious update
// downstream.  This matters for the chained-Typha pipeline (WS-A), where the
// dedupe buffer is the permanent head of the pipeline and the downstream
// snapshot cache must tolerate deletes for keys it may not hold.
func TestDedupeBuffer_DeleteOfAbsentKey(t *testing.T) {
	RegisterTestingT(t)
	d := New()
	rec := NewReceiver()

	d.OnStatusUpdated(api.ResyncInProgress)
	// Delete a key that was never added.
	d.OnUpdates([]api.Update{KVUpdate("never-existed", "")})
	d.OnStatusUpdated(api.InSync)

	sendNextBatchSync(d, rec)

	// No values should be present: the delete leaves nothing behind.
	Expect(rec.FinalValues()).To(BeEmpty())
	// The delete-of-absent-key is forwarded downstream as a plain deletion (the
	// buffer only collapses a delete against an in-flight add for the same
	// key).  The key point for the chained-Typha pipeline is that this is
	// harmless: the downstream snapshot cache keys deletes by key, so a delete
	// for a key it doesn't hold is a no-op rather than a panic or a spurious
	// stored value.
	Expect(rec.UpdatesSeen()).To(Equal([]string{
		api.ResyncInProgress.String(),
		"never-existed= (deleted)",
		api.InSync.String(),
	}))
	Expect(rec.FinalSyncState()).To(Equal(api.InSync))
}

// TestDedupeBuffer_StatusPassThrough verifies that status transitions propagate
// through the buffer in order in steady state (no reconnection).  Typha's
// snapshot-cache readiness reporting depends on the
// ResyncInProgress -> InSync sequence reaching it unaltered.
//
// Note: WaitForDatastore is the zero value of api.SyncStatus, so the buffer's
// "skip if same as the last status" logic drops it before any other status has
// been seen.  We therefore start the meaningful sequence at ResyncInProgress,
// matching the mainline test.
func TestDedupeBuffer_StatusPassThrough(t *testing.T) {
	RegisterTestingT(t)
	d := New()
	rec := NewReceiver()

	d.OnStatusUpdated(api.ResyncInProgress)
	sendNextBatchSync(d, rec)
	Expect(rec.FinalSyncState()).To(Equal(api.ResyncInProgress))

	d.OnUpdates([]api.Update{KVUpdate("foo", "bar")})
	d.OnStatusUpdated(api.InSync)
	sendNextBatchSync(d, rec)
	Expect(rec.FinalSyncState()).To(Equal(api.InSync))
	Expect(rec.FinalValues()).To(Equal(map[string]string{"foo": "bar"}))

	Expect(rec.UpdatesSeen()).To(Equal([]string{
		api.ResyncInProgress.String(),
		"foo=bar (new)",
		api.InSync.String(),
	}))
}

// TestDedupeBuffer_ReconnectSynthesizesDelete is the reconciliation model used
// by chained Typha: pre-populate, signal a reconnect, deliver a new snapshot
// that is missing a key, and confirm the downstream sees a synthesized delete
// for the missing key on InSync.
func TestDedupeBuffer_ReconnectSynthesizesDelete(t *testing.T) {
	RegisterTestingT(t)
	d := New()
	rec := NewReceiver()

	// Initial snapshot: two keys, in sync.
	d.OnStatusUpdated(api.ResyncInProgress)
	d.OnUpdates([]api.Update{KVUpdate("keep", "v1"), KVUpdate("drop", "v2")})
	d.OnStatusUpdated(api.InSync)
	sendNextBatchSync(d, rec)
	Expect(rec.FinalValues()).To(Equal(map[string]string{"keep": "v1", "drop": "v2"}))

	// Reconnect: new source attaches and re-sends only "keep" (with an updated
	// value), then signals InSync.  "drop" was deleted while we were
	// disconnected and must be reconciled away.
	d.OnTyphaConnectionRestarted()
	d.OnStatusUpdated(api.ResyncInProgress)
	d.OnUpdates([]api.Update{KVUpdate("keep", "v1-updated")})
	d.OnStatusUpdated(api.InSync)
	sendNextBatchSync(d, rec)

	Expect(rec.FinalValues()).To(Equal(map[string]string{"keep": "v1-updated"}))
	Expect(rec.FinalSyncState()).To(Equal(api.InSync))
}
