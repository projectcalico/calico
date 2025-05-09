// Copyright (c) 2023-2024 Tigera, Inc. All rights reserved.
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
	"fmt"
	"sync"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

func init() {
	// Set up logging formatting.
	logutils.ConfigureFormatter("test")
	logrus.SetLevel(logrus.DebugLevel)
}

func TestDedupeBuffer_SyncNoDupes(t *testing.T) {
	for _, onUpdatesVersion := range []string{"KeysKnown", "KeysNotKnown"} {
		t.Run(onUpdatesVersion, func(t *testing.T) {
			RegisterTestingT(t)
			d := New()
			onUpdates := wrapOnUpdates(d, onUpdatesVersion)
			rec := NewReceiver()

			d.OnStatusUpdated(api.WaitForDatastore)
			d.OnStatusUpdated(api.ResyncInProgress)
			onUpdates([]api.Update{KVUpdate("foo", "bar")})
			onUpdates([]api.Update{KVUpdate("foo2", "bar2")})
			d.OnStatusUpdated(api.InSync)

			sendNextBatchSync(d, rec)

			Expect(rec.FinalValues()).To(Equal(map[string]string{
				"foo":  "bar",
				"foo2": "bar2",
			}))
			Expect(rec.FinalSyncState()).To(Equal(api.InSync))
			Expect(rec.UpdatesSeen()).To(Equal([]string{
				// WaitForDatastore gets skipped since it's in the same batch.
				api.ResyncInProgress.String(),
				"foo=bar (new)",
				"foo2=bar2 (new)",
				api.InSync.String(),
			}))

			// Now send in a deletion.
			rec.ResetUpdatesSeen()
			onUpdates([]api.Update{KVUpdate("foo", "")})
			sendNextBatchSync(d, rec)
			Expect(rec.FinalValues()).To(Equal(map[string]string{
				"foo2": "bar2",
			}))
			Expect(rec.FinalSyncState()).To(Equal(api.InSync))
			Expect(rec.UpdatesSeen()).To(Equal([]string{
				"foo= (deleted)",
			}))

			// Now send in a deletion, which is reverted before being sent.
			rec.ResetUpdatesSeen()
			onUpdates([]api.Update{KVUpdate("foo2", "")})
			onUpdates([]api.Update{KVUpdate("foo2", "bar3")})
			sendNextBatchSync(d, rec)
			Expect(rec.FinalValues()).To(Equal(map[string]string{
				"foo2": "bar3",
			}))
			Expect(rec.FinalSyncState()).To(Equal(api.InSync))
			Expect(rec.UpdatesSeen()).To(Equal([]string{
				"foo2=bar3 (updated)",
			}))

			// Update both keys, should work as normal.
			rec.ResetUpdatesSeen()
			onUpdates([]api.Update{KVUpdate("foo", "bar")})
			onUpdates([]api.Update{KVUpdate("foo2", "bar2")})
			sendNextBatchSync(d, rec)
			Expect(rec.FinalValues()).To(Equal(map[string]string{
				"foo":  "bar",
				"foo2": "bar2",
			}))
			Expect(rec.FinalSyncState()).To(Equal(api.InSync))
			Expect(rec.UpdatesSeen()).To(Equal([]string{
				// WaitForDatastore gets skipped since it's in the same batch.
				"foo=bar (new)",
				"foo2=bar2 (updated)",
			}))
		})
	}
}

func TestDedupeBuffer_SyncWithDupes(t *testing.T) {
	for _, onUpdatesVersion := range []string{"KeysKnown", "KeysNotKnown"} {
		t.Run(onUpdatesVersion, func(t *testing.T) {
			RegisterTestingT(t)
			d := New()
			onUpdates := wrapOnUpdates(d, onUpdatesVersion)
			rec := NewReceiver()

			d.OnStatusUpdated(api.WaitForDatastore)
			d.OnStatusUpdated(api.ResyncInProgress)
			onUpdates([]api.Update{KVUpdate("foo", "bar")})
			onUpdates([]api.Update{KVUpdate("foo2", "bar2")})
			onUpdates([]api.Update{KVUpdate("foo3", "bar3")})
			onUpdates([]api.Update{KVUpdate("foo", "bar3")})
			onUpdates([]api.Update{KVUpdate("foo2", "")})
			d.OnStatusUpdated(api.InSync)
			d.OnStatusUpdated(api.ResyncInProgress)
			d.OnStatusUpdated(api.ResyncInProgress)
			d.OnStatusUpdated(api.InSync)

			sendNextBatchSync(d, rec)

			Expect(rec.FinalValues()).To(Equal(map[string]string{
				"foo":  "bar3",
				"foo3": "bar3",
			}))
			Expect(rec.FinalSyncState()).To(Equal(api.InSync))
			Expect(rec.UpdatesSeen()).To(Equal([]string{
				// WaitForDatastore skipped.
				api.ResyncInProgress.String(),
				"foo=bar3 (new)", // Update leap-frogs the original value.
				"foo3=bar3 (new)",
				api.InSync.String(),
			}))
		})
	}
}

// TestDedupeBuffer_TyphaResyncMainline tests resync with Typha where some keys
// stay the same, some are modified and some deleted during the resync.
func TestDedupeBuffer_TyphaResyncMainline(t *testing.T) {
	for _, onUpdatesVersion := range []string{"KeysKnown", "KeysNotKnown"} {
		t.Run(onUpdatesVersion, func(t *testing.T) {
			RegisterTestingT(t)
			d := New()
			onUpdates := wrapOnUpdates(d, onUpdatesVersion)
			rec := NewReceiver()

			// Send a simple initial state.
			d.OnStatusUpdated(api.WaitForDatastore)
			d.OnStatusUpdated(api.ResyncInProgress)
			onUpdates([]api.Update{KVUpdate("key1", "v1")})
			onUpdates([]api.Update{KVUpdate("key2", "v2")})
			onUpdates([]api.Update{KVUpdate("key3", "v3")})
			d.OnStatusUpdated(api.InSync)
			sendNextBatchSync(d, rec)
			Expect(rec.FinalValues()).To(Equal(map[string]string{
				"key1": "v1",
				"key2": "v2",
				"key3": "v3",
			}))
			Expect(rec.FinalSyncState()).To(Equal(api.InSync))
			Expect(rec.UpdatesSeen()).To(Equal([]string{
				// WaitForDatastore skipped.
				api.ResyncInProgress.String(),
				"key1=v1 (new)",
				"key2=v2 (new)",
				"key3=v3 (new)",
				api.InSync.String(),
			}))
			rec.ResetUpdatesSeen()

			// Typha reconnection.
			d.OnTyphaConnectionRestarted()
			d.OnStatusUpdated(api.WaitForDatastore)
			d.OnStatusUpdated(api.ResyncInProgress)
			onUpdates([]api.Update{KVUpdate("key1", "v1")})  // Same
			onUpdates([]api.Update{KVUpdate("key2", "v2b")}) // Changed
			// onUpdates([]api.Update{KVUpdate("key3", "v3")}) // Deleted as part of resync.
			onUpdates([]api.Update{KVUpdate("key4", "v4")})
			d.OnStatusUpdated(api.InSync)
			sendNextBatchSync(d, rec)
			Expect(rec.FinalValues()).To(Equal(map[string]string{
				"key1": "v1",
				"key2": "v2b",
				"key4": "v4",
			}))
			Expect(rec.FinalSyncState()).To(Equal(api.InSync))
			Expect(rec.UpdatesSeen()).To(Equal([]string{
				api.ResyncInProgress.String(),
				"key1=v1 (updated)",
				"key2=v2b (updated)",
				"key4=v4 (new)",
				"key3= (deleted)",
				api.InSync.String(),
			}))
		})
	}
}

// TestDedupeBuffer_TyphaDoubleResyncNoFlush tests a back-to-back resync with
// Typha without flushing the queue. When the second resync begins the queue
// should get thrown away so the end result should be the same as if the first
// resync never started.
func TestDedupeBuffer_TyphaDoubleResyncNoFlush(t *testing.T) {
	// Tests a resync with Typha that itself gets interrupted by a new resync.

	for _, onUpdatesVersion := range []string{"KeysKnown", "KeysNotKnown"} {
		t.Run(onUpdatesVersion, func(t *testing.T) {
			RegisterTestingT(t)
			d := New()
			onUpdates := wrapOnUpdates(d, onUpdatesVersion)
			rec := NewReceiver()

			// Send a simple initial state.
			d.OnStatusUpdated(api.WaitForDatastore)
			d.OnStatusUpdated(api.ResyncInProgress)
			onUpdates([]api.Update{KVUpdate("key1", "v1")})
			onUpdates([]api.Update{KVUpdate("key2", "v2")})
			onUpdates([]api.Update{KVUpdate("key3", "v3")})
			d.OnStatusUpdated(api.InSync)
			sendNextBatchSync(d, rec)
			Expect(rec.FinalValues()).To(Equal(map[string]string{
				"key1": "v1",
				"key2": "v2",
				"key3": "v3",
			}))
			Expect(rec.FinalSyncState()).To(Equal(api.InSync))
			Expect(rec.UpdatesSeen()).To(Equal([]string{
				// WaitForDatastore skipped.
				api.ResyncInProgress.String(),
				"key1=v1 (new)",
				"key2=v2 (new)",
				"key3=v3 (new)",
				api.InSync.String(),
			}))
			rec.ResetUpdatesSeen()

			// Typha reconnection.
			d.OnTyphaConnectionRestarted()
			d.OnStatusUpdated(api.WaitForDatastore)
			d.OnStatusUpdated(api.ResyncInProgress)
			onUpdates([]api.Update{KVUpdate("key1", "v1")})  // Same
			onUpdates([]api.Update{KVUpdate("key2", "v2b")}) // Changed
			// onUpdates([]api.Update{KVUpdate("key3", "v3")}) // Deleted as part of resync.
			onUpdates([]api.Update{KVUpdate("key4", "v4")})

			// And another one before we flush the queue.
			d.OnTyphaConnectionRestarted()
			d.OnStatusUpdated(api.WaitForDatastore)
			d.OnStatusUpdated(api.ResyncInProgress)
			onUpdates([]api.Update{KVUpdate("key1", "v1b")}) // Same
			onUpdates([]api.Update{KVUpdate("key2", "v2")})  // Changed
			// onUpdates([]api.Update{KVUpdate("key3", "v3")}) // Deleted as part of resync.
			onUpdates([]api.Update{KVUpdate("key4", "v4")})

			d.OnStatusUpdated(api.InSync)
			sendNextBatchSync(d, rec)
			Expect(rec.FinalValues()).To(Equal(map[string]string{
				"key1": "v1b",
				"key2": "v2",
				"key4": "v4",
			}))
			Expect(rec.FinalSyncState()).To(Equal(api.InSync))
			Expect(rec.UpdatesSeen()).To(Equal([]string{
				api.ResyncInProgress.String(),
				"key1=v1b (updated)",
				"key2=v2 (updated)",
				"key4=v4 (new)",
				"key3= (deleted)",
				api.InSync.String(),
			}))
		})
	}
}

// TestDedupeBuffer_TyphaDoubleResyncAfterFlush tests a back-to-back Typha
// resync where some updates make it off the queue before the second resync
// starts.
func TestDedupeBuffer_TyphaDoubleResyncAfterFlush(t *testing.T) {
	// Tests a resync with Typha that itself gets interrupted by a new resync.

	for _, onUpdatesVersion := range []string{"KeysKnown", "KeysNotKnown"} {
		t.Run(onUpdatesVersion, func(t *testing.T) {
			RegisterTestingT(t)
			d := New()
			onUpdates := wrapOnUpdates(d, onUpdatesVersion)
			rec := NewReceiver()

			// Send a simple initial state.
			d.OnStatusUpdated(api.WaitForDatastore)
			d.OnStatusUpdated(api.ResyncInProgress)
			onUpdates([]api.Update{KVUpdate("key1", "v1")})
			onUpdates([]api.Update{KVUpdate("key2", "v2")})
			onUpdates([]api.Update{KVUpdate("key3", "v3")})
			d.OnStatusUpdated(api.InSync)
			sendNextBatchSync(d, rec)
			Expect(rec.FinalValues()).To(Equal(map[string]string{
				"key1": "v1",
				"key2": "v2",
				"key3": "v3",
			}))
			Expect(rec.FinalSyncState()).To(Equal(api.InSync))
			Expect(rec.UpdatesSeen()).To(Equal([]string{
				// WaitForDatastore skipped.
				api.ResyncInProgress.String(),
				"key1=v1 (new)",
				"key2=v2 (new)",
				"key3=v3 (new)",
				api.InSync.String(),
			}))
			rec.ResetUpdatesSeen()

			// Typha reconnection.
			d.OnTyphaConnectionRestarted()
			d.OnStatusUpdated(api.WaitForDatastore)
			d.OnStatusUpdated(api.ResyncInProgress)
			onUpdates([]api.Update{KVUpdate("key1", "v1")})  // Same
			onUpdates([]api.Update{KVUpdate("key2", "v2b")}) // Changed
			// onUpdates([]api.Update{KVUpdate("key3", "v3")}) // Deleted as part of resync.
			onUpdates([]api.Update{KVUpdate("key4", "v4")})

			// Flush the queue before we send the in-sync.
			sendNextBatchSync(d, rec)

			// This update will go onto the queue but then get thrown away
			// by OnTyphaConnectionRestarted().
			onUpdates([]api.Update{KVUpdate("key5", "v5")})

			// Then start a new resync.
			d.OnTyphaConnectionRestarted()
			d.OnStatusUpdated(api.WaitForDatastore)
			d.OnStatusUpdated(api.ResyncInProgress)
			onUpdates([]api.Update{KVUpdate("key1", "v1b")}) // Same
			onUpdates([]api.Update{KVUpdate("key2", "v2")})  // Changed
			// onUpdates([]api.Update{KVUpdate("key3", "v3")}) // Deleted as part of resync.
			onUpdates([]api.Update{KVUpdate("key4", "v4")})

			d.OnStatusUpdated(api.InSync)
			sendNextBatchSync(d, rec)
			Expect(rec.FinalValues()).To(Equal(map[string]string{
				"key1": "v1b",
				"key2": "v2",
				"key4": "v4",
			}))
			Expect(rec.FinalSyncState()).To(Equal(api.InSync))
			Expect(rec.UpdatesSeen()).To(Equal([]string{
				api.ResyncInProgress.String(),
				"key1=v1 (updated)",
				"key2=v2b (updated)",
				"key4=v4 (new)",
				api.ResyncInProgress.String(),
				"key1=v1b (updated)",
				"key2=v2 (updated)",
				"key4=v4 (updated)",
				"key3= (deleted)", // Only deleted when we se in-sync.
				api.InSync.String(),
			}))
		})
	}
}

// TestDedupeBuffer_TyphaResyncNothingToDelete covers the case where the
// liveKeysNotSeenSinceReconnect set is empty at the end of the resync.
func TestDedupeBuffer_TyphaResyncNothingToDelete(t *testing.T) {
	for _, onUpdatesVersion := range []string{"KeysKnown", "KeysNotKnown"} {
		t.Run(onUpdatesVersion, func(t *testing.T) {
			RegisterTestingT(t)
			d := New()
			onUpdates := wrapOnUpdates(d, onUpdatesVersion)
			rec := NewReceiver()

			// Send a simple initial state.
			d.OnStatusUpdated(api.WaitForDatastore)
			d.OnStatusUpdated(api.ResyncInProgress)
			onUpdates([]api.Update{KVUpdate("key1", "v1")})
			onUpdates([]api.Update{KVUpdate("key2", "v2")})
			d.OnStatusUpdated(api.InSync)
			sendNextBatchSync(d, rec)
			Expect(rec.FinalValues()).To(Equal(map[string]string{
				"key1": "v1",
				"key2": "v2",
			}))
			Expect(rec.FinalSyncState()).To(Equal(api.InSync))
			Expect(rec.UpdatesSeen()).To(Equal([]string{
				// WaitForDatastore skipped.
				api.ResyncInProgress.String(),
				"key1=v1 (new)",
				"key2=v2 (new)",
				api.InSync.String(),
			}))
			rec.ResetUpdatesSeen()

			// Typha reconnection.
			d.OnTyphaConnectionRestarted()
			d.OnStatusUpdated(api.WaitForDatastore)
			d.OnStatusUpdated(api.ResyncInProgress)
			onUpdates([]api.Update{KVUpdate("key1", "v1")})  // Same
			onUpdates([]api.Update{KVUpdate("key2", "v2b")}) // Changed
			d.OnStatusUpdated(api.InSync)
			sendNextBatchSync(d, rec)
			Expect(rec.FinalValues()).To(Equal(map[string]string{
				"key1": "v1",
				"key2": "v2b",
			}))
			Expect(rec.FinalSyncState()).To(Equal(api.InSync))
			Expect(rec.UpdatesSeen()).To(Equal([]string{
				api.ResyncInProgress.String(),
				"key1=v1 (updated)",
				"key2=v2b (updated)",
				api.InSync.String(),
			}))
		})
	}
}

func TestDedupeBuffer_Async(t *testing.T) {
	for _, onUpdatesVersion := range []string{"KeysKnown", "KeysNotKnown"} {
		t.Run(onUpdatesVersion, func(t *testing.T) {
			RegisterTestingT(t)
			d := New()
			onUpdates := wrapOnUpdates(d, onUpdatesVersion)
			rec := NewReceiver()
			go d.SendToSinkForever(rec)
			defer d.Stop()

			rec.BlockAfterNextUpdate()
			defer rec.Unblock()

			// Send updates and wait for them to show up.
			onUpdates([]api.Update{
				KVUpdate("key1", "1a"),
				KVUpdate("key2", "2a"),
				KVUpdate("key3", "3a"),
				KVUpdate("key4", "4a"),
			})
			Eventually(rec.FinalValues).Should(Equal(map[string]string{
				"key1": "1a",
				"key2": "2a",
				"key3": "3a",
				"key4": "4a",
			}))
			Expect(rec.UpdatesSeen()).To(ConsistOf(
				"key1=1a (new)",
				"key2=2a (new)",
				"key3=3a (new)",
				"key4=4a (new)",
			))
			rec.ResetUpdatesSeen()

			// Receiver should now be blocked.  Send in a series of updates,
			// some of which replace earlier updates.
			onUpdates([]api.Update{
				KVUpdate("key1", "1a"), // No-op update
				KVUpdate("key2", "2b"), // Genuine change
				KVUpdate("key3", "3b"), // Genuine change x2
				KVUpdate("key4", ""),   // delete
				KVUpdate("key5", "5a"), // add
				KVUpdate("key6", "6a"), // add
				KVUpdate("key7", "7a"), // add
			})
			d.OnStatusUpdated(api.InSync)
			d.OnStatusUpdated(api.ResyncInProgress)
			d.OnStatusUpdated(api.ResyncInProgress)
			onUpdates([]api.Update{
				KVUpdate("key1", "1a"), // No-op update
				KVUpdate("key3", "3c"), // Genuine change; should replace earlier change
				KVUpdate("key5", ""),   // Delete before ever being sent
				KVUpdate("key7", "7b"), // Update before ever being sent
				KVUpdate("key8", "8a"), // add
			})
			d.OnStatusUpdated(api.InSync)
			d.OnStatusUpdated(api.ResyncInProgress)
			d.OnStatusUpdated(api.InSync)
			rec.Unblock()

			Eventually(rec.FinalValues).Should(Equal(
				map[string]string{
					"key1": "1a",
					"key2": "2b",
					"key3": "3c",
					"key6": "6a",
					"key7": "7b",
					"key8": "8a",
				}),
				"After sending various updates should get correct final result.",
			)
			Eventually(rec.FinalSyncState).Should(Equal(api.InSync))

			// The updates come out in the same order that we sent them
			// but a key that gets updated twice between flushes of the queue
			// is only sent once with its most recent value.
			Expect(rec.UpdatesSeen()).To(Equal([]string{
				"key1=1a (updated)", // Only dedupe things that are on the queue so this dupe does get sent.
				"key2=2b (updated)",
				"key3=3c (updated)", // The 3b update gets suppressed
				"key4= (deleted)",   // key4 was sent before so the deletion is sent
				// key5 should never be sent.
				"key6=6a (new)",
				"key7=7b (new)",
				"resync",
				"key8=8a (new)",
				"in-sync",
			}))
		})
	}
}

func sendNextBatchSync(d *DedupeBuffer, r *Receiver) {
	ExpectWithOffset(1, d.sendNextBatchToSinkNoBlock(r)).NotTo(HaveOccurred())
}

func wrapOnUpdates(d *DedupeBuffer, onUpdatesVersion string) func(updates []api.Update) {
	onUpdates := d.OnUpdates
	if onUpdatesVersion == "KeysKnown" {
		onUpdates = func(updates []api.Update) {
			var keys []string
			for _, upd := range updates {
				key, err := model.KeyToDefaultPath(upd.Key)
				Expect(err).NotTo(HaveOccurred())
				keys = append(keys, key)
			}
			d.OnUpdatesKeysKnown(updates, keys)
		}
	}
	return onUpdates
}

func KVUpdate(key, value string) api.Update {
	u := api.Update{
		KVPair: model.KVPair{
			Key: model.HostConfigKey{
				Hostname: "foo",
				Name:     key,
			},
		},
	}
	if value != "" {
		u.KVPair.Value = value
	} else {
		u.UpdateType = api.UpdateTypeKVDeleted
	}
	return u
}

type Receiver struct {
	mutex sync.Mutex
	cond  *sync.Cond

	finalValues    map[string]string
	updatesSeen    []string
	finalSyncState api.SyncStatus

	block bool
}

func NewReceiver() *Receiver {
	r := &Receiver{
		finalValues: map[string]string{},
	}
	r.cond = sync.NewCond(&r.mutex)
	return r
}

func (r *Receiver) FinalValues() map[string]string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	fvCopy := map[string]string{}
	for k, v := range r.finalValues {
		fvCopy[k] = v
	}
	return fvCopy
}

func (r *Receiver) UpdatesSeen() []string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	var usCopy []string
	for _, v := range r.updatesSeen {
		usCopy = append(usCopy, v)
	}
	return usCopy
}

func (r *Receiver) FinalSyncState() api.SyncStatus {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.finalSyncState
}

func (r *Receiver) OnStatusUpdated(status api.SyncStatus) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.updatesSeen = append(r.updatesSeen, status.String())
	r.finalSyncState = status
}

func (r *Receiver) OnUpdates(updates []api.Update) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	for _, update := range updates {
		k := update.Key.(model.HostConfigKey).Name
		var v string
		if update.Value == nil {
			delete(r.finalValues, k)
		} else {
			v = update.Value.(string)
			r.finalValues[k] = v
		}
		r.updatesSeen = append(r.updatesSeen, fmt.Sprintf("%s=%s (%v)", k, v, update.UpdateType))
	}
	for r.block {
		r.cond.Wait()
	}
}

func (r *Receiver) ResetUpdatesSeen() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.updatesSeen = nil
}

func (r *Receiver) BlockAfterNextUpdate() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.block = true
}

func (r *Receiver) Unblock() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.block = false
	r.cond.Signal()
}
