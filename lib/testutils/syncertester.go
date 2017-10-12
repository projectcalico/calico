// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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
package testutils

import (
	"fmt"
	"sync"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
)

// Create a new SyncerTester.  This helper class implements the api.SyncerCallbacks
// and provides a number of useful methods for asserting the data that has been
// supplied on the callbacks.
func NewSyncerTester() *SyncerTester {
	return &SyncerTester{
		cache:  make(map[string]model.KVPair),
		status: UnsetSyncStatus,
	}
}

var (
	UnsetSyncStatus = api.SyncStatus(255)
)

// Encapsulates parse error details for easy handling with a single channel.
type parseError struct {
	rawKey   string
	rawValue string
}

type SyncerTester struct {
	status        api.SyncStatus
	statusChanged bool
	statusBlocker sync.WaitGroup
	updateBlocker sync.WaitGroup
	lock          sync.Mutex

	// Stored update information.
	cache       map[string]model.KVPair
	onUpdates   [][]api.Update
	updates     []api.Update
	parseErrors []parseError
}

// OnStatusUpdated updates the current status and then blocks until a call to
// ExpectStatusUpdate() has been called.
func (st *SyncerTester) OnStatusUpdated(status api.SyncStatus) {
	st.lock.Lock()
	current := st.status
	st.status = status
	st.statusChanged = true
	st.statusBlocker.Add(1)
	st.lock.Unlock()

	// If this is not the first status event then perform additional validation on the status.
	if current != UnsetSyncStatus {
		// None of the concrete syncers that we are testing expect should have the same
		// status update repeated, nor should the status decrease.  Log and panic.
		if status == current {
			log.WithField("Status", status).Fatal("Duplicate identical status updates from syncer")
		}
		if status < current {
			log.WithFields(log.Fields{
				"NewStatus": status,
				"OldStatus": st.status,
			}).Fatal("Decrementing status updates from syncer")
		}
	}

	log.Infof("Status set and blocking for ack: %s", status)

	// For statuses, this requires the consumer to explicitly expect the status updates
	// to unblock the processing.
	st.statusBlocker.Wait()
	log.Info("OnStatusUpdated now unblocked")

}

// OnUpdates just stores the update and asserts the state of the cache and the update.
func (st *SyncerTester) OnUpdates(updates []api.Update) {
	// Store the updates and onUpdates.
	st.lock.Lock()
	st.onUpdates = append(st.onUpdates, updates)
	for _, u := range updates {
		// Append the updates to the total set of updates.
		st.updates = append(st.updates, u)

		// Update our cache of current entries.
		k, err := model.KeyToDefaultPath(u.Key)
		Expect(err).NotTo(HaveOccurred())
		switch u.UpdateType {
		case api.UpdateTypeKVDeleted:
			Expect(st.cache).To(HaveKey(k))
			delete(st.cache, k)
		case api.UpdateTypeKVNew:
			log.WithFields(log.Fields{
				"Key":   k,
				"Value": u.KVPair.Value,
			}).Info("Handling new cache entry")
			Expect(st.cache).NotTo(HaveKey(k))
			Expect(u.Value).NotTo(BeNil())
			st.cache[k] = u.KVPair
		case api.UpdateTypeKVUpdated:
			log.WithFields(log.Fields{
				"Key":   k,
				"Value": u.KVPair.Value,
			}).Info("Handling modified cache entry")
			Expect(st.cache).To(HaveKey(k))
			Expect(u.Value).NotTo(BeNil())
			st.cache[k] = u.KVPair
		}
	}
	st.lock.Unlock()

	// We may need to block if the test has blocked the main event processing.
	st.updateBlocker.Wait()
}

// ParseFailed just stores the parse failure.
func (st *SyncerTester) ParseFailed(rawKey string, rawValue string) {
	st.lock.Lock()
	defer st.lock.Unlock()
	st.parseErrors = append(st.parseErrors, parseError{rawKey: rawKey, rawValue: rawValue})
}

// ExpectStatusUpdate verifies a status update message has been received.  This should only
// be called *after* a new status change has occurred.  Since the concrete implementations
// of the syncer API only migrate status in increasing readiness, this means it should be
// called once each for the following statuses in order:  WaitingForDatastore, ResyncInProgress, InSync.
// The OnStatusUpdate callback will panic if the above is not true.
func (st *SyncerTester) ExpectStatusUpdate(status api.SyncStatus) {
	log.Infof("Expecting status of: %s", status)
	cs := func() api.SyncStatus {
		st.lock.Lock()
		defer st.lock.Unlock()
		return st.status
	}
	Eventually(cs).Should(Equal(status))
	Consistently(cs).Should(Equal(status))

	log.Infof("Status is at expected status: %s", status)

	// Get the current statusChanged status, and reset it.  Validate that the status was actually
	// updated to this state (i.e. the test code hasn't re-called this with the same status).
	st.lock.Lock()
	current := st.statusChanged
	st.statusChanged = false
	st.lock.Unlock()
	Expect(current).To(BeTrue())

	// We've verified the status, so reset the statusChanged flag.
	st.lock.Lock()
	st.statusChanged = false
	st.lock.Unlock()

	// If you hit a panic here, it's because you must have called this again with the
	// same status.
	st.statusBlocker.Done()
}

// ExpectStatusUnchanged verifies that the status has not changed since the last ExpectStatusUpdate
// call.
func (st *SyncerTester) ExpectStatusUnchanged() {
	sc := func() bool {
		st.lock.Lock()
		defer st.lock.Unlock()
		return st.statusChanged
	}
	Eventually(sc).Should(BeFalse())
	Consistently(sc).Should(BeFalse())
}

// ExpectCacheSize verifies that the cache size is as expected.
func (st *SyncerTester) ExpectCacheSize(size int) {
	sfn := func() int {
		st.lock.Lock()
		defer st.lock.Unlock()
		return len(st.cache)
	}
	Eventually(sfn).Should(Equal(size))
	Consistently(sfn).Should(Equal(size))
}

// ExpectData verifies that a KVPair is in the cache.
func (st *SyncerTester) ExpectData(kvp model.KVPair) {
	key, err := model.KeyToDefaultPath(kvp.Key)
	Expect(err).NotTo(HaveOccurred())
	efn := func() model.KVPair {
		st.lock.Lock()
		defer st.lock.Unlock()
		return st.cache[key]
	}
	Eventually(efn).Should(Equal(kvp))
	Consistently(efn).Should(Equal(kvp))
}

// ExpectNoData verifies that a Key is not in the cache.
func (st *SyncerTester) ExpectNoData(k model.Key) {
	key, err := model.KeyToDefaultPath(k)
	Expect(err).NotTo(HaveOccurred())
	efn := func() bool {
		st.lock.Lock()
		defer st.lock.Unlock()
		_, ok := st.cache[key]
		return ok
	}
	Eventually(efn).Should(BeFalse(), fmt.Sprintf("Found key %s in cache - not expected", key))
	Consistently(efn).Should(BeFalse(), fmt.Sprintf("Found key %s in cache - not expected", key))
}

// GetCacheEntries returns a slice of the current cache entries.
func (st *SyncerTester) GetCacheEntries() []model.KVPair {
	st.lock.Lock()
	defer st.lock.Unlock()
	es := []model.KVPair{}
	for _, e := range st.cache {
		es = append(es, e)
	}
	return es
}

// Call to test the onUpdate events (without worrying about which specific
// OnUpdate events were received).
// This removes all updates/onUpdate events from this receiver, so that the
// next call to this just requires the next set of updates.
//
// Note that for this function to be useful, your test code needs to have
// fine grained control over the order in which events occur.
func (st *SyncerTester) ExpectUpdates(expected []api.Update) {
	log.Infof("Expecting updates of %v", expected)

	// Poll until we have the correct number of updates to check.
	nu := func() int {
		st.lock.Lock()
		defer st.lock.Unlock()
		return len(st.updates)
	}
	Eventually(nu).Should(Equal(len(expected)))

	// Extract the updates and remove the updates and onUpdates from our cache.
	st.lock.Lock()
	defer st.lock.Unlock()
	updates := st.updates
	st.updates = nil
	st.onUpdates = nil
	Expect(updates).To(Equal(expected))
}

// Call to test which onUpdate events were received.
// This removes all updates/onUpdate events from this receiver, so that the
// next call to this just requires the next set of updates.
//
// Note that for this function to be useful, your test code needs to have
// fine grained control over the order in which events occur.
func (st *SyncerTester) ExpectOnUpdates(expected [][]api.Update) {
	log.Infof("Expecting OnUpdates of %v", expected)

	// Poll until we have the correct number of updates to check.
	nu := func() int {
		st.lock.Lock()
		defer st.lock.Unlock()
		return len(st.onUpdates)
	}
	Eventually(nu).Should(Equal(len(expected)))

	// Extract the onUpdates and remove the updates and onUpdates from our cache.
	st.lock.Lock()
	defer st.lock.Unlock()
	onUpdates := st.onUpdates
	st.updates = nil
	st.onUpdates = nil
	Expect(onUpdates).To(Equal(expected))
}

// Call to test the next parse error that we expect to have received.
// This removes the parse error from the receiver.
func (st *SyncerTester) ExpectParseError(key, value string) {
	log.Infof("Expecting parse error: %v=%v", key, value)
	// Poll until we have an error to check.
	ne := func() int {
		st.lock.Lock()
		defer st.lock.Unlock()
		return len(st.parseErrors)
	}
	Eventually(ne).Should(Not(BeZero()))

	// Extract the parse error and remove from our cache.
	st.lock.Lock()
	defer st.lock.Unlock()
	pe := st.parseErrors[0]
	st.parseErrors = st.parseErrors[1:]
	Expect(pe.rawKey).To(Equal(key))
	Expect(pe.rawValue).To(Equal(value))
}

// Block the update handling.
func (st *SyncerTester) BlockUpdateHandling() {
	st.updateBlocker.Add(1)
}

// Unblock the update handling.
func (st *SyncerTester) UnblockUpdateHandling() {
	st.updateBlocker.Done()
}
