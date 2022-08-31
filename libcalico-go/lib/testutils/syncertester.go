// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.

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
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	gomegatypes "github.com/onsi/gomega/types"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// Create a new SyncerTester.  This helper class implements the api.SyncerCallbacks
// and provides a number of useful methods for asserting the data that has been
// supplied on the callbacks.
func NewSyncerTester() *SyncerTester {
	return &SyncerTester{
		cache:  make(map[string]CacheEntry),
		status: UnsetSyncStatus,
	}
}

var UnsetSyncStatus = api.SyncStatus(255)

// Encapsulates parse error details for easy handling with a single channel.
type parseError struct {
	rawKey   string
	rawValue string
}

type CacheEntry struct {
	model.KVPair
	Seen bool
}

type SyncerTester struct {
	status        api.SyncStatus
	statusChanged bool
	statusBlocker sync.WaitGroup
	updateBlocker sync.WaitGroup
	lock          sync.Mutex

	// Stored update information.
	cache       map[string]CacheEntry
	onUpdates   [][]api.Update
	updates     []api.Update
	parseErrors []parseError
}

// OnStatusUpdated updates the current status and then blocks until a call to
// ExpectStatusUpdate() has been called.
func (st *SyncerTester) OnStatusUpdated(status api.SyncStatus) {
	defer GinkgoRecover()
	st.lock.Lock()
	current := st.status
	st.status = status
	st.statusChanged = true
	st.statusBlocker.Add(1)
	st.lock.Unlock()

	// If this is not the first status event then perform additional validation on the status.
	if current != UnsetSyncStatus {
		// None of the concrete syncers that we are testing expect should have the same
		// status update repeated.  Log and panic.
		if status == current {
			log.WithField("Status", status).Panic("Duplicate identical status updates from syncer")
		}
	}

	log.Infof("Status set and blocking for ack: %s", status)

	// For statuses, this requires the consumer to explicitly expect the status updates
	// to unblock the processing.
	st.statusBlocker.Wait()
	log.Infof("OnStatusUpdated now unblocked waiting for: %s", status)
}

// OnUpdates just stores the update and asserts the state of the cache and the update.
func (st *SyncerTester) OnUpdates(updates []api.Update) {
	defer GinkgoRecover()

	func() {
		// Store the updates and onUpdates.
		st.lock.Lock()
		defer st.lock.Unlock()
		st.onUpdates = append(st.onUpdates, updates)
		for _, u := range updates {
			// Append the updates to the total set of updates.
			st.updates = append(st.updates, u)

			// Update our cache of current entries.
			k, err := model.KeyToDefaultPath(u.Key)
			Expect(err).NotTo(HaveOccurred())
			switch u.UpdateType {
			case api.UpdateTypeKVDeleted:
				log.WithFields(log.Fields{
					"Key": k,
				}).Info("Handling delete cache entry")
				Expect(st.cache).To(HaveKey(k))
				delete(st.cache, k)
			case api.UpdateTypeKVNew:
				log.WithFields(log.Fields{
					"Key":   k,
					"Value": u.KVPair.Value,
				}).Info("Handling new cache entry")
				Expect(st.cache).NotTo(HaveKey(k))
				Expect(u.Value).NotTo(BeNil())
				st.cache[k] = CacheEntry{KVPair: u.KVPair}
			case api.UpdateTypeKVUpdated:
				log.WithFields(log.Fields{
					"Key":   k,
					"Value": u.KVPair.Value,
				}).Info("Handling modified cache entry")
				Expect(st.cache).To(HaveKey(k))
				Expect(u.Value).NotTo(BeNil())
				st.cache[k] = CacheEntry{KVPair: u.KVPair}
			}

			// Check that KeyFromDefaultPath supports parsing the path again;
			// this is required for typha to support this resource.
			parsedKey := model.KeyFromDefaultPath(k)
			Expect(parsedKey).NotTo(BeNil(), fmt.Sprintf(
				"KeyFromDefaultPath unable to parse %s, generated from %+v; typha won't support this key",
				k, u.Key))
		}
	}()

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
// be called *after* a new status change has occurred.  The possible state changes are:
// WaitingForDatastore -> ResyncInProgress -> InSync -> WaitingForDatastore.
// ExpectStatusUpdate will panic if called with the same status twice in a row.
func (st *SyncerTester) ExpectStatusUpdate(status api.SyncStatus, timeout ...time.Duration) {
	log.Infof("Expecting status of: %s", status)
	cs := func() api.SyncStatus {
		st.lock.Lock()
		defer st.lock.Unlock()
		return st.status
	}
	if len(timeout) == 0 {
		EventuallyWithOffset(1, cs, "6s", "1ms").Should(Equal(status))
	} else {
		EventuallyWithOffset(1, cs, timeout[0], "1ms").Should(Equal(status))
	}
	ConsistentlyWithOffset(1, cs).Should(Equal(status))

	log.Infof("Status is at expected status: %s", status)

	// Get the current statusChanged status, and reset it.  Validate that the status was actually
	// updated to this state (i.e. the test code hasn't re-called this with the same status).
	st.lock.Lock()
	current := st.statusChanged
	st.statusChanged = false
	st.lock.Unlock()
	ExpectWithOffset(1, current).To(BeTrue())

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
	EventuallyWithOffset(1, sc, "6s", "1ms").Should(BeFalse())
	ConsistentlyWithOffset(1, sc).Should(BeFalse(), "Status changed unexpectedly")
}

// ExpectCacheSize verifies that the cache size is as expected. If this fails, the entire cache is included in the
// logs - entries that were explicitly checked will be marked as `Seen: true`.
func (st *SyncerTester) ExpectCacheSize(size int) {
	EventuallyWithOffset(1, st.CacheSnapshot, "6s", "1ms").Should(HaveLen(size))
	ConsistentlyWithOffset(1, st.CacheSnapshot).Should(HaveLen(size), "Cache size incorrect")
}

// ExpectData verifies that a KVPair is in the cache. For instance specific data (such as revision, or creation
// timestamp) - those values are only compared if set in the supplied kvp. Important details such as name, namespace,
// type and value are always compared. This marks the cache entry as "Seen".
func (st *SyncerTester) ExpectData(kvp model.KVPair) {
	key, err := model.KeyToDefaultPath(kvp.Key)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), fmt.Sprintf("failed to convert key to default path: %v", kvp.Key))

	comp := func() error {
		cachedKvp := st.GetCacheKVPair(key)
		if cachedKvp == nil {
			return fmt.Errorf("Missing entry in cache: \n%s", kvpAsDebugString(kvp))
		}
		if !kvpsEqual(*cachedKvp, kvp) {
			return fmt.Errorf("Incorrect entry in cache.\n  Found:\n%s\n\n  Expected:\n%s",
				kvpAsDebugString(*cachedKvp), kvpAsDebugString(kvp))
		}
		return nil
	}

	EventuallyWithOffset(1, comp, "6s", "20ms").ShouldNot(HaveOccurred())
	ConsistentlyWithOffset(1, comp).ShouldNot(HaveOccurred())
}

// ExpectPath verifies that a KVPair with a specified path is in the cache. This will mark the cache entry as "Seen".
func (st *SyncerTester) ExpectPath(path string) {
	kv := func() interface{} {
		return st.GetCacheKVPair(path)
	}
	EventuallyWithOffset(1, kv, "6s", "20ms").ShouldNot(BeNil())
	ConsistentlyWithOffset(1, kv).ShouldNot(BeNil())
}

// ExpectDataMatch verifies that the KV in the cache exists and matches the GomegaMatcher.
func (st *SyncerTester) ExpectValueMatches(k model.Key, match gomegatypes.GomegaMatcher) {
	key, err := model.KeyToDefaultPath(k)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	value := func() interface{} {
		return st.GetCacheValue(key)
	}

	EventuallyWithOffset(1, value, "6s", "20ms").Should(match)
	ConsistentlyWithOffset(1, value).Should(match)
}

// ExpectNoData verifies that a Key is not in the cache.
func (st *SyncerTester) ExpectNoData(k model.Key) {
	key, err := model.KeyToDefaultPath(k)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	EventuallyWithOffset(1, st.CacheSnapshot).ShouldNot(HaveKey(key), fmt.Sprintf("Found key %s in cache - not expected", key))
	ConsistentlyWithOffset(1, st.CacheSnapshot).ShouldNot(HaveKey(key), fmt.Sprintf("Found key %s in cache - not expected", key))
}

// GetCacheValue returns the value of the KVPair from the cache and flags the entry as "Seen". This makes debugging
// easier.
func (st *SyncerTester) GetCacheKVPair(k string) *model.KVPair {
	st.lock.Lock()
	defer st.lock.Unlock()
	if entry, ok := st.cache[k]; ok {
		entry.Seen = true
		st.cache[k] = entry
		return &entry.KVPair
	}
	return nil
}

// GetCacheValue returns the value of the KVPair from the cache or nil if not present.
func (st *SyncerTester) GetCacheValue(k string) interface{} {
	st.lock.Lock()
	defer st.lock.Unlock()
	return st.cache[k].Value
}

// CacheSnapshot returns a copy of the cache.  The copy is made with the lock held.
func (st *SyncerTester) CacheSnapshot() map[string]CacheEntry {
	st.lock.Lock()
	defer st.lock.Unlock()
	cacheCopy := map[string]CacheEntry{}
	for k, v := range st.cache {
		cacheCopy[k] = v
	}
	return cacheCopy
}

// GetCacheEntries returns a slice of the current cache entries.
func (st *SyncerTester) GetCacheEntries() []model.KVPair {
	st.lock.Lock()
	defer st.lock.Unlock()
	es := []model.KVPair{}
	for _, e := range st.cache {
		es = append(es, e.KVPair)
	}
	return es
}

// HasUpdates checks whether the syncer has the specified updates.
func (st *SyncerTester) hasUpdates(expectedUpdates []api.Update, checkOrder bool, sanitizer func(u []api.Update) []api.Update) error {
	// Get the actualUpdates and make a local copy.
	st.lock.Lock()
	defer st.lock.Unlock()
	actualUpdates := sanitizer(st.updates[:])

	// Start by checking which entries are present and which are missing. Populate the actual updates map which is
	// keyed off the update type and default path - we may have multiple entries for the same key, so append to existing
	// entries.
	actualUpdatesMap := make(map[string][]api.Update)
	var errs []string

	// updateAsKey converts the update to a key for the map.
	updateAsKey := func(update api.Update) string {
		path, err := model.KeyToDefaultPath(update.Key)
		Expect(err).NotTo(HaveOccurred())
		return fmt.Sprintf("%s;%s", update.UpdateType, path)
	}

	// removeFromActualUpdatesMap removes the update from the map, and returns an error if not found. It will remove
	// at most one entry - so duplicates, if they exist, will not be removed.
	removeFromActualUpdatesMap := func(expected api.Update) string {
		key := updateAsKey(expected)
		actualUpdates := actualUpdatesMap[key]
		var newActualUpdates []api.Update
		var found bool
		for _, actual := range actualUpdates {
			if !found && updatesEqual(actual, expected) {
				found = true
			} else {
				newActualUpdates = append(newActualUpdates, actual)
			}
		}
		if !found {
			return fmt.Sprintf("Update expected but not received:\n%v", updateAsDebugString(expected))
		}
		if newActualUpdates == nil {
			delete(actualUpdatesMap, key)
		} else {
			actualUpdatesMap[key] = newActualUpdates
		}
		return ""
	}

	// Populate the lookup map.
	for _, actual := range actualUpdates {
		key := updateAsKey(actual)
		actualUpdatesMap[key] = append(actualUpdatesMap[key], actual)
	}

	// Loop through the expected results and remove entries that are found.
	for _, expected := range expectedUpdates {
		if err := removeFromActualUpdatesMap(expected); err != "" {
			errs = append(errs, err)
		}
	}

	// Any entries remaining are not expected.
	for _, actualUpdates := range actualUpdatesMap {
		for _, actual := range actualUpdates {
			errs = append(errs, fmt.Sprintf("Update received but not expected:\n%v", updateAsDebugString(actual)))
		}
	}

	// If we need to check the order, let's do that now - failing at the first miss.
	if checkOrder {
		num := len(actualUpdates)
		if len(expectedUpdates) < num {
			num = len(expectedUpdates)
		}
		for i := 0; i < num; i++ {
			if !updatesEqual(actualUpdates[i], expectedUpdates[i]) {
				errs = append(errs, fmt.Sprintf(
					"Incorrect order of updates at index %d;\nExpected:\n%v;\nReceived:\n%v",
					i, updateAsDebugString(actualUpdates[i]), updateAsDebugString(expectedUpdates[i])),
				)
				break
			}
		}
	}

	if len(errs) == 0 {
		return nil
	}

	return errors.New(strings.Join(errs, "\n\n"))
}

// ExpectUpdates tests the onUpdate events.
// This removes all updates/onUpdate events from this receiver, so that the next call to this just requires the next
// set of updates.
func (st *SyncerTester) ExpectUpdates(expectedUpdates []api.Update, checkOrder bool, sanitizer ...func(u []api.Update) []api.Update) {
	var sfn func(u []api.Update) []api.Update
	if len(sanitizer) == 1 {
		sfn = sanitizer[0]
	} else if len(sanitizer) > 1 {
		log.Panic("Multiple sanitizers passed in - only one expected")
	}
	if sfn == nil {
		sfn = st.DefaultSanitizer
	}

	// Sanitize the expected updates.
	expectedUpdates = sfn(expectedUpdates)

	// Wait for the sanitized cache updates to match the sanitized expected updates.
	expectFn := func() error {
		return st.hasUpdates(expectedUpdates, checkOrder, sfn)
	}
	EventuallyWithOffset(1, expectFn, "20s", "200ms").ShouldNot(HaveOccurred())

	// Extract the updates and remove the updates and onUpdates from our cache.
	st.lock.Lock()
	defer st.lock.Unlock()
	st.updates = nil
	st.onUpdates = nil
}

// ExpectOnUpdates tests which onUpdate events were received.
//
// This removes all updates/onUpdate events from this receiver, so that the next call to this just requires the next set
// of updates.
//
// Note that for this function to be useful, your test code needs to have fine grained control over the order in which
// events occur.
func (st *SyncerTester) ExpectOnUpdates(expected [][]api.Update) {
	log.Infof("Expecting OnUpdates of %v", expected)

	// Poll until we have the correct number of updates to check.
	nu := func() int {
		st.lock.Lock()
		defer st.lock.Unlock()
		return len(st.onUpdates)
	}
	EventuallyWithOffset(1, nu).Should(Equal(len(expected)))

	// Extract the onUpdates and remove the updates and onUpdates from our cache.
	st.lock.Lock()
	defer st.lock.Unlock()
	onUpdates := st.onUpdates
	st.updates = nil
	st.onUpdates = nil
	ExpectWithOffset(1, onUpdates).To(Equal(expected))
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
	EventuallyWithOffset(1, ne).Should(Not(BeZero()))

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

// DefaultSanitizer provides a default filtering of the updates, used when comparing sets of updates.  This filter
// removes updates for certain resource types that are updated outside of the test code. In addition, the update
// comparer (see updatesEqual and kvpsEqual) are careful to remove resource versions when comparing create/delete
// updates for the same resource types.
func (st *SyncerTester) DefaultSanitizer(updates []api.Update) []api.Update {
	// In the FVs there are some resources that get updated quite frequently and outside of our control. Filter out
	// any updates associated with the following resources since it makes comparison super tricky. We only need to do
	// this for updates and not create or delete events - since these are much more controllable.
	// - Nodes
	// - Services and Endpoints
	var filtered []api.Update
	for _, update := range updates {
		if update.UpdateType == api.UpdateTypeKVUpdated && isExternallyControlled(update.Key) {
			continue
		}

		filtered = append(filtered, update)
	}

	return filtered
}

// All of the Kubernetes resources that we care about implement both of these interfaces.
type resource interface {
	runtime.Object
	v1.ObjectMetaAccessor
}

// isExternallyControlled returns true if the resource is externally controlled outside of our testing framework. In
// this case we filter out updates for these resources and never check the revision number - it makes the tests too
// flakey.
func isExternallyControlled(key model.Key) bool {
	switch key.(type) {
	case model.WireguardKey, model.HostConfigKey, model.HostIPKey:
		return true
	case model.ResourceKey:
		switch key.(model.ResourceKey).Kind {
		case libapiv3.KindNode, model.KindKubernetesEndpointSlice, model.KindKubernetesService:
			return true
		}
	}
	return false
}

// updatesEqual checks if two updates are the same. This does not do a full comparison of every field in a v3 resource
// Metadata.  UID, Revision, APIGroup/Kind, CreationTimestamp are only compared if they are specified in the expected
// update - this makes writing tests simpler.
func updatesEqual(actual, expected api.Update) bool {
	if actual.UpdateType != expected.UpdateType {
		return false
	}
	return kvpsEqual(actual.KVPair, expected.KVPair)
}

// kvpsEqual checks if two KVPairs are the same. This does not do a full comparison of every field in a v3 resource
// Metadata.  UID, Revision, APIGroup/Kind, CreationTimestamp are only compared if they are specified in the expected
// update - this makes writing tests simpler.
func kvpsEqual(actual, expected model.KVPair) bool {
	if !reflect.DeepEqual(expected.Key, actual.Key) {
		log.Debug("Keys are not equal: %#v != %#v", expected.Key, actual.Key)
		return false
	}
	if expected.UID != nil && (actual.UID == nil || *actual.UID != *expected.UID) {
		return false
	}

	// For externally controlled resources we never check the revision, otherwise we only check if the expected
	// revision is specified.
	if !isExternallyControlled(actual.Key) && expected.Revision != "" && (actual.Revision == "" || actual.Revision != expected.Revision) {
		return false
	}

	if actual.Value == nil {
		if expected.Value != nil {
			return false
		}
		return true
	}

	if expected.Value == nil {
		return false
	}

	switch expected.Key.(type) {
	case model.ResourceKey:
		// For resources, take
		actualCopy, ok := actual.Value.(resource)
		if !ok {
			// Some of the tests use a ResourceKey with an arbitrary value - in this case just compare the values
			// without any of the special case MetaData processing.
			return reflect.DeepEqual(actual, expected)
		}
		expectedCopy, ok := expected.Value.(resource)
		if !ok {
			// Some of the tests use a ResourceKey with an arbitrary value - in this case just compare the values
			// without any of the special case MetaData processing.
			return reflect.DeepEqual(actual, expected)
		}

		// Take copies because we are going to manipulate the data for easier comparison.
		actualCopy = actualCopy.DeepCopyObject().(resource)
		expectedCopy = expectedCopy.DeepCopyObject().(resource)

		// Some tests just want to compare key/spec type data and some will compare against actual instance specific
		// settings. If the expected data contains TypeMeta, ResourceVersion, UID, CreationTimestamp then compare
		// them individually. Not all tests include these - so we keep this optional based on the expected data.
		if actualCopy.GetObjectKind().GroupVersionKind().Kind != "" && expectedCopy.GetObjectKind().GroupVersionKind().Kind != "" {
			if actualCopy.GetObjectKind().GroupVersionKind().Kind != expectedCopy.GetObjectKind().GroupVersionKind().Kind {
				return false
			}
		}
		if actualCopy.GetObjectKind().GroupVersionKind().Group != "" && expectedCopy.GetObjectKind().GroupVersionKind().Group != "" {
			if actualCopy.GetObjectKind().GroupVersionKind().Group != expectedCopy.GetObjectKind().GroupVersionKind().Group {
				return false
			}
		}
		if actualCopy.GetObjectKind().GroupVersionKind().Version != "" && expectedCopy.GetObjectKind().GroupVersionKind().Version != "" {
			if actualCopy.GetObjectKind().GroupVersionKind().Version != expectedCopy.GetObjectKind().GroupVersionKind().Version {
				return false
			}
		}
		if !isExternallyControlled(actual.Key) && expectedCopy.GetObjectMeta().GetResourceVersion() != "" &&
			actualCopy.GetObjectMeta().GetResourceVersion() != expectedCopy.GetObjectMeta().GetResourceVersion() {
			return false
		}
		if expectedCopy.GetObjectMeta().GetUID() != "" &&
			actualCopy.GetObjectMeta().GetUID() != expectedCopy.GetObjectMeta().GetUID() {
			return false
		}

		// Now copy across the fields from actual to expected for things we've already compared above, or that we
		// don't want to compare. All that remains are the fields we always compare (Name, Namespace, Labels,
		// Annotations).
		expectedCopy.GetObjectKind().SetGroupVersionKind(actualCopy.GetObjectKind().GroupVersionKind())
		expectedCopy.GetObjectMeta().SetGenerateName(actualCopy.GetObjectMeta().GetGenerateName())
		expectedCopy.GetObjectMeta().SetUID(actualCopy.GetObjectMeta().GetUID())
		expectedCopy.GetObjectMeta().SetResourceVersion(actualCopy.GetObjectMeta().GetResourceVersion())
		expectedCopy.GetObjectMeta().SetGeneration(actualCopy.GetObjectMeta().GetGeneration())
		expectedCopy.GetObjectMeta().SetSelfLink(actualCopy.GetObjectMeta().GetSelfLink())
		expectedCopy.GetObjectMeta().SetCreationTimestamp(actualCopy.GetObjectMeta().GetCreationTimestamp())
		expectedCopy.GetObjectMeta().SetDeletionTimestamp(actualCopy.GetObjectMeta().GetDeletionTimestamp())
		expectedCopy.GetObjectMeta().SetDeletionGracePeriodSeconds(actualCopy.GetObjectMeta().GetDeletionGracePeriodSeconds())
		expectedCopy.GetObjectMeta().SetFinalizers(actualCopy.GetObjectMeta().GetFinalizers())
		expectedCopy.GetObjectMeta().SetOwnerReferences(actualCopy.GetObjectMeta().GetOwnerReferences())
		expectedCopy.GetObjectMeta().SetManagedFields(actualCopy.GetObjectMeta().GetManagedFields())

		// Finally compare the structs.
		return reflect.DeepEqual(actualCopy, expectedCopy)
	case model.BlockKey:
		// For blocks, the value contains a field that is calculated based on timestamp.
		// We should ignore the actual value of the field.
		actual.Value.(*model.AllocationBlock).SequenceNumber = 0
		actual.Value.(*model.AllocationBlock).SequenceNumberForAllocation = nil

		return reflect.DeepEqual(actual.Value, expected.Value)
	default:
		// For non-resource stuff we can always just compare the values.
		return reflect.DeepEqual(actual.Value, expected.Value)
	}
}

// updateAsDebugString converts the update into a debug friendly string.
func updateAsDebugString(update api.Update) string {
	val, err := json.MarshalIndent(update, "    ", "  ")
	Expect(err).NotTo(HaveOccurred())
	path, err := model.KeyToDefaultPath(update.Key)
	Expect(err).NotTo(HaveOccurred())
	return fmt.Sprintf("  KeyPath: %s\n  Update:\n    %s", path, string(val))
}

// kvpAsDebugString converts the KVPair into a debug friendly string.
func kvpAsDebugString(kv model.KVPair) string {
	val, err := json.MarshalIndent(kv, "    ", "  ")
	Expect(err).NotTo(HaveOccurred())
	path, err := model.KeyToDefaultPath(kv.Key)
	Expect(err).NotTo(HaveOccurred())
	return fmt.Sprintf("  KeyPath: %s\n  KVPair:\n    %s", path, string(val))
}
