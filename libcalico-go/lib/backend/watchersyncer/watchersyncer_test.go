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

package watchersyncer_test

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
)

var (
	dsError = cerrors.ErrorDatastoreError{Err: errors.New("Generic datastore error")}
	l1Key1  = model.ResourceKey{
		Kind:      apiv3.KindNetworkPolicy,
		Namespace: "namespace1",
		Name:      "policy-1",
	}
	l1Key2 = model.ResourceKey{
		Kind:      apiv3.KindNetworkPolicy,
		Namespace: "namespace1",
		Name:      "policy-2",
	}
	l1Key3 = model.ResourceKey{
		Kind:      apiv3.KindNetworkPolicy,
		Namespace: "namespace2",
		Name:      "policy-1",
	}
	l1Key4 = model.ResourceKey{
		Kind:      apiv3.KindNetworkPolicy,
		Namespace: "namespace2999",
		Name:      "policy-1000",
	}
	l2Key1 = model.ResourceKey{
		Kind: apiv3.KindIPPool,
		Name: "ippool-1",
	}
	l2Key2 = model.ResourceKey{
		Kind: apiv3.KindIPPool,
		Name: "ippool-2",
	}
	l3Key1 = model.BlockAffinityKey{
		CIDR: cnet.MustParseCIDR("1.2.3.0/24"),
		Host: "mynode",
	}
	emptyList = &model.KVPairList{
		Revision: "abcdef12345",
	}
	notSupported = cerrors.ErrorOperationNotSupported{}
	notExists    = cerrors.ErrorResourceDoesNotExist{}
	tooOldRV     = kerrors.NewResourceExpired("test error")
	genError     = errors.New("Generic error")
)

var _ = Describe("Test the backend datastore multi-watch syncer", func() {
	r1 := watchersyncer.ResourceType{
		ListInterface: model.ResourceListOptions{Kind: apiv3.KindNetworkPolicy},
	}
	r2 := watchersyncer.ResourceType{
		ListInterface: model.ResourceListOptions{Kind: apiv3.KindIPPool},
	}
	r3 := watchersyncer.ResourceType{
		ListInterface: model.BlockAffinityListOptions{},
	}

	It("should receive a sync event when the watchers have listed current settings", func() {
		rs := newWatcherSyncerTester([]watchersyncer.ResourceType{r1, r2, r3})
		rs.ExpectStatusUpdate(api.WaitForDatastore)
		rs.clientListResponse(r1, emptyList)
		rs.ExpectStatusUpdate(api.ResyncInProgress)
		rs.clientListResponse(r2, emptyList)
		rs.ExpectStatusUnchanged()
		rs.clientListResponse(r3, emptyList)
		rs.ExpectStatusUpdate(api.InSync)
	})

	It("should not change status if watch returns multiple ErrorOperationNotSupported errors", func() {
		rs := newWatcherSyncerTester([]watchersyncer.ResourceType{r1})
		rs.ExpectStatusUpdate(api.WaitForDatastore)
		rs.clientListResponse(r1, emptyList)
		rs.ExpectStatusUpdate(api.ResyncInProgress)
		rs.ExpectStatusUpdate(api.InSync)
		rs.clientWatchResponse(r1, notSupported)
		rs.ExpectStatusUnchanged()
		rs.clientWatchResponse(r1, notSupported)
		rs.ExpectStatusUnchanged()
		rs.clientWatchResponse(r1, notSupported)
		rs.ExpectStatusUnchanged()
		rs.clientWatchResponse(r1, notSupported)
		rs.ExpectStatusUnchanged()
		rs.clientWatchResponse(r1, notSupported)
		rs.ExpectStatusUnchanged()
	})

	It("should not change status if watch returns multiple ErrorResourceDoesNotExist errors", func() {
		rs := newWatcherSyncerTester([]watchersyncer.ResourceType{r1})
		rs.ExpectStatusUpdate(api.WaitForDatastore)
		rs.clientListResponse(r1, emptyList)
		rs.ExpectStatusUpdate(api.ResyncInProgress)
		rs.ExpectStatusUpdate(api.InSync)
		rs.clientWatchResponse(r1, notExists)
		rs.ExpectStatusUnchanged()
		rs.clientWatchResponse(r1, notExists)
		rs.ExpectStatusUnchanged()
		rs.clientWatchResponse(r1, notExists)
		rs.ExpectStatusUnchanged()
		rs.clientWatchResponse(r1, notExists)
		rs.ExpectStatusUnchanged()
		rs.clientWatchResponse(r1, notExists)
		rs.ExpectStatusUnchanged()
	})

	// Tests the scenario found in this issue: https://github.com/projectcalico/calico/issues/6032
	It("should handle resourceVersion expired errors", func() {
		// Temporarily reduce the watch and list poll interval to make the tests faster.
		// Since we are timing the processing, we still need the interval to be sufficiently
		// large to make the measurements more accurate.
		defer setWatchIntervals(watchersyncer.ListRetryInterval, watchersyncer.WatchPollInterval)
		setWatchIntervals(500*time.Millisecond, 2000*time.Millisecond)

		rs := newWatcherSyncerTester([]watchersyncer.ResourceType{r1})
		rs.ExpectStatusUpdate(api.WaitForDatastore)
		rs.clientListResponse(r1, tooOldRV)
		rs.clientListResponse(r1, emptyList)
		rs.ExpectStatusUpdate(api.ResyncInProgress)
		rs.ExpectStatusUpdate(api.InSync)

		// Send a watch error. This will trigger a re-list from the revision
		// the watcher cache has stored.
		rs.clientWatchResponse(r1, notSupported)
		rs.clientListResponse(r1, emptyList)

		// Expect List and watch be called with the emptylist revision.
		Eventually(rs.fc.getLatestListRevision, 5*time.Second, 100*time.Millisecond).Should(Equal(emptyList.Revision))
		Eventually(rs.fc.getLatestWatchRevision, 5*time.Second, 100*time.Millisecond).Should(Equal(emptyList.Revision))

		// Send a watch error, followed by a resource version too old error
		// on the list. This should trigger the watcher cache to retry the list
		// without a revision.
		rs.clientWatchResponse(r1, genError)
		rs.clientListResponse(r1, tooOldRV)
		Eventually(rs.fc.getLatestListRevision, 5*time.Second, 100*time.Millisecond).Should(Equal("0"))

		// Simulate a successful list using the 0 revision - we should see the watch started from the correct
		// revision again.
		rs.clientListResponse(r1, emptyList)
		Eventually(rs.fc.getLatestWatchRevision, 5*time.Second, 100*time.Millisecond).Should(Equal(emptyList.Revision))
	})

	It("should handle reconnection if watchers fail to be created", func() {
		rs := newWatcherSyncerTester([]watchersyncer.ResourceType{r1, r2, r3})
		rs.ExpectStatusUpdate(api.WaitForDatastore)

		// Temporarily reduce the watch and list poll interval to make the tests faster.
		// Since we are timing the processing, we still need the interval to be sufficiently
		// large to make the measurements more accurate.
		defer setWatchIntervals(watchersyncer.ListRetryInterval, watchersyncer.WatchPollInterval)
		setWatchIntervals(500*time.Millisecond, 2000*time.Millisecond)

		// All of the events should have been consumed within a time frame dictated by the
		// list retry and poll timers.
		//
		// For resource 1, the client responses should be:
		// - list succeeds
		// - watch fails gen error (immediate retry)
		// - list fails (list interval)
		// - list succeeds
		// - watch succeeds ...
		//
		// For resource 2, the client responses should be:
		// - list succeeds
		// - watch fails with not supported (watch interval)
		// - list succeeds
		// - watch fails with not supported (watch interval)
		// - list succeeds
		// - watch succeeds ...
		//
		// The longest of these is resource 2 (since the watcher poll timer is longer).  We'll
		// check that connection succeeds within -30% and +50% of the expected interval.
		By("Driving a bunch of List complete, Watch fail events for 2/3 resource types")
		expectedDuration := watchersyncer.WatchPollInterval * 2
		minDuration := 70 * expectedDuration / 100
		maxDuration := 150 * expectedDuration / 100
		before := time.Now()
		rs.clientListResponse(r1, emptyList)
		rs.ExpectStatusUpdate(api.ResyncInProgress)
		rs.clientWatchResponse(r1, genError)
		rs.ExpectStatusUnchanged()
		rs.clientListResponse(r1, emptyList)
		rs.ExpectStatusUnchanged()
		// rs.ExpectStatusUpdate(api.InSync)
		rs.clientWatchResponse(r1, nil)
		rs.clientListResponse(r2, emptyList)
		rs.clientWatchResponse(r2, notSupported)
		rs.clientListResponse(r2, emptyList)
		rs.clientWatchResponse(r2, notSupported)
		rs.clientListResponse(r2, emptyList)
		rs.clientWatchResponse(r2, nil)
		By("Expecting the time for all events to be handled is within a sensible window")
		for i := time.Duration(0); i < maxDuration/(10*time.Millisecond); i++ {
			if rs.allEventsHandled() {
				break
			}
			time.Sleep(minDuration / 50)
		}
		duration := time.Now().Sub(before)
		rs.expectAllEventsHandled()
		Expect(duration).To(BeNumerically(">", minDuration))
		Expect(duration).To(BeNumerically("<", maxDuration))
		rs.ExpectStatusUnchanged()

		// Sim. for resource 3.  We send in these client responses:
		// - list succeeds
		// - watch fails with not supported (watch interval)
		// - list fails (list interval)
		// - list succeeds
		// - watch succeeds ... total 6s
		By("Driving a bunch of List complete, Watch fail events for the 3rd resource type")
		expectedDuration = watchersyncer.WatchPollInterval * watchersyncer.ListRetryInterval
		minDuration = 70 * expectedDuration / 100
		maxDuration = 130 * expectedDuration / 100
		before = time.Now()
		rs.clientListResponse(r3, emptyList)
		rs.ExpectStatusUpdate(api.InSync)
		rs.clientWatchResponse(r3, notSupported)
		rs.ExpectStatusUnchanged()
		rs.clientListResponse(r3, genError)
		rs.ExpectStatusUnchanged()
		rs.clientListResponse(r3, emptyList)
		rs.ExpectStatusUnchanged()
		rs.clientWatchResponse(r3, nil)
		rs.ExpectStatusUnchanged()
		By("Expecting the time for the events of the final resource sync to be handled is within sensible window")
		for i := time.Duration(0); i < maxDuration/(10*time.Millisecond); i++ {
			if rs.allEventsHandled() {
				break
			}
			time.Sleep(minDuration / 50)
		}
		duration = time.Now().Sub(before)
		rs.expectAllEventsHandled()
		Expect(duration).To(BeNumerically(">", minDuration))
		Expect(duration).To(BeNumerically("<", maxDuration))
	})

	It("Should handle reconnection and syncing when the watcher sends a watch terminated error", func() {
		rs := newWatcherSyncerTester([]watchersyncer.ResourceType{r1, r2, r3})
		rs.ExpectStatusUpdate(api.WaitForDatastore)
		rs.clientListResponse(r1, emptyList)
		rs.ExpectStatusUpdate(api.ResyncInProgress)
		rs.clientWatchResponse(r1, nil)
		rs.clientListResponse(r2, emptyList)
		rs.clientWatchResponse(r2, nil)
		rs.ExpectStatusUnchanged()
		rs.clientListResponse(r3, emptyList)
		rs.ExpectStatusUpdate(api.InSync)
		rs.clientWatchResponse(r3, nil)
		rs.sendEvent(r3, api.WatchEvent{
			Type:  api.WatchError,
			Error: dsError,
		})
		rs.ExpectStatusUnchanged()
		rs.clientListResponse(r3, emptyList)
		rs.ExpectStatusUnchanged()
		rs.clientWatchResponse(r3, nil)
		rs.ExpectStatusUnchanged()

		// Watch fails, but gets created again immediately.  This should happen without
		// additional pauses.
		rs.expectAllEventsHandled()
	})

	It("Should handle receiving events while one watcher fails and fails to recreate", func() {
		rs := newWatcherSyncerTester([]watchersyncer.ResourceType{r1, r2, r3})
		eventL1Added1 := addEvent(l1Key1)
		eventL2Added1 := addEvent(l2Key1)
		eventL2Added2 := addEvent(l2Key2)
		eventL3Added1 := addEvent(l3Key1)

		// Temporarily reduce the watch and list poll interval to make the tests faster.
		defer setWatchIntervals(watchersyncer.ListRetryInterval, watchersyncer.WatchPollInterval)
		setWatchIntervals(100*time.Millisecond, 500*time.Millisecond)

		By("Syncing a single result for resource 1 and creating the watch")
		rs.ExpectStatusUpdate(api.WaitForDatastore)
		rs.clientListResponse(r1, &model.KVPairList{
			Revision: "aabababababa",
			KVPairs: []*model.KVPair{
				{
					Revision: eventL1Added1.New.Revision,
					Key:      eventL1Added1.New.Key,
					Value:    eventL1Added1.New.Value,
				},
			},
		})
		rs.ExpectStatusUpdate(api.ResyncInProgress)
		rs.clientWatchResponse(r1, nil)

		// For resource 2 we fail to create a watch.  This will invoke the watch poll interval.
		By("Syncing no results for resource 2, failing to create a watch, retrying successfully.")
		rs.clientListResponse(r2, emptyList)
		rs.clientWatchResponse(r2, genError)
		rs.ExpectStatusUnchanged()
		rs.clientListResponse(r2, emptyList)
		rs.ExpectStatusUnchanged()
		rs.clientWatchResponse(r2, nil)
		time.Sleep(130 * watchersyncer.WatchPollInterval / 100)
		rs.expectAllEventsHandled()

		By("Sending two watch events for resource 2.")
		rs.sendEvent(r2, eventL2Added1)
		rs.sendEvent(r2, eventL2Added2)

		By("Syncing no results for resource 3, creating a watcher and then terminating the watcher.")
		rs.clientListResponse(r3, emptyList)
		rs.ExpectStatusUpdate(api.InSync)
		rs.clientWatchResponse(r3, nil)
		rs.sendEvent(r3, api.WatchEvent{
			Type:  api.WatchError,
			Error: dsError,
		})
		rs.ExpectStatusUnchanged()
		rs.clientListResponse(r3, emptyList)
		rs.ExpectStatusUnchanged()
		rs.clientWatchResponse(r3, nil)
		rs.ExpectStatusUnchanged()
		rs.clientWatchResponse(r3, nil)
		// All events should be handled.
		rs.expectAllEventsHandled()

		By("Validating we are still resyncing and we have received all the current events thus far")
		rs.ExpectUpdates([]api.Update{
			{
				KVPair:     *eventL1Added1.New,
				UpdateType: api.UpdateTypeKVNew,
			},
			{
				KVPair:     *eventL2Added1.New,
				UpdateType: api.UpdateTypeKVNew,
			},
			{
				KVPair:     *eventL2Added2.New,
				UpdateType: api.UpdateTypeKVNew,
			},
		}, true)

		By("Checking that resource 3 can reconnect and then receive events")
		rs.clientListResponse(r3, emptyList)
		rs.clientWatchResponse(r3, nil)
		rs.ExpectStatusUnchanged()
		rs.sendEvent(r3, eventL3Added1)
		rs.ExpectUpdates([]api.Update{
			{
				KVPair:     *eventL3Added1.New,
				UpdateType: api.UpdateTypeKVNew,
			},
		}, true)
	})

	It("Should not resend add events during a resync and should delete stale entries", func() {
		rs := newWatcherSyncerTester([]watchersyncer.ResourceType{r1})
		eventL1Added1 := addEvent(l1Key1)
		eventL1Deleted1 := deleteEvent(l1Key1)
		eventL1Added2 := addEvent(l1Key2)
		eventL1Added3 := addEvent(l1Key3)
		eventL1Added4 := addEvent(l1Key4)
		eventL1Modified4 := modifiedEvent(l1Key4)
		eventL1Modified4_2 := modifiedEvent(l1Key4)

		// Temporarily reduce the watch and list poll interval to make the tests faster.
		defer setWatchIntervals(watchersyncer.ListRetryInterval, watchersyncer.WatchPollInterval)
		setWatchIntervals(100*time.Millisecond, 500*time.Millisecond)

		By("returning a sync list with three entries and then failing the watch")
		rs.ExpectStatusUpdate(api.WaitForDatastore)
		rs.clientListResponse(r1, &model.KVPairList{
			Revision: "12345",
			KVPairs: []*model.KVPair{
				eventL1Added1.New,
				eventL1Added2.New,
				eventL1Added3.New,
			},
		})
		rs.ExpectStatusUpdate(api.ResyncInProgress)
		rs.ExpectStatusUpdate(api.InSync)

		// The retry thread will be blocked for the watch poll interval.
		rs.clientWatchResponse(r1, genError)
		time.Sleep(watchersyncer.WatchPollInterval)
		rs.ExpectStatusUnchanged()

		By("returning a sync list with one entry removed and a new one added")
		rs.clientListResponse(r1, &model.KVPairList{
			Revision: "12346",
			KVPairs: []*model.KVPair{
				eventL1Added1.New,
				eventL1Added3.New,
				eventL1Added4.New,
			},
		})

		rs.ExpectStatusUnchanged()

		rs.clientWatchResponse(r1, nil)

		By("Expecting new events for the first three entries followed by an add and then the delete")
		rs.ExpectUpdates([]api.Update{
			{
				KVPair:     *eventL1Added1.New,
				UpdateType: api.UpdateTypeKVNew,
			},
			{
				KVPair:     *eventL1Added2.New,
				UpdateType: api.UpdateTypeKVNew,
			},
			{
				KVPair:     *eventL1Added3.New,
				UpdateType: api.UpdateTypeKVNew,
			},
			{
				KVPair:     *eventL1Added4.New,
				UpdateType: api.UpdateTypeKVNew,
			},
			{
				// Remove the Value for deleted.
				KVPair: model.KVPair{
					Key: eventL1Added2.New.Key,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			},
		}, true)

		By("Sending a watch event updating one of the entries and deleting another")
		rs.sendEvent(r1, eventL1Modified4)
		rs.sendEvent(r1, eventL1Deleted1)

		By("Sending the same events (bug) but same revision, so no updates expected")
		rs.sendEvent(r1, eventL1Modified4)
		rs.sendEvent(r1, eventL1Deleted1)

		By("Failing the watch, and resyncing with another modified entry")
		rs.sendEvent(r1, api.WatchEvent{
			Type:  api.WatchError,
			Error: dsError,
		})
		rs.ExpectStatusUnchanged()
		rs.clientListResponse(r1, &model.KVPairList{
			Revision: "12347",
			KVPairs: []*model.KVPair{
				eventL1Added3.New,
				eventL1Modified4_2.New,
			},
		})
		rs.ExpectStatusUnchanged()

		By("Expecting mod, delete, mod updates")
		rs.ExpectUpdates([]api.Update{
			{
				KVPair:     *eventL1Modified4.New,
				UpdateType: api.UpdateTypeKVUpdated,
			},
			{
				// Remove the Value for deleted.
				KVPair: model.KVPair{
					Key: eventL1Deleted1.Old.Key,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			},
			{
				KVPair:     *eventL1Modified4_2.New,
				UpdateType: api.UpdateTypeKVUpdated,
			},
		}, true)
	})

	It("Should accumulate updates into a single update when the handler thread is blocked", func() {
		rs := newWatcherSyncerTester([]watchersyncer.ResourceType{r1, r2})
		eventL1Added1 := addEvent(l1Key1)
		eventL2Added1 := addEvent(l2Key1)
		eventL2Added2 := addEvent(l2Key2)
		eventL2Modified1 := modifiedEvent(l2Key1)
		eventL1Delete1 := deleteEvent(l1Key1)

		rs.ExpectStatusUpdate(api.WaitForDatastore)
		rs.clientListResponse(r1, emptyList)
		rs.ExpectStatusUpdate(api.ResyncInProgress)
		rs.clientWatchResponse(r1, nil)
		rs.clientListResponse(r2, emptyList)
		rs.ExpectStatusUpdate(api.InSync)
		rs.clientWatchResponse(r2, nil)

		// Block the handling thread.  We need a single event to actual cause the main
		// handling loop to block though, so send one.
		rs.BlockUpdateHandling()
		rs.sendEvent(r1, eventL1Added1)

		// We should get the first update in a single update message, and then the update handler will block.
		rs.ExpectOnUpdates([][]api.Update{{
			{
				KVPair:     *eventL1Added1.New,
				UpdateType: api.UpdateTypeKVNew,
			},
		}})

		// Send a few more events.
		rs.sendEvent(r2, eventL2Added1)
		rs.sendEvent(r2, eventL2Added2)
		rs.sendEvent(r2, eventL2Modified1)

		// Pause briefly before unblocking the update thread.
		// We should receive three events in 1 OnUpdate message.
		time.Sleep(100 * time.Millisecond)
		rs.UnblockUpdateHandling()
		rs.ExpectOnUpdates([][]api.Update{{
			{
				KVPair:     *eventL2Added1.New,
				UpdateType: api.UpdateTypeKVNew,
			},
			{
				KVPair:     *eventL2Added2.New,
				UpdateType: api.UpdateTypeKVNew,
			},
			{
				KVPair:     *eventL2Modified1.New,
				UpdateType: api.UpdateTypeKVUpdated,
			},
		}})

		// Block the update process again and send in a Delete and wait for the update.
		rs.BlockUpdateHandling()
		rs.sendEvent(r1, eventL1Delete1)
		rs.ExpectOnUpdates([][]api.Update{{
			{
				KVPair: model.KVPair{
					Key: eventL1Delete1.Old.Key,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			},
		}})
	})

	It("should emit all events when stop is called", func() {
		eventL1Added1 := addEvent(l1Key1)
		eventL2Added1 := addEvent(l2Key1)
		eventL2Added2 := addEvent(l2Key2)

		rs := newWatcherSyncerTester([]watchersyncer.ResourceType{r1, r2})
		rs.ExpectStatusUpdate(api.WaitForDatastore)
		rs.clientListResponse(r1, emptyList)
		rs.clientListResponse(r2, emptyList)
		rs.ExpectStatusUpdate(api.ResyncInProgress)

		rs.ExpectStatusUpdate(api.InSync)
		rs.clientWatchResponse(r1, nil)
		rs.clientWatchResponse(r2, nil)

		rs.sendEvent(r1, eventL1Added1)
		rs.sendEvent(r2, eventL2Added1)
		rs.sendEvent(r2, eventL2Added2)

		rs.ExpectUpdates([]api.Update{
			{
				KVPair:     *eventL1Added1.New,
				UpdateType: api.UpdateTypeKVNew,
			},
			{
				KVPair:     *eventL2Added1.New,
				UpdateType: api.UpdateTypeKVNew,
			},
			{
				KVPair:     *eventL2Added2.New,
				UpdateType: api.UpdateTypeKVNew,
			},
		}, false)

		// Now stop it and check that deleted events are sent
		rs.watcherSyncer.Stop()
		rs.ExpectUpdates([]api.Update{
			{
				KVPair:     model.KVPair{Key: eventL1Added1.New.Key},
				UpdateType: api.UpdateTypeKVDeleted,
			},
			{
				KVPair:     model.KVPair{Key: eventL2Added1.New.Key},
				UpdateType: api.UpdateTypeKVDeleted,
			},
			{
				KVPair:     model.KVPair{Key: eventL2Added2.New.Key},
				UpdateType: api.UpdateTypeKVDeleted,
			},
		}, false)
	})

	It("Should invoke the supplied converter to alter the update", func() {
		rc1 := watchersyncer.ResourceType{
			UpdateProcessor: &fakeConverter{},
			ListInterface:   model.ResourceListOptions{Kind: apiv3.KindNetworkPolicy},
		}

		// Since the fake converter doesn't actually look at the incoming event we can
		// send in arbitrary data.  Block the handler thread and send in 1 event and wait for it -
		// this event will block the update handling process.
		// Send in another 6 events to cover the different branches of the fake converter.
		//
		// See fakeConverter for details on what is returned each invocation.
		rs := newWatcherSyncerTester([]watchersyncer.ResourceType{rc1})
		rs.ExpectStatusUpdate(api.WaitForDatastore)
		rs.clientListResponse(r1, emptyList)
		rs.ExpectStatusUpdate(api.ResyncInProgress)
		rs.ExpectStatusUpdate(api.InSync)
		rs.clientWatchResponse(r1, nil)
		rs.BlockUpdateHandling()
		rs.sendEvent(r1, addEvent(l1Key1))
		rs.ExpectOnUpdates([][]api.Update{{{
			KVPair:     *fakeConverterKVP1,
			UpdateType: api.UpdateTypeKVNew, // key: l1Key1
		}}})
		rs.sendEvent(r1, addEvent(l1Key1))
		rs.sendEvent(r1, addEvent(l1Key1))
		rs.sendEvent(r1, addEvent(l1Key1))
		rs.sendEvent(r1, addEvent(l1Key1))
		rs.sendEvent(r1, addEvent(l1Key1))
		rs.sendEvent(r1, addEvent(l1Key1))

		// Pause briefly and then unblock the thread.  The events should be collated
		// except that an error will cause the events to be sent immediately.
		time.Sleep(100 * time.Millisecond)
		rs.UnblockUpdateHandling()
		rs.ExpectOnUpdates([][]api.Update{
			{
				{
					KVPair:     *fakeConverterKVP2,
					UpdateType: api.UpdateTypeKVUpdated, // key: l1Key1
				},
				{
					KVPair:     *fakeConverterKVP3,
					UpdateType: api.UpdateTypeKVNew, // key: l1Key2
				},
			},
			{
				{
					KVPair: model.KVPair{
						Key: fakeConverterKVP4.Key,
					},
					UpdateType: api.UpdateTypeKVDeleted, // key: l1Key2
				},
			},
			{
				{
					KVPair:     *fakeConverterKVP5,
					UpdateType: api.UpdateTypeKVUpdated, // key: l1Key1
				},
				{
					KVPair:     *fakeConverterKVP6,
					UpdateType: api.UpdateTypeKVUpdated, // key: l1Key1
				},
			},
		})

		// We should have received a parse error.
		rs.ExpectParseError("abcdef", "aabbccdd")

		// Send a deleted event.  We should get a single deletion event for l1Key1 since
		// l1Key2 is already deleted.  We should also get an updated Parse error.
		rs.sendEvent(r1, deleteEvent(l1Key1))
		time.Sleep(100 * time.Millisecond)
		rs.ExpectOnUpdates([][]api.Update{
			{
				{
					KVPair: model.KVPair{
						Key: l1Key1,
					},
					UpdateType: api.UpdateTypeKVDeleted,
				},
			},
		})
		rs.ExpectParseError("zzzzz", "xxxxx")
	})
})

var (
	// Test events for the conversion code.
	fakeConverterKVP1 = &model.KVPair{
		Key:      l1Key1,
		Value:    "abcdef",
		Revision: "abcdefg",
	}
	fakeConverterKVP2 = &model.KVPair{
		Key:      l1Key1,
		Value:    "abcdefgh",
		Revision: "abcdfg",
	}
	fakeConverterKVP3 = &model.KVPair{
		Key:      l1Key2,
		Value:    "abcdef",
		Revision: "abcdefg",
	}
	fakeConverterKVP4 = &model.KVPair{
		Key:      l1Key2,
		Revision: "abfdgscdfg",
	}
	fakeConverterKVP5 = &model.KVPair{
		Key:      l1Key1,
		Value:    "abcdeddfgh",
		Revision: "abfdgffffscdfg",
	}
	fakeConverterKVP6 = &model.KVPair{
		Key:      l1Key1,
		Value:    "abcdeddgjdfgjdfgdfgh",
		Revision: "abfdgscdfg",
	}
)

// Set the list interval and watch interval in the WatcherSyncer.  We do this to reduce
// the test time.
func setWatchIntervals(listRetryInterval, watchPollInterval time.Duration) {
	watchersyncer.ListRetryInterval = listRetryInterval
	watchersyncer.WatchPollInterval = watchPollInterval
}

// Fake converter used to cover error and update handling paths.
type fakeConverter struct {
	i int
}

func (fc *fakeConverter) Process(kvp *model.KVPair) ([]*model.KVPair, error) {
	if kvp.Value == nil {
		// This is a delete.
		return []*model.KVPair{
				{
					Key: l1Key1,
				},
				{
					Key: l1Key2,
				},
			}, cerrors.ErrorParsingDatastoreEntry{
				RawKey:   "zzzzz",
				RawValue: "xxxxx",
			}
	}

	// This is an add.
	fc.i++
	switch fc.i {
	case 1: // First update used to block update thread in test.
		return []*model.KVPair{
			fakeConverterKVP1,
		}, nil
	case 2: // Second contains two updates.
		return []*model.KVPair{
			fakeConverterKVP2,
			fakeConverterKVP3,
		}, nil
	case 3: // Third contains an error, which will result in the update event.
		return nil, errors.New("Fake error that we should handle gracefully")
	case 4: // Fourth contains event and error, event will be sent and parse error will be stored.
		return []*model.KVPair{
				fakeConverterKVP4,
			}, cerrors.ErrorParsingDatastoreEntry{
				RawKey:   "abcdef",
				RawValue: "aabbccdd",
			}
	case 5: // Fifth contains an update.
		return []*model.KVPair{
			fakeConverterKVP5,
		}, nil
	case 6: // Sixth contains nothing.
		return nil, nil
	case 7: // Seventh contains another update that will be appended to the one in case 5.
		return []*model.KVPair{
			fakeConverterKVP6,
		}, nil
	}
	return nil, nil
}

func (fc *fakeConverter) OnSyncerStarting() {
}

// Create a delete event from a Key. The value types don't need to match the
// Key types since we aren't unmarshaling/marshaling them in this package.
func deleteEvent(key model.Key) api.WatchEvent {
	return api.WatchEvent{
		Type: api.WatchDeleted,
		Old: &model.KVPair{
			Key:      key,
			Value:    uuid.NewString(),
			Revision: uuid.NewString(),
		},
	}
}

// Create an add event from a Key. The value types don't need to match the
// Key types since we aren't unmarshaling/marshaling them in this package.
func addEvent(key model.Key) api.WatchEvent {
	return api.WatchEvent{
		Type: api.WatchAdded,
		New: &model.KVPair{
			Key:      key,
			Value:    uuid.NewString(),
			Revision: uuid.NewString(),
		},
	}
}

// Create a modified event from a Key. The value types don't need to match the
// Key types since we aren't unmarshaling/marshaling them in this package.
func modifiedEvent(key model.Key) api.WatchEvent {
	return api.WatchEvent{
		Type: api.WatchModified,
		New: &model.KVPair{
			Key:      key,
			Value:    uuid.NewString(),
			Revision: uuid.NewString(),
		},
	}
}

// Create a new watcherSyncerTester - this creates and starts a WatcherSyncer with
// client and sync consumer interfaces implemented and controlled by the test.
func newWatcherSyncerTester(l []watchersyncer.ResourceType) *watcherSyncerTester {
	// Create the required watchers.  This hs methods that we use to drive
	// responses.
	lws := map[string]*listWatchSource{}
	for _, r := range l {
		// We create a watcher for each resource type.  We'll store these off the
		// default enumeration path for that resource.
		name := model.ListOptionsToDefaultPathRoot(r.ListInterface)
		lws[name] = &listWatchSource{
			name:            name,
			watchCallError:  make(chan error, 50),
			listCallResults: make(chan interface{}, 200),
			stopEvents:      make(chan struct{}, 200),
			results:         make(chan api.WatchEvent, 200),
		}
	}

	fc := &fakeClient{
		lws: lws,
	}

	// Create the syncer tester.
	st := testutils.NewSyncerTester()
	rst := &watcherSyncerTester{
		SyncerTester:  st,
		fc:            fc,
		watcherSyncer: watchersyncer.New(fc, l, st),
		lws:           lws,
	}
	rst.watcherSyncer.Start()
	return rst
}

// watcherSyncerTester is used to create, start and validate a watcherSyncer.  It
// contains a number of useful methods used for asserting current state.
//
// This helper extends the function of the testutils SyncerTester.
type watcherSyncerTester struct {
	*testutils.SyncerTester
	fc            *fakeClient
	lws           map[string]*listWatchSource
	watcherSyncer api.Syncer
}

// Call to test that all of the client and watcher events have been processed.
// Note that an unhandled event could easily be a problem with the test rather
// than the watcherSyncer.
func (rst *watcherSyncerTester) expectAllEventsHandled() {
	log.Infof("Expecting all events to have been handled")
	for _, l := range rst.lws {
		Expect(l.listCallResults).To(HaveLen(0), "pending list results to be processed")
		Expect(l.stopEvents).To(HaveLen(0), "pending stop events to be processed")
		Expect(l.results).To(HaveLen(0), "pending watch results to be processed")
	}
}

// Call to test whether the client and watcher events have been processed.
// If you expect all events to be handled, use expectAllEventsHandled as the diagnostics
// are better.
func (rst *watcherSyncerTester) allEventsHandled() bool {
	eventsHandled := true
	for _, l := range rst.lws {
		eventsHandled = eventsHandled && (len(l.listCallResults) == 0)
		eventsHandled = eventsHandled && (len(l.stopEvents) == 0)
		eventsHandled = eventsHandled && (len(l.results) == 0)
	}
	return eventsHandled
}

// Call to send an event via a particular watcher.
func (rst *watcherSyncerTester) sendEvent(r watchersyncer.ResourceType, event api.WatchEvent) {
	name := model.ListOptionsToDefaultPathRoot(r.ListInterface)
	log.WithField("Name", name).Infof("Sending event")

	// The test framework uses a single results channel for each resource, so to send the
	// results deterministically we need to wait for a terminating watcher to finish
	// terminating (so we know exactly which mock watcher invocation the result will be sent
	// from).
	log.Info("Waiting for previous watcher to terminate (if any)")
	rst.lws[name].termWg.Wait()
	log.Info("Previous watcher terminated (if any)")

	if event.Type == api.WatchError {
		// Watch errors are treated as a terminating event.  Our test framework will shut down the previous
		// watcher as part of the creation of the new one.  Increment the init wait group
		// in the watcher which will be decremented once the old one has fully terminated.
		log.WithField("Name", name).Info("Watcher error will trigger restart - increment termination count")
		rst.lws[name].termWg.Add(1)

	}

	log.WithField("Name", name).Info("Sending event")
	rst.lws[name].results <- event

	if event.Type == api.WatchError {
		// Finally, since this is a terminating event then we expect a corresponding Stop()
		// invocation (now that the event has been sent).
		log.WithField("Name", name).Info("Expecting a stop invocation")
		rst.expectStop(r)
		log.WithField("Name", name).Info("Stop invoked")
	}
}

// Call to verify that stop has been invoked on the watcher.
func (rst *watcherSyncerTester) expectStop(r watchersyncer.ResourceType) {
	name := model.ListOptionsToDefaultPathRoot(r.ListInterface)
	log.WithField("Name", name).Infof("Expecting Stop")
	Eventually(func() bool {
		return len(rst.lws[name].stopEvents) > 0
	}).Should(BeTrue())

	// Pull the stop event to acknowledge it.
	<-rst.lws[name].stopEvents
}

// Call to specify the response of the client List invocation.  The List call will block
// until the response has been specified.
// The response should either be of type error, or type *KVPairList.
func (rst *watcherSyncerTester) clientListResponse(r watchersyncer.ResourceType, response interface{}) {
	name := model.ListOptionsToDefaultPathRoot(r.ListInterface)
	log.WithFields(log.Fields{
		"Name":     name,
		"Response": response,
	}).Info("Setting client List response")
	switch response.(type) {
	case error, *model.KVPairList:
		rst.lws[name].listCallResults <- response
	default:
		panic("Error in test, wrong type specified")
	}
}

// Call to specify the response of the client Watch invocation.  The Watch call will block
// until the response has been specified.
// The response should either be error type or nil (indicating no error).
func (rst *watcherSyncerTester) clientWatchResponse(r watchersyncer.ResourceType, err error) {
	name := model.ListOptionsToDefaultPathRoot(r.ListInterface)
	log.WithFields(log.Fields{
		"Name":  name,
		"Error": err,
	}).Info("Setting client Watch response")

	// Send the required response.
	rst.lws[name].watchCallError <- err
}

// fakeClient implements the api.Client interface.  We mock this out so that we can control
// the events
type fakeClient struct {
	lws map[string]*listWatchSource

	// Allows us to track the revision that the syncer is using.
	latestListRevision  string
	latestWatchRevision string
}

func (c *fakeClient) getLatestListRevision() string {
	return c.latestListRevision
}

func (c *fakeClient) getLatestWatchRevision() string {
	return c.latestWatchRevision
}

// We don't implement any of the CRUD related methods, just the Watch method to return
// a fake watcher that the test code will drive.
func (c *fakeClient) Create(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	panic("should not be called")
	return nil, nil
}

func (c *fakeClient) Update(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	panic("should not be called")
	return nil, nil
}

func (c *fakeClient) Apply(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	panic("should not be called")
	return nil, nil
}

func (c *fakeClient) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	panic("should not be called")
	return nil, nil
}

func (c *fakeClient) Delete(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	panic("should not be called")
	return nil, nil
}

func (c *fakeClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	panic("should not be called")
	return nil, nil
}

func (c *fakeClient) Syncer(callbacks api.SyncerCallbacks) api.Syncer {
	panic("should not be called")
	return nil
}

func (c *fakeClient) EnsureInitialized() error {
	panic("should not be called")
	return nil
}

func (c *fakeClient) Clean() error {
	panic("should not be called")
	return nil
}

func (c *fakeClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	// Create a fake watcher keyed off the ListOptions (root path).
	name := model.ListOptionsToDefaultPathRoot(list)
	log.WithField("Name", name).WithField("rev", revision).Info("List request")
	if l, ok := c.lws[name]; !ok || l == nil {
		panic("List for unhandled resource type")
	} else {
		c.latestListRevision = revision
		return l.list()
	}
}

func (c *fakeClient) Watch(ctx context.Context, list model.ListInterface, revision string) (api.WatchInterface, error) {
	// Create a fake watcher keyed off the ListOptions (root path).
	name := model.ListOptionsToDefaultPathRoot(list)
	log.WithField("Name", name).Info("Watch request")
	if l, ok := c.lws[name]; !ok || l == nil {
		panic("Watch for unhandled resource type")
	} else {
		c.latestWatchRevision = revision
		return l.watch()
	}
}

// listWatchSource provides the resource type specific control of the client List and Watch response,
// and the data returned by the watcher.
type listWatchSource struct {
	name string

	// The client Watch call will block until it receives on this channel.  A nil
	// error indicates the a watcher should be returned, a non-nil error will be
	// returned by the watch command.
	watchCallError chan error

	// The list results.  This channel with contain either:
	// - an error
	// - a *model.KVPairList
	listCallResults chan interface{}

	// Stop events channel.  We add an event each time stop is called for a watcher.
	stopEvents chan struct{}

	// The watcher blocks until it receives some events on the results chan.
	results chan api.WatchEvent

	// Current watcher.
	watcher *watcher

	// Termination wait group.  This is used to block sending events until the current watcher
	// has terminated.  This is required for this test harness due to the sharing of the results
	// channel.
	termWg sync.WaitGroup
}

// List returns the list results specified on the listCallError or listCallResults channel.
func (fw *listWatchSource) list() (*model.KVPairList, error) {
	result := <-fw.listCallResults
	switch r := result.(type) {
	case error:
		log.WithField("Name", fw.name).WithError(r).Info("Returning error from List invocation")
		return nil, r
	case *model.KVPairList:
		log.WithField("Name", fw.name).Info("Returning results from List invocation")
		return r, nil
	default:
		log.WithField("Result", r).Panic("Unexpected result on list result channel")
		return nil, nil
	}
}

// List returns the list results specified on the listCallError or listCallResults channel.
func (fw *listWatchSource) watch() (api.WatchInterface, error) {
	// another, wait for the previous watcher thread to terminate.  If Stop is not called then
	// this will block (but won't block the test) so the test will time out.
	if fw.watcher != nil {
		fw.watcher.terminate()
		fw.watcher = nil

		// Perform a non-blocking check to see if there is any unexpected data on the
		// results channel.
		select {
		case r := <-fw.results:
			log.Panicf("Test harness for %s expects results chan to be empty during watch creation: %v", fw.name, r)
		default:
		}

		// Previous watcher, if there was one has now terminated.
		log.WithField("Name", fw.name).Info("Marking termWg as done")
		fw.termWg.Done()
	}

	// Receive from the watchCallError channel to determine the result of this Watch invocation.
	e := <-fw.watchCallError
	if e != nil {
		log.WithField("Name", fw.name).WithError(e).Info("Returning error from watch invocation")
		return nil, e
	}

	// Create a new watcher and start the receive thread.  Note that the channels we use here are
	// blocking - so that we only drain from the test source channel when we actually process the
	// various events - this allows us to assert that when the main test channels are empty then
	// the watcher has sent/received all notification.
	log.WithField("Name", fw.name).Info("Returning new watcher")
	fw.watcher = &watcher{
		name:       fw.name,
		stopEvents: fw.stopEvents,
		results:    make(chan api.WatchEvent),
		done:       make(chan struct{}),
	}

	fw.watcher.start(fw.results)
	return fw.watcher, nil
}

// Each fake watcher has it's own results channel to ensure the WatcherSyncer is pulling from
// the correct watcher.
type watcher struct {
	name             string
	watcherRunningWg sync.WaitGroup
	stopEvents       chan<- struct{}
	results          chan api.WatchEvent
	done             chan struct{}
}

func (w *watcher) Stop() {
	log.WithField("Name", w.name).Info("Stop called on watcher")
	if w.stopEvents != nil {
		// It is ok for Stop() to be called multiple times, but we are only interested in
		// one call per watcher, so nil out the channel after sending so we don't send again.
		w.stopEvents <- struct{}{}
		w.stopEvents = nil
	}
}

func (w *watcher) ResultChan() <-chan api.WatchEvent {
	return w.results
}

func (w *watcher) HasTerminated() bool {
	// Never invoked by the syncer code, so no need to return anything sensible.
	log.WithField("Name", w.name).Panicf("HasTerminated called on watcher - not expected")
	return false
}

// start the watcher goroutine.
func (w *watcher) start(results <-chan api.WatchEvent) {
	log.WithField("Name", w.name).Info("start watcher")
	w.watcherRunningWg.Add(1)
	go w.run(results)
}

// terminate this watcher - this blocks until the watcher loop has exited.
func (w *watcher) terminate() {
	log.WithField("Name", w.name).Info("terminate watcher")
	w.done <- struct{}{}
	close(w.results)
	w.watcherRunningWg.Wait()
}

func (w *watcher) run(results <-chan api.WatchEvent) {
	defer w.watcherRunningWg.Done()
	for {
		select {
		// Funnel the result directly down this watchers result channel.
		case result := <-results:
			log.WithField("Name", w.name).Info("Sending watch event")
			select {
			case w.results <- result:
				log.WithField("Name", w.name).Info("Sent watch event")
			case <-w.done:
				log.WithField("Name", w.name).Info("Watcher loop is terminating")
				return
			}

		// Exit if we receive a done notification.
		case <-w.done:
			log.WithField("Name", w.name).Info("Watcher loop is terminating")
			return
		}
	}
}
