// Copyright (c) 2017,2021 Tigera, Inc. All rights reserved.
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

package snapcache_test

import (
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"

	"github.com/projectcalico/calico/typha/pkg/snapcache"

	"context"
	"fmt"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

type healthRecord struct {
	time time.Time
	health.HealthReport
}

type healthRecorder struct {
	expectedName string
	lock         sync.Mutex
	reports      []healthRecord
}

func (r *healthRecorder) RegisterReporter(name string, reports *health.HealthReport, timeout time.Duration) {

}

func (r *healthRecorder) Report(name string, report *health.HealthReport) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if name != r.expectedName {
		return
	}
	r.reports = append(r.reports, healthRecord{
		time:         time.Now(),
		HealthReport: *report,
	})
}

func (r *healthRecorder) NumReports() int {
	r.lock.Lock()
	defer r.lock.Unlock()
	return len(r.reports)
}

func (r *healthRecorder) LastReport() (rep health.HealthReport) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if len(r.reports) > 0 {
		rep = r.reports[len(r.reports)-1].HealthReport
	}
	return
}

func crumbToSnapshotUpdates(crumb *snapcache.Breadcrumb) []api.Update {
	var snapshotUpdates []api.Update
	for entry := range crumb.KVs.Iterator(nil) {
		upd, err := entry.Value.(syncproto.SerializedUpdate).ToUpdate()
		Expect(err).NotTo(HaveOccurred())
		snapshotUpdates = append(snapshotUpdates, upd)
	}
	return snapshotUpdates
}

var _ = Describe("Snapshot cache FV tests", func() {
	var cacheConfig snapcache.Config
	var cache *snapcache.Cache
	var cxt context.Context
	var cancel context.CancelFunc
	var wg sync.WaitGroup
	var mockHealth *healthRecorder

	BeforeEach(func() {
		log.SetLevel(log.InfoLevel)
		mockHealth = &healthRecorder{expectedName: "my-cache"}
		cacheConfig = snapcache.Config{
			MaxBatchSize:     10,
			WakeUpInterval:   10 * time.Second,
			HealthAggregator: mockHealth,
			HealthName:       "my-cache",
		}
		cache = snapcache.New(cacheConfig)
		cxt, cancel = context.WithCancel(context.Background())
		cache.Start(cxt)
	})

	AfterEach(func() {
		cancel()
	})

	Describe("after sending v3Node @ rev 10", func() {
		var kvNodeRev10 model.KVPair
		var crumb *snapcache.Breadcrumb
		var updateNodeRev10 api.Update

		BeforeEach(func() {
			kvNodeRev10 = model.KVPair{
				Key: model.ResourceKey{Name: "node1", Kind: v3.KindNode},
				Value: &v3.Node{
					ObjectMeta: metav1.ObjectMeta{
						ResourceVersion: "10",
						Name:            "foo",
					},
					Spec: v3.NodeSpec{
						IPv4VXLANTunnelAddr: "10.0.0.1",
					},
				},
				Revision: "10",
			}
			updateNodeRev10 = api.Update{
				KVPair:     kvNodeRev10,
				UpdateType: api.UpdateTypeKVNew,
			}
			cache.OnUpdates([]api.Update{updateNodeRev10})

			// Wait for the update to flow through...
			Eventually(func() bool {
				crumb = cache.CurrentBreadcrumb()
				crumbSize := crumb.KVs.Size()
				// Check snapshot is read-only.
				Expect(func() {
					crumb.KVs.Insert([]byte("abcd"), "unused")
				}).To(Panic())
				log.WithField("crumb", crumb).WithField("size", crumbSize).Info("Current crumb now...")
				Consistently(func() uint { return crumb.KVs.Size() }).Should(Equal(crumbSize))
				return crumbSize > 0
			}).Should(BeTrue())
			log.WithField("crumb", crumb).Info("Got initial crumb")

			// Put a time limit on how long these tests wait.
			go func() {
				time.Sleep(10 * time.Second)
				cancel()
			}()
		})

		It("should coalesce idempotent updates", func() {
			// Then send in another update with same value, and another value to make sure we generate another
			// crumb.
			kvNodeRev11 := model.KVPair{
				Key: model.ResourceKey{Name: "node1", Kind: v3.KindNode},
				Value: &v3.Node{
					ObjectMeta: metav1.ObjectMeta{
						ResourceVersion: "11",
						Name:            "foo",
					},
					Spec: v3.NodeSpec{
						IPv4VXLANTunnelAddr: "10.0.0.1",
					},
				},
				Revision: "11",
			}
			updateNodeRev11 := api.Update{
				KVPair:     kvNodeRev11,
				UpdateType: api.UpdateTypeKVUpdated,
			}

			updateBiff := api.Update{
				KVPair: model.KVPair{
					Key:      model.GlobalConfigKey{Name: "biff"},
					Value:    "baz",
					Revision: "12",
					TTL:      0,
				},
				UpdateType: api.UpdateTypeKVNew,
			}
			cache.OnUpdates([]api.Update{updateNodeRev11, updateBiff})

			// Wait for the next crumb...
			crumb, err := crumb.Next(cxt)
			Expect(err).NotTo(HaveOccurred())

			// Its snapshot should contain both items...
			snapshotUpdates := crumbToSnapshotUpdates(crumb)
			Expect(snapshotUpdates).To(ConsistOf(updateNodeRev10, updateBiff), "Snapshot cache should ignore no-op update")

			// Deltas should only contain the new update.
			Expect(deserialiseUpdates(crumb.Deltas)).To(ConsistOf(updateBiff), "Should only receive the second update as a delta")
		})
	})

	Describe("after sending GlobalConfigKey{foo}=bar @ rev 10", func() {
		var kvFooBarRev10 model.KVPair
		var crumb *snapcache.Breadcrumb
		var updateFooBarRev10 api.Update

		BeforeEach(func() {
			kvFooBarRev10 = model.KVPair{
				Key:      model.GlobalConfigKey{Name: "foo"},
				Value:    "bar",
				Revision: "10",
			}
			updateFooBarRev10 = api.Update{
				KVPair:     kvFooBarRev10,
				UpdateType: api.UpdateTypeKVNew,
			}
			cache.OnUpdates([]api.Update{updateFooBarRev10})

			// Wait for the update to flow through...
			Eventually(func() bool {
				crumb = cache.CurrentBreadcrumb()
				crumbSize := crumb.KVs.Size()
				// Check snapshot is read-only.
				Expect(func() {
					crumb.KVs.Insert([]byte("abcd"), "unused")
				}).To(Panic())
				log.WithField("crumb", crumb).WithField("size", crumbSize).Info("Current crumb now...")
				Consistently(func() uint { return crumb.KVs.Size() }).Should(Equal(crumbSize))
				return crumbSize > 0
			}).Should(BeTrue())
			log.WithField("crumb", crumb).Info("Got initial crumb")

			// Put a time limit on how long these tests wait.
			go func() {
				time.Sleep(10 * time.Second)
				cancel()
			}()
		})

		It("should coalesce idempotent updates", func() {
			// Then send in another update with same value, and another value to make sure we generate another
			// crumb.
			kvFooBarRev11 := kvFooBarRev10
			kvFooBarRev11.Revision = "11"
			updateFoo2 := api.Update{
				KVPair:     kvFooBarRev11,
				UpdateType: api.UpdateTypeKVUpdated,
			}

			updateBiff := api.Update{
				KVPair: model.KVPair{
					Key:      model.GlobalConfigKey{Name: "biff"},
					Value:    "baz",
					Revision: "12",
					TTL:      0,
				},
				UpdateType: api.UpdateTypeKVNew,
			}
			cache.OnUpdates([]api.Update{updateFoo2, updateBiff})

			// Wait for the next crumb...
			crumb, err := crumb.Next(cxt)
			Expect(err).NotTo(HaveOccurred())

			// Its snapshot should contain both items...
			snapshotUpdates := crumbToSnapshotUpdates(crumb)
			Expect(snapshotUpdates).To(ConsistOf(updateFooBarRev10, updateBiff))

			// Deltas should only contain the new update.
			Expect(deserialiseUpdates(crumb.Deltas)).To(ConsistOf(updateBiff))
		})

		It("should coalesce the update types of non-idempotent updates", func() {
			// Then send in another update with a new value.
			kvFooUpdatedRev11 := model.KVPair{
				Key:      model.GlobalConfigKey{Name: "foo"},
				Value:    "updated",
				Revision: "11",
				TTL:      0,
			}
			updateFooUpdatedRev11 := api.Update{
				KVPair:     kvFooUpdatedRev11,
				UpdateType: api.UpdateTypeKVUpdated,
			}

			cache.OnUpdates([]api.Update{updateFooUpdatedRev11})

			// Wait for the next crumb...
			crumb, err := crumb.Next(cxt)
			Expect(err).NotTo(HaveOccurred())

			// Its snapshot should contain the updated KV but with KV type new...
			snapshotUpdates := crumbToSnapshotUpdates(crumb)
			mergedUpdate := api.Update{
				KVPair:     kvFooUpdatedRev11,
				UpdateType: api.UpdateTypeKVNew,
			}
			Expect(snapshotUpdates).To(ConsistOf(mergedUpdate))

			// Deltas should contain the update, not the merged version.
			Expect(deserialiseUpdates(crumb.Deltas)).To(ConsistOf(updateFooUpdatedRev11))
		})

		It("should handle a delete", func() {
			// Then send in another update with a deletion for the original value.
			deletionUpdate := api.Update{
				KVPair: model.KVPair{
					Key:      model.GlobalConfigKey{Name: "foo"},
					Revision: "11",
				},
				UpdateType: api.UpdateTypeKVDeleted,
			}
			cache.OnUpdates([]api.Update{deletionUpdate})

			// Wait for the next crumb...
			crumb, err := crumb.Next(cxt)
			Expect(err).NotTo(HaveOccurred())
			log.WithField("crumb", crumb).Info("Got crumb that should contain the deletion")

			// Its snapshot should be empty.
			snapshotUpdates := crumbToSnapshotUpdates(crumb)
			Expect(snapshotUpdates).To(BeEmpty(), fmt.Sprintf("Deltas were: %#v", crumb.Deltas))
			Expect(deserialiseUpdates(crumb.Deltas)).To(ConsistOf(deletionUpdate))
		})
	})

	It("should report health eagerly", func() {
		// Force 4 updates.
		cache.OnStatusUpdated(api.InSync)
		cache.OnStatusUpdated(api.ResyncInProgress)
		cache.OnStatusUpdated(api.InSync)
		cache.OnStatusUpdated(api.ResyncInProgress)
		// Expect 5 updates in total because there's an eager start-of-day update.
		Eventually(mockHealth.NumReports).Should(BeNumerically("==", 5))
	})

	It("should report not-ready before in sync", func() {
		// Wait for start-of-day update.
		Eventually(mockHealth.LastReport).Should(Equal(health.HealthReport{Live: true, Ready: false}))
		// Shouldn't get any changes after that.
		Consistently(mockHealth.LastReport).Should(Equal(health.HealthReport{Live: true, Ready: false}))
	})

	It("should report ready when in sync", func() {
		cache.OnStatusUpdated(api.InSync)
		Eventually(mockHealth.LastReport).Should(Equal(health.HealthReport{Live: true, Ready: true}))
	})

	generateUpdates := func(num int) []api.Update {
		var updates []api.Update
		var seenKeys = set.New()
		for i := 0; i < num; i++ {
			configIdx := i % 100
			value := fmt.Sprintf("config%v", i%55)
			name := fmt.Sprintf("config%v", configIdx)
			updateType := api.UpdateTypeKVNew
			if seenKeys.Contains(name) {
				updateType = api.UpdateTypeKVUpdated
			}
			seenKeys.Add(name)
			key := model.GlobalConfigKey{
				Name: name,
			}
			upd := api.Update{
				KVPair: model.KVPair{
					Key:      key,
					Value:    value,
					Revision: strconv.Itoa(i),
					TTL:      0,
				},
				UpdateType: updateType,
			}
			updates = append(updates, upd)
		}
		return updates
	}

	injectUpdates := func(num int, blockSize int) map[model.Key]api.Update {
		// Generate the required number of updates
		updates := generateUpdates(num)
		expectedEndResult := map[model.Key]api.Update{}
		for _, upd := range updates {
			upd.UpdateType = api.UpdateTypeKVUnknown
			expectedEndResult[upd.Key] = upd
		}
		for i := 0; i < len(updates); i += blockSize {
			end := i + blockSize
			if end > len(updates) {
				end = len(updates)
			}
			cache.OnUpdates(updates[i:end])
			if i == 0 {
				// Cover the "skip empty updates" branch.
				cache.OnUpdates(nil)
			}
		}
		cache.OnStatusUpdated(api.InSync)
		go func() {
			time.Sleep(20 * time.Second)
			cancel()
		}()
		log.Info("Done sending updates. Waiting for followers to finish")
		wg.Wait()
		log.Info("Finished waiting.")
		return expectedEndResult
	}

	Describe("with a variety of followers", func() {
		// In this test, we run the snapshot cache with several followers, each
		// with different behaviour.  Some aggressively try to keep up with the
		// current snapshot; others deliberately try to fall behind by a set amount.
		// This tests both the blocking and non-blocking code paths.
		var followers []*follower
		BeforeEach(func() {
			followers = []*follower{
				newFollower(cache, "happy", &wg,
					0, 0),
				newFollower(cache, "sleepy", &wg,
					100*time.Millisecond, 100*time.Millisecond),
				newFollower(cache, "grumpy", &wg,
					10*time.Millisecond, 100*time.Millisecond),
				newFollower(cache, "bashful", &wg,
					1*time.Millisecond, 1*time.Millisecond),
			}
			for _, f := range followers {
				go f.Loop(cxt)
			}
		})

		expectFollowersCorrect := func(expectedEndResult map[model.Key]api.Update) {
			var maxRev int
			for _, upd := range expectedEndResult {
				newRev, err := strconv.Atoi(upd.Revision)
				Expect(err).NotTo(HaveOccurred())
				if newRev > maxRev {
					maxRev = newRev
				}
			}
			for _, f := range followers {
				Expect(f.StateAsUpdates()).To(Equal(expectedEndResult),
					fmt.Sprintf("Follower %s had incorrect state", f.name))
				Expect(f.inSyncAt).To(Equal(maxRev))
				Expect(f.problems).To(BeEmpty())
			}
		}

		It("a short test should give expected results in each follower", func() {
			expectedEndResult := injectUpdates(123, 1)
			expectFollowersCorrect(expectedEndResult)
		})
		It("a long test should give expected results in each follower", func() {
			expectedEndResult := injectUpdates(12345, 1)
			expectFollowersCorrect(expectedEndResult)
		})
		It("a long test with blocks of 100 should give expected results in each follower", func() {
			expectedEndResult := injectUpdates(12345, 100)
			expectFollowersCorrect(expectedEndResult)
		})
		It("a long test with blocks of 101 should give expected results in each follower", func() {
			expectedEndResult := injectUpdates(12345, 101)
			expectFollowersCorrect(expectedEndResult)
		})
		It("a soak test should give expected results in each follower [slow]", func() {
			expectedEndResult := injectUpdates(123456, 1)
			expectFollowersCorrect(expectedEndResult)
		})
	})
})

var _ = Describe("With a short wake-up interval", func() {
	var cache *snapcache.Cache
	var cxt context.Context
	var cancel context.CancelFunc
	var wg sync.WaitGroup
	BeforeEach(func() {
		log.SetLevel(log.InfoLevel)
		cacheConfig := snapcache.Config{
			MaxBatchSize: 10,
			// Short wake-up time so the test doesn't run too long.
			WakeUpInterval: 1 * time.Millisecond,
		}
		cache = snapcache.New(cacheConfig)
		cxt, cancel = context.WithCancel(context.Background())
		cache.Start(cxt)
	})

	AfterEach(func() {
		cancel()
	})

	It("should be possible to stop a follower", func() {
		// This checks that a follower still gets killed by the cancel function, even
		// if it's blocked in Next().
		follower := newFollower(cache, "happy", &wg, 0, 0)
		followerCxt, cancelFollower := context.WithCancel(cxt)
		go follower.Loop(followerCxt)
		<-follower.loopStartedC
		cancelFollower()
		done := make(chan struct{})
		// Do the wait in a goroutine so we don't block forever on fail.
		go func() {
			wg.Wait()
			close(done)
		}()
		Eventually(done).Should(BeClosed())
	})
})

func newFollower(cache *snapcache.Cache, name string, wg *sync.WaitGroup, initDelay, targetLatency time.Duration) *follower {
	wg.Add(1)
	return &follower{
		name:          name,
		cache:         cache,
		initialDelay:  initDelay,
		targetLatency: targetLatency,
		state:         map[string]syncproto.SerializedUpdate{},
		wg:            wg,
		loopStartedC:  make(chan struct{}),
	}
}

type follower struct {
	name  string
	cache *snapcache.Cache

	initialDelay  time.Duration
	targetLatency time.Duration

	state    map[string]syncproto.SerializedUpdate
	problems []string
	inSyncAt int

	loopStarted  bool
	loopStartedC chan struct{}

	maxRev int

	wg *sync.WaitGroup
}

func (f *follower) StateAsUpdates() map[model.Key]api.Update {
	actualState := map[model.Key]api.Update{}
	for k, v := range f.state {
		Expect(k).To(Equal(v.Key))
		upd, err := v.ToUpdate()
		Expect(err).NotTo(HaveOccurred())
		// Followers won't agree on update types. If a follower joins after the final update of a KV then it'll see
		// the KV as new where a follower that joined earlier should have got a UpdateTypeKVNew and then a
		// UpdateTypeKVUpdate.
		upd.UpdateType = api.UpdateTypeKVUnknown
		actualState[upd.Key] = upd
	}
	return actualState
}

func (f *follower) storeKV(upd syncproto.SerializedUpdate) {
	if _, ok := f.state[upd.Key]; !ok {
		if upd.UpdateType != api.UpdateTypeKVNew {
			f.problems = append(f.problems, fmt.Sprintf(
				"First time we've seen this KV but update says it's an update: %#v", upd))
		}
	}
	f.state[upd.Key] = upd
	newRev, err := strconv.Atoi(upd.Revision.(string))
	Expect(err).NotTo(HaveOccurred())
	if newRev > f.maxRev {
		f.maxRev = newRev
	}
}

func (f *follower) Loop(cxt context.Context) {
	defer f.wg.Done()
	logCxt := log.WithField("name", f.name)
	time.Sleep(f.initialDelay)
	crumb := f.cache.CurrentBreadcrumb()
	logCxt.WithField("crumb", crumb.SequenceNumber).Info("Got first crumb")
	done := false
	for item := range crumb.KVs.Iterator(cxt.Done()) {
		upd := item.Value.(syncproto.SerializedUpdate)
		f.storeKV(upd)
		if crumb.SyncStatus == api.InSync {
			f.inSyncAt = f.maxRev
			done = true
		}
	}
	var minSleepCrumbSeqNo uint64
	for !done && cxt.Err() == nil {
		var err error
		if !f.loopStarted {
			close(f.loopStartedC)
			f.loopStarted = true
		}
		newCrumb, err := crumb.Next(cxt)
		if err != nil {
			break
		}
		crumb = newCrumb
		//logCxt.WithField("crumb", crumb.SequenceNumber).Info("Got next crumb")
		for _, upd := range crumb.Deltas {
			f.storeKV(upd)
		}
		if crumb.SyncStatus == api.InSync {
			f.inSyncAt = f.maxRev
			done = true
			logCxt.WithField("crumb", crumb.SequenceNumber).Info("Got final crumb")
		}

		currentCrumb := f.cache.CurrentBreadcrumb()
		behind := currentCrumb.Timestamp.Sub(crumb.Timestamp)
		if !done && cxt.Err() == nil && behind < f.targetLatency && crumb.SequenceNumber > minSleepCrumbSeqNo {
			time.Sleep(f.targetLatency)

			// Forbid any more sleeps until we pass the snapshot we just peeked at.  Otherwise, we'll
			// never reach the end of the test.
			minSleepCrumbSeqNo = currentCrumb.SequenceNumber
		}
	}
	logCxt.WithError(cxt.Err()).WithField("crumb", crumb.SequenceNumber).Info("Exiting")
}

var _ = Describe("Zero config after applying defaults", func() {
	var config snapcache.Config

	BeforeEach(func() {
		config = snapcache.Config{}
		config.ApplyDefaults()
	})

	It("should default max batch size", func() {
		Expect(config.MaxBatchSize).To(Equal(100))
	})
	It("should default the wake up interval", func() {
		Expect(config.WakeUpInterval).To(Equal(time.Second))
	})
})

var _ = Describe("Non-zero config after applying defaults", func() {
	var config snapcache.Config

	BeforeEach(func() {
		config = snapcache.Config{
			WakeUpInterval: 10 * time.Second,
			MaxBatchSize:   1000,
		}
		config.ApplyDefaults()
	})

	It("should not default max batch size", func() {
		Expect(config.MaxBatchSize).To(Equal(1000))
	})
	It("should not default the wake up interval", func() {
		Expect(config.WakeUpInterval).To(Equal(10 * time.Second))
	})
})

func deserialiseUpdates(serializedUpdates []syncproto.SerializedUpdate) []api.Update {
	updates := []api.Update{}
	for _, sUpd := range serializedUpdates {
		upd, err := sUpd.ToUpdate()
		Expect(err).NotTo(HaveOccurred())
		updates = append(updates, upd)
	}
	return updates
}
