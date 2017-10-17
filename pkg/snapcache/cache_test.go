// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/typha/pkg/snapcache"

	"context"
	"fmt"
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/health"
	"github.com/projectcalico/typha/pkg/syncproto"
)

type healthRecord struct {
	time time.Time
	health.HealthReport
}

type healthRecorder struct {
	lock    sync.Mutex
	reports []healthRecord
}

func (r *healthRecorder) RegisterReporter(name string, reports *health.HealthReport, timeout time.Duration) {

}

func (r *healthRecorder) Report(name string, report *health.HealthReport) {
	r.lock.Lock()
	defer r.lock.Unlock()
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

var _ = Describe("Snapshot cache FV tests", func() {
	var cacheConfig snapcache.Config
	var cache *snapcache.Cache
	var cxt context.Context
	var cancel context.CancelFunc
	var wg sync.WaitGroup
	var mockHealth *healthRecorder

	BeforeEach(func() {
		log.SetLevel(log.InfoLevel)
		mockHealth = &healthRecorder{}
		cacheConfig = snapcache.Config{
			MaxBatchSize:     10,
			WakeUpInterval:   10 * time.Second,
			HealthAggregator: mockHealth,
		}
		cache = snapcache.New(cacheConfig)
		cxt, cancel = context.WithCancel(context.Background())
		cache.Start(cxt)
	})

	AfterEach(func() {
		cancel()
	})

	It("should coalesce idempotent updates", func() {
		kv := model.KVPair{
			Key:      model.GlobalConfigKey{Name: "foo"},
			Value:    "bar",
			Revision: "10",
			TTL:      0,
		}
		updateFoo1 := api.Update{
			KVPair:     kv,
			UpdateType: api.UpdateTypeKVNew,
		}
		cache.OnUpdates([]api.Update{updateFoo1})

		// Wait for the update to flow through...
		var crumb *snapcache.Breadcrumb
		Eventually(func() bool {
			crumb = cache.CurrentBreadcrumb()
			return crumb.KVs.Size() > 0
		}).Should(BeTrue())

		// Then send in another update with same value, and another value to make sure we generate another
		// crumb.
		kv.Revision = "11"
		updateFoo2 := api.Update{
			KVPair:     kv,
			UpdateType: api.UpdateTypeKVUpdated,
		}

		kv2 := model.KVPair{
			Key:      model.GlobalConfigKey{Name: "biff"},
			Value:    "baz",
			Revision: "12",
			TTL:      0,
		}
		updateBiff := api.Update{
			KVPair:     kv2,
			UpdateType: api.UpdateTypeKVNew,
		}
		cache.OnUpdates([]api.Update{updateFoo2, updateBiff})

		// Make sure we don't block forever waiting on the next crumb...
		go func() {
			time.Sleep(10 * time.Second)
			cancel()
		}()

		// Wait for the next crumb...
		crumb, err := crumb.Next(cxt)
		Expect(err).NotTo(HaveOccurred())

		// Its snapshot should contain both items...
		snapshotUpdates := []api.Update{}
		for entry := range crumb.KVs.Iterator(nil) {
			upd, err := entry.Value.(syncproto.SerializedUpdate).ToUpdate()
			Expect(err).NotTo(HaveOccurred())
			snapshotUpdates = append(snapshotUpdates, upd)
		}
		Expect(snapshotUpdates).To(ConsistOf(updateFoo1, updateBiff))

		// Deltas should only contain the new update.
		Expect(deserialiseUpdates(crumb.Deltas)).To(ConsistOf(updateBiff))
	})

	It("should handle a delete", func() {
		kv := model.KVPair{
			Key:      model.GlobalConfigKey{Name: "foo"},
			Value:    "bar",
			Revision: "10",
			TTL:      0,
		}
		updateFoo1 := api.Update{
			KVPair:     kv,
			UpdateType: api.UpdateTypeKVNew,
		}
		cache.OnUpdates([]api.Update{updateFoo1})

		// Wait for the update to flow through...
		var crumb *snapcache.Breadcrumb
		Eventually(func() bool {
			crumb = cache.CurrentBreadcrumb()
			return crumb.KVs.Size() > 0
		}).Should(BeTrue())

		// Then send in another update with same value, and another value to make sure we generate another
		// crumb.
		kv.Revision = "11"
		kv.Value = nil
		deletionUpdate := api.Update{
			KVPair:     kv,
			UpdateType: api.UpdateTypeKVDeleted,
		}
		cache.OnUpdates([]api.Update{deletionUpdate})

		// Make sure we don't block forever waiting on the next crumb...
		go func() {
			time.Sleep(10 * time.Second)
			cancel()
		}()

		// Wait for the next crumb...
		crumb, err := crumb.Next(cxt)
		Expect(err).NotTo(HaveOccurred())

		// Its snapshot should be empty.
		Expect(crumb.KVs.Size()).To(BeZero())
		Expect(deserialiseUpdates(crumb.Deltas)).To(ConsistOf(deletionUpdate))
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
		for i := 0; i < num; i++ {
			configIdx := i % 100
			value := fmt.Sprintf("config%v", i%55)
			key := model.GlobalConfigKey{
				Name: fmt.Sprintf("config%v", configIdx),
			}
			upd := api.Update{
				KVPair: model.KVPair{
					Key:      key,
					Value:    value,
					Revision: strconv.Itoa(i),
					TTL:      0,
				},
				UpdateType: api.UpdateTypeKVNew,
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
	inSyncAt int

	loopStarted  bool
	loopStartedC chan struct{}

	wg *sync.WaitGroup
}

func (f *follower) StateAsUpdates() map[model.Key]api.Update {
	actualState := map[model.Key]api.Update{}
	for k, v := range f.state {
		Expect(k).To(Equal(v.Key))
		upd, err := v.ToUpdate()
		Expect(err).NotTo(HaveOccurred())
		actualState[upd.Key] = upd
	}
	return actualState
}

func (f *follower) Loop(cxt context.Context) {
	defer f.wg.Done()
	logCxt := log.WithField("name", f.name)
	time.Sleep(f.initialDelay)
	crumb := f.cache.CurrentBreadcrumb()
	logCxt.WithField("crumb", crumb.SequenceNumber).Info("Got first crumb")
	done := false
	maxRev := 0
	for item := range crumb.KVs.Iterator(cxt.Done()) {
		upd := item.Value.(syncproto.SerializedUpdate)
		f.state[upd.Key] = upd
		newRev, err := strconv.Atoi(upd.Revision)
		Expect(err).NotTo(HaveOccurred())
		if newRev > maxRev {
			maxRev = newRev
		}
		if crumb.SyncStatus == api.InSync {
			f.inSyncAt = maxRev
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
			f.state[upd.Key] = upd
			newRev, err := strconv.Atoi(upd.Revision)
			Expect(err).NotTo(HaveOccurred())
			if newRev > maxRev {
				maxRev = newRev
			}
		}
		if crumb.SyncStatus == api.InSync {
			f.inSyncAt = maxRev
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
