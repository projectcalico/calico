// Copyright (c) 2016-2019 Tigera, Inc. All rights reserved.

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

package statusrep

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/jitter"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	calierrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

const hostname = "localhostname"

var localWlEPKey = model.WorkloadEndpointStatusKey{
	Hostname:       hostname,
	OrchestratorID: "orch",
	WorkloadID:     "wlid",
	EndpointID:     "epid",
	RegionString:   "no-region",
}

var localHostEPKey = model.HostEndpointStatusKey{
	Hostname:   hostname,
	EndpointID: "epid",
}

var remoteWlEPKey = model.WorkloadEndpointStatusKey{
	Hostname:       "foobar",
	OrchestratorID: "orch",
	WorkloadID:     "wlid",
	EndpointID:     "epid",
	RegionString:   "no-region",
}

var remoteHostEPKey = model.HostEndpointStatusKey{
	Hostname:   "foobar",
	EndpointID: "epid",
}

var wlEPUp = model.WorkloadEndpointStatus{
	Status: "up",
}

var wlEPDown = model.WorkloadEndpointStatus{
	Status: "down",
}

var hostEPDown = model.HostEndpointStatus{
	Status: "down",
}

var protoWlID = proto.WorkloadEndpointID{
	OrchestratorId: "orch",
	WorkloadId:     "updatedWL",
	EndpointId:     "updatedEP",
}

var protoUp = proto.EndpointStatus{Status: "up"}
var protoDown = proto.EndpointStatus{Status: "down"}

var wlEPUpdateUp = proto.WorkloadEndpointStatusUpdate{
	Id:     &protoWlID,
	Status: &protoUp,
}
var wlEPRemove = proto.WorkloadEndpointStatusRemove{
	Id: &protoWlID,
}
var wlEPUpdateDown = proto.WorkloadEndpointStatusUpdate{
	Id:     &protoWlID,
	Status: &protoDown,
}
var updatedWlEPKey = model.WorkloadEndpointStatusKey{
	Hostname:       hostname,
	OrchestratorID: "orch",
	WorkloadID:     "updatedWL",
	EndpointID:     "updatedEP",
	RegionString:   "no-region",
}
var updatedWlEPKeyRegion = model.WorkloadEndpointStatusKey{
	Hostname:       hostname,
	OrchestratorID: "orch",
	WorkloadID:     "updatedWL",
	EndpointID:     "updatedEP",
	RegionString:   "region-Europe",
}

var protoHostID = proto.HostEndpointID{
	EndpointId: "updatedEP",
}
var hostEPUpdateUp = proto.HostEndpointStatusUpdate{
	Id:     &protoHostID,
	Status: &protoUp,
}
var hostEPRemove = proto.HostEndpointStatusRemove{
	Id: &protoHostID,
}
var hostEPUpdateDown = proto.HostEndpointStatusUpdate{
	Id:     &protoHostID,
	Status: &protoDown,
}
var updatedHostEPKey = model.HostEndpointStatusKey{
	Hostname:   hostname,
	EndpointID: "updatedEP",
}

var _ = Describe("Status", func() {
	var esr *EndpointStatusReporter
	var epUpdates chan interface{}
	var inSyncChan chan bool
	var datastore *mockDatastore
	var resyncTicker, rateLimitTicker *mockStoppable
	var resyncTickerChan, rateLimitTickerChan chan time.Time
	var region string

	BeforeEach(func() {
		// No region configured, by default.
		region = ""
	})

	JustBeforeEach(func() {
		log.Info("JustBeforeEach called, creating EndpointStatusReporter")
		epUpdates = make(chan interface{})
		inSyncChan = make(chan bool)
		datastore = newMockDatastore()
		resyncTicker = &mockStoppable{}
		rateLimitTicker = &mockStoppable{}
		resyncTickerChan = make(chan time.Time)
		rateLimitTickerChan = make(chan time.Time)

		esr = newEndpointStatusReporterWithTickerChans(
			hostname,
			region,
			epUpdates,
			inSyncChan,
			datastore,
			resyncTicker,
			resyncTickerChan,
			rateLimitTicker,
			rateLimitTickerChan,
			1*time.Second,
			2*time.Second,
		)
		esr.Start()
		log.Info("Started EndpointStatusReporter")
	})
	AfterEach(func() {
		log.Info("Stopping EndpointStatusReporter")
		esr.Stop()
		log.Info("Called Stop() on EndpointStatusReporter")
	})

	Describe("with empty datastore", func() {
		Describe("after sending in-sync message", func() {
			JustBeforeEach(func() {
				inSyncChan <- true
			})
			It("Should start a resync", func() {
				resyncTickerChan <- time.Now()
				Eventually(func() bool {
					datastore.mutex.Lock()
					defer datastore.mutex.Unlock()
					return datastore.workloadsListed
				}, "1s").Should(BeTrue())
			})
			It("should coalesce flapping workload EP updates", func() {
				epUpdates <- &wlEPUpdateUp
				epUpdates <- &wlEPUpdateUp
				epUpdates <- &wlEPUpdateDown
				epUpdates <- &wlEPUpdateUp
				epUpdates <- &wlEPUpdateDown
				rateLimitTickerChan <- time.Now()
				rateLimitTickerChan <- time.Now()
				Eventually(datastore.snapshot).Should(Equal(map[model.Key]interface{}{
					updatedWlEPKey: wlEPDown,
				}))
			})
			It("should coalesce flapping workload EP create/deletes", func() {
				epUpdates <- &wlEPUpdateUp
				epUpdates <- &wlEPUpdateUp
				epUpdates <- &wlEPRemove
				epUpdates <- &wlEPUpdateUp
				epUpdates <- &wlEPRemove
				rateLimitTickerChan <- time.Now()
				rateLimitTickerChan <- time.Now()
				Eventually(datastore.snapshot).Should(BeEmpty())
			})
			It("should coalesce flapping host EP updates", func() {
				epUpdates <- &hostEPUpdateUp
				epUpdates <- &hostEPUpdateUp
				epUpdates <- &hostEPUpdateDown
				epUpdates <- &hostEPUpdateUp
				epUpdates <- &hostEPUpdateDown
				rateLimitTickerChan <- time.Now()
				rateLimitTickerChan <- time.Now()
				Eventually(datastore.snapshot).Should(Equal(map[model.Key]interface{}{
					updatedHostEPKey: hostEPDown,
				}))
			})
			It("should coalesce flapping host EP create/deletes", func() {
				epUpdates <- &hostEPUpdateUp
				epUpdates <- &hostEPUpdateUp
				epUpdates <- &hostEPRemove
				epUpdates <- &hostEPUpdateUp
				epUpdates <- &hostEPRemove
				rateLimitTickerChan <- time.Now()
				rateLimitTickerChan <- time.Now()
				Eventually(datastore.snapshot).Should(BeEmpty())
			})

			Describe("with an error on the first 2 Apply() calls", func() {
				JustBeforeEach(func() {
					datastore.ApplyErrs = []error{
						errors.New("datastore FAIL"),
						errors.New("datastore FAIL"),
					}
				})
				It("should retry write", func() {
					epUpdates <- &wlEPUpdateUp
					rateLimitTickerChan <- time.Now() // Copies queued to active
					rateLimitTickerChan <- time.Now() // Tries first write
					rateLimitTickerChan <- time.Now() // Tries second write
					time.Sleep(20 * time.Millisecond)
					Expect(datastore.snapshot()).To(BeEmpty())
					rateLimitTickerChan <- time.Now() // Triggers successful retry.
					Eventually(datastore.snapshot).Should(Equal(map[model.Key]interface{}{
						updatedWlEPKey: wlEPUp,
					}))
				})
			})

			Describe("with a non-empty region configured", func() {
				BeforeEach(func() {
					region = "Europe"
				})
				It("should report status with that region", func() {
					epUpdates <- &wlEPUpdateUp
					rateLimitTickerChan <- time.Now() // Copies queued to active
					rateLimitTickerChan <- time.Now() // Tries first write
					Eventually(datastore.snapshot).Should(Equal(map[model.Key]interface{}{
						updatedWlEPKeyRegion: wlEPUp,
					}))
				})
			})
		})
	})
	Describe("with defunct local and remote endpoints in datastore", func() {
		JustBeforeEach(func() {
			datastore.kvs[localWlEPKey] = &wlEPUp
			datastore.kvs[localHostEPKey] = &hostEPDown
			datastore.kvs[remoteWlEPKey] = &wlEPUp
			datastore.kvs[remoteHostEPKey] = &hostEPDown
		})
		Describe("after sending in-sync", func() {
			JustBeforeEach(func() {
				inSyncChan <- true
			})
			It("should only clean up local endpoints", func() {
				// Kick off the resync.
				resyncTickerChan <- time.Now()
				rateLimitTickerChan <- time.Now()
				rateLimitTickerChan <- time.Now()
				rateLimitTickerChan <- time.Now()
				rateLimitTickerChan <- time.Now()
				Eventually(datastore.snapshot).Should(Equal(map[model.Key]interface{}{
					remoteWlEPKey:   wlEPUp,
					remoteHostEPKey: hostEPDown,
				}))
			}, 1)
			It("should clean up one endpoint per tick", func() {
				// Kick off the resync.
				resyncTickerChan <- time.Now()
				// Then send a no-op event (so that we block until
				// the above event finishes).  No cleanup should happen yet.
				inSyncChan <- true
				Expect(datastore.numKVs()).To(Equal(4))
				// Rate limit tick should trigger cleanup.
				rateLimitTickerChan <- time.Now()
				inSyncChan <- true
				Expect(datastore.numKVs()).To(Equal(3))
				rateLimitTickerChan <- time.Now()
				inSyncChan <- true
				Expect(datastore.numKVs()).To(Equal(2))
			}, 1)

			It("with concurrent datastore changes, it should handle key not found", func() {
				// Kick off the resync.
				resyncTickerChan <- time.Now()
				// Trigger first deletion.
				rateLimitTickerChan <- time.Now()
				Eventually(datastore.numKVs).Should(Equal(3))
				Expect(datastore.NumDeletes()).To(Equal(1))
				// Now clear the datastore so the next delete will fail.
				By("giving up after failing to delete second endpoint")
				datastore.clear()
				// Send in a few timer ticks to give it a
				// chance to retry...
				rateLimitTickerChan <- time.Now()
				rateLimitTickerChan <- time.Now()
				rateLimitTickerChan <- time.Now()
				rateLimitTickerChan <- time.Now()
				// But it should only try each delete once.
				Expect(datastore.NumDeletes()).To(Equal(2))
			}, 1)

			Describe("with an error on the first 2 List() calls", func() {
				JustBeforeEach(func() {
					datastore.ListErrs = []error{
						errors.New("datastore FAIL"),
						errors.New("datastore FAIL"),
					}
				})
				It("should retry clean up", func() {
					// Kick off the first resync.
					resyncTickerChan <- time.Now()
					rateLimitTickerChan <- time.Now()
					rateLimitTickerChan <- time.Now()
					Eventually(datastore.numKVs).Should(Equal(4),
						"datastore should still contain all original keys")
					// Send in second resync tick and enough
					// timer ticks to finish the cleanup.
					resyncTickerChan <- time.Now()
					rateLimitTickerChan <- time.Now()
					rateLimitTickerChan <- time.Now()
					Eventually(datastore.numKVs).Should(Equal(2))
				})
			})

			Describe("with an error on the first 2 Delete() calls", func() {
				JustBeforeEach(func() {
					datastore.DeleteErrs = []error{
						errors.New("datastore FAIL"),
						errors.New("datastore FAIL"),
					}
				})
				It("should retry the deletes", func() {
					// Kick off the first resync.
					resyncTickerChan <- time.Now()
					rateLimitTickerChan <- time.Now() // Triggers first delete.
					rateLimitTickerChan <- time.Now() // Triggers second.
					inSyncChan <- false               // Wait for next loop
					Expect(datastore.numKVs()).To(Equal(4),
						"datastore should still contain all original keys")
					// Send in timer ticks to finish retries.
					rateLimitTickerChan <- time.Now()
					rateLimitTickerChan <- time.Now()
					Eventually(datastore.numKVs).Should(Equal(2))
				})
			})
		})
		Describe("without sending in-sync", func() {
			It("should ignore timer ticks", func() {
				// Kick off the resync.
				go func() { resyncTickerChan <- time.Now() }()
				go func() { rateLimitTickerChan <- time.Now() }()
				By("deleting first endpoint immediately after resync")
				time.Sleep(20 * time.Millisecond)
				Eventually(datastore.numKVs).Should(Equal(4))
			}, 1)
			It("should process workload update", func() {
				epUpdates <- &wlEPUpdateUp
				rateLimitTickerChan <- time.Now() // Copy to active.
				rateLimitTickerChan <- time.Now() // Do the write.
				Eventually(datastore.snapshot).Should(Equal(map[model.Key]interface{}{
					localWlEPKey:    wlEPUp,
					localHostEPKey:  hostEPDown,
					remoteWlEPKey:   wlEPUp,
					remoteHostEPKey: hostEPDown,
					updatedWlEPKey:  wlEPUp,
				}))
			})
			It("should coalesce flapping updates", func() {
				epUpdates <- &wlEPUpdateUp
				epUpdates <- &wlEPUpdateUp
				epUpdates <- &wlEPUpdateUp
				epUpdates <- &wlEPUpdateDown
				rateLimitTickerChan <- time.Now()
				rateLimitTickerChan <- time.Now()
				Eventually(datastore.snapshot).Should(Equal(map[model.Key]interface{}{
					localWlEPKey:    wlEPUp,
					localHostEPKey:  hostEPDown,
					remoteWlEPKey:   wlEPUp,
					remoteHostEPKey: hostEPDown,
					updatedWlEPKey:  wlEPDown,
				}))
			})
		})
	})

	Describe("with malformed local and remote endpoints in datastore", func() {
		JustBeforeEach(func() {
			datastore.kvs[localWlEPKey] = nil
			datastore.kvs[localHostEPKey] = nil
			datastore.kvs[remoteWlEPKey] = nil
			datastore.kvs[remoteHostEPKey] = nil
		})
		Describe("after sending in-sync", func() {
			JustBeforeEach(func() {
				inSyncChan <- true
			})
			It("should only clean up local endpoints", func() {
				// Kick off the resync.
				resyncTickerChan <- time.Now()
				rateLimitTickerChan <- time.Now()
				rateLimitTickerChan <- time.Now()
				rateLimitTickerChan <- time.Now()
				rateLimitTickerChan <- time.Now()
				Eventually(datastore.snapshot).Should(Equal(map[model.Key]interface{}{
					remoteWlEPKey:   nil,
					remoteHostEPKey: nil,
				}))
			}, 1)
			It("should clean up one endpoint per tick", func() {
				// Kick off the resync.
				resyncTickerChan <- time.Now()
				rateLimitTickerChan <- time.Now()
				By("deleting first endpoint after resync")
				Eventually(datastore.numKVs).Should(Equal(3))
				By("deleting second endpoint after rate limit timer tick")
				rateLimitTickerChan <- time.Now()
				Eventually(datastore.numKVs).Should(Equal(2))
			}, 1)
		})
	})
})

var _ = Describe("Non-mocked EndpointStatusReporter", func() {
	var esr *EndpointStatusReporter
	var epUpdates chan interface{}
	var inSyncChan chan bool
	var datastore *mockDatastore

	BeforeEach(func() {
		epUpdates = make(chan interface{})
		inSyncChan = make(chan bool)
		datastore = newMockDatastore()
		esr = NewEndpointStatusReporter(
			hostname,
			"",
			epUpdates,
			inSyncChan,
			datastore,
			10*time.Second,  // Rate limit.
			100*time.Second, // Resync interval.
		)
	})
	It("correctly initialises resync ticker", func() {
		resyncTicker := esr.resyncTicker.(*jitter.Ticker)
		Expect(esr.resyncTickerC).To(Equal(resyncTicker.C))
		Expect(resyncTicker.MinDuration).To(Equal(100 * time.Second))
		Expect(resyncTicker.MaxJitter).To(Equal(10 * time.Second))
	})
	It("correctly initialises rate-limit ticker", func() {
		rateLimitTicker := esr.rateLimitTicker.(*jitter.Ticker)
		Expect(esr.rateLimitTickerC).To(Equal(rateLimitTicker.C))
		Expect(rateLimitTicker.MinDuration).To(Equal(10 * time.Second))
		Expect(rateLimitTicker.MaxJitter).To(Equal(1 * time.Second))
	})
})

type mockDatastore struct {
	mutex                           sync.Mutex
	kvs                             map[model.Key]interface{}
	workloadsListed, hostsListed    bool
	ListErrs, ApplyErrs, DeleteErrs []error
	numDeletes                      int
}

func newMockDatastore() *mockDatastore {
	return &mockDatastore{
		kvs: make(map[model.Key]interface{}),
	}
}

func (d *mockDatastore) snapshot() map[model.Key]interface{} {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	snap := make(map[model.Key]interface{})
	for k, v := range d.kvs {
		// Return values rather than pointers for ease of comparison.
		if v == nil {
			snap[k] = nil
		} else {
			snap[k] = reflect.ValueOf(v).Elem().Interface()
		}
	}
	return snap
}

func (d *mockDatastore) numKVs() int {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	return len(d.kvs)
}

func (d *mockDatastore) NumDeletes() int {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	return d.numDeletes
}

func (d *mockDatastore) clear() {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	d.kvs = make(map[model.Key]interface{})
}

func (d *mockDatastore) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	log.WithField("list", list).Info("List() called")

	if len(d.ListErrs) > 0 {
		err := d.ListErrs[0]
		d.ListErrs = d.ListErrs[1:]
		return nil, err
	}

	switch list := list.(type) {
	case model.WorkloadEndpointStatusListOptions:
		d.workloadsListed = true
		Expect(list.Hostname).To(Equal("localhostname"))
	case model.HostEndpointStatusListOptions:
		d.hostsListed = true
		Expect(list.Hostname).To(Equal("localhostname"))
	default:
		log.Panicf("Unexpected list type: %#v", list)
	}

	kvs := make([]*model.KVPair, 0)
	for key, value := range d.kvs {
		defaultPath, err := model.KeyToDefaultPath(key)
		if err != nil {
			log.WithError(err).Panic("Failed to stringify key")
		}
		if list.KeyFromDefaultPath(defaultPath) != nil {
			kvs = append(kvs, &model.KVPair{Key: key, Value: value})
		}
	}

	log.WithField("KVs", kvs).Info("List() returning")

	return &model.KVPairList{KVPairs: kvs}, nil
}

func (d *mockDatastore) Apply(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if len(d.ApplyErrs) > 0 {
		err := d.ApplyErrs[0]
		d.ApplyErrs = d.ApplyErrs[1:]
		return nil, err
	}

	log.WithField("kv", object).Info("Apply() called")

	d.kvs[object.Key] = object.Value
	return object, nil
}

func (d *mockDatastore) Delete(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	d.numDeletes++

	if len(d.DeleteErrs) > 0 {
		err := d.DeleteErrs[0]
		d.DeleteErrs = d.DeleteErrs[1:]
		return nil, err
	}

	matchingValue, ok := d.kvs[key]
	log.WithFields(log.Fields{
		"key":           key,
		"matchingValue": matchingValue,
	}).Info("Delete() called")
	if ok {
		delete(d.kvs, key)
	} else {
		log.Info("Key wasn't present, returning not-found")
		return nil, calierrors.ErrorResourceDoesNotExist{}
	}

	log.WithField("kvs", d.kvs).Info("Datastore updated")
	// Felix's Delete calls don't use the returned (and deleted) object, so we can get away with
	// returning nil for it here.
	return nil, nil
}

type mockStoppable struct {
	stopped bool
}

func (s *mockStoppable) Stop() {
	s.stopped = true
}
