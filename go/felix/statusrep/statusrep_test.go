// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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
	log "github.com/Sirupsen/logrus"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"sync"
	"time"
)

const hostname = "localhostname"

var _ = Describe("Status", func() {
	var esr *EndpointStatusReporter
	var epUpdates chan interface{}
	var inSyncChan chan bool
	var datastore *mockDatastore
	var resyncTicker, rateLimitTicker *mockStoppable
	var resyncTickerChan, rateLimitTickerChan chan time.Time

	BeforeEach(func() {
		log.Info("BeforeEach called, creating EndpointStatusReporter")
		epUpdates = make(chan interface{})
		inSyncChan = make(chan bool)
		datastore = newMockDatastore()
		resyncTicker = &mockStoppable{}
		rateLimitTicker = &mockStoppable{}
		resyncTickerChan = make(chan time.Time)
		rateLimitTickerChan = make(chan time.Time)

		esr = newEndpointStatusReporterWithTickerChans(
			hostname,
			epUpdates,
			inSyncChan,
			datastore,
			resyncTicker,
			resyncTickerChan,
			rateLimitTicker,
			rateLimitTickerChan,
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
			BeforeEach(func() {
				inSyncChan <- true
			})
			It("Should start a resync", func() {
				resyncTickerChan <- time.Now()
				Eventually(func() bool {
					datastore.mutex.Lock()
					defer datastore.mutex.Unlock()
					return datastore.workloadsListed
				}).Should(BeTrue())
			}, 1)
		})
	})
	Describe("with cruft in datastore", func() {
		BeforeEach(func() {
			wlKey := model.WorkloadEndpointStatusKey{
				Hostname:       hostname,
				OrchestratorID: "orch",
				WorkloadID:     "wlid",
				EndpointID:     "epid",
			}
			datastore.kvs[wlKey] = &model.WorkloadEndpointStatus{
				Status: "up",
			}
			hostKey := model.HostEndpointStatusKey{
				Hostname:   hostname,
				EndpointID: "epid",
			}
			datastore.kvs[hostKey] = &model.HostEndpointStatus{
				Status: "down",
			}
		})
		Describe("after sending in-sync", func() {
			BeforeEach(func() {
				inSyncChan <- true
			})
			It("should clean up one endpoint per tick", func() {
				// Kick off the resync.
				resyncTickerChan <- time.Now()
				By("deleting first endpoint immediately after resync")
				Eventually(datastore.numKVs).Should(Equal(1))
				By("deleting second endpoint after rate limit timer tick")
				rateLimitTickerChan <- time.Now()
				Eventually(datastore.numKVs).Should(Equal(0))
			}, 1)
		})
	})
})

type mockDatastore struct {
	mutex                        sync.Mutex
	kvs                          map[model.Key]interface{}
	workloadsListed, hostsListed bool
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
		snap[k] = v
	}
	return snap
}

func (d *mockDatastore) numKVs() int {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	return len(d.kvs)
}

func (d *mockDatastore) List(list model.ListInterface) ([]*model.KVPair, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	log.WithField("list", list).Info("List() called")

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

	return kvs, nil
}

func (d *mockDatastore) Apply(object *model.KVPair) (*model.KVPair, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	log.WithField("kv", object).Info("Apply() called")

	d.kvs[object.Key] = object.Value
	return object, nil
}

func (d *mockDatastore) Delete(object *model.KVPair) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	log.WithFields(log.Fields{
		"key":           object.Key,
		"matchingValue": d.kvs[object.Key],
	}).Info("Delete() called")

	delete(d.kvs, object.Key)

	log.WithField("kvs", d.kvs).Info("Datastore updated")
	return nil
}

type mockStoppable struct {
	stopped bool
}

func (s *mockStoppable) Stop() {
	s.stopped = true
}
