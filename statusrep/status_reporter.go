// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

package statusrep

import (
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/jitter"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/set"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"time"
)

type EndpointStatusReporter struct {
	hostname           string
	endpointUpdates    <-chan interface{}
	inSync             <-chan bool
	stop               chan bool
	datastore          datastore
	epStatusIDToStatus map[model.Key]string
	queuedDirtyIDs     set.Set
	activeDirtyIDs     set.Set
	reportingDelay     time.Duration
	resyncInterval     time.Duration
	resyncTicker       stoppable
	resyncTickerC      <-chan time.Time
	rateLimitTicker    stoppable
	rateLimitTickerC   <-chan time.Time
}

func NewEndpointStatusReporter(hostname string,
	endpointUpdates <-chan interface{},
	inSync <-chan bool,
	datastore datastore,
	reportingDelay time.Duration,
	resyncInterval time.Duration) *EndpointStatusReporter {

	resyncSchedulingTicker := jitter.NewTicker(resyncInterval, resyncInterval/10)
	updateRateLimitTicker := jitter.NewTicker(reportingDelay, reportingDelay/10)

	return newEndpointStatusReporterWithTickerChans(
		hostname,
		endpointUpdates,
		inSync,
		datastore,
		resyncSchedulingTicker,
		resyncSchedulingTicker.C,
		updateRateLimitTicker,
		updateRateLimitTicker.C,
		reportingDelay,
		resyncInterval,
	)
}

// newEndpointStatusReporterWithTickerChans is an internal constructor allowing
// the tickers to be mocked for UT.
func newEndpointStatusReporterWithTickerChans(hostname string,
	endpointUpdates <-chan interface{},
	inSync <-chan bool,
	datastore datastore,
	resyncTicker stoppable,
	resyncTickerChan <-chan time.Time,
	rateLimitTicker stoppable,
	rateLimitTickerChan <-chan time.Time,
	reportingDelay time.Duration,
	resyncInterval time.Duration) *EndpointStatusReporter {
	return &EndpointStatusReporter{
		hostname:           hostname,
		endpointUpdates:    endpointUpdates,
		datastore:          datastore,
		inSync:             inSync,
		stop:               make(chan bool),
		epStatusIDToStatus: make(map[model.Key]string),
		queuedDirtyIDs:     set.New(),
		activeDirtyIDs:     set.New(),
		resyncTicker:       resyncTicker,
		resyncTickerC:      resyncTickerChan,
		rateLimitTicker:    rateLimitTicker,
		rateLimitTickerC:   rateLimitTickerChan,
		reportingDelay:     reportingDelay,
		resyncInterval:     resyncInterval,
	}
}

// datastore is a copy of the parts of the backend client API that we need.
// See github.com/projectcalico/libcalico-go/lib/backend/api for more detail.
type datastore interface {
	List(list model.ListInterface) ([]*model.KVPair, error)
	Apply(object *model.KVPair) (*model.KVPair, error)
	Delete(object *model.KVPair) error
}

type stoppable interface {
	Stop()
}

func (esr *EndpointStatusReporter) Start() {
	go esr.loopHandlingEndpointStatusUpdates()
}

// loopHandlingEndpointStatusUpdates is the main loop for the status reporter;
// its processing is divided into two phases.  In the first phase, it waits on
// its various input channels and updates its cached state.  In the second
// phase, it works to bring the datastore into sync.  Datastore updates are
// rate-limited and jittered to coalesce flapping status updates and to avoid
// thundering herd issues.
func (esr *EndpointStatusReporter) loopHandlingEndpointStatusUpdates() {
	log.Infof("Starting endpoint status reporter loop with resync "+
		"interval %v, report rate limit: 1/%v", esr.resyncInterval,
		esr.reportingDelay)
	datamodelInSync := false
	resyncRequested := false

	for {
		updatesAllowed := false
		select {
		case <-esr.stop:
			log.Info("Stopping endpoint status reporter")
			esr.resyncTicker.Stop()
			esr.rateLimitTicker.Stop()
			break
		case <-esr.resyncTickerC:
			log.Debug("Endpoint status resync tick: scheduling cleanup")
			resyncRequested = true
		case <-esr.rateLimitTickerC:
			updatesAllowed = true
		case inSync := <-esr.inSync:
			log.Debug("Datamodel in sync, enabling status resync")
			datamodelInSync = datamodelInSync || inSync
		case msg := <-esr.endpointUpdates:
			var statID model.Key
			var status string
			switch msg := msg.(type) {
			case *proto.WorkloadEndpointStatusUpdate:
				statID = model.WorkloadEndpointStatusKey{
					Hostname:       esr.hostname,
					OrchestratorID: msg.Id.OrchestratorId,
					WorkloadID:     msg.Id.WorkloadId,
					EndpointID:     msg.Id.EndpointId,
				}
				status = msg.Status.Status
			case *proto.WorkloadEndpointStatusRemove:
				statID = model.WorkloadEndpointStatusKey{
					Hostname:       esr.hostname,
					OrchestratorID: msg.Id.OrchestratorId,
					WorkloadID:     msg.Id.WorkloadId,
					EndpointID:     msg.Id.EndpointId,
				}
			case *proto.HostEndpointStatusUpdate:
				statID = model.HostEndpointStatusKey{
					Hostname:   esr.hostname,
					EndpointID: msg.Id.EndpointId,
				}
				status = msg.Status.Status
			case *proto.HostEndpointStatusRemove:
				statID = model.HostEndpointStatusKey{
					Hostname:   esr.hostname,
					EndpointID: msg.Id.EndpointId,
				}
			default:
				log.Panicf("Unexpected message: %#v", msg)
			}
			if esr.epStatusIDToStatus[statID] != status {
				if status != "" {
					esr.epStatusIDToStatus[statID] = status
				} else {
					delete(esr.epStatusIDToStatus, statID)
				}
				if !esr.activeDirtyIDs.Contains(statID) &&
					!esr.queuedDirtyIDs.Contains(statID) {
					// Add the update into the queued set so that
					// we delay its initial update.  That prevent
					// flapping at start of day.
					esr.queuedDirtyIDs.Add(statID)
				}
			}
		}

		if datamodelInSync && resyncRequested {
			// We're in sync and the resync timer has popped,
			// do a resync with the datastore.  This will look for
			// out-of-sync keys in the datastore and mark them as
			// dirty so that we'll make delete/update them below.
			log.Debug("Doing endpoint status resync")
			esr.attemptResync()
			resyncRequested = false
		}

		if updatesAllowed {
			if esr.activeDirtyIDs.Len() > 0 {
				// Not throttled and there's at least one update
				// pending.  Choose an arbitrary update from the dirty
				// set.
				log.WithField("numDirtyEndpoints", esr.activeDirtyIDs.Len()).Debug(
					"Unthrottled and updates pending")
				var statID model.Key
				esr.activeDirtyIDs.Iter(func(item interface{}) error {
					statID = item.(model.Key)
					return set.StopIteration
				})
				// Then try to write the update to the datastore.
				// Note: the update could be a deletion, in which case
				// the read from the cache wil return nil.
				err := esr.writeEndpointStatus(statID,
					esr.epStatusIDToStatus[statID])
				if err != nil {
					log.WithError(err).Warn(
						"Failed to write endpoint status; is datastore up?")
				} else {
					// Success, remove the status from the dirty set.
					log.WithField("statID", statID).Debug("Write successful")
					esr.activeDirtyIDs.Discard(statID)
				}
			}
			if esr.queuedDirtyIDs.Len() > 0 {
				// Now copy the queued statuses to the main dirty set.
				// Doing this after the attempt to write above means that
				// endpoints always spend at least one interval in the
				// queued set.
				log.WithField("numQueuedUpdates", esr.queuedDirtyIDs.Len()).Debug(
					"Copying queued set to dirty set")
				esr.queuedDirtyIDs.Iter(func(item interface{}) error {
					esr.activeDirtyIDs.Add(item)
					return nil
				})
				esr.queuedDirtyIDs = set.New()
			}
		}
	}
}

func (esr *EndpointStatusReporter) attemptResync() {
	wlListOpts := model.WorkloadEndpointStatusListOptions{
		Hostname: esr.hostname,
	}
	kvs, err := esr.datastore.List(wlListOpts)
	if err != nil {
		log.WithError(err).Errorf("Failed to load workload endpoint statuses")
		kvs = nil // Skip the loop and try host endpoints.
	}
	for _, kv := range kvs {
		if kv.Value == nil {
			// Parse error, needs refresh.
			esr.activeDirtyIDs.Add(kv.Key)
		} else {
			status := kv.Value.(*model.WorkloadEndpointStatus).Status
			if status != esr.epStatusIDToStatus[kv.Key] {
				log.WithFields(log.Fields{
					"key":            kv.Key,
					"datastoreState": status,
					"desiredState":   esr.epStatusIDToStatus[kv.Key],
				}).Info("Found out-of-sync workload endpoint status")
				esr.activeDirtyIDs.Add(kv.Key)
			}
		}
	}

	hostListOpts := model.HostEndpointStatusListOptions{
		Hostname: esr.hostname,
	}
	kvs, err = esr.datastore.List(hostListOpts)
	if err != nil {
		log.WithError(err).Error("Failed to load host endpoint statuses")
		kvs = nil // Make sure we skip the loop.
	}
	for _, kv := range kvs {
		if kv.Value == nil {
			// Parse error, needs refresh.
			esr.activeDirtyIDs.Add(kv.Key)
		} else {
			status := kv.Value.(*model.HostEndpointStatus).Status
			if status != esr.epStatusIDToStatus[kv.Key] {
				log.WithFields(log.Fields{
					"key":            kv.Key,
					"datastoreState": status,
					"desiredState":   esr.epStatusIDToStatus[kv.Key],
				}).Infof("Found out-of-sync host endpoint status")
				esr.activeDirtyIDs.Add(kv.Key)
			}
		}
	}
}

func (esr *EndpointStatusReporter) writeEndpointStatus(epID model.Key, status string) (err error) {
	kv := model.KVPair{Key: epID}
	logCxt := log.WithFields(log.Fields{
		"newStatus":  status,
		"endpointID": epID,
	})
	if status != "" {
		logCxt.Info("Writing endpoint status")
		switch epID.(type) {
		case model.HostEndpointStatusKey:
			kv.Value = &model.HostEndpointStatus{status}
		case model.WorkloadEndpointStatusKey:
			kv.Value = &model.WorkloadEndpointStatus{status}
		}
		_, err = esr.datastore.Apply(&kv)
	} else {
		logCxt.Info("Deleting endpoint status")
		err = esr.datastore.Delete(&kv)
		if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
			// Ignore non-existent resource.
			err = nil
		}
	}
	return
}

func (esr *EndpointStatusReporter) Stop() {
	log.Info("Stopping endpoint status reporter")
	esr.stop <- true
}
