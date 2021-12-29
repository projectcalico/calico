// Copyright (c) 2016-2022 Tigera, Inc. All rights reserved.

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

package etcdv3

import (
	"context"
	"strconv"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

const (
	resultsBufSize = 100
)

// Watch entries in the datastore matching the resources specified by the ListInterface.
func (c *etcdV3Client) Watch(cxt context.Context, l model.ListInterface, revision string) (api.WatchInterface, error) {
	var rev int64
	if len(revision) != 0 {
		var err error
		rev, err = strconv.ParseInt(revision, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	wc := &watcher{
		client:     c,
		list:       l,
		initialRev: rev,
		resultChan: make(chan api.WatchEvent, resultsBufSize),
	}
	wc.ctx, wc.cancel = context.WithCancel(cxt)
	go wc.watchLoop()
	return wc, nil
}

// watcher implements watch.Interface.
type watcher struct {
	client     *etcdV3Client
	initialRev int64
	ctx        context.Context
	cancel     context.CancelFunc
	resultChan chan api.WatchEvent
	list       model.ListInterface
	terminated uint32
}

// Stop stops the watcher and releases associated resources.
// This calls through to the context cancel function.
func (wc *watcher) Stop() {
	wc.cancel()
}

// ResultChan returns a channel used to receive WatchEvents.
func (wc *watcher) ResultChan() <-chan api.WatchEvent {
	return wc.resultChan
}

// HasTerminated returns true when the watcher has completed termination processing.
func (wc *watcher) HasTerminated() bool {
	return atomic.LoadUint32(&wc.terminated) != 0
}

// watchLoop starts a watch on the required path prefix and sends a stream of
// event updates for internal processing.
func (wc *watcher) watchLoop() {
	// When this loop exits, make sure we terminate the watcher resources.
	defer wc.terminateWatcher()

	// If we are not watching a specific resource then this is a prefix watch.
	logCxt := log.WithField("list", wc.list)
	key, opts := calculateListKeyAndOptions(logCxt, wc.list)

	log.Debug("Starting watcher.watchLoop")
	if wc.initialRev == 0 {
		// No initial revision supplied, so perform a list of current configuration
		// which will also get the current revision we will start our watch from.
		var kvps *model.KVPairList
		var err error
		if kvps, err = wc.listCurrent(); err != nil {
			log.Errorf("failed to list current with latest state: %v", err)
			// Error considered as terminating error, hence terminate watcher.
			wc.sendError(err)
			return
		}

		// If we're handling profiles, filter out the default-allow profile.
		if len(kvps.KVPairs) > 0 && (key == profilesKey || key == defaultAllowProfileKey) {
			wc.removeDefaultAllowProfile(kvps)
		}

		// We are sending an initial sync of entries to the watcher to provide current
		// state.  To the perspective of the watcher, these are added entries, so set the
		// event type to WatchAdded.
		log.WithField("NumEntries", len(kvps.KVPairs)).Debug("Sending create events for each existing entry")
		wc.sendAddedEvents(kvps)
	}

	opts = append(opts, clientv3.WithRev(wc.initialRev+1), clientv3.WithPrevKV())
	logCxt = logCxt.WithFields(log.Fields{
		"etcdv3-etcdKey": key,
		"rev":            wc.initialRev,
	})
	logCxt.Debug("Starting etcdv3 watch")
	wch := wc.client.etcdClient.Watch(wc.ctx, key, opts...)
	for wres := range wch {
		if wres.Err() != nil {
			// A watch channel error is a terminating event, so exit the loop.
			err := wres.Err()
			log.WithError(err).Warning("Watch channel error")
			wc.sendError(err)
			return
		}
		for _, e := range wres.Events {
			// Convert the etcdv3 event to the equivalent Watcher event.  An error
			// parsing the event is returned as an error, but don't exit the watcher as
			// restarting the watcher is unlikely to fix the conversion error.
			if ae, err := convertWatchEvent(e, wc.list); ae != nil {
				wc.sendEvent(ae)
			} else if err != nil {
				wc.sendError(err)
			}
		}
	}

	// If we exit the loop, it means the watcher has closed for some reason.
	log.Warn("etcdv3 watch channel closed")
}

// listCurrent retrieves the existing entries.
func (wc *watcher) listCurrent() (*model.KVPairList, error) {
	log.Info("Performing initial list with no revision")
	list, err := wc.client.List(wc.ctx, wc.list, "")
	if err != nil {
		return nil, err
	}

	wc.initialRev, err = strconv.ParseInt(list.Revision, 10, 64)
	if err != nil {
		log.WithError(err).Error("List returned revision that could not be parsed")
		return nil, err
	}

	return list, nil
}

// removeDefaultAllowProfile filters out the default-allow profile out of the
// given kvps list.
func (wc *watcher) removeDefaultAllowProfile(list *model.KVPairList) {
	log.Debugf("Filtering the default-allow profile out of the kvps list")
	n := 0
	s := list.KVPairs
	for _, kvp := range s {
		if kvp.Key != defaultAllowProfileResourceKey {
			s[n] = kvp
			n++
		}
	}
	list.KVPairs = s[:n]
}

// sendAddedEvents sends an ADDED event for each entry in the kvp list.
func (wc *watcher) sendAddedEvents(list *model.KVPairList) {
	for _, kv := range list.KVPairs {
		wc.sendEvent(&api.WatchEvent{
			Type: api.WatchAdded,
			New:  kv,
		})
	}
}

// terminateWatcher terminates the resources associated with the watcher.
func (wc *watcher) terminateWatcher() {
	log.Debug("Terminating etcdv3 watcher")
	// Cancel the context - which will cancel the etcd Watch, this may have already been
	// cancelled through an explicit Stop, but it is fine to cancel multiple times.
	wc.cancel()

	// Close the results channel.
	close(wc.resultChan)

	// Increment the terminated counter using a goroutine safe operation.
	atomic.AddUint32(&wc.terminated, 1)
}

// sendError packages up the error as an event and sends it in the results channel.
func (wc *watcher) sendError(err error) {
	// The response from etcd commands may include a context.Canceled error if the context
	// was cancelled before completion.  Since with our Watcher we don't include that as
	// an error type skip over the Canceled error, the error processing in the main
	// watch thread will terminate the watcher.
	if err == context.Canceled {
		return
	}

	// Wrap the error up in a WatchEvent and use sendEvent to send it.
	errEvent := &api.WatchEvent{
		Type:  api.WatchError,
		Error: err,
	}
	wc.sendEvent(errEvent)
}

// sendEvent sends an event in the results channel.
func (wc *watcher) sendEvent(e *api.WatchEvent) {
	if len(wc.resultChan) == resultsBufSize {
		log.Warningf("Watch events backing up: %d events", resultsBufSize)
	}
	select {
	case wc.resultChan <- *e:
	case <-wc.ctx.Done():
	}
}
