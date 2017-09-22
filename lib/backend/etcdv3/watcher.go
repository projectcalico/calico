// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

	"github.com/coreos/etcd/clientv3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
)

const (
	outgoingBufSize = 100
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
		resultChan: make(chan api.WatchEvent, outgoingBufSize),
		errChan:    make(chan error, 1),
	}
	wc.ctx, wc.cancel = context.WithCancel(cxt)
	go wc.run()
	return wc, nil
}

// watcher implements watch.Interface.
type watcher struct {
	client     *etcdV3Client
	initialRev int64
	ctx        context.Context
	cancel     context.CancelFunc
	resultChan chan api.WatchEvent
	errChan    chan error
	list       model.ListInterface
}

func (wc *watcher) run() {
	log.Info("Running watcher main loop")
	watchClosedCh := make(chan struct{})
	go wc.watchLoop(watchClosedCh)

	select {
	case err := <-wc.errChan:
		log.Debug("watcher.run() loop received error event")
		if err == context.Canceled {
			log.Debug("error event was a cancel - ignoring")
			break
		}
		errResult := &api.WatchEvent{
			Type:  api.WatchError,
			Error: err,
		}

		// Send the error result unless the user has cancelled.
		select {
		case wc.resultChan <- *errResult:
		case <-wc.ctx.Done():
		}
	case <-watchClosedCh:
		log.Debug("watcher.run loop received watch closed event")
	case <-wc.ctx.Done(): // user cancel
		log.Debug("watcher.run loop received done event")
	}
	log.Info("watcher.run loop exiting")

	// We use wc.ctx to reap all goroutines. Under whatever condition, we should stop them all.
	// It's fine to double cancel.
	wc.cancel()
	close(wc.resultChan)
}

// Stop implements the api.WatchInterface.
// This calls through to the context cancel function.
func (wc *watcher) Stop() {
	wc.cancel()
}

// ResultChan implements the api.WatchInterface.
func (wc *watcher) ResultChan() <-chan api.WatchEvent {
	return wc.resultChan
}

// listCurrent retrieves the existing entries and sends an event for each listed
func (wc *watcher) listCurrent() error {
	log.Info("Performing initial list with no revision")
	list, err := wc.client.List(wc.ctx, wc.list, "")
	if err != nil {
		return err
	}

	wc.initialRev, err = strconv.ParseInt(list.Revision, 10, 64)
	if err != nil {
		log.WithError(err).Error("List returned revision that could not be parsed")
		return err
	}

	// We are sending an initial sync of entries to the watcher to provide current
	// state.  To the perspective of the watcher, these are added entries, so set the
	// event type to WatchAdded.
	for _, kv := range list.KVPairs {
		log.Info("Sending create events for each existing entry")
		wc.sendEvent(&api.WatchEvent{
			Type: api.WatchAdded,
			New:  kv,
		})
	}
	return nil
}

// watchLoop starts a watch on the required path prefix and sends a stream of
// event updates for internal processing.
func (wc *watcher) watchLoop(watchClosedCh chan struct{}) {
	log.Debug("Starting watcher.watchLoop")
	if wc.initialRev == 0 {
		// No initial revision supplied, so perform a list of current configuration
		// which will also get the current revision we will start our watch from.
		if err := wc.listCurrent(); err != nil {
			log.Errorf("failed to list current with latest state: %v", err)
			wc.sendError(err)
			return
		}
	}
	opts := []clientv3.OpOption{clientv3.WithRev(wc.initialRev + 1), clientv3.WithPrevKV()}

	// If we are not watching a specific resource then this is a prefix watch.
	key := model.ListOptionsToDefaultPathRoot(wc.list)
	logCxt := log.WithFields(log.Fields{
		"etcdv3-key": key,
		"rev":        wc.initialRev,
	})
	logCxt.Debug("Starting etcdv3 watch")
	if !model.ListOptionsIsFullyQualified(wc.list) {
		logCxt.Debug("Performing prefix watch")
		opts = append(opts, clientv3.WithPrefix())
		key += "/"
	}
	wch := wc.client.etcdClient.Watch(wc.ctx, key, opts...)
	for wres := range wch {
		if wres.Err() != nil {
			err := wres.Err()
			log.WithError(err).Error("Watch channel error")
			wc.sendError(err)
			return
		}
		for _, e := range wres.Events {
			if ae, err := convertWatchEvent(e, wc.list); ae != nil {
				wc.sendEvent(ae)
			} else if err != nil {
				wc.sendError(err)
			}
		}
	}

	// The watch has been ended through a client action (e.g context cancelled or timedout).
	//
	// When we come to this point, it's only possible that client side ends the watch.
	// e.g. cancel the context, close the client.etcdClient.
	close(watchClosedCh)
}

// sendError sends an error down the errChan or waits for done notification.
func (wc *watcher) sendError(err error) {
	select {
	case wc.errChan <- err:
	case <-wc.ctx.Done():
	}
}

func (wc *watcher) sendEvent(e *api.WatchEvent) {
	if len(wc.resultChan) == outgoingBufSize {
		log.Warningf("Watch events backing up: %d events", outgoingBufSize)
	}
	select {
	case wc.resultChan <- *e:
	case <-wc.ctx.Done():
	}
}
