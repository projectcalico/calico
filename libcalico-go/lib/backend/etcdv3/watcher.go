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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

const (
	resultsBufSize = 100
)

// Watch entries in the datastore matching the resources specified by the ListInterface.
func (c *etcdV3Client) Watch(cxt context.Context, l model.ListInterface, options api.WatchOptions) (api.WatchInterface, error) {
	var rev int64
	if len(options.Revision) != 0 {
		var err error
		rev, err = strconv.ParseInt(options.Revision, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	// etcdv3 backend doesn't support WatchList, watch revision must be greater than 0.
	if rev == 0 {
		allErrs := field.ErrorList{}
		allErrs = append(allErrs, field.Invalid(field.NewPath("revision"), rev, "watch revision must be greater than 0 for etcdv3 backend"))
		// return the same error as apiserver, let watcherCache fallback to list.
		return nil, apierrors.NewInvalid(schema.GroupKind{Group: metav1.GroupName, Kind: "ListOptions"}, "", allErrs)
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
