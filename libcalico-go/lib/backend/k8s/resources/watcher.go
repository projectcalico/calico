// Copyright (c) 2016-2020 Tigera, Inc. All rights reserved.

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

package resources

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	kwatch "k8s.io/apimachinery/pkg/watch"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

const (
	resultsBufSize = 100
)

func newK8sWatcherConverter(
	ctx context.Context,
	name string,
	converter ConvertK8sResourceToKVPair,
	k8sWatch kwatch.Interface,
) api.WatchInterface {
	return newK8sWatcherConverterOneToMany(ctx, name, ConvertK8sResourceOneToOneAdapter(converter), k8sWatch)
}

// newK8sWatcherConverterOneToMany is used when the input kvp converts to multiple output kvps. This results in multiple
// watch events for a single input kvp.
func newK8sWatcherConverterOneToMany(
	ctx context.Context,
	name string,
	converter ConvertK8sResourceToKVPairs,
	k8sWatch kwatch.Interface,
) api.WatchInterface {
	ctx, cancel := context.WithCancel(ctx)
	wc := &k8sWatcherConverter{
		logCxt:     logrus.WithField("resource", name),
		converter:  converter,
		k8sWatch:   k8sWatch,
		context:    ctx,
		cancel:     cancel,
		resultChan: make(chan api.WatchEvent, resultsBufSize),
	}
	go wc.processK8sEvents()
	return wc
}

type k8sWatcherConverter struct {
	logCxt     *logrus.Entry
	converter  ConvertK8sResourceToKVPairs
	k8sWatch   kwatch.Interface
	context    context.Context
	cancel     context.CancelFunc
	resultChan chan api.WatchEvent
	terminated uint32
}

// Stop stops the watcher and releases associated resources.
// This calls through to the context cancel function.
func (crw *k8sWatcherConverter) Stop() {
	crw.cancel()
	crw.k8sWatch.Stop()
}

// ResultChan returns a channel used to receive WatchEvents.
func (crw *k8sWatcherConverter) ResultChan() <-chan api.WatchEvent {
	return crw.resultChan
}

// HasTerminated returns true when the watcher has completed termination processing.
func (crw *k8sWatcherConverter) HasTerminated() bool {
	return atomic.LoadUint32(&crw.terminated) != 0
}

// Loop to process the events stream from the underlying k8s Watcher and convert them to
// backend KVPs.
func (crw *k8sWatcherConverter) processK8sEvents() {
	crw.logCxt.Debug("Kubernetes watcher/converter started")
	defer func() {
		crw.logCxt.Debug("Kubernetes watcher/converter stopped, closing result channel")
		crw.Stop()
		close(crw.resultChan)
		atomic.AddUint32(&crw.terminated, 1)
	}()

	for {
		select {
		case event, ok := <-crw.k8sWatch.ResultChan():
			var events []*api.WatchEvent
			if !ok {
				// Watch channel is closed by remote k8s hence, return from loop.
				crw.logCxt.Debug("Watcher channel closed by remote")
				return
			} else {
				// We have a valid event, so convert it.
				events = crw.convertEvent(event)
				if len(events) == 0 {
					crw.logCxt.WithField("event", event).Debug("Event converted to a no-op")
					continue
				}
			}

			for _, e := range events {
				select {
				case crw.resultChan <- *e:
					crw.logCxt.Debug("Kubernetes event converted and sent to backend watcher")
				case <-crw.context.Done():
					crw.logCxt.Debug("Process watcher done event during watch event in kdd client")
					return
				}
			}
		case <-crw.context.Done(): // user cancel
			crw.logCxt.Debug("Process watcher done event in kdd client")
			return
		}
	}
}

// convertEvent converts a Kubernetes Watch event into the equivalent Calico backend client watch event(s). It first converts
// the kubernetes object in the event to the corresponding calico object(s), and for each calico object an event is create
// using the original kubernetes event as a template.
func (crw *k8sWatcherConverter) convertEvent(kevent kwatch.Event) []*api.WatchEvent {
	var kvps []*model.KVPair
	var err error

	switch kevent.Type {
	case kwatch.Error:
		// An error directly from the k8s watcher is a terminating event.
		return []*api.WatchEvent{{
			Type:  api.WatchError,
			Error: apierrors.FromObject(kevent.Object),
		}}
	case kwatch.Deleted:
		fallthrough
	case kwatch.Added:
		fallthrough
	case kwatch.Modified:
		k8sRes := kevent.Object.(Resource)
		kvps, err = crw.converter(k8sRes)
		if err != nil {
			crw.logCxt.WithError(err).Warning("Error converting Kubernetes resource to Calico resource")
			return []*api.WatchEvent{{
				Type:  api.WatchError,
				Error: err,
			}}
		}

		if len(kvps) == 0 {
			return nil
		}

		return crw.buildEventsFromKVPs(kvps, kevent.Type)
	case kwatch.Bookmark:
		// For bookmarks we send an empty KVPair with the current resource
		// version only.
		k8sRes := kevent.Object.(Resource)
		revision := k8sRes.GetObjectMeta().GetResourceVersion()
		return []*api.WatchEvent{{
			Type: api.WatchBookmark,
			New: &model.KVPair{
				Revision: revision,
			},
		}}
	default:
		return []*api.WatchEvent{{
			Type:  api.WatchError,
			Error: fmt.Errorf("unhandled Kubernetes watcher event type: %v", kevent.Type),
		}}
	}

}

func (crw *k8sWatcherConverter) buildEventsFromKVPs(kvps []*model.KVPair, t kwatch.EventType) []*api.WatchEvent {
	var getEvent func(*model.KVPair) *api.WatchEvent
	switch t {
	case kwatch.Deleted:
		getEvent = func(kvp *model.KVPair) *api.WatchEvent {
			return &api.WatchEvent{Type: api.WatchDeleted, Old: kvp}
		}
	case kwatch.Added:
		getEvent = func(kvp *model.KVPair) *api.WatchEvent {
			return &api.WatchEvent{Type: api.WatchAdded, New: kvp}
		}
	case kwatch.Modified:
		// In KDD we don't have access to the previous settings, so just set the current settings.
		getEvent = func(kvp *model.KVPair) *api.WatchEvent {
			return &api.WatchEvent{Type: api.WatchModified, New: kvp}
		}
	default:
		crw.logCxt.WithField("type", t).Error("unexpected event type when building events")
		return nil
	}

	var wEvents []*api.WatchEvent
	for _, kvp := range kvps {
		wEvents = append(wEvents, getEvent(kvp))
	}
	return wEvents
}
