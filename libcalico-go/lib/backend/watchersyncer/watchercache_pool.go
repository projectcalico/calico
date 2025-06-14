// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package watchersyncer

import (
	"reflect"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
)

type resourceTypeToCacheMapping struct {
	resourceType ResourceType

	realWatcherCache *watcherCache
	fanout           *watcherCacheFanout
}

// WatcherCachePool is the simplest WatcherCacheProvider implementation.
// It creates a new WatcherCache for each call to WatcherCache.
type WatcherCachePool struct {
	client api.Client

	caches []*resourceTypeToCacheMapping
}

func NewWatcherCachePool(client api.Client) WatcherCacheProvider {
	return &WatcherCachePool{
		client: client,
	}
}

func (w *WatcherCachePool) WatcherCache(resourceType ResourceType, results chan interface{}, watchTimeout time.Duration) WatcherCacheIface {
	mapping := w.getOrCreateCache(resourceType, watchTimeout)
	mapping.fanout.addOutput(results)
	return mapping.fanout
}

func (w *WatcherCachePool) getOrCreateCache(resourceType ResourceType, watchTimeout time.Duration) *resourceTypeToCacheMapping {
	// ResourceType may not be comparable, so we need to do a scan...
	for _, mapping := range w.caches {
		if reflect.DeepEqual(mapping.resourceType, resourceType) {
			return mapping
		}
	}
	results := make(chan interface{})
	cache := newWatcherCache(w.client, resourceType, results, watchTimeout)
	fo := &watcherCacheFanout{
		resourceType:  resourceType,
		upstreamCache: cache,
		input:         results,
	}
	w.caches = append(w.caches, &resourceTypeToCacheMapping{
		resourceType:     resourceType,
		realWatcherCache: cache,
		fanout:           fo,
	})
	return w.caches[len(w.caches)-1]
}

type watcherCacheFanout struct {
	resourceType ResourceType
	input        <-chan any

	lock          sync.Mutex
	wg            sync.WaitGroup
	outputs       []chan<- any
	started       bool
	upstreamCache *watcherCache
}

func (f *watcherCacheFanout) run(ctx context.Context) {
	f.lock.Lock()
	if f.started {
		<-ctx.Done()
		return // FIXME should we make intermediate object to avoid this?
	}
	f.started = true
	f.lock.Unlock()

	if len(f.outputs) > 1 {
		logrus.WithFields(logrus.Fields{
			"outputs":      len(f.outputs),
			"resourceType": f.resourceType,
		}).Info("Sharing watcher cache for resource type.")
	} else {
		logrus.WithFields(logrus.Fields{
			"resourceType": f.resourceType,
		}).Info("Not sharing watcher cache for resource type.")
	}

	// FIXME we can be called multiple times so we don't want to stop for
	//       the individual context.
	go f.upstreamCache.run(context.TODO())
	go f.loopFanningOut(context.TODO())

	<-ctx.Done()
}

func (f *watcherCacheFanout) addOutput(output chan<- any) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if f.started {
		logrus.Panic("Cannot add output after starting fanout.")
	}
	f.outputs = append(f.outputs, output)
}

func (f *watcherCacheFanout) loopFanningOut(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case result := <-f.input:
			for _, output := range f.outputs {
				output <- result
			}
		}
	}
}
