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
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
)

// WatcherCacheFactory is the simplest WatcherCacheProvider implementation.
// It creates a new WatcherCache for each call to WatcherCache.
type WatcherCacheFactory struct {
	client api.Client
}

func (w WatcherCacheFactory) WatcherCache(resourceType ResourceType, results chan interface{}) WatcherCacheIface {
	return newWatcherCache(w.client, resourceType, results)
}

func NewWatcherCacheFactory(client api.Client) WatcherCacheProvider {
	return &WatcherCacheFactory{client: client}
}
