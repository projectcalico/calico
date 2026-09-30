// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package utils

import (
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/accounting"
)

// IPAMFeed keeps one accounting.Tracker current from the data feed, so every controller in the process reads the
// same IPAM state instead of keeping its own copy.
type IPAMFeed struct {
	tracker *accounting.Tracker
}

func NewIPAMFeed() *IPAMFeed {
	tracker := accounting.NewTracker()

	// The feed names every node that exists, so a block affine to one it never names is stale.
	tracker.AddNodes()
	return &IPAMFeed{tracker: tracker}
}

// RegisterWith subscribes to the feed. Register before the controllers that read the tracker, so it is updated first.
func (f *IPAMFeed) RegisterWith(feed *DataFeed) {
	feed.RegisterForNotification(model.BlockKey{}, f.OnUpdate)
	feed.RegisterForNotification(model.ResourceKey{}, f.OnUpdate)
}

// Tracker is safe to read from any goroutine. Callers must not add to or remove from it.
func (f *IPAMFeed) Tracker() *accounting.Tracker {
	return f.tracker
}

// OnUpdate applies one syncer update to the tracker. It runs on the syncer goroutine, so it must not block.
func (f *IPAMFeed) OnUpdate(update bapi.Update) {
	switch key := update.Key.(type) {
	case model.BlockKey:
		f.onBlockUpdate(key, update.Value)
	case model.ResourceKey:
		f.onResourceUpdate(key, update.Value)
	}
}

func (f *IPAMFeed) onBlockUpdate(key model.BlockKey, value any) {
	if value == nil {
		f.tracker.RemoveBlock(model.IPNetFromPrefix(key.CIDR))
		return
	}
	if block, ok := asType[*model.AllocationBlock](key, value); ok {
		f.tracker.AddBlocks(block)
	}
}

func (f *IPAMFeed) onResourceUpdate(key model.ResourceKey, value any) {
	switch key.Kind {
	case apiv3.KindIPPool:
		if value == nil {
			f.tracker.RemovePool(key.Name)
		} else if pool, ok := asType[*apiv3.IPPool](key, value); ok {
			// A Terminating pool stays: its status tells the tracker to keep its blocks until it is gone.
			f.tracker.AddPools(pool)
		}
	case apiv3.KindIPReservation:
		if value == nil {
			f.tracker.RemoveReservation(key.Name)
		} else if reservation, ok := asType[*apiv3.IPReservation](key, value); ok {
			f.tracker.AddReservations(reservation)
		}
	case internalapi.KindNode:
		if value == nil {
			f.tracker.RemoveNode(key.Name)
		} else {
			f.tracker.AddNodes(key.Name)
		}
	}
}

func asType[T any](key model.Key, value any) (T, bool) {
	v, ok := value.(T)
	if !ok {
		logrus.WithField("key", key).Warnf("Unexpected value type %T", value)
	}
	return v, ok
}
