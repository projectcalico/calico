// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

package api

import (
	"fmt"
	. "github.com/tigera/libcalico-go/lib/backend/model"
)

// SyncStatus represents the overall state of the datastore.
// When the status changes, the Syncer calls OnStatusUpdated() on its callback.
type SyncStatus uint8

const (
	// WaitForDatastore means the Syncer is waiting to connect to the datastore.
	// (Or, it is waiting for the data in the datastore to be ready to use.)
	WaitForDatastore SyncStatus = iota
	// ResyncInProgress means the Syncer is resyncing with the datastore.
	// During the first resync, the Syncer sends updates for all keys that
	// exist in the datastore as well as any updates that occur
	// concurrently.
	ResyncInProgress
	// InSync means the Syncer has now sent all the existing keys in the
	// datastore and the user of hte API has the full picture.
	InSync
)

func (s SyncStatus) String() string {
	switch s {
	case WaitForDatastore:
		return "wait-for-ready"
	case InSync:
		return "in-sync"
	case ResyncInProgress:
		return "resync"
	default:
		return fmt.Sprintf("Unknown<%v>", uint8(s))
	}
}

type Client interface {
	Create(object *KVPair) (*KVPair, error)
	Update(object *KVPair) (*KVPair, error)
	Apply(object *KVPair) (*KVPair, error)
	Delete(object *KVPair) error
	Get(key Key) (*KVPair, error)
	List(list ListInterface) ([]*KVPair, error)

	// Syncer creates an object that generates a series of KVPair updates,
	// which paint an eventually-consistent picture of the full state of
	// the datastore and then generates subsequent KVPair updates for
	// changes to the datastore.
	Syncer(callbacks SyncerCallbacks) Syncer
}

type Syncer interface {
	Start()
}

type SyncerCallbacks interface {
	OnStatusUpdated(status SyncStatus)
	// OnUpdates is called when the Syncer has one or more updates to report.
	// Updates consist of typed key-value pairs.  The keys are drawn from the
	// backend.model package.  The values are either nil, to indicate a
	// deletion, or a pointer to a value of the associated value type.
	OnUpdates(updates []KVPair)
}

type SyncerParseFailCallbacks interface {
	ParseFailed(rawKey string, rawValue *string)
}
