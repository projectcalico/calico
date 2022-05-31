// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.
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

package node

import (
	"reflect"

	"github.com/sirupsen/logrus"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

type UpdateHandler func(bapi.Update)
type StatusHandler func(bapi.SyncStatus)

func NewDataFeed(c client.Interface) *DataFeed {
	// Kinds to register with on the syncer API.
	resourceTypes := []watchersyncer.ResourceType{
		{
			ListInterface: model.ResourceListOptions{Kind: libapiv3.KindNode},
		},
		{
			ListInterface: model.ResourceListOptions{Kind: apiv3.KindClusterInformation},
		},
		{
			ListInterface: model.BlockListOptions{},
		},
		{
			ListInterface: model.ResourceListOptions{Kind: apiv3.KindIPPool},
		},
	}
	type accessor interface {
		Backend() bapi.Client
	}

	d := &DataFeed{
		registrations:       map[interface{}][]UpdateHandler{},
		statusRegistrations: []StatusHandler{},
	}
	d.syncer = watchersyncer.New(c.(accessor).Backend(), resourceTypes, d)
	return d
}

type DataFeed struct {
	syncer bapi.Syncer

	// Registrations
	registrations       map[interface{}][]UpdateHandler
	statusRegistrations []StatusHandler
}

func (d *DataFeed) Start() {
	d.syncer.Start()
}

func (d *DataFeed) RegisterForSyncStatus(h StatusHandler) {
	d.statusRegistrations = append(d.statusRegistrations, h)
}

// RegisterForNotification registers a channel to receive an update when the given kind receives an update.
// kind should be a pointer to the struct type received over the syncer.
func (d *DataFeed) RegisterForNotification(key model.Key, h UpdateHandler) {
	kType := reflect.TypeOf(key)
	d.registrations[kType] = append(d.registrations[kType], h)
}

func (d *DataFeed) OnStatusUpdated(status bapi.SyncStatus) {
	logrus.Infof("Node controller syncer status updated: %s", status)
	for _, f := range d.statusRegistrations {
		f(status)
	}
}

func (c *DataFeed) OnUpdates(updates []bapi.Update) {
	for _, upd := range updates {
		c.onUpdate(upd)
	}
}

func (c DataFeed) onUpdate(update bapi.Update) {
	// Pull out the update type.
	t := reflect.TypeOf(update.Key)

	// For each consumer registered for this type, send an update.
	for _, f := range c.registrations[t] {
		f(update)
	}
}
