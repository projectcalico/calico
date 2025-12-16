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

package utils

import (
	"reflect"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

const (
	Etcdv3 = "etcdv3"
)

type (
	UpdateHandler func(bapi.Update)
	StatusHandler func(bapi.SyncStatus)
)

func NewDataFeed(c client.Interface, dataStore string) *DataFeed {
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
		{
			ListInterface: model.ResourceListOptions{Kind: apiv3.KindHostEndpoint},
		},

		// Network policy types
		{
			ListInterface: model.ResourceListOptions{Kind: apiv3.KindNetworkPolicy},
		},
		{
			ListInterface: model.ResourceListOptions{Kind: apiv3.KindGlobalNetworkPolicy},
		},
		{
			ListInterface: model.ResourceListOptions{Kind: apiv3.KindStagedNetworkPolicy},
		},
		{
			ListInterface: model.ResourceListOptions{Kind: apiv3.KindStagedGlobalNetworkPolicy},
		},
	}
	type accessor interface {
		Backend() bapi.Client
	}

	d := &DataFeed{
		registrations:       map[any][]UpdateHandler{},
		statusRegistrations: []StatusHandler{},
		dataStore:           dataStore,
	}
	d.syncer = watchersyncer.New(c.(accessor).Backend(), resourceTypes, d)
	return d
}

type DataFeed struct {
	syncer bapi.Syncer

	// Registrations
	registrations       map[any][]UpdateHandler
	statusRegistrations []StatusHandler
	dataStore           string
}

func (d *DataFeed) Start() {
	// We can skip this if there are no registrations.
	if len(d.registrations) == 0 && len(d.statusRegistrations) == 0 {
		logrus.Info("No registrations for data feed, skipping start")
		return
	}

	logrus.Info("Starting syncer")
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

func (d *DataFeed) OnUpdates(updates []bapi.Update) {
	for _, upd := range updates {
		d.onUpdate(upd)
	}
}

func (d *DataFeed) onUpdate(update bapi.Update) {
	// Pull out the update type.
	t := reflect.TypeOf(update.Key)

	if d.dataStore == Etcdv3 {
		d.updateResourceVersion(update)
	}

	// For each consumer registered for this type, send an update.
	for _, f := range d.registrations[t] {
		f(update)
	}
}

// updateResourceVersion updates the resourceVersion of the resource when we run in etcd mode. The resource version is revision on the KVPair
// This is a workaround for a fact that the backend syncer api does not update the resourceVersion.
// Kube-controller syncer should not have to be aware of the datastore and the backend syncer should correctly update the resourceVersion
// This can be removed once the backend syncer code is updates
func (d *DataFeed) updateResourceVersion(update bapi.Update) {
	if update.Value == nil {
		// We received delete, we don't have to update the resourceVersion as the resource does not exist
		return
	}

	switch key := update.Key.(type) {
	case model.ResourceKey:
		switch key.Kind {
		case libapiv3.KindNode:
			node := update.Value.(*libapiv3.Node)
			node.ResourceVersion = update.Revision
		case apiv3.KindClusterInformation:
			clusterInformation := update.Value.(*apiv3.ClusterInformation)
			clusterInformation.ResourceVersion = update.Revision
		case apiv3.KindIPPool:
			pool := update.Value.(*apiv3.IPPool)
			pool.ResourceVersion = update.Revision
		case apiv3.KindHostEndpoint:
			endpoint := update.Value.(*apiv3.HostEndpoint)
			endpoint.ResourceVersion = update.Revision
		}
	}
}
