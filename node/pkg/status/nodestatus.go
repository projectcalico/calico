// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

package status

import (
	"fmt"
	"os"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/nodestatussyncer"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/node/buildinfo"
	"github.com/projectcalico/calico/node/pkg/calicoclient"
	"github.com/projectcalico/calico/node/pkg/lifecycle/startup"
	populator "github.com/projectcalico/calico/node/pkg/status/populators"
	"github.com/projectcalico/calico/typha/pkg/syncclientutils"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

// This file contains the main processing and common logic for node status reporter.

// Run runs the node status reporter.
func Run() {

	startup.ConfigureLogging()

	// This binary is only ever invoked _after_ the
	// startup binary has been invoked and the modified environments have
	// been sourced.  Therefore, the NODENAME environment will always be
	// set at this point.
	nodename := os.Getenv("NODENAME")
	if nodename == "" {
		log.Panic("NODENAME environment is not set")
	}

	// Load the client config from environment.
	cfg, c := calicoclient.CreateClient()

	// This is running as a daemon. Create a long-running NodeStatusReporter.
	r := NewNodeStatusReporter(nodename, cfg, c, GetPopulators())

	// Either create a typha syncclient or a local syncer depending on configuration. This calls back into the
	// NodeStatusReporter to trigger updates when necessary.

	// Read Typha settings from the environment.
	// When Typha is in use, there will already be variables prefixed with FELIX_, so it's
	// convenient if we honor those as well as the CALICO variables.
	typhaConfig := syncclientutils.ReadTyphaConfig([]string{"FELIX_", "CALICO_"})
	if syncclientutils.MustStartSyncerClientIfTyphaConfigured(
		&typhaConfig, syncproto.SyncerTypeNodeStatus,
		buildinfo.GitVersion, nodename, fmt.Sprintf("node-status %s", buildinfo.GitVersion),
		r,
	) {
		log.Debug("Using typha syncclient")
	} else {
		// Use the syncer locally.
		log.Debug("Using local syncer")
		syncer := nodestatussyncer.New(c.(backendClientAccessor).Backend(), r)
		syncer.Start()
	}

	// Run the NodeStatusReporter.
	r.Run()
}

// Map IPFamily to a map from each class to a populator.
// Currently all the reporters would have the same populator for each class but
// it can be extended in the future.
type PopulatorRegistry map[populator.IPFamily]map[apiv3.NodeStatusClassType]populator.Interface

// getPopulators get current PopulatorRegistry.
func GetPopulators() PopulatorRegistry {
	// Get all the populator.Interface
	populators := make(map[populator.IPFamily]map[apiv3.NodeStatusClassType]populator.Interface)

	for _, ipv := range []populator.IPFamily{populator.IPFamilyV4, populator.IPFamilyV6} {
		populators[ipv] = make(map[apiv3.NodeStatusClassType]populator.Interface)
		populators[ipv][apiv3.NodeStatusClassTypeAgent] = populator.NewBirdInfo(ipv)
		populators[ipv][apiv3.NodeStatusClassTypeBGP] = populator.NewBirdBGPPeers(ipv)
		populators[ipv][apiv3.NodeStatusClassTypeRoutes] = populator.NewBirdRoutes(ipv)
	}

	return populators
}

// Show prints status information from all populators.
func Show() {
	for _, ipv := range []populator.IPFamily{populator.IPFamilyV4, populator.IPFamilyV6} {
		for _, class := range []apiv3.NodeStatusClassType{
			apiv3.NodeStatusClassTypeAgent,
			apiv3.NodeStatusClassTypeBGP,
			apiv3.NodeStatusClassTypeRoutes,
		} {
			if p, ok := GetPopulators()[ipv][class]; ok {
				p.Show()
			}
		}
		fmt.Print("\n\n")
	}
}

// NodeStatusReporter watches node status resource and creates/maintains reporter for each request.
type NodeStatusReporter struct {
	// Node name.
	nodename string

	// Calico client config
	cfg *apiconfig.CalicoAPIConfig

	// Calico client
	client client.Interface

	// Channel for getting updates and status updates from syncer.
	syncerC chan interface{}

	// cache for pending updates.
	// No lock needed for updating the cache since it is updated in main loop only.
	pendingUpdates map[string]*apiv3.CalicoNodeStatus

	// Cache to map the name of node status object to the reporter.
	reporter map[string]*reporter

	// Map IPFamily to a map from each class to a populator.
	populators PopulatorRegistry

	// Channel to indicate node status reporter routine is not needed anymore.
	done chan struct{}

	// Flag to show we are in-sync.
	inSync bool
}

// NewNodeStatusReporter creates a node status reporter.
func NewNodeStatusReporter(node string,
	cfg *apiconfig.CalicoAPIConfig,
	client client.Interface,
	populators PopulatorRegistry) *NodeStatusReporter {
	return &NodeStatusReporter{
		nodename:       node,
		cfg:            cfg,
		client:         client,
		syncerC:        make(chan interface{}, 1),
		reporter:       make(map[string]*reporter),
		pendingUpdates: make(map[string]*apiv3.CalicoNodeStatus),
		populators:     populators,
		done:           make(chan struct{}),
	}
}

// Return number of current reporters.
func (r *NodeStatusReporter) GetNumberOfReporters() int {
	return len(r.reporter)
}

// cleanup releases current reporters.
func (r *NodeStatusReporter) cleanup() {
	for name, reporter := range r.reporter {
		reporter.KillAndWait()
		delete(r.reporter, name)
	}
}

func (r *NodeStatusReporter) Stop() {
	r.done <- struct{}{}
}

// Run is the main reconciliation loop, it loops until done.
// Here the logic for handling syncer updates is
//   - If we get a value update, cache it to pendingUpdates.
//   - If we get a inSync message, set inSync to true.
//     We don't need to worry about any status message after inSync message,
//     getting a non-in sync status after an in-sync isn't important here, there's no real impact.
//     It'd just mean that we've got slightly old data.
//   - After handling syncer event, process pendingUpdates if we are in-sync.
func (r *NodeStatusReporter) Run() {
	// Loop forever, updating whenever we get a kick. The first kick will happen as soon as the syncer is in sync.
	for {
		select {
		case e := <-r.syncerC:
			switch event := e.(type) {
			case []bapi.Update:
				r.onUpdates(event)
			case bapi.SyncStatus:
				if event == bapi.InSync {
					r.inSync = true
				}
			default:
				log.Panicf("Unknown type %T in syncer channel", event)
			}
		case <-r.done:
			r.cleanup()
			return
		}

		if r.inSync {
			r.processPendingUpdates()
		}
	}
}

// OnUpdated handles the syncer update callback method.
func (r *NodeStatusReporter) OnUpdates(updates []bapi.Update) {
	r.syncerC <- updates
}

// OnStatusUpdated handles the syncer status callback method.
func (r *NodeStatusReporter) OnStatusUpdated(status bapi.SyncStatus) {
	if status == bapi.InSync {
		r.syncerC <- status
	}
}

// onUpdates caches the syncer resource updates in main loop.
func (r *NodeStatusReporter) onUpdates(updates []bapi.Update) {
	for _, u := range updates {
		var name string
		// Get resource name from the key.
		// Node status is non-namespaced resources hence
		// resource name is unique.
		if v, ok := u.Key.(model.ResourceKey); ok {
			name = v.Name
		} else {
			log.Warningf("Unexpected resource update: %s", u.Key)
			continue
		}

		if u.Value != nil {
			// Resource is created or updated. Cache latest value to pending updates.
			switch v := u.Value.(type) {
			case *apiv3.CalicoNodeStatus:
				if v.Spec.Node != r.nodename {
					// Node status request is not for us.
					continue
				}
				if v.Spec.UpdatePeriodSeconds == nil {
					log.Errorf("UpdatePeriodSeconds not set for node status resource: %s", u.Key)
					continue
				}
				log.Debugf("Updated node status resource: %s", u.Key)
				r.pendingUpdates[name] = v
			default:
				log.Warningf("Unexpected resource update: %s", u.Key)
				continue
			}
		} else {
			// In some corner cases, Value could be nil if validations failed in typha
			// even for KVNew / KVUpdated messages. We treat the update as a deletion.

			// Resource is deleted. Set nil pointer for pending updates.
			r.pendingUpdates[name] = nil
			log.Infof("Deleted node status resource: %s", u.Key)
		}
	}
}

// processPendingUpdates processes pending updates in main loop.
// It is called when we are in-sync.
func (r *NodeStatusReporter) processPendingUpdates() {
	for name, data := range r.pendingUpdates {
		if data == nil {
			// we have a deletion of the resource.
			if reporter, ok := r.reporter[name]; ok {
				reporter.KillAndWait()
				delete(r.reporter, name)
			}
		} else {
			// We have a new or updated resource.
			if _, ok := r.reporter[name]; !ok {
				// new resource.
				reporter := newReporter(name, r.client, r.populators, data)
				r.reporter[name] = reporter
			} else {
				// updated resource.
				// Check if it has the same spec with the current status being handled by the reporter.
				if r.reporter[name].HasSameSpec(data) {
					// we don't need to do anything. It is possible we get here
					// because the resource has been updated by the reporter itself.
					log.Debugf("Anticipated resource update: %s. Do nothing.", name)
					continue
				}
			}
			// Send updated data to reporter.
			r.reporter[name].RequestUpdate(data)
		}
		delete(r.pendingUpdates, name)
	}
}

// backendClientAccessor is an interface to access the backend client from the main v2 client.
type backendClientAccessor interface {
	Backend() bapi.Client
}
