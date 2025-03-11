// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package calc

import (
	"maps"
	"reflect"
	"sort"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/dispatcher"
	libv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	sel "github.com/projectcalico/calico/libcalico-go/lib/selector"
)

// ActiveBGPPeerCalculator pairs BGPPeers with local endpoints and
// determines which endpoint should establish an active BGP peer with its host.
// It calls the PolicyResolver to tell it to include the local BGP peer info on the
// WorkloadEndpoint data that is passed to the dataplane.
type ActiveBGPPeerCalculator struct {
	// Local host name.
	hostname string

	// Node labels for this host.
	nodeLabels map[string]string

	// Labels of active local endpoints.
	labelsByID map[model.WorkloadEndpointKey]map[string]string

	// All BGP peers.
	allBGPPeersByName map[string]*v3.BGPPeer

	// Local Workload selectors of active BGP peers.  I.e. only those that match the current node.
	workloadSelectorsByPeerName map[string]sel.Selector

	// peer data of active local endpoints.
	peersByID map[model.WorkloadEndpointKey]EndpointBGPPeer

	// Callbacks.
	OnEndpointBGPPeerDataUpdate func(id model.WorkloadEndpointKey, peerData *EndpointBGPPeer)
}

// Peer information that we track for each active local endpoint.
type EndpointBGPPeer struct {
	// Name of the V3 BGPPeer resource.
	v3PeerName string
}

// Return true if the peer data is empty.
func (p EndpointBGPPeer) isEmpty() bool {
	return len(p.v3PeerName) == 0
}

// Return true if the peer data is associated with a BGPPeer resource.
func (p EndpointBGPPeer) associatedWith(name string) bool {
	return p.v3PeerName == name
}

func NewActiveBGPPeerCalculator(hostname string) *ActiveBGPPeerCalculator {
	abp := &ActiveBGPPeerCalculator{
		hostname:                    hostname,
		nodeLabels:                  map[string]string{},
		labelsByID:                  map[model.WorkloadEndpointKey]map[string]string{},
		workloadSelectorsByPeerName: map[string]sel.Selector{},
		allBGPPeersByName:           map[string]*v3.BGPPeer{},
		peersByID:                   map[model.WorkloadEndpointKey]EndpointBGPPeer{},
	}
	return abp
}

func (abp *ActiveBGPPeerCalculator) RegisterWith(localEndpointDispatcher, allUpdDispatcher *dispatcher.Dispatcher) {
	// It needs local workload endpoints.
	localEndpointDispatcher.Register(model.WorkloadEndpointKey{}, abp.OnUpdate)
	// It also needs Nodes and BGPPeers.
	allUpdDispatcher.Register(model.ResourceKey{}, abp.OnUpdate)
}

func (abp *ActiveBGPPeerCalculator) OnUpdate(update api.Update) (_ bool) {
	logCxt := logrus.WithField("update", update)
	switch id := update.Key.(type) {
	case model.WorkloadEndpointKey:
		if update.Value != nil {
			logCxt.Debug("Updating abp with endpoint update")
			endpoint := update.Value.(*model.WorkloadEndpoint)
			abp.onEndpointUpdate(id, endpoint.Labels)
		} else {
			logCxt.Debug("Deleting endpoint from abp")
			abp.onEndpointDelete(id)
		}
	case model.ResourceKey:
		switch id.Kind {
		case v3.KindBGPPeer:
			if update.Value != nil {
				logCxt.Info("Updating abp with BGPPeer")
				bgpPeer := update.Value.(*v3.BGPPeer)

				name := bgpPeer.Name
				// Save latest bgpPeer.
				abp.allBGPPeersByName[name] = bgpPeer

				if !abp.bgpPeerSelectsLocalNode(bgpPeer) {
					// Trying to delete BGPPeer if it does not select the host.
					abp.onBGPPeerDelete(name)
				} else {
					abp.updateActiveBGPPeer(bgpPeer)
				}
			} else {
				logCxt.Debug("Deleting BGPPeer from abp")
				abp.onBGPPeerDelete(id.Name)
				delete(abp.allBGPPeersByName, id.Name)
			}
		case libv3.KindNode:
			nodeName := update.Key.(model.ResourceKey).Name
			if nodeName != abp.hostname {
				return
			}
			if update.Value != nil {
				node := update.Value.(*libv3.Node)
				abp.onNodeUpdate(node)
			} else {
				abp.onNodeDelete()
			}
		default:
			// Ignore other kinds of v3 resource.
		}
	default:
		logrus.Infof("Ignoring unexpected update: %v %#v",
			reflect.TypeOf(update.Key), update)
	}

	return
}

// Return peer data if the label is validated by an existing selector.
func (abp *ActiveBGPPeerCalculator) calculatePeerDataFromLabels(labels map[string]string) EndpointBGPPeer {
	// Extract keys
	keys := []string{}
	for k := range abp.workloadSelectorsByPeerName {
		keys = append(keys, k)
	}

	// Sort keys alphabetically
	sort.Strings(keys)

	// Iterate in sorted order.
	for _, name := range keys {
		selector := abp.workloadSelectorsByPeerName[name]
		if selector.Evaluate(labels) {
			return EndpointBGPPeer{
				v3PeerName: name,
			}
		}
	}

	// Otherwise return an empty peer data.
	return EndpointBGPPeer{}
}

// Given a new peer data, check and update the cache if needed.
func (abp *ActiveBGPPeerCalculator) checkAndUpdatePeerData(id model.WorkloadEndpointKey, newPeerData EndpointBGPPeer) {
	// Get current peer data of the endpoint.
	peerData := abp.peersByID[id]

	// If peer data hasn't changed, we don't need to send any update.
	if newPeerData == peerData {
		return
	}

	// Update peer data for the endpoint.
	if newPeerData.isEmpty() {
		delete(abp.peersByID, id)
	} else {
		abp.peersByID[id] = newPeerData
	}

	// Send the update.
	logrus.Debugf("Send BGP Peer data update %s on endpoint %s", newPeerData.v3PeerName, id)
	abp.OnEndpointBGPPeerDataUpdate(id, &newPeerData)
}

func (abp *ActiveBGPPeerCalculator) onEndpointUpdate(id model.WorkloadEndpointKey, newLabels map[string]string) {
	// Save new label for this endpoint if it is different with the old one.
	labels, exists := abp.labelsByID[id]
	if exists {
		if maps.Equal(labels, newLabels) {
			return
		}
	}
	abp.labelsByID[id] = newLabels

	// Calculate peer data based on the new label.
	newPeerData := abp.calculatePeerDataFromLabels(newLabels)

	abp.checkAndUpdatePeerData(id, newPeerData)
}

func (abp *ActiveBGPPeerCalculator) onEndpointDelete(id model.WorkloadEndpointKey) {
	// Find and delete the data for this endpoint.
	if _, exists := abp.labelsByID[id]; !exists {
		return
	}
	delete(abp.labelsByID, id)

	// Get current peer data of the endpoint.
	if _, exists := abp.peersByID[id]; !exists {
		return
	}

	// Update peer data for the endpoint.
	delete(abp.peersByID, id)

	// Send the update.
	logrus.Debugf("Clear BGP Peer data on endpoint %s", id)
	abp.OnEndpointBGPPeerDataUpdate(id, nil)
}

func (abp *ActiveBGPPeerCalculator) onNodeUpdate(node *libv3.Node) {
	logCxt := logrus.WithField("node", node.Name)

	if !maps.Equal(node.Labels, abp.nodeLabels) {
		logCxt.Info("Labels of the host updated.")
		abp.nodeLabels = node.Labels
		// if node labels has been updated, re-evaluate it againt all bgp peers.
		for name, bgpPeer := range abp.allBGPPeersByName {
			if !abp.bgpPeerSelectsLocalNode(bgpPeer) {
				// Trying to delete BGPPeer if it does not select the host.
				abp.onBGPPeerDelete(name)
			} else {
				abp.updateActiveBGPPeer(bgpPeer)
			}
		}
	}
}

func (abp *ActiveBGPPeerCalculator) onNodeDelete() {
	for id := range abp.peersByID {
		abp.OnEndpointBGPPeerDataUpdate(id, nil)
	}
	abp.peersByID = make(map[model.WorkloadEndpointKey]EndpointBGPPeer)
}

func (abp *ActiveBGPPeerCalculator) bgpPeerSelectsLocalNode(bgpPeer *v3.BGPPeer) bool {
	if bgpPeer.Spec.Node == abp.hostname {
		return true
	}

	selector, err := sel.Parse(bgpPeer.Spec.NodeSelector)
	if err != nil {
		logrus.WithError(err).Errorf("Couldn't parse selector: %s", bgpPeer.Spec.NodeSelector)
		return false
	}

	if len(abp.nodeLabels) != 0 {
		if selector.Evaluate(abp.nodeLabels) {
			return true
		}
	}

	return false
}

func (abp *ActiveBGPPeerCalculator) updateActiveBGPPeer(bgpPeer *v3.BGPPeer) {
	logrus.WithField("bgppeer", bgpPeer).Debugf("On BGP Peer update")
	name := bgpPeer.Name

	abp.allBGPPeersByName[name] = bgpPeer

	rawSelector := bgpPeer.Spec.LocalWorkloadSelector
	newSelector, err := sel.Parse(rawSelector)
	if err != nil {
		logrus.WithError(err).Errorf("Couldn't parse selector: %s", rawSelector)
		return
	}

	// Save new selector for this BGP peer if it is different with the old one.
	selector, exists := abp.workloadSelectorsByPeerName[name]
	if exists {
		if selector.UniqueID() == newSelector.UniqueID() {
			return
		}
	}
	abp.workloadSelectorsByPeerName[name] = newSelector

	// Scan through workload endpoint labels and update peer data for any endpoint.
	// If an endpoint is associated with multiple BGP peers, only the first one counts.
	for id, labels := range abp.labelsByID {
		// Recalculate peer data.
		newPeerData := abp.calculatePeerDataFromLabels(labels)

		abp.checkAndUpdatePeerData(id, newPeerData)
	}
}

func (abp *ActiveBGPPeerCalculator) onBGPPeerDelete(name string) {
	// Find and delete the selector for this peer.
	if _, exists := abp.workloadSelectorsByPeerName[name]; !exists {
		return
	}
	logrus.WithField("name", name).Debugf("On BGP Peer delete")
	delete(abp.workloadSelectorsByPeerName, name)

	// Scan the current peer data and send an update if it matches the specified peer name.
	keysToDelete := []model.WorkloadEndpointKey{}
	for id, peerData := range abp.peersByID {
		if peerData.associatedWith(name) {
			logrus.Debugf("Clear BGP Peer data on endpoint %s", id)
			abp.OnEndpointBGPPeerDataUpdate(id, nil)
			keysToDelete = append(keysToDelete, id)
		}
	}

	for _, id := range keysToDelete {
		delete(abp.peersByID, id)
	}
}
