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
	"github.com/projectcalico/calico/felix/labelindex"
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

	// Node labels for this host (or nil if we haven't yet received our Node resource).
	nodeLabels map[string]string

	// All BGP peers.
	allBGPPeersByName map[string]*v3.BGPPeer

	// Label index, matching active BGPPeers against local endpoints.
	labelIndex *labelindex.InheritIndex

	// Sorted list of BGPPeer names for peers that match each endpoint.
	peersByWorkloadID map[model.WorkloadEndpointKey][]string

	// Callbacks.
	OnEndpointBGPPeerDataUpdate func(id model.WorkloadEndpointKey, peerData *EndpointBGPPeer)
}

// Peer information that we track for each active local endpoint.
type EndpointBGPPeer struct {
	// Name of the V3 BGPPeer resource.
	v3PeerName string
}

func (e *EndpointBGPPeer) Empty() bool {
	return e == nil || len(e.v3PeerName) == 0
}

func NewActiveBGPPeerCalculator(hostname string) *ActiveBGPPeerCalculator {
	abp := &ActiveBGPPeerCalculator{
		hostname:          hostname,
		nodeLabels:        map[string]string{},
		allBGPPeersByName: map[string]*v3.BGPPeer{},
		peersByWorkloadID: map[model.WorkloadEndpointKey][]string{},
	}
	abp.labelIndex = labelindex.NewInheritIndex(abp.onPeerEndpointMatchStarted, abp.onPeerEndpointMatchStopped)
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
		// Delegate to the label index.  It will call us back when the match status changes.
		abp.labelIndex.OnUpdate(update)
	case model.ResourceKey:
		switch id.Kind {
		case v3.KindBGPPeer:
			if update.Value != nil {
				logCxt.Info("Updating abp with BGPPeer")

				// Save off the peer so that we can re-do the match if the node labels are updated.
				bgpPeer := update.Value.(*v3.BGPPeer)
				name := bgpPeer.Name
				abp.allBGPPeersByName[name] = bgpPeer

				if !abp.bgpPeerSelectsLocalNode(bgpPeer) {
					// Trying to delete BGPPeer if it does not select the host.
					abp.onPeerInactive(name)
				} else {
					abp.onPeerActive(bgpPeer)
				}
			} else {
				logCxt.Debug("Deleting BGPPeer from abp")
				abp.onPeerInactive(id.Name)
				delete(abp.allBGPPeersByName, id.Name)
			}
		case libv3.KindNode:
			nodeName := update.Key.(model.ResourceKey).Name
			if nodeName != abp.hostname {
				return
			}
			if update.Value != nil {
				node := update.Value.(*libv3.Node)
				abp.onLocalNodeLabelUpdate(node.Labels)
			} else {
				// Our node was deleted.  We must handle this as if the node
				// never existed in order to maintain the calculation graph's
				// invariant.
				logrus.Warning("Node resource for this node was deleted. Local BGP peer calculation may be disrupted.")
				abp.onLocalNodeLabelUpdate(nil)
			}
		case v3.KindProfile:
			abp.labelIndex.OnUpdate(update)
		default:
			// Ignore other kinds of v3 resource.
		}
	default:
		logrus.Infof("Ignoring unexpected update: %v %#v",
			reflect.TypeOf(update.Key), update)
	}

	return
}

func (abp *ActiveBGPPeerCalculator) onLocalNodeLabelUpdate(labels map[string]string) {
	if maps.Equal(labels, abp.nodeLabels) {
		return
	}
	logrus.WithFields(logrus.Fields{
		"old": abp.nodeLabels,
		"new": labels,
	}).Info("Labels of the local host updated.")
	abp.nodeLabels = labels

	// Recheck all BGPPeers.  We don't expect node label updates that often and
	// we don't expect there to be _that_ many BGPPeers.
	for name, bgpPeer := range abp.allBGPPeersByName {
		if abp.bgpPeerSelectsLocalNode(bgpPeer) {
			abp.onPeerActive(bgpPeer)
		} else {
			abp.onPeerInactive(name)
		}
	}
}

func (abp *ActiveBGPPeerCalculator) bgpPeerSelectsLocalNode(bgpPeer *v3.BGPPeer) bool {
	if bgpPeer.Spec.Node == abp.hostname {
		return true
	}
	if bgpPeer.Spec.Node != "" {
		return false
	}

	selector, err := sel.Parse(bgpPeer.Spec.NodeSelector)
	if err != nil {
		logrus.WithError(err).Errorf("BGPPeer had invalid node selector: %q.  Will ignore this BGPPeer.", bgpPeer.Spec.NodeSelector)
		selector = sel.NoMatch
	}

	return selector.Evaluate(abp.nodeLabels)
}

func (abp *ActiveBGPPeerCalculator) onPeerActive(bgpPeer *v3.BGPPeer) {
	var newSelector *sel.Selector
	var err error

	logrus.WithField("bgppeer", bgpPeer).Debugf("BGPPeer is active.")
	name := bgpPeer.Name
	abp.allBGPPeersByName[name] = bgpPeer
	rawSelector := bgpPeer.Spec.LocalWorkloadSelector
	if len(rawSelector) == 0 {
		newSelector = sel.NoMatch
	} else {
		newSelector, err = sel.Parse(rawSelector)
		if err != nil {
			logrus.WithError(err).Errorf("BGPPeer had invalid local workload selector: %q.  Will ignore this BGPPeer.", rawSelector)
			newSelector = sel.NoMatch
		}
	}

	abp.labelIndex.UpdateSelector(name, newSelector) // May trigger callbacks to onPeerEndpointMatchStarted/onPeerEndpointMatchStopped.
}

func (abp *ActiveBGPPeerCalculator) onPeerInactive(name string) {
	abp.labelIndex.DeleteSelector(name) // May trigger callbacks to onPeerEndpointMatchStopped.
}

func (abp *ActiveBGPPeerCalculator) onPeerEndpointMatchStarted(bgpPeerNameIface any, workloadIDIface any) {
	bgpPeerName := bgpPeerNameIface.(string)
	workloadID := workloadIDIface.(model.WorkloadEndpointKey)
	oldPeer := abp.calculateActivePeer(workloadID)
	abp.peersByWorkloadID[workloadID] = append(abp.peersByWorkloadID[workloadID], bgpPeerName)
	sort.Strings(abp.peersByWorkloadID[workloadID])
	newPeer := abp.calculateActivePeer(workloadID)
	if oldPeer != newPeer {
		abp.sendPeerUpdate(workloadID, newPeer)
	}
}

func (abp *ActiveBGPPeerCalculator) onPeerEndpointMatchStopped(bgpPeerNameIface any, workloadIDIface any) {
	bgpPeerName := bgpPeerNameIface.(string)
	workloadID := workloadIDIface.(model.WorkloadEndpointKey)
	oldPeer := abp.calculateActivePeer(workloadID)

	peers := abp.peersByWorkloadID[workloadID][:0]
	for _, name := range abp.peersByWorkloadID[workloadID] {
		if name == bgpPeerName {
			continue
		}
		peers = append(peers, name)
	}
	if len(peers) == 0 {
		delete(abp.peersByWorkloadID, workloadID)
	} else {
		abp.peersByWorkloadID[workloadID] = peers
	}

	newPeer := abp.calculateActivePeer(workloadID)
	if oldPeer != newPeer {
		abp.sendPeerUpdate(workloadID, newPeer)
	}
}

func (abp *ActiveBGPPeerCalculator) calculateActivePeer(id model.WorkloadEndpointKey) string {
	peers := abp.peersByWorkloadID[id]
	if len(peers) == 0 {
		return ""
	}
	return peers[0]
}

func (abp *ActiveBGPPeerCalculator) sendPeerUpdate(workloadID model.WorkloadEndpointKey, peer string) {
	if peer == "" {
		abp.OnEndpointBGPPeerDataUpdate(workloadID, nil)
		return
	}
	abp.OnEndpointBGPPeerDataUpdate(workloadID, &EndpointBGPPeer{v3PeerName: peer})
}
