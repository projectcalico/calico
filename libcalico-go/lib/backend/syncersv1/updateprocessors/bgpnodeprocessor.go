// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.

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

package updateprocessors

import (
	"errors"

	log "github.com/sirupsen/logrus"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// Create a new SyncerUpdateProcessor to sync Node data in v1 format for
// consumption by the BGP daemon.
func NewBGPNodeUpdateProcessor(usePodCIDR bool) watchersyncer.SyncerUpdateProcessor {
	return &bgpNodeUpdateProcessor{
		usePodCIDR:      usePodCIDR,
		nodeCIDRTracker: newNodeCIDRTracker(),
	}
}

// bgpNodeUpdateProcessor implements the SyncerUpdateProcessor interface.
// This converts the v3 node configuration into the v1 data types consumed by confd.
type bgpNodeUpdateProcessor struct {
	usePodCIDR      bool
	nodeCIDRTracker nodeCIDRTracker
}

func (c *bgpNodeUpdateProcessor) Process(kvp *model.KVPair) ([]*model.KVPair, error) {
	// Extract the name.
	name, err := c.extractName(kvp.Key)
	if err != nil {
		return nil, err
	}

	// Extract the separate bits of BGP config - these are stored as separate keys in the
	// v1 model.  For a delete these will all be nil.
	var asNum, ipv4, netv4, ipv6, netv6, rrClusterID interface{}
	var node *libapiv3.Node
	var ok bool
	if kvp.Value != nil {
		node, ok = kvp.Value.(*libapiv3.Node)
		if !ok {
			return nil, errors.New("Incorrect value type - expecting resource of kind Node")
		}

		// The bird templates always expects the BGP IP keys to be present for a node even
		// if they are not specified (the value in that case should be a blank string).  All
		// other fields should have their corresponding configuration removed when they are
		// not present in the Spec.  Store failures to convert, but treat as if unassigned.
		// Return the first error that was hit.
		ipv4 = ""
		ipv6 = ""
		rrClusterID = ""
		if bgp := node.Spec.BGP; bgp != nil {
			if len(bgp.IPv4Address) != 0 {
				ip, cidr, perr := net.ParseCIDROrIP(bgp.IPv4Address)
				if perr == nil {
					ipv4 = ip.String()
					netv4 = cidr.Network().String()
				} else {
					err = perr
				}
			}
			if len(bgp.IPv6Address) != 0 {
				ip, cidr, perr := net.ParseCIDROrIP(bgp.IPv6Address)
				if perr == nil {
					ipv6 = ip.String()
					netv6 = cidr.Network().String()
				} else if err == nil {
					err = perr
				}
			}
			if bgp.ASNumber != nil {
				asNum = bgp.ASNumber.String()
			}
			rrClusterID = bgp.RouteReflectorClusterID
		}
	}

	kvps := []*model.KVPair{
		{
			Key: model.NodeBGPConfigKey{
				Nodename: name,
				Name:     "ip_addr_v4",
			},
			Value:    ipv4,
			Revision: kvp.Revision,
		},
		{
			Key: model.NodeBGPConfigKey{
				Nodename: name,
				Name:     "ip_addr_v6",
			},
			Value:    ipv6,
			Revision: kvp.Revision,
		},
		{
			Key: model.NodeBGPConfigKey{
				Nodename: name,
				Name:     "network_v4",
			},
			Value:    netv4,
			Revision: kvp.Revision,
		},
		{
			Key: model.NodeBGPConfigKey{
				Nodename: name,
				Name:     "network_v6",
			},
			Value:    netv6,
			Revision: kvp.Revision,
		},
		{
			Key: model.NodeBGPConfigKey{
				Nodename: name,
				Name:     "as_num",
			},
			Value:    asNum,
			Revision: kvp.Revision,
		},
		{
			Key: model.NodeBGPConfigKey{
				Nodename: name,
				Name:     "rr_cluster_id",
			},
			Value:    rrClusterID,
			Revision: kvp.Revision,
		},
	}

	if c.usePodCIDR {
		// If we're using host-local IPAM based off the Kubernetes node PodCIDR, then
		// we need to send affinities based on the CIDRs to confd.
		var currentPodCIDRs []string
		if node != nil {
			currentPodCIDRs = node.Status.PodCIDRs
		}
		toRemove := c.nodeCIDRTracker.SetNodeCIDRs(name, currentPodCIDRs)

		// Send deletes for any CIDRs which are no longer present.
		for _, c := range toRemove {
			_, cidr, err := cnet.ParseCIDR(c)
			if err != nil {
				log.WithError(err).WithField("CIDR", c).Warn("Failed to parse Node PodCIDR")
				continue
			}
			kvps = append(kvps, &model.KVPair{
				Key:      model.BlockAffinityKey{Host: name, CIDR: *cidr},
				Value:    nil,
				Revision: kvp.Revision,
			})
		}

		// Send updates for any CIDRs which are still present.
		for _, c := range currentPodCIDRs {
			_, cidr, err := cnet.ParseCIDR(c)
			if err != nil {
				log.WithError(err).WithField("CIDR", c).Warn("Failed to parse Node PodCIDR")
				continue
			}

			kvps = append(kvps, &model.KVPair{
				Key:      model.BlockAffinityKey{Host: name, CIDR: *cidr},
				Value:    &model.BlockAffinity{State: model.StateConfirmed},
				Revision: kvp.Revision,
			})
		}
	}

	return kvps, err
}

// Sync is restarting - nothing to do for this processor.
func (c *bgpNodeUpdateProcessor) OnSyncerStarting() {
	log.Debug("Sync starting called on BGP node update processor")
}

func (c *bgpNodeUpdateProcessor) extractName(k model.Key) (string, error) {
	rk, ok := k.(model.ResourceKey)
	if !ok || rk.Kind != libapiv3.KindNode {
		return "", errors.New("Incorrect key type - expecting resource of kind Node")
	}
	return rk.Name, nil
}
