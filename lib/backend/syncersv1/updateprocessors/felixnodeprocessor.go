// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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
	"fmt"

	log "github.com/sirupsen/logrus"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/watchersyncer"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
)

// Create a new SyncerUpdateProcessor to sync Node data in v1 format for
// consumption by Felix.
func NewFelixNodeUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return &FelixNodeUpdateProcessor{}
}

// FelixNodeUpdateProcessor implements the SyncerUpdateProcessor interface.
// This converts the v3 node configuration into the v1 data types consumed by confd.
type FelixNodeUpdateProcessor struct {
}

func (c *FelixNodeUpdateProcessor) Process(kvp *model.KVPair) ([]*model.KVPair, error) {
	// Extract the name.
	name, err := c.extractName(kvp.Key)
	if err != nil {
		return nil, err
	}

	// Extract the separate bits of BGP config - these are stored as separate keys in the
	// v1 model.  For a delete these will all be nil.  If we fail to convert any value then
	// just treat that as a delete on the underlying key and return the error alongside
	// the updates.
	var ipv4, ipv4Tunl, vxlanTunl interface{}
	if kvp.Value != nil {
		node, ok := kvp.Value.(*apiv3.Node)
		if !ok {
			return nil, errors.New("Incorrect value type - expecting resource of kind Node")
		}

		if bgp := node.Spec.BGP; bgp != nil {
			var ip *cnet.IP
			var cidr *cnet.IPNet

			// Parse the IPv4 address, Felix expects this as a HostIPKey.  If we fail to parse then
			// treat as a delete (i.e. leave ipv4 as nil).
			if len(bgp.IPv4Address) != 0 {
				ip, cidr, err = cnet.ParseCIDROrIP(bgp.IPv4Address)
				if err == nil {
					log.WithFields(log.Fields{"ip": ip, "cidr": cidr}).Debug("Parsed IPv4 address")
					ipv4 = ip
				} else {
					log.WithError(err).WithField("IPv4Address", bgp.IPv4Address).Warn("Failed to parse IPv4Address")
				}
			}

			// Parse the IPv4 IPIP tunnel address, Felix expects this as a HostConfigKey.  If we fail to parse then
			// treat as a delete (i.e. leave ipv4Tunl as nil).
			if len(bgp.IPv4IPIPTunnelAddr) != 0 {
				ip := cnet.ParseIP(bgp.IPv4IPIPTunnelAddr)
				if ip != nil {
					log.WithField("ip", ip).Debug("Parsed IPIP tunnel address")
					ipv4Tunl = ip.String()
				} else {
					log.WithField("IPv4IPIPTunnelAddr", bgp.IPv4IPIPTunnelAddr).Warn("Failed to parse IPv4IPIPTunnelAddr")
					err = fmt.Errorf("failed to parsed IPv4IPIPTunnelAddr as an IP address")
				}
			}
		}

		// Parse the IPv4 VXLAN tunnel address, Felix expects this as a HostConfigKey.  If we fail to parse then
		// treat as a delete (i.e. leave ipv4Tunl as nil).
		if len(node.Spec.IPv4VXLANTunnelAddr) != 0 {
			ip := cnet.ParseIP(node.Spec.IPv4VXLANTunnelAddr)
			if ip != nil {
				log.WithField("ip", ip).Debug("Parsed VXLAN tunnel address")
				vxlanTunl = ip.String()
			} else {
				log.WithField("IPv4VXLANTunnelAddr", node.Spec.IPv4VXLANTunnelAddr).Warn("Failed to parse IPv4VXLANTunnelAddr")
				err = fmt.Errorf("failed to parsed IPv4VXLANTunnelAddr as an IP address")
			}
		}
	}

	// Return the add/delete updates and any errors.
	return []*model.KVPair{
		{
			Key: model.HostIPKey{
				Hostname: name,
			},
			Value:    ipv4,
			Revision: kvp.Revision,
		},
		{
			Key: model.HostConfigKey{
				Hostname: name,
				Name:     "IpInIpTunnelAddr",
			},
			Value:    ipv4Tunl,
			Revision: kvp.Revision,
		},
		{
			Key: model.HostConfigKey{
				Hostname: name,
				Name:     "IPv4VXLANTunnelAddr",
			},
			Value:    vxlanTunl,
			Revision: kvp.Revision,
		},
	}, err
}

// Sync is restarting - nothing to do for this processor.
func (c *FelixNodeUpdateProcessor) OnSyncerStarting() {
	log.Debug("Sync starting called on Felix node update processor")
}

func (c *FelixNodeUpdateProcessor) extractName(k model.Key) (string, error) {
	rk, ok := k.(model.ResourceKey)
	if !ok || rk.Kind != apiv3.KindNode {
		return "", errors.New("Incorrect key type - expecting resource of kind Node")
	}
	return rk.Name, nil
}
