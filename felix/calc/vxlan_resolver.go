// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.

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
	"crypto/sha1"
	gonet "net"

	"github.com/sirupsen/logrus"

	apiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/set"

	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/proto"
)

// VXLANResolver is responsible for resolving node IPs and node config to calculate the
// VTEP for each host.  It registers for:
//
//   - model.HostIPKey
//   - model.HostConfigKey
//
// VXLAN routes are calculated by the L3RouteResolver, and to be valid for the dataplane
// must target a VXLAN tunnel endpoint (VTEP) which comprises a node IP address, VXLAN
// tunnel address, and a deterministically calculated MAC address. The VXLAN resolver
// calculates the VTEPs.  The dataplane is responsible for only programming routes once
// the VTEP is ready.
//
// For each VTEP, this component will send a *proto.VXLANTunnelEndpointUpdate.
//
// If a VTEP is no longer fully specified (e.g., due to a vxlan tunnel address removal),
// a *proto.VXLANTunnelEndpointRemove message is sent.
//
// If a VTEP changes (e.g., due to a vxlan tunnel address changing), this component will treat
// it as a delete followed by an add.
type VXLANResolver struct {
	hostname  string
	callbacks vxlanCallbacks

	// Store node metadata indexed by node name, and routes by the
	// block that contributed them. The following comprises the full internal data model.
	nodeNameToVXLANTunnelAddr map[string]string
	nodeNameToIPAddr          map[string]string
	nodeNameToNode            map[string]*apiv3.Node
	nodeNameToVXLANMac        map[string]string
	blockToRoutes             map[string]set.Set
	vxlanPools                map[string]model.IPPool
	useNodeResourceUpdates    bool
}

func NewVXLANResolver(hostname string, callbacks vxlanCallbacks, useNodeResourceUpdates bool) *VXLANResolver {
	return &VXLANResolver{
		hostname:                  hostname,
		callbacks:                 callbacks,
		nodeNameToVXLANTunnelAddr: map[string]string{},
		nodeNameToIPAddr:          map[string]string{},
		nodeNameToNode:            map[string]*apiv3.Node{},
		nodeNameToVXLANMac:        map[string]string{},
		blockToRoutes:             map[string]set.Set{},
		vxlanPools:                map[string]model.IPPool{},
		useNodeResourceUpdates:    useNodeResourceUpdates,
	}
}

func (c *VXLANResolver) RegisterWith(allUpdDispatcher *dispatcher.Dispatcher) {
	if c.useNodeResourceUpdates {
		allUpdDispatcher.Register(model.ResourceKey{}, c.OnResourceUpdate)
	} else {
		allUpdDispatcher.Register(model.HostIPKey{}, c.OnHostIPUpdate)
	}

	allUpdDispatcher.Register(model.HostConfigKey{}, c.OnHostConfigUpdate)
}

func (c *VXLANResolver) OnResourceUpdate(update api.Update) (_ bool) {
	resourceKey := update.Key.(model.ResourceKey)
	if resourceKey.Kind != apiv3.KindNode {
		return
	}

	nodeName := update.Key.(model.ResourceKey).Name
	logCxt := logrus.WithField("node", nodeName).WithField("update", update)
	logCxt.Debug("OnResourceUpdate triggered")
	if update.Value != nil && update.Value.(*apiv3.Node).Spec.BGP != nil {
		node := update.Value.(*apiv3.Node)
		bgp := node.Spec.BGP
		c.nodeNameToNode[nodeName] = node
		ipv4, _, err := cnet.ParseCIDROrIP(bgp.IPv4Address)
		if err != nil {
			logCxt.WithError(err).Error("couldn't parse ipv4 address from node bgp info")
			return
		}

		c.onNodeIPUpdate(nodeName, ipv4.String())
	} else {
		delete(c.nodeNameToNode, nodeName)
		c.onRemoveNode(nodeName)
	}

	return
}

// OnHostIPUpdate gets called whenever a node IP address changes. On an add/update,
// we need to check if there is a VTEP which is now valid, and trigger programming
// of them to the data plane. On a delete, we need to withdraw the VTEP associated
// with the node.
func (c *VXLANResolver) OnHostIPUpdate(update api.Update) (_ bool) {
	nodeName := update.Key.(model.HostIPKey).Hostname
	logrus.WithField("node", nodeName).Debug("OnHostIPUpdate triggered")

	if update.Value != nil {
		c.onNodeIPUpdate(nodeName, update.Value.(*cnet.IP).String())
	} else {
		c.onRemoveNode(nodeName)
	}
	return
}

func (c *VXLANResolver) onNodeIPUpdate(nodeName string, newIP string) {
	logCxt := logrus.WithField("node", nodeName)
	// Host IP updated or added. If it was added, we should check to see if we're ready
	// to send a VTEP and associated routes. If we already knew about this one, we need to
	// see if it has changed. If it has, we should reprogram the VTEP.
	currIP := c.nodeNameToIPAddr[nodeName]
	logCxt = logCxt.WithFields(logrus.Fields{"newIP": newIP, "currIP": currIP})
	if c.vtepSent(nodeName) {
		if currIP == newIP {
			// If we've already handled this node, there's nothing to do. Deduplicate.
			logCxt.Debug("Skipping duplicate node IP update")
			return
		}

		// We've already sent a VTEP for this node, and the node's IP address has changed.
		logCxt.Info("Withdrawing VTEP, node changed IP address")
		c.sendVTEPRemove(nodeName)
	}

	// Try sending a VTEP update.
	c.nodeNameToIPAddr[nodeName] = newIP
	c.sendVTEPUpdate(nodeName)
}

func (c *VXLANResolver) onRemoveNode(nodeName string) {
	logCxt := logrus.WithField("node", nodeName)
	logCxt.Info("Withdrawing VTEP, node IP address deleted")
	delete(c.nodeNameToIPAddr, nodeName)
	c.sendVTEPRemove(nodeName)
}

// OnHostConfigUpdate gets called whenever a node's host config changes. We only care about
// VXLAN tunnel IP/MAC address updates. On an add/update, we need to check if there are VTEPs which
// are now valid, and trigger programming of them to the data plane. On a delete, we need to withdraw any
// VTEPs associated with the node.
func (c *VXLANResolver) OnHostConfigUpdate(update api.Update) (_ bool) {
	switch update.Key.(model.HostConfigKey).Name {
	case "IPv4VXLANTunnelAddr":
		nodeName := update.Key.(model.HostConfigKey).Hostname
		vtepSent := c.vtepSent(nodeName)
		logCxt := logrus.WithField("node", nodeName).WithField("value", update.Value)
		logCxt.Debug("IPv4VXLANTunnelAddr update")
		if update.Value != nil {
			// Update for a VXLAN tunnel address.
			newIP := update.Value.(string)
			currIP := c.nodeNameToVXLANTunnelAddr[nodeName]
			logCxt = logCxt.WithFields(logrus.Fields{"newIP": newIP, "currIP": currIP})
			if vtepSent {
				if currIP == newIP {
					// If we've already handled this node, there's nothing to do. Deduplicate.
					logCxt.Debug("Skipping duplicate tunnel addr update")
					return
				}
				c.sendVTEPRemove(nodeName)
			}

			// Try sending a VTEP update.
			c.nodeNameToVXLANTunnelAddr[nodeName] = newIP
			c.sendVTEPUpdate(nodeName)
		} else {
			// Withdraw the VTEP.
			logCxt.Info("Withdrawing VTEP, node tunnel address deleted")
			delete(c.nodeNameToVXLANTunnelAddr, nodeName)
			c.sendVTEPRemove(nodeName)
		}
	case "VXLANTunnelMACAddr":
		nodeName := update.Key.(model.HostConfigKey).Hostname
		vtepSent := c.vtepSent(nodeName)
		logCxt := logrus.WithField("node", nodeName).WithField("value", update.Value)
		logCxt.Debug("VXLANTunnelMACAddr update")
		if update.Value != nil {
			// Update for a VXLAN tunnel MAC address.
			newMAC := update.Value.(string)
			currMAC := c.vtepMACForHost(nodeName)
			logCxt = logCxt.WithFields(logrus.Fields{"newMAC": newMAC, "currMAC": currMAC})
			c.nodeNameToVXLANMac[nodeName] = newMAC
			if vtepSent {
				if currMAC == newMAC {
					// If we've already handled this node, there's nothing to do. Deduplicate.
					logCxt.Debug("Skipping duplicate tunnel MAC addr update")
					return
				}

				// Try sending a VTEP update.
				c.sendVTEPUpdate(nodeName)
			}

		} else {
			logCxt.Info("Update the VTEP with the system generated MAC address and send it to dataplane")
			delete(c.nodeNameToVXLANMac, nodeName)
			c.sendVTEPUpdate(nodeName)
		}
	}
	return
}

// vtepSent returns whether or not we should have sent the VTEP for the given node
// based on our current internal state.
func (c *VXLANResolver) vtepSent(node string) bool {
	if _, ok := c.nodeNameToVXLANTunnelAddr[node]; !ok {
		return false
	}
	if _, ok := c.nodeNameToIPAddr[node]; !ok {
		return false
	}
	return true
}

func (c *VXLANResolver) sendVTEPUpdate(node string) bool {
	logCxt := logrus.WithField("node", node)
	tunlAddr, ok := c.nodeNameToVXLANTunnelAddr[node]
	if !ok {
		logCxt.Info("Missing vxlan tunnel address for node, cannot send VTEP yet")
		return false
	}
	parentDeviceIP, ok := c.nodeNameToIPAddr[node]
	if !ok {
		logCxt.Info("Missing IP for node, cannot send VTEP yet")
		return false
	}

	logCxt.Debug("Sending VTEP to dataplane")
	vtep := &proto.VXLANTunnelEndpointUpdate{
		Node:             node,
		ParentDeviceIpv4: parentDeviceIP,
		Mac:              c.vtepMACForHost(node),
		Ipv4Addr:         tunlAddr,
	}
	c.callbacks.OnVTEPUpdate(vtep)
	return true
}

func (c *VXLANResolver) sendVTEPRemove(node string) {
	logrus.WithField("node", node).Debug("Withdrawing VTEP from dataplane")
	c.callbacks.OnVTEPRemove(node)
}

// vtepMACForHost checks if there is new MAC present in host config.
// If new MAC is present in host config, then vtepMACForHost returns the MAC present in  host config else
// vtepMACForHost calculates a deterministic MAC address based on the provided host.
// The returned address matches the address assigned to the VXLAN device on that node.
func (c *VXLANResolver) vtepMACForHost(nodename string) string {
	mac := c.nodeNameToVXLANMac[nodename]

	if mac != "" {
		return mac
	}

	hasher := sha1.New()
	_, err := hasher.Write([]byte(nodename))
	if err != nil {
		logrus.WithError(err).WithField("node", nodename).Panic("Failed to write hash for node")
	}
	sha := hasher.Sum(nil)
	hw := gonet.HardwareAddr(append([]byte("f"), sha[0:5]...))
	return hw.String()
}
