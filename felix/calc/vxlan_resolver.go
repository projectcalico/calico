// Copyright (c) 2019-2022 Tigera, Inc. All rights reserved.

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
	nodeNameToNode              map[string]*apiv3.Node
	nodeNameToVXLANTunnelAddr   map[string]string
	nodeNameToIPv4Addr          map[string]string
	nodeNameToVXLANMac          map[string]string
	nodeNameToVXLANTunnelAddrV6 map[string]string
	nodeNameToIPv6Addr          map[string]string
	nodeNameToVXLANMacV6        map[string]string
	nodeNameToSentVTEP          map[string]*proto.VXLANTunnelEndpointUpdate
	blockToRoutes               map[string]set.Set
	vxlanPools                  map[string]model.IPPool
	useNodeResourceUpdates      bool
}

func NewVXLANResolver(hostname string, callbacks vxlanCallbacks, useNodeResourceUpdates bool) *VXLANResolver {
	return &VXLANResolver{
		hostname:                    hostname,
		callbacks:                   callbacks,
		nodeNameToNode:              map[string]*apiv3.Node{},
		nodeNameToVXLANTunnelAddr:   map[string]string{},
		nodeNameToIPv4Addr:          map[string]string{},
		nodeNameToVXLANMac:          map[string]string{},
		nodeNameToVXLANTunnelAddrV6: map[string]string{},
		nodeNameToIPv6Addr:          map[string]string{},
		nodeNameToVXLANMacV6:        map[string]string{},
		nodeNameToSentVTEP:          map[string]*proto.VXLANTunnelEndpointUpdate{},
		blockToRoutes:               map[string]set.Set{},
		vxlanPools:                  map[string]model.IPPool{},
		useNodeResourceUpdates:      useNodeResourceUpdates,
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
	logCtx := logrus.WithField("node", nodeName).WithField("update", update)
	logCtx.Debug("OnResourceUpdate triggered")
	if update.Value != nil && update.Value.(*apiv3.Node).Spec.BGP != nil {
		node := update.Value.(*apiv3.Node)
		bgp := node.Spec.BGP
		c.nodeNameToNode[nodeName] = node
		ipv4, _, err := cnet.ParseCIDROrIP(bgp.IPv4Address)
		if err != nil {
			logCtx.WithError(err).Error("couldn't parse ipv4 address from node bgp info")
			return
		}
		ipv6, _, err := cnet.ParseCIDROrIP(bgp.IPv6Address)
		if err != nil {
			logCtx.WithError(err).Error("couldn't parse ipv6 address from node bgp info")
			return
		}

		c.onNodeIPUpdate(nodeName, ipv4.String(), ipv6.String())
	} else {
		delete(c.nodeNameToNode, nodeName)
		delete(c.nodeNameToIPv4Addr, nodeName)
		delete(c.nodeNameToIPv6Addr, nodeName)
		c.sendVTEPUpdateOrRemove(nodeName)
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
		c.onNodeIPUpdate(nodeName, update.Value.(*cnet.IP).String(), "")
	} else {
		delete(c.nodeNameToIPv4Addr, nodeName)
		c.sendVTEPUpdateOrRemove(nodeName)
	}
	return
}

func (c *VXLANResolver) onNodeIPUpdate(nodeName string, newIPv4 string, newIPv6 string) {
	logCtx := logrus.WithField("node", nodeName)
	// Host IP updated or added. If it was added, we should check to see if we're ready
	// to send a VTEP and associated routes. If we already knew about this one, we need to
	// see if it has changed. If it has, we should reprogram the VTEP.
	currIPv4 := c.nodeNameToIPv4Addr[nodeName]
	currIPv6 := c.nodeNameToIPv6Addr[nodeName]

	logCtx = logCtx.WithFields(logrus.Fields{
		"newIPv4":  newIPv4,
		"currIPv4": currIPv4,
		"newIPv6":  newIPv6,
		"currIPv6": currIPv6})
	logCtx.Debug("Node IP update")

	// net.IP.String() may return an actual string with value "<nil>"
	if newIPv4 == "" || newIPv4 == "<nil>" {
		delete(c.nodeNameToIPv4Addr, nodeName)
	} else {
		c.nodeNameToIPv4Addr[nodeName] = newIPv4
	}

	// net.IP.String() may return an actual string with value "<nil>"
	if newIPv6 == "" || newIPv6 == "<nil>" {
		delete(c.nodeNameToIPv6Addr, nodeName)
	} else {
		c.nodeNameToIPv6Addr[nodeName] = newIPv6
	}

	// Try sending a VTEP update.
	c.sendVTEPUpdateOrRemove(nodeName)
}

// OnHostConfigUpdate gets called whenever a node's host config changes. We only care about
// VXLAN tunnel IP/MAC address updates. On an add/update, we need to check if there are VTEPs which
// are now valid, and trigger programming of them to the data plane. On a delete, we need to withdraw any
// VTEPs associated with the node.
func (c *VXLANResolver) OnHostConfigUpdate(update api.Update) (_ bool) {
	switch update.Key.(model.HostConfigKey).Name {
	case "IPv4VXLANTunnelAddr":
		nodeName := update.Key.(model.HostConfigKey).Hostname
		logCtx := logrus.WithField("node", nodeName).WithField("value", update.Value)
		logCtx.Debug("IPv4VXLANTunnelAddr update")
		if update.Value != nil {
			// Update for a VXLAN tunnel address.
			newIPv4 := update.Value.(string)
			currIPv4 := c.nodeNameToVXLANTunnelAddr[nodeName]
			logCtx = logCtx.WithFields(logrus.Fields{"newIPv4": newIPv4, "currIPv4": currIPv4})
			logCtx.Debug("IPv4VXLANTunnelAddr update")
			// Try sending a VTEP update.
			c.nodeNameToVXLANTunnelAddr[nodeName] = newIPv4
		} else {
			// Withdraw the VTEP.
			logCtx.Info("Node IPv4 tunnel address deleted")
			delete(c.nodeNameToVXLANTunnelAddr, nodeName)
		}
		c.sendVTEPUpdateOrRemove(nodeName)
	case "VXLANTunnelMACAddr":
		nodeName := update.Key.(model.HostConfigKey).Hostname
		logCtx := logrus.WithField("node", nodeName).WithField("value", update.Value)
		logCtx.Debug("VXLANTunnelMACAddr update")
		if update.Value != nil {
			// Update for a VXLAN tunnel MAC address.
			newMAC := update.Value.(string)
			currMAC := c.vtepMACForHost(nodeName, 4)
			logCtx = logCtx.WithFields(logrus.Fields{"newMAC": newMAC, "currMAC": currMAC})
			logCtx.Debug("VXLANTunnelMACAddr update")
			c.nodeNameToVXLANMac[nodeName] = newMAC
		} else {
			logCtx.Info("Update the VTEP with the system generated MAC address and send it to dataplane")
			delete(c.nodeNameToVXLANMac, nodeName)
		}
		c.sendVTEPUpdateOrRemove(nodeName)
	case "IPv6VXLANTunnelAddr":
		nodeName := update.Key.(model.HostConfigKey).Hostname
		logCtx := logrus.WithField("node", nodeName).WithField("value", update.Value)
		logCtx.Debug("IPv6VXLANTunnelAddr update")
		if update.Value != nil {
			// Update for a VXLAN tunnel address.
			newIPv6 := update.Value.(string)
			currIPv6 := c.nodeNameToVXLANTunnelAddrV6[nodeName]
			logCtx = logCtx.WithFields(logrus.Fields{"newIPv6": newIPv6, "currIPv6": currIPv6})
			logCtx.Debug("IPv6VXLANTunnelAddr update")
			// Try sending a VTEP update.
			c.nodeNameToVXLANTunnelAddrV6[nodeName] = newIPv6
		} else {
			// Withdraw the VTEP.
			logCtx.Info("Node IPv6 tunnel address deleted")
			delete(c.nodeNameToVXLANTunnelAddrV6, nodeName)
		}
		c.sendVTEPUpdateOrRemove(nodeName)
	case "VXLANTunnelMACAddrV6":
		nodeName := update.Key.(model.HostConfigKey).Hostname
		logCtx := logrus.WithField("node", nodeName).WithField("value", update.Value)
		logCtx.Debug("VXLANTunnelMACAddrV6 update")
		if update.Value != nil {
			// Update for a VXLAN tunnel MAC address.
			newMACV6 := update.Value.(string)
			currMACV6 := c.vtepMACForHost(nodeName, 6)
			logCtx = logCtx.WithFields(logrus.Fields{"newMACV6": newMACV6, "currMAC": currMACV6})
			logCtx.Debug("VXLANTunnelMACAddrV6 update")
			c.nodeNameToVXLANMacV6[nodeName] = newMACV6
		} else {
			logCtx.Info("Update the VTEP with the system generated MAC address and send it to dataplane")
			delete(c.nodeNameToVXLANMacV6, nodeName)
		}
		c.sendVTEPUpdateOrRemove(nodeName)
	}
	return
}

// hasVTEPInfo returns whether there is IPv4 and/or IPv6 VTEP information fully available in vxlanResolver's
// internal state
func (c *VXLANResolver) hasVTEPInfo(node string) (bool, bool) {
	logCtx := logrus.WithField("node", node)
	hasV4Info, hasV6Info := true, true

	if _, ok := c.nodeNameToVXLANTunnelAddr[node]; !ok {
		logCtx.Info("Missing IPv4 VXLAN tunnel address for node")
		hasV4Info = false
	}
	if _, ok := c.nodeNameToIPv4Addr[node]; !ok {
		logCtx.Info("Missing IPv4 address for node")
		hasV4Info = false
	}

	if _, ok := c.nodeNameToVXLANTunnelAddrV6[node]; !ok {
		logCtx.Info("Missing IPv6 VXLAN tunnel address for node")
		hasV6Info = false
	}
	if _, ok := c.nodeNameToIPv6Addr[node]; !ok {
		logCtx.Info("Missing IPv6 address for node")
		hasV6Info = false
	}

	return hasV4Info, hasV6Info
}

// sendVTEPUpdateOrRemove either sends a VTEP update, a VTEP remove or does nothing based on internal vxlanResolver state.
// When full information for one or both of IPv4, IPv6 is available, it checks if a VTEP was previously sent, then checks
// if the VTEP information has changed. If it did change (or a VTEP was not previously sent), a VTEP update is sent
// (preceded by a VTEP remove if a previous update had already been sent). If neither IPv4 nor IPv6 information is available
// and a VTEP update was sent previously, a VTEP remove is sent. Otherwise, nothing is sent.
func (c *VXLANResolver) sendVTEPUpdateOrRemove(node string) {
	logCtx := logrus.WithField("node", node)

	hasV4Info, hasV6Info := c.hasVTEPInfo(node)
	oldVTEP, hasSentVTEP := c.nodeNameToSentVTEP[node]

	if !(hasV4Info || hasV6Info) {
		if hasSentVTEP {
			logCtx.Info("Missing both IPv4 and IPv6 VTEP information for node, withdrawing VTEP from dataplane")
			delete(c.nodeNameToSentVTEP, node)
			c.callbacks.OnVTEPRemove(node)
			return
		}
		logCtx.Info("Missing both IPv4 and IPv6 VTEP information for node, cannot send VTEP yet")
		return
	}

	vtep := &proto.VXLANTunnelEndpointUpdate{
		Node: node,
	}
	if hasV4Info {
		vtep.ParentDeviceIpv4 = c.nodeNameToIPv4Addr[node]
		vtep.MacV4 = c.vtepMACForHost(node, 4)
		vtep.Ipv4Addr = c.nodeNameToVXLANTunnelAddr[node]
	}
	if hasV6Info {
		vtep.ParentDeviceIpv6 = c.nodeNameToIPv6Addr[node]
		vtep.MacV6 = c.vtepMACForHost(node, 6)
		vtep.Ipv6Addr = c.nodeNameToVXLANTunnelAddrV6[node]
	}

	if hasSentVTEP {
		if c.vtepEqual(oldVTEP, vtep) {
			logCtx.Info("VTEP information has not changed, skipping duplicate update")
			return
		}
		// Skip removing node from c.nodeNameToSentVTEP because it will be updated below
		// Send a remove for the old VTEP information
		c.callbacks.OnVTEPRemove(node)
	}

	logCtx.Info("Sending VTEP update")
	c.nodeNameToSentVTEP[node] = vtep
	c.callbacks.OnVTEPUpdate(vtep)
}

// vtepEqual compares if 2 proto.VXLANTunnelEndpointUpdate messages contain the same information
func (c *VXLANResolver) vtepEqual(vtep1, vtep2 *proto.VXLANTunnelEndpointUpdate) bool {
	switch {
	case vtep1.Node != vtep2.Node:
		return false
	case vtep1.MacV4 != vtep2.MacV4:
		return false
	case vtep1.Ipv4Addr != vtep2.Ipv4Addr:
		return false
	case vtep1.ParentDeviceIpv4 != vtep2.ParentDeviceIpv4:
		return false
	case vtep1.MacV6 != vtep2.MacV6:
		return false
	case vtep1.Ipv6Addr != vtep2.Ipv6Addr:
		return false
	case vtep1.ParentDeviceIpv6 != vtep2.ParentDeviceIpv6:
		return false
	}

	return true
}

// vtepMACForHost checks if there is new MAC present in host config.
// If new MAC is present in host config, then vtepMACForHost returns the MAC present in  host config else
// vtepMACForHost calculates a deterministic MAC address based on the provided host.
// The returned address matches the address assigned to the VXLAN device on that node.
func (c *VXLANResolver) vtepMACForHost(nodename string, ipVersion int) string {
	logCtx := logrus.WithFields(logrus.Fields{"node": nodename, "ipVersion": ipVersion})
	var mac string

	switch ipVersion {
	case 4:
		mac = c.nodeNameToVXLANMac[nodename]
	case 6:
		mac = c.nodeNameToVXLANMacV6[nodename]
		nodename += "-v6"
	default:
		logCtx.Panic("Invalid IP version")
	}

	// Return stored MAC address if present
	if mac != "" {
		return mac
	}

	// Otherwise generate a MAC address
	hasher := sha1.New()
	_, err := hasher.Write([]byte(nodename))
	if err != nil {
		logCtx.Panic("Failed to write hash for node")
	}
	sha := hasher.Sum(nil)
	hw := gonet.HardwareAddr(append([]byte("f"), sha[0:5]...))
	return hw.String()
}
