// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	"errors"
	"fmt"
	gonet "net"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/dispatcher"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/proto"
	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/set"
)

// VXLANResolver is responsible for resolving node IPs, node config, IPAM blocks,
// and IP pools to determine the correct set of programming to send to the dataplane.
// Specifically, it registers to get updates on the following:
//
//   - model.HostIPKey
//   - model.HostConfigKey
//   - model.BlockKey
//   - model.IPPoolKey
//
// VXLAN routes are contributed by blocks within IP pools that have VXLAN enabled, and
// must target a VXLAN tunnel endpoint (VTEP) which comprises a node IP address, VXLAN
// tunnel address, and a deterministically calculated MAC address. The VXLAN resolver
// ensures that routes are only sent to the data plane when a fully specified VTEP
// exists.
//
// For each VTEP, this component will send a *proto.VXLANTunnelEndpointUpdate followed by
// a *proto.RouteUpdate for each route which targets that VTEP. As routes are added and
// removed, subsequent *proto.RouteUpdate and *proto.RouteRemove messages will be sent.
//
// If a VTEP is no longer fully specified (e.g., due to a vxlan tunnel address removal),
// a *proto.RouteRemove message will be sent for each route targeting that VTEP, followed
// by a *proto.VXLANTunnelEndpointRemove message for the VTEP itself.
//
// If a VTEP changes (e.g., due to a vxlan tunnel address changing), this component will treat
// it as a delete followed by an add.
type VXLANResolver struct {
	hostname  string
	callbacks PipelineCallbacks

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

func NewVXLANResolver(hostname string, callbacks PipelineCallbacks, useNodeResourceUpdates bool) *VXLANResolver {
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
	allUpdDispatcher.Register(model.BlockKey{}, c.OnBlockUpdate)
	allUpdDispatcher.Register(model.IPPoolKey{}, c.OnPoolUpdate)
}

func (c *VXLANResolver) OnBlockUpdate(update api.Update) (_ bool) {
	// Update the routes map based on the provided block update.
	key := update.Key.String()

	deletes := set.New()
	adds := set.New()
	if update.Value != nil {
		// Block has been created or updated.
		// We don't allow multiple blocks with the same CIDR, so no need to check
		// for duplicates here. Look at the routes contributed by this block and determine if we
		// need to send any updates.
		newRoutes := c.routesFromBlock(key, update.Value.(*model.AllocationBlock))
		cachedRoutes, ok := c.blockToRoutes[key]
		if !ok {
			cachedRoutes = set.New()
			c.blockToRoutes[key] = cachedRoutes
		}

		// Now scan the old routes, looking for any that are no-longer associated with the block.
		// Remove no longer active routes from the cache and queue up deletions.
		cachedRoutes.Iter(func(item interface{}) error {
			r := item.(vxlanRoute)

			// For each existing route which is no longer present, we need to delete it.
			// Note: since r.Key() only contains the destination, we need to check equality too in case
			// the gateway has changed.
			if newRoute, ok := newRoutes[r.Key()]; ok && newRoute == r {
				// Exists, and we want it to - nothing to do.
				return nil
			}

			// Current route is not in new set - we need to withdraw the route, and also
			// remove it from internal state.
			deletes.Add(r)
			return set.RemoveItem
		})

		// Now scan the new routes, looking for additions.  Cache them and queue up adds.
		for _, r := range newRoutes {
			logCxt := logrus.WithField("newRoute", r)
			if cachedRoutes.Contains(r) {
				logCxt.Debug("Desired VXLAN route already exists, skip")
				continue
			}

			cachedRoutes.Add(r)
			adds.Add(r)
		}

		// At this point we've determined the correct diff to perform based on the block update.
		// Delete any routes which are gone for good, withdraw modified routes, and send updates for
		// new ones.
		deletes.Iter(func(item interface{}) error {
			c.withdrawRoute(item.(vxlanRoute))
			return nil
		})
		c.kickPendingRoutes(adds)
	} else {
		// Block has been deleted. Clean up routes that were contributed by this block.
		routes := c.blockToRoutes[key]
		if routes != nil {
			routes.Iter(func(item interface{}) error {
				c.withdrawRoute(item.(vxlanRoute))
				return nil
			})
		}
		delete(c.blockToRoutes, key)
	}
	return
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
// we need to check if there are VTEPs or routes which are now valid, and trigger programming
// of them to the data plane. On a delete, we need to withdraw any routes and VTEPs associated
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
	// see if it has changed. If it has, we should remove and reprogram the VTEP and routes.
	currIP := c.nodeNameToIPAddr[nodeName]
	pendingSet, sentSet := c.routeSets()
	logCxt = logCxt.WithFields(logrus.Fields{"newIP": newIP, "currIP": currIP})
	if c.vtepSent(nodeName) {
		if currIP == newIP {
			// If we've already handled this node, there's nothing to do. Deduplicate.
			logCxt.Debug("Skipping duplicate node IP update")
			return
		}

		// We've already sent a VTEP for this node, and the node's IP address has changed.
		// We need to revoke it and any routes before sending any updates.
		logCxt.Info("Withdrawing routes and VTEP, node changed IP address")
		sentSet.Iter(func(item interface{}) error {
			r := item.(vxlanRoute)
			if r.node == nodeName {
				c.withdrawRoute(r)
				pendingSet.Add(r)
			}
			return nil
		})
		c.sendVTEPRemove(nodeName)
	}

	// Try sending a VTEP update. If we do, this will trigger a kick of any
	// pending routes which might now be ready to send.
	c.nodeNameToIPAddr[nodeName] = newIP
	if c.sendVTEPUpdate(nodeName) {
		// We've successfully sent a new VTEP - check to see if any pending routes
		// are now ready to be programmed.
		logCxt.Info("Sent VTEP to dataplane, check pending routes")
		c.kickPendingRoutes(pendingSet)
	}
}

func (c *VXLANResolver) onRemoveNode(nodeName string) {
	_, sentSet := c.routeSets()

	// Withdraw any routes which target this VTEP, followed by the VTEP itself.
	logCxt := logrus.WithField("node", nodeName)
	logCxt.Info("Withdrawing routes and VTEP, node IP address deleted")
	delete(c.nodeNameToIPAddr, nodeName)
	sentSet.Iter(func(item interface{}) error {
		r := item.(vxlanRoute)
		if r.node == nodeName {
			c.withdrawRoute(r)
		}
		return nil
	})
	c.sendVTEPRemove(nodeName)
}

// OnHostConfigUpdate gets called whenever a node's host config changes. We only care about
// VXLAN tunnel address updates. On an add/update, we need to check if there are VTEPs or routes which
// are now valid, and trigger programming of them to the data plane. On a delete, we need to withdraw any
// routes and VTEPs associated with the node.
func (c *VXLANResolver) OnHostConfigUpdate(update api.Update) (_ bool) {
	pendingSet, sentSet := c.routeSets()
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

				// We've already sent a VTEP for this node, and the node's IP address has changed.
				// We need to revoke it and any routes before sending any updates.
				logCxt.Info("Withdrawing routes and VTEP, node changed tunnel address")
				sentSet.Iter(func(item interface{}) error {
					r := item.(vxlanRoute)
					if r.node == nodeName {
						c.withdrawRoute(r)
						pendingSet.Add(r)
					}
					return nil
				})
				c.sendVTEPRemove(nodeName)
			}

			// Try sending a VTEP update. If we do, this will trigger a kick of any
			// pending routes which might now be ready to send.
			c.nodeNameToVXLANTunnelAddr[nodeName] = newIP
			if c.sendVTEPUpdate(nodeName) {
				// We've successfully sent a new VTEP - check to see if any pending routes
				// are now ready to be programmed.
				logCxt.Info("Sent VTEP to dataplane, check pending routes")
				c.kickPendingRoutes(pendingSet)
			}
		} else {
			// Withdraw any routes which target this VTEP, followed by the VTEP itself.
			logCxt.Info("Withdrawing routes and VTEP, node tunnel address deleted")
			delete(c.nodeNameToVXLANTunnelAddr, nodeName)
			sentSet.Iter(func(item interface{}) error {
				r := item.(vxlanRoute)
				if r.node == nodeName {
					c.withdrawRoute(r)
				}
				return nil
			})
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
				if c.sendVTEPUpdate(nodeName) {
					// We've successfully sent a new VTEP
					logCxt.Info("Sent VTEP to dataplane")
				}
			}

		} else {
			logCxt.Info("Update the VTEP with the system generated MAC address and send it to dataplane")
			delete(c.nodeNameToVXLANMac, nodeName)

			if c.sendVTEPUpdate(nodeName) {
				// We've successfully sent a new VTEP
				logCxt.Info("Sent VTEP to dataplane")
			}
		}
	}
	return
}

// OnPoolUpdate gets called whenever an IP pool changes. If a new VXLAN pool is added, kick
// pending routes to see if any should now be programmed. If a VXLAN pool is removed, then
// find any routes which need to be withdrawn and remove them.
func (c *VXLANResolver) OnPoolUpdate(update api.Update) (_ bool) {
	k := update.Key.(model.IPPoolKey)
	pendingSet, sentSet := c.routeSets()
	if update.Value != nil && update.Value.(*model.IPPool).VXLANMode != encap.Undefined {
		// This is an add/update of a pool with VXLAN enabled.
		logrus.WithField("pool", k.CIDR).Info("Update of VXLAN-enabled IP pool.")
		if curr, ok := c.vxlanPools[k.String()]; ok {
			// We already know about the IP pool. Check to see if any fields have changed.
			vxlanModeChanged := curr.VXLANMode != update.Value.(*model.IPPool).VXLANMode
			// Check to see if the CIDR has changed.
			// While this isn't possible directly in the user-facing API, it's possible that
			// we see a delete/recreate as an update over the Syncer in rare cases.
			cidrChanged := curr.CIDR.String() != update.Value.(*model.IPPool).CIDR.String()

			if !cidrChanged && !vxlanModeChanged {
				// No change - we can ignore this update.
				return
			}
			fields := logrus.Fields{"cidrChanged": cidrChanged, "modeChanged": vxlanModeChanged, "pool": k.CIDR}
			logrus.WithFields(fields).Info("IP pool has changed")

			// The pool has changed, treat this as a delete followed by a re-create
			// with the new CIDR. Iterate through sent routes and withdraw any within
			// the old pool's CIDR. We'll kick the pending set below to trigger any updates.
			delete(c.vxlanPools, k.String())
			sentSet.Iter(func(item interface{}) error {
				r := item.(vxlanRoute)
				if c.containsRoute(curr, r) {
					c.withdrawRoute(r)
					pendingSet.Add(r)
				}
				return nil
			})
		}

		// This is a new VXLAN pool - update the cache and trigger a kick of pending routes.
		logrus.WithField("pool", k.CIDR).Info("New/Updated VXLAN IP pool")
		c.vxlanPools[k.String()] = *update.Value.(*model.IPPool)
		c.kickPendingRoutes(pendingSet)
	} else if curr, ok := c.vxlanPools[k.String()]; ok {
		// A VXLAN pool has either been deleted, or no longer has VXLAN enabled.
		// Withdraw any routes within the IP pool and remove internal state.
		logrus.WithField("pool", k.CIDR).Info("Removed VXLAN IP pool")
		sentSet.Iter(func(item interface{}) error {
			r := item.(vxlanRoute)
			if c.containsRoute(curr, r) {
				c.withdrawRoute(r)
			}
			return nil
		})
		delete(c.vxlanPools, k.String())
	} else {
		logrus.WithField("pool", k.CIDR).Debug("Ignoring non-VXLAN IP pool")
	}
	return
}

func (c *VXLANResolver) containsRoute(pool model.IPPool, r vxlanRoute) bool {
	return pool.CIDR.Contains(r.dst.ToIPNet().IP)
}

// routeSets returns the subset of routes we know about which haven't been
// sent to the dataplane, as well as the subset that has. It does this by
// calculating whether or not each route should have been sent, given the current state.
func (c *VXLANResolver) routeSets() (pending, sent set.Set) {
	pending = set.New()
	sent = set.New()
	for _, routes := range c.blockToRoutes {
		routes.Iter(func(item interface{}) error {
			if !c.routeReady(item.(vxlanRoute)) {
				pending.Add(item.(vxlanRoute))
			} else {
				sent.Add(item.(vxlanRoute))
			}
			return nil
		})
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

// routeReady returns true if the route is ready to be sent to the data plane, and
// false otherwise.
func (c *VXLANResolver) routeReady(r vxlanRoute) bool {
	logCxt := logrus.WithField("route", r)
	if !c.routeWithinVXLANPool(r) {
		logCxt.Debug("Route not within VXLAN IP pool")
		return false
	}

	routeType, err := c.routeTypeForRoute(r)
	if err != nil {
		logCxt.WithError(err).Debug("an error occurred getting the route type, will try again later")
		return false
	}

	gw := c.determineGatewayForRoute(r, routeType)
	if gw == "" {
		logCxt.Debug("No gateway yet for VXLAN route, skip")
		return false
	}

	if !c.vtepSent(r.node) {
		logCxt.Debug("Don't yet know the VTEP for this route")
		return false
	}

	return true
}

func (c *VXLANResolver) nodeCidr(nodeName string) (*cnet.IPNet, error) {
	logCxt := logrus.WithField("node", nodeName)

	if _, ok := c.nodeNameToNode[nodeName]; !ok {
		return nil, fmt.Errorf("no node info seen yet for node %s", nodeName)
	}

	node := c.nodeNameToNode[nodeName]

	//NOTE we don't need to check if this is null because nodes that don't have bgp information aren't added to the map
	bgp := node.Spec.BGP

	_, cidr, err := cnet.ParseCIDROrIP(bgp.IPv4Address)
	if err != nil {
		logCxt.WithError(err).Error("couldn't parse cidr information from bgp ipv4 address")
		return nil, err
	}

	return cidr, nil
}

// kickPendingRoutes loops through the provided routes to see if there are any which are now programmable,
// and will send any that are.
func (c *VXLANResolver) kickPendingRoutes(pendingRouteUpdates set.Set) {
	pendingRouteUpdates.Iter(func(item interface{}) error {
		r := item.(vxlanRoute)
		logCxt := logrus.WithField("route", r)
		if !c.routeReady(r) {
			return nil
		}
		logCxt.Info("Sending VXLAN route update")

		routeType, err := c.routeTypeForRoute(r)
		if err != nil {
			logCxt.WithError(err).Errorf("an error occurred determining the RouteType for the route")
			return nil
		}

		routeUpdate := &proto.RouteUpdate{
			Type: routeType,
			Node: r.node,
			Dst:  r.dst.String(),
			Gw:   c.determineGatewayForRoute(r, routeType),
		}

		c.callbacks.OnRouteUpdate(routeUpdate)
		return nil
	})
}

func (c *VXLANResolver) routeTypeForRoute(r vxlanRoute) (proto.RouteType, error) {
	logCxt := logrus.WithField("route", r)
	pool := c.vxlanPoolForRoute(r)

	if pool == nil {
		return proto.RouteType_VXLAN, errors.New("no matching ippool for route")
	}

	if pool.VXLANMode == encap.CrossSubnet {
		logCxt.WithField("pool", pool).Debug("pool has VXLAN CrossSubnet mode enabled")
		// if we're not using resource updates we'll never get the CIDR block need to check if the route's node's subnet
		// overlaps with this node's subnet
		if !c.useNodeResourceUpdates {
			logCxt.WithField("pool", pool).Warning(
				"CrossSubnet mode detected on pool but resource updates aren't being used. Defaulting to RouteType_VXLAN")
			return proto.RouteType_VXLAN, nil
		}

		localNodeCidr, err := c.nodeCidr(c.hostname)
		if err != nil {
			return proto.RouteType_VXLAN, err
		}

		nodeCidr, err := c.nodeCidr(r.node)
		if err != nil {
			return proto.RouteType_VXLAN, err
		}

		if nodeCidr.IsNetOverlap(localNodeCidr.IPNet) {
			gw := c.nodeNameToIPAddr[r.node]
			logCxt.Debugf("CrossSubnet enabled and subnets overlap, using node gateway %s for route", gw)

			return proto.RouteType_NOENCAP, nil
		}
	}

	return proto.RouteType_VXLAN, nil
}

// withdrawRoute will send a *proto.RouteRemove for the given route.
func (c *VXLANResolver) withdrawRoute(r vxlanRoute) {
	logrus.WithField("route", r).Info("Sending VXLAN route remove")
	c.callbacks.OnRouteRemove(r.dst.String())
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
		Node:           node,
		ParentDeviceIp: parentDeviceIP,
		Mac:            c.vtepMACForHost(node),
		Ipv4Addr:       tunlAddr,
	}
	c.callbacks.OnVTEPUpdate(vtep)
	return true
}

func (c *VXLANResolver) sendVTEPRemove(node string) {
	logrus.WithField("node", node).Debug("Withdrawing VTEP from dataplane")
	c.callbacks.OnVTEPRemove(node)
}

// routeWithinVXLANPool checks if the provided route is within a configured IP pool with
// VXLAN enabled.
func (c *VXLANResolver) routeWithinVXLANPool(r vxlanRoute) bool {
	for _, pool := range c.vxlanPools {
		if c.containsRoute(pool, r) {
			return true
		}
	}
	return false
}

func (c *VXLANResolver) vxlanPoolForRoute(r vxlanRoute) *model.IPPool {
	for _, pool := range c.vxlanPools {
		if c.containsRoute(pool, r) {
			return &pool
		}
	}
	return nil
}

// routesFromBlock returns a list of routes which should exist based on the provided
// allocation block.
func (c *VXLANResolver) routesFromBlock(blockKey string, b *model.AllocationBlock) map[string]vxlanRoute {
	routes := make(map[string]vxlanRoute)

	for _, alloc := range b.NonAffineAllocations() {
		if alloc.Host == "" {
			logrus.WithField("IP", alloc.Addr).Warn(
				"Unable to create VXLAN route for IP; the node it belongs to was not recorded")
			continue
		}
		r := vxlanRoute{
			dst:  ip.CIDRFromNetIP(alloc.Addr.IP),
			node: alloc.Host,
		}
		routes[r.Key()] = r
	}

	host := b.Host()
	if host == c.hostname {
		logrus.Debug("Skipping VXLAN routes for local node")
	} else if host != "" {
		logrus.WithField("host", host).Debug("Block has a host, including host route")
		r := vxlanRoute{
			dst:  ip.CIDRFromCalicoNet(b.CIDR),
			node: host,
		}
		routes[r.Key()] = r
	}

	return routes
}

// determineGatewayForRoute determines which gateway to use for this route. For VXLAN routes, the
// gateway is the remote node's IPv4VXLANTunnelAddr. If we don't know the remote node's tunnel
// address, this function will return an empty string.
func (c *VXLANResolver) determineGatewayForRoute(r vxlanRoute, routeType proto.RouteType) string {
	if routeType == proto.RouteType_NOENCAP {
		return c.nodeNameToIPAddr[r.node]
	} else {
		return c.nodeNameToVXLANTunnelAddr[r.node]
	}
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

// vxlanRoute is the VXLANResolver's internal representation of a route.
type vxlanRoute struct {
	node string
	dst  ip.CIDR
}

func (r vxlanRoute) Key() string {
	return r.dst.String()
}

func (r vxlanRoute) String() string {
	return fmt.Sprintf("vxlanRoute(dst: %s, node: %s)", r.dst.String(), r.node)
}
