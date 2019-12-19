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
	"fmt"

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

// L3RouteResolver is responsible for indexing IPAM blocks, IP pools and node information (either from the Node
// resource, if available, or from HostIP) and emitting basic routes containing the node's IP as next hop.
// Such routes are useful directly for BPF load balancing.  However, they are incomplete for VXLAN.
type L3RouteResolver struct {
	hostname  string
	callbacks routeCallbacks

	// Store node metadata indexed by node name, and routes by the
	// block that contributed them. The following comprises the full internal data model.
	nodeNameToIPAddr       map[string]string
	nodeNameToNode         map[string]*apiv3.Node
	blockToRoutes          map[string]set.Set
	allPools               map[string]model.IPPool
	useNodeResourceUpdates bool
}

func NewL3RouteResolver(hostname string, callbacks PipelineCallbacks, useNodeResourceUpdates bool) *L3RouteResolver {
	logrus.Info("Creating L3 route resolver")
	return &L3RouteResolver{
		hostname:               hostname,
		callbacks:              callbacks,
		nodeNameToIPAddr:       map[string]string{},
		nodeNameToNode:         map[string]*apiv3.Node{},
		blockToRoutes:          map[string]set.Set{},
		allPools:               map[string]model.IPPool{},
		useNodeResourceUpdates: useNodeResourceUpdates,
	}
}

func (c *L3RouteResolver) RegisterWith(allUpdDispatcher *dispatcher.Dispatcher) {
	if c.useNodeResourceUpdates {
		logrus.Info("Registering L3 route resolver (node resources on)")
		allUpdDispatcher.Register(model.ResourceKey{}, c.OnResourceUpdate)
	} else {
		logrus.Info("Registering L3 route resolver (node resources off)")
		allUpdDispatcher.Register(model.HostIPKey{}, c.OnHostIPUpdate)
	}

	allUpdDispatcher.Register(model.BlockKey{}, c.OnBlockUpdate)
	allUpdDispatcher.Register(model.IPPoolKey{}, c.OnPoolUpdate)
}

func (c *L3RouteResolver) OnBlockUpdate(update api.Update) (_ bool) {
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
		logrus.WithField("numRoutes", len(newRoutes)).Debug("IPAM block update")
		cachedRoutes, ok := c.blockToRoutes[key]
		if !ok {
			cachedRoutes = set.New()
			c.blockToRoutes[key] = cachedRoutes
		}

		// Now scan the old routes, looking for any that are no-longer associated with the block.
		// Remove no longer active routes from the cache and queue up deletions.
		cachedRoutes.Iter(func(item interface{}) error {
			r := item.(nodenameRoute)

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
			logrus.WithField("route", r).Debug("Found stale route")
			return set.RemoveItem
		})

		// Now scan the new routes, looking for additions.  Cache them and queue up adds.
		for _, r := range newRoutes {
			logCxt := logrus.WithField("newRoute", r)
			if cachedRoutes.Contains(r) {
				logCxt.Debug("Desired VXLAN route already exists, skip")
				continue
			}

			logrus.WithField("route", r).Debug("Found new route")
			cachedRoutes.Add(r)
			adds.Add(r)
		}

		// At this point we've determined the correct diff to perform based on the block update.
		// Delete any routes which are gone for good, withdraw modified routes, and send updates for
		// new ones.
		deletes.Iter(func(item interface{}) error {
			c.withdrawRouteIfActive(item.(nodenameRoute))
			return nil
		})
		adds.Iter(func(item interface{}) error {
			c.sendRouteIfActive(item.(nodenameRoute))
			return nil
		})
	} else {
		// Block has been deleted. Clean up routes that were contributed by this block.
		logrus.WithField("update", update).Debug("IPAM block deleted")
		routes := c.blockToRoutes[key]
		if routes != nil {
			routes.Iter(func(item interface{}) error {
				c.withdrawRouteIfActive(item.(nodenameRoute))
				return nil
			})
		}
		delete(c.blockToRoutes, key)
	}
	return
}

func (c *L3RouteResolver) OnResourceUpdate(update api.Update) (_ bool) {
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
// we need to check if there are routes which are now valid, and trigger programming
// of them to the data plane. On a delete, we need to withdraw any routes and VTEPs associated
// with the node.
func (c *L3RouteResolver) OnHostIPUpdate(update api.Update) (_ bool) {
	nodeName := update.Key.(model.HostIPKey).Hostname
	logrus.WithField("node", nodeName).Debug("OnHostIPUpdate triggered")

	if update.Value != nil {
		c.onNodeIPUpdate(nodeName, update.Value.(*cnet.IP).String())
	} else {
		c.onRemoveNode(nodeName)
	}
	return
}

func (c *L3RouteResolver) onNodeIPUpdate(nodeName string, newIP string) {
	logCxt := logrus.WithFields(logrus.Fields{"node": nodeName, "newIP": newIP})

	oldIP := c.nodeNameToIPAddr[nodeName]
	if oldIP == newIP {
		logCxt.Debug("IP update but IP is unchanged, ignoring")
		return
	}

	if oldIP != "" {
		logCxt.Info("Node's IP has changed, withdrawing all the old routes")
		c.withdrawAllNodeRoutes(nodeName)
	}

	if newIP == "" {
		delete(c.nodeNameToIPAddr, nodeName)
		return
	}

	c.nodeNameToIPAddr[nodeName] = newIP
	c.sendAllNodeRoutes(nodeName)
}

func (c *L3RouteResolver) onRemoveNode(nodeName string) {
	c.onNodeIPUpdate(nodeName, "")
}

func (c *L3RouteResolver) withdrawAllNodeRoutes(nodeName string) {
	c.visitAllRoutes(func(route nodenameRoute) {
		if route.nodeName != nodeName {
			return
		}
		c.withdrawRouteIfActive(route)
	})
}

func (c *L3RouteResolver) sendAllNodeRoutes(nodeName string) {
	c.visitAllRoutes(func(route nodenameRoute) {
		if route.nodeName != nodeName {
			return
		}
		c.sendRouteIfActive(route)
	})
}

func (c *L3RouteResolver) withdrawAllPoolRoutes(pool model.IPPool) {
	c.visitAllRoutes(func(route nodenameRoute) {
		if !c.containsRoute(pool, route) {
			return
		}
		c.withdrawRouteIfActive(route)
	})
}

func (c *L3RouteResolver) sendAllPoolRoutes(pool model.IPPool) {
	c.visitAllRoutes(func(route nodenameRoute) {
		if !c.containsRoute(pool, route) {
			return
		}
		c.sendRouteIfActive(route)
	})
}

func (c *L3RouteResolver) visitAllRoutes(v func(route nodenameRoute)) {
	for _, routes := range c.blockToRoutes {
		routes.Iter(func(item interface{}) error {
			v(item.(nodenameRoute))
			return nil
		})
	}
}

// OnPoolUpdate gets called whenever an IP pool changes.
func (c *L3RouteResolver) OnPoolUpdate(update api.Update) (_ bool) {
	k := update.Key.(model.IPPoolKey)
	poolKey := k.String()
	oldPool, oldPoolExists := c.allPools[poolKey]
	oldPoolType := PoolTypeUnknown
	if oldPoolExists {
		// Need explicit oldPoolExists check so that we don't pass a zero-struct to poolTypeForPool.
		oldPoolType = c.poolTypeForPool(&oldPool)
	}
	var newPool *model.IPPool
	if update.Value != nil {
		newPool = update.Value.(*model.IPPool)
	}
	newPoolType := c.poolTypeForPool(newPool)

	if oldPoolType == newPoolType {
		logrus.WithField("poolType", newPoolType).Debug(
			"Ignoring change to IPPool that didn't change pool type.")
		return
	}

	logCxt := logrus.WithFields(logrus.Fields{"oldType": oldPoolType, "newType": newPoolType})
	if oldPoolType != PoolTypeUnknown {
		logCxt.Info("IP pool type changed; withdrawing all the old routes in the pool.")
		c.withdrawAllPoolRoutes(oldPool)
	}

	if newPool != nil && newPoolType != PoolTypeUnknown {
		logCxt.Info("Pool is active, sending all its routes")
		c.allPools[poolKey] = *newPool
		c.sendAllPoolRoutes(*newPool)
	} else {
		delete(c.allPools, poolKey)
	}

	return
}

func (c *L3RouteResolver) containsRoute(pool model.IPPool, r nodenameRoute) bool {
	return pool.CIDR.Contains(r.dst.ToIPNet().IP)
}

// routeReady returns true if the route is ready to be sent to the data plane, and
// false otherwise.
func (c *L3RouteResolver) routeReady(r nodenameRoute) bool {
	logCxt := logrus.WithField("route", r)

	poolType := c.poolTypeForRoute(r)
	if poolType == PoolTypeUnknown {
		logCxt.Debug("Route not ready: Route's pool is not known")
		return false
	}

	gw := c.nodeNameToIPAddr[r.nodeName]
	if gw == "" {
		logCxt.Debug("Route not ready: No gateway yet for route, skip")
		return false
	}

	return true
}

func (c *L3RouteResolver) poolForRoute(r nodenameRoute) *model.IPPool {
	for _, pool := range c.allPools {
		if c.containsRoute(pool, r) {
			return &pool
		}
	}
	return nil
}

type PoolType int

const (
	PoolTypeUnknown PoolType = iota
	PoolTypeNoEncap
	PoolTypeVXLAN
	PoolTypeVXLANCrossSubnet
	PoolTypeIPIP
	PoolTypeIPIPCrossSubnet
)

func (t PoolType) String() string {
	switch t {
	case PoolTypeUnknown:
		return "PoolTypeUnknown"
	case PoolTypeNoEncap:
		return "PoolTypeNoEncap"
	case PoolTypeVXLAN:
		return "PoolTypeVXLAN"
	case PoolTypeVXLANCrossSubnet:
		return "PoolTypeVXLANCrossSubnet"
	case PoolTypeIPIP:
		return "PoolTypeIPIP"
	case PoolTypeIPIPCrossSubnet:
		return "PoolTypeIPIPCrossSubnet"
	default:
		return fmt.Sprintf("PoolType(%d)", int(t))
	}
}

func (c *L3RouteResolver) poolTypeForRoute(r nodenameRoute) PoolType {
	pool := c.poolForRoute(r)
	return c.poolTypeForPool(pool)
}

func (c *L3RouteResolver) poolTypeForPool(pool *model.IPPool) PoolType {
	if pool == nil {
		return PoolTypeUnknown
	}
	if pool.VXLANMode == encap.CrossSubnet {
		return PoolTypeVXLANCrossSubnet
	}
	if pool.VXLANMode == encap.Always {
		return PoolTypeVXLAN
	}
	if pool.IPIPMode == encap.CrossSubnet {
		return PoolTypeIPIPCrossSubnet
	}
	if pool.IPIPMode == encap.Always {
		return PoolTypeIPIP
	}
	return PoolTypeNoEncap
}

// withdrawRouteIfActive will send a *proto.RouteRemove for the given route.
func (c *L3RouteResolver) withdrawRouteIfActive(r nodenameRoute) {
	if !c.routeReady(r) {
		logrus.WithField("route", r).Debug("Route wasn't ready, ignoring withdraw")
		return
	}
	logrus.WithField("route", r).Info("Sending route remove")
	c.callbacks.OnRouteRemove(proto.RouteType_WORKLOADS_NODE, r.dst.String())
}

// sendRouteIfActive will send a *proto.RouteUpdate for the given route.
func (c *L3RouteResolver) sendRouteIfActive(r nodenameRoute) {
	if !c.routeReady(r) {
		logrus.WithField("route", r).Debug("Route wasn't ready, ignoring send")
		return
	}
	logrus.WithField("route", r).Info("Sending route update")
	c.callbacks.OnRouteUpdate(&proto.RouteUpdate{
		Type: proto.RouteType_WORKLOADS_NODE, // FIXME we throw away the route type, will want that if we rework VXLAN resolver to use our routes.
		Dst:  r.dst.String(),
		Node: r.nodeName,
		Gw:   c.nodeNameToIPAddr[r.nodeName],
	})
}

// routesFromBlock returns a list of routes which should exist based on the provided
// allocation block.
func (c *L3RouteResolver) routesFromBlock(blockKey string, b *model.AllocationBlock) map[string]nodenameRoute {
	routes := make(map[string]nodenameRoute)

	for _, alloc := range b.NonAffineAllocations() {
		if alloc.Host == "" {
			logrus.WithField("IP", alloc.Addr).Warn(
				"Unable to create route for IP; the node it belongs to was not recorded in IPAM")
			continue
		}
		r := nodenameRoute{
			dst:      ip.CIDRFromNetIP(alloc.Addr.IP),
			nodeName: alloc.Host,
		}
		routes[r.Key()] = r
	}

	host := b.Host()
	if host == c.hostname {
		logrus.Debug("Skipping routes for local node")
	} else if host != "" {
		logrus.WithField("host", host).Debug("Block has a host, including block-via-host route")
		r := nodenameRoute{
			dst:      ip.CIDRFromCalicoNet(b.CIDR),
			nodeName: host,
		}
		routes[r.Key()] = r
	}

	return routes
}

// nodenameRoute is the L3RouteResolver's internal representation of a route.
type nodenameRoute struct {
	nodeName string
	dst      ip.CIDR
}

func (r nodenameRoute) Key() string {
	return r.dst.String()
}

func (r nodenameRoute) String() string {
	return fmt.Sprintf("hostnameRoute(dst: %s, node: %s)", r.dst.String(), r.nodeName)
}
