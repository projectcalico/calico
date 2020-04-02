// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

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
	"strings"

	"github.com/sirupsen/logrus"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/set"

	"github.com/projectcalico/felix/dispatcher"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/proto"
)

// L3RouteResolver is responsible for indexing
//
// - IPAM blocks
// - IP pools
// - Node metadata (either from the Node resource, if available, or from HostIP)
//
// and emitting a set of longest prefix match routes that include:
//
// - The relevant destination CIDR.
// - The IP pool type that contains the CIDR (or none).
// - Other metadata about the containing IP pool.
// - Whether this (/32) CIDR is a host or not.
// - For workload CIDRs, the IP and name of the host that contains the workload.
//
// The BPF dataplane use the above to form a map of IP space so it can look up whether a particular
// IP belongs to a workload/host/IP pool etc. and where to forward that IP to if it needs to.
// The VXLAN dataplane combines routes for remote workloads with VTEPs from the VXLANResolver to
// form VXLAN routes.
type L3RouteResolver struct {
	myNodeName string
	callbacks  routeCallbacks

	trie *RouteTrie

	// Store node metadata indexed by node name, and routes by the
	// block that contributed them.
	nodeNameToIPAddr       map[string]string
	nodeNameToNode         map[string]*apiv3.Node
	blockToRoutes          map[string]set.Set
	allPools               map[string]model.IPPool
	useNodeResourceUpdates bool
}

func NewL3RouteResolver(hostname string, callbacks PipelineCallbacks, useNodeResourceUpdates bool) *L3RouteResolver {
	logrus.Info("Creating L3 route resolver")
	return &L3RouteResolver{
		myNodeName: hostname,
		callbacks:  callbacks,

		trie: NewRouteTrie(),

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
	// Queue up a flush.
	defer c.flush()

	// Update the routes map based on the provided block update.
	key := update.Key.String()

	deletes := set.New()
	adds := set.New()
	if update.Value != nil {
		// Block has been created or updated.
		// We don't allow multiple blocks with the same CIDR, so no need to check
		// for duplicates here. Look at the routes contributed by this block and determine if we
		// need to send any updates.
		newRoutes := c.v4RoutesFromBlock(update.Value.(*model.AllocationBlock))
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
				logCxt.Debug("Desired route already exists, skip")
				continue
			}

			logrus.WithField("route", r).Debug("Found new route")
			cachedRoutes.Add(r)
			adds.Add(r)
		}

		// At this point we've determined the correct diff to perform based on the block update. Queue up
		// updates.
		deletes.Iter(func(item interface{}) error {
			nr := item.(nodenameRoute)
			c.trie.RemoveBlockRoute(nr.dst)
			return nil
		})
		adds.Iter(func(item interface{}) error {
			nr := item.(nodenameRoute)
			c.trie.UpdateBlockRoute(nr.dst, nr.nodeName)
			return nil
		})
	} else {
		// Block has been deleted. Clean up routes that were contributed by this block.
		logrus.WithField("update", update).Debug("IPAM block deleted")
		routes := c.blockToRoutes[key]
		if routes != nil {
			routes.Iter(func(item interface{}) error {
				nr := item.(nodenameRoute)
				c.trie.RemoveBlockRoute(nr.dst)
				return nil
			})
		}
		delete(c.blockToRoutes, key)
	}
	return
}

func (c *L3RouteResolver) OnResourceUpdate(update api.Update) (_ bool) {
	// We only care about nodes, not other resources.
	resourceKey := update.Key.(model.ResourceKey)
	if resourceKey.Kind != apiv3.KindNode {
		return
	}

	// Queue up a flush.
	defer c.flush()

	// Extract the nodename and check whether the node was known already.
	nodeName := update.Key.(model.ResourceKey).Name
	_, nodeExisted := c.nodeNameToNode[nodeName]

	logCxt := logrus.WithField("node", nodeName).WithField("update", update)
	logCxt.Debug("OnResourceUpdate triggered")
	var myOldCIDR, myNewCIDR *cnet.IPNet
	if nodeName == c.myNodeName {
		// Our node, look up our old CIDR to see if it changes.
		logCxt.Debug("Update to this node's resource.")
		myOldCIDR, _ = c.nodeCidr(c.myNodeName)
	}

	// Update our tracking data structures.
	if update.Value != nil && update.Value.(*apiv3.Node).Spec.BGP != nil {
		node := update.Value.(*apiv3.Node)
		bgp := node.Spec.BGP
		c.nodeNameToNode[nodeName] = node
		ipv4, _, err := cnet.ParseCIDROrIP(bgp.IPv4Address)
		if err != nil {
			// Validation should prevent this...
			logCxt.WithError(err).Error("couldn't parse ipv4 address from node bgp info")
			if nodeExisted {
				logCxt.WithError(err).Error("Treating as deletion")
				delete(c.nodeNameToNode, nodeName)
				c.onRemoveNode(nodeName)
			}
		} else {
			c.onNodeIPUpdate(nodeName, ipv4.String())
		}
	} else {
		delete(c.nodeNameToNode, nodeName)
		c.onRemoveNode(nodeName)
	}

	if nodeName == c.myNodeName {
		// Check if our CIDR has changed and if so recalculate the "same subnet" tracking.
		myNewCIDR, _ = c.nodeCidr(c.myNodeName)
		if !safeCIDRsEqual(myOldCIDR, myNewCIDR) {
			// This node's CIDR has changed; some routes may now have an incorrect value for same-subnet.
			c.visitAllRoutes(func(r nodenameRoute) {
				if r.nodeName == c.myNodeName {
					return // Ignore self.
				}
				otherNodesCIDR, err := c.nodeCidr(r.nodeName)
				if err != nil {
					return // Don't know this node's CIDR so ignore for now.
				}
				wasSameSubnet := myOldCIDR != nil && myOldCIDR.Contains(otherNodesCIDR.IP)
				nowSameSubnet := myNewCIDR != nil && myNewCIDR.Contains(otherNodesCIDR.IP)
				if wasSameSubnet != nowSameSubnet {
					logrus.WithField("route", r).Debug("Update to our subnet invalidated route")
					c.trie.MarkCIDRDirty(r.dst)
				}
			})
		}
	}
	return
}

func safeCIDRsEqual(a *cnet.IPNet, b *cnet.IPNet) bool {
	if a != nil && b != nil {
		// Both non-nil, check the details.
		aSize, aBits := a.Mask.Size()
		bSize, bBits := b.Mask.Size()
		return a.IP.Equal(b.IP) && aSize == bSize && aBits == bBits
	}
	// If one is nil can only be equal if both are nil.
	return a == nil && b == nil
}

// OnHostIPUpdate gets called whenever a node IP address changes.
func (c *L3RouteResolver) OnHostIPUpdate(update api.Update) (_ bool) {
	// Queue up a flush.
	defer c.flush()

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

	if strings.Contains(newIP, ":") {
		logrus.Debug("Ignoring IPv6 address for node")
		newIP = ""
	}

	oldIP := c.nodeNameToIPAddr[nodeName]
	if oldIP == newIP {
		logCxt.Debug("IP update but IP is unchanged, ignoring")
		return
	}
	if oldIP != "" {
		oldCIDR := ip.MustParseCIDROrIP(oldIP).(ip.V4CIDR)
		c.trie.RemoveHost(oldCIDR)
	}

	if newIP == "" {
		delete(c.nodeNameToIPAddr, nodeName)
	} else {
		c.nodeNameToIPAddr[nodeName] = newIP
		newCIDR := ip.MustParseCIDROrIP(newIP).(ip.V4CIDR)
		c.trie.AddHost(newCIDR, nodeName)
	}
	c.markAllNodeRoutesDirty(nodeName)
}

func (c *L3RouteResolver) onRemoveNode(nodeName string) {
	c.onNodeIPUpdate(nodeName, "")
}

func (c *L3RouteResolver) markAllNodeRoutesDirty(nodeName string) {
	c.visitAllRoutes(func(route nodenameRoute) {
		if route.nodeName != nodeName {
			return
		}
		c.trie.MarkCIDRDirty(route.dst)
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
	// Queue up a flush.
	defer c.flush()

	k := update.Key.(model.IPPoolKey)
	poolKey := k.String()
	oldPool, oldPoolExists := c.allPools[poolKey]
	oldPoolType := proto.IPPoolType_NONE
	var poolCIDR ip.V4CIDR
	if oldPoolExists {
		// Need explicit oldPoolExists check so that we don't pass a zero-struct to poolTypeForPool.
		oldPoolType = c.poolTypeForPool(&oldPool)
		poolCIDR = ip.CIDRFromCalicoNet(oldPool.CIDR).(ip.V4CIDR)
	}
	var newPool *model.IPPool
	if update.Value != nil {
		newPool = update.Value.(*model.IPPool)
		if len(newPool.CIDR.IP.To4()) == 0 {
			logrus.Debug("Ignoring IPv6 pool")
			newPool = nil
		}
	}
	newPoolType := c.poolTypeForPool(newPool)
	logCxt := logrus.WithFields(logrus.Fields{"oldType": oldPoolType, "newType": newPoolType})
	if newPool != nil && newPoolType != proto.IPPoolType_NONE {
		logCxt.Info("Pool is active")
		c.allPools[poolKey] = *newPool
		poolCIDR = ip.CIDRFromCalicoNet(newPool.CIDR).(ip.V4CIDR)
		crossSubnet := newPool.IPIPMode == encap.CrossSubnet || newPool.VXLANMode == encap.CrossSubnet
		c.trie.UpdatePool(poolCIDR, newPoolType, newPool.Masquerade, crossSubnet)
	} else {
		delete(c.allPools, poolKey)
		c.trie.RemovePool(poolCIDR)
	}

	return
}

func (c *L3RouteResolver) poolTypeForPool(pool *model.IPPool) proto.IPPoolType {
	if pool == nil {
		return proto.IPPoolType_NONE
	}
	if pool.VXLANMode != encap.Undefined {
		return proto.IPPoolType_VXLAN
	}
	if pool.IPIPMode != encap.Undefined {
		return proto.IPPoolType_IPIP
	}
	return proto.IPPoolType_NO_ENCAP
}

// v4RoutesFromBlock returns a list of routes which should exist based on the provided
// allocation block.
func (c *L3RouteResolver) v4RoutesFromBlock(b *model.AllocationBlock) map[string]nodenameRoute {
	if len(b.CIDR.IP.To4()) == 0 {
		logrus.Debug("Ignoring IPv6 block")
		return nil
	}

	routes := make(map[string]nodenameRoute)
	for _, alloc := range b.NonAffineAllocations() {
		if alloc.Host == "" {
			logrus.WithField("IP", alloc.Addr).Warn(
				"Unable to create route for IP; the node it belongs to was not recorded in IPAM")
			continue
		}
		r := nodenameRoute{
			dst:      ip.CIDRFromNetIP(alloc.Addr.IP).(ip.V4CIDR),
			nodeName: alloc.Host,
		}
		routes[r.Key()] = r
	}

	host := b.Host()
	if host != "" {
		logrus.WithField("host", host).Debug("Block has a host, including block-via-host route")
		r := nodenameRoute{
			dst:      ip.CIDRFromCalicoNet(b.CIDR).(ip.V4CIDR),
			nodeName: host,
		}
		routes[r.Key()] = r
	}

	return routes
}

// flush() iterates over the CIDRs that are marked dirty in the trie and sends any route updates
// that it finds.
func (c *L3RouteResolver) flush() {
	var buf []ip.V4TrieEntry
	c.trie.dirtyCIDRs.Iter(func(item interface{}) error {
		logCxt := logrus.WithField("cidr", item)
		logCxt.Debug("Flushing dirty route")
		cidr := item.(ip.V4CIDR)

		// We know the CIDR may be dirty, look up the path through the trie to the CIDR.  This will
		// give us the information about the enclosing CIDRs.  For example, if we have:
		// - IP pool     10.0.0.0/16 VXLAN
		// - IPAM block  10.0.1.0/26 node x
		// - IP          10.0.0.1/32 node y
		// Then, we'll see the pool, block and IP in turn on the lookup path allowing us to collect the
		// relevant information from each.
		buf = c.trie.t.LookupPath(buf, cidr)

		if len(buf) == 0 {
			// CIDR is not in the trie.  Nothing to do.  Route removed before it had even been sent?
			logCxt.Debug("CIDR not in trie, ignoring.")
			return set.RemoveItem
		}

		// Otherwise, check if the route is removed.
		ri := buf[len(buf)-1].Data.(RouteInfo)
		if ri.WasSent && ri.IsEmpty() {
			logCxt.Debug("CIDR was sent before but now needs to be removed.")
			c.callbacks.OnRouteRemove(cidr.String())
			c.trie.SetRouteSent(cidr, false)
			return set.RemoveItem
		}

		rt := &proto.RouteUpdate{
			Type:       proto.RouteType_CIDR_INFO,
			IpPoolType: proto.IPPoolType_NONE,
			Dst:        cidr.String(),
		}
		poolAllowsCrossSubnet := false
		for _, entry := range buf {
			ri := entry.Data.(RouteInfo)
			if ri.Pool.Type != proto.IPPoolType_NONE {
				logCxt.WithField("type", ri.Pool.Type).Debug("Found containing IP pool.")
				rt.IpPoolType = ri.Pool.Type
			}
			if ri.Pool.NATOutgoing {
				logCxt.Debug("NAT outgoing enabled on this CIDR.")
				rt.NatOutgoing = true
			}
			if ri.Pool.CrossSubnet {
				logCxt.Debug("Cross-subnet enabled on this CIDR.")
				poolAllowsCrossSubnet = true
			}
			if ri.Block.NodeName != "" {
				rt.DstNodeName = ri.Block.NodeName
				rt.DstNodeIP = c.nodeNameToIPAddr[rt.DstNodeName]
				if rt.DstNodeName == c.myNodeName {
					logCxt.Debug("Local workload route.")
					rt.Type = proto.RouteType_LOCAL_WORKLOAD
				} else {
					logCxt.Debug("Remote workload route.")
					rt.Type = proto.RouteType_REMOTE_WORKLOAD
				}
			}
			if ri.Host.NodeName != "" {
				rt.DstNodeName = ri.Host.NodeName
				if rt.DstNodeName == c.myNodeName {
					logCxt.Debug("Local host route.")
					rt.Type = proto.RouteType_LOCAL_HOST
				} else {
					logCxt.Debug("Remote host route.")
					rt.Type = proto.RouteType_REMOTE_HOST
				}
			}
		}

		rt.SameSubnet = poolAllowsCrossSubnet && c.nodeInOurSubnet(rt.DstNodeName)

		logrus.WithField("route", rt).Debug("Sending route")
		c.callbacks.OnRouteUpdate(rt)
		c.trie.SetRouteSent(cidr, true)

		return set.RemoveItem
	})
}

// nodeInOurSubnet returns true if the IP of the given node is known and it's in our subnet.
// Return false if either the remote IP or our subnet is not known.
func (c *L3RouteResolver) nodeInOurSubnet(name string) bool {
	localNodeCidr, err := c.nodeCidr(c.myNodeName)
	if err != nil {
		return false
	}
	nodeCidr, err := c.nodeCidr(name)
	if err != nil {
		return false
	}

	return localNodeCidr.Contains(nodeCidr.IP)
}

func (c *L3RouteResolver) nodeCidr(nodeName string) (*cnet.IPNet, error) {
	logCxt := logrus.WithField("node", nodeName)

	if _, ok := c.nodeNameToNode[nodeName]; !ok {
		return nil, fmt.Errorf("no node info seen yet for node %s", nodeName)
	}

	node := c.nodeNameToNode[nodeName]

	// NOTE we don't need to check if this is null because nodes that don't have bgp information aren't added to the map
	bgp := node.Spec.BGP

	_, cidr, err := cnet.ParseCIDROrIP(bgp.IPv4Address)
	if err != nil {
		logCxt.WithError(err).Error("couldn't parse cidr information from bgp ipv4 address")
		return nil, err
	}

	return cidr, nil
}

// nodenameRoute is the L3RouteResolver's internal representation of a route.
type nodenameRoute struct {
	nodeName string
	dst      ip.V4CIDR
}

func (r nodenameRoute) Key() string {
	return r.dst.String()
}

func (r nodenameRoute) String() string {
	return fmt.Sprintf("hostnameRoute(dst: %s, node: %s)", r.dst.String(), r.nodeName)
}

// RouteTrie stores the information that we've gleaned from various, potentially overlapping sources.
//
// In general, we get updates about IPAM pools, blocks, nodes and individual pod IPs (extracted from the blocks).
// If none of those were allowed to overlap, things would be simple.  Unfortunately, we have to deal with:
//
// - Disabled IPAM pools that contain no blocks, which are used for tagging "external" IPs as safe destinations that
//   don't require SNAT.
// - IPAM pools that are the same size as their blocks and so share a CIDR.
// - IPAM blocks that are /32s so they overlap with the pod IP inside them (and potentially with a
//   misconfigured host IP).
// - Transient misconfigurations during a resync where we may see things out of order.
// - In future, /32s that we've learned from workload endpoints that are not contained within IP pools.
//
// In addition, the BPF program can only do a single lookup but it wants to know all the information about
// an IP, some of which is derived from the metadata further up the tree.  Means that, for each CIDR or IP that we
// care about, we want to maintain:
//
// - The next hop (for /32s and blocks).
// - The type of IP pool that it's inside of (or none).
// - Whether the IP pool have NAT-outgoing turned on or not.
//
// Approach: for each CIDR in the trie, we store a RouteInfo, which has fields for tracking the pool, block and
// next hop.  All updates are done via the updateCIDR method, which handles cleaning up RouteInfo structs that are no
// longer needed.
//
// The RouteTrie maintains a set of dirty CIDRs.  When an IPAM pool is updated, all the CIDRs under it are marked dirty.
type RouteTrie struct {
	t          *ip.V4Trie
	dirtyCIDRs set.Set
}

func NewRouteTrie() *RouteTrie {
	return &RouteTrie{
		t:          &ip.V4Trie{},
		dirtyCIDRs: set.New(),
	}
}

func (r *RouteTrie) UpdatePool(cidr ip.V4CIDR, poolType proto.IPPoolType, natOutgoing bool, crossSubnet bool) {
	logrus.WithFields(logrus.Fields{
		"cidr":        cidr,
		"poolType":    poolType,
		"nat":         natOutgoing,
		"crossSubnet": crossSubnet,
	}).Debug("IP pool update")
	changed := r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.Pool.Type = poolType
		ri.Pool.NATOutgoing = natOutgoing
		ri.Pool.CrossSubnet = crossSubnet
	})
	if !changed {
		return
	}
	r.markChildrenDirty(cidr)
}

func (r *RouteTrie) markChildrenDirty(cidr ip.V4CIDR) {
	// TODO: avoid full scan to mark children dirty
	r.t.Visit(func(c ip.V4CIDR, data interface{}) bool {
		if cidr.ContainsV4(c.Addr().(ip.V4Addr)) {
			r.MarkCIDRDirty(c)
		}
		return true
	})
}

func (r *RouteTrie) MarkCIDRDirty(cidr ip.V4CIDR) {
	r.dirtyCIDRs.Add(cidr)
}

func (r *RouteTrie) RemovePool(cidr ip.V4CIDR) {
	r.UpdatePool(cidr, proto.IPPoolType_NONE, false, false)
}

func (r *RouteTrie) UpdateBlockRoute(cidr ip.V4CIDR, nodeName string) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.Block.NodeName = nodeName
	})
}

func (r *RouteTrie) RemoveBlockRoute(cidr ip.V4CIDR) {
	r.UpdateBlockRoute(cidr, "")
}

func (r *RouteTrie) AddHost(cidr ip.V4CIDR, nodename string) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.Host.NodeName = nodename
	})
}

func (r *RouteTrie) RemoveHost(cidr ip.V4CIDR) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.Host.NodeName = ""
	})
}

func (r *RouteTrie) SetRouteSent(cidr ip.V4CIDR, sent bool) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.WasSent = sent
	})
}

func (r RouteTrie) updateCIDR(cidr ip.V4CIDR, updateFn func(info *RouteInfo)) bool {
	// Get the RouteInfo for the given CIDR and take a copy so we can compare.
	ri := r.Get(cidr)
	riCopy := ri

	// Apply the update, whatever that is.
	updateFn(&ri)

	// Check if the update was a no-op.
	if riCopy == ri {
		// Change was a no-op, ignore.
		return false
	}

	// Not a no-op; mark CIDR as dirty.
	logrus.WithFields(logrus.Fields{"old": riCopy, "new": ri}).Debug("Route updated, marking dirty.")
	r.MarkCIDRDirty(cidr)
	if ri.IsZero() {
		// No longer have anything to track about this CIDR, clean it up.
		r.t.Delete(cidr)
		return true
	}
	r.t.Update(cidr, ri)
	return true
}

func (r RouteTrie) Get(cidr ip.V4CIDR) RouteInfo {
	ri := r.t.Get(cidr)
	if ri == nil {
		return RouteInfo{}
	}
	return ri.(RouteInfo)
}

type RouteInfo struct {
	// Pool contains information extracted from the IP pool that has this CIDR.
	Pool struct {
		Type        proto.IPPoolType // Only set if this CIDR represents an IP pool
		NATOutgoing bool
		CrossSubnet bool
	}

	// Block contains route information extracted from IPAM blocks.
	Block struct {
		NodeName string // Set for each route that comes from an IPAM block.
	}

	// Host contains information extracted from the node/host config updates.
	Host struct {
		NodeName string // set if this CIDR _is_ a node's own IP.
	}

	// WasSent is set to true when the route is sent downstream.
	WasSent bool
}

// IsEmpty returns true if the RouteInfo no longer has any useful information; I.e. the CIDR it represents
// is not a pool, block route or host.
func (r RouteInfo) IsEmpty() bool {
	return r.Pool.Type == proto.IPPoolType_NONE &&
		r.Block.NodeName == "" &&
		r.Host.NodeName == "" &&
		!r.Pool.NATOutgoing
}

// IsZero returns true if the RouteInfo no longer has any useful information; I.e. the CIDR it represents
// is not a pool, block route or host.
func (r RouteInfo) IsZero() bool {
	return r == RouteInfo{}
}
