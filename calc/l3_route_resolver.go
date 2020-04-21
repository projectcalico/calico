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
	"reflect"
	"sort"

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

// L3RouteResolver is responsible for indexing (currently only IPv4 versions of):
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
	nodeNameToNodeInfo     map[string]l3rrNodeInfo
	blockToRoutes          map[string]set.Set
	allPools               map[string]model.IPPool
	workloadIDToCIDRs      map[model.WorkloadEndpointKey][]cnet.IPNet
	useNodeResourceUpdates bool
	routeSource            string
}

type l3rrNodeInfo struct {
	Addr ip.V4Addr
	CIDR ip.V4CIDR
}

func (i l3rrNodeInfo) AddrAsCIDR() ip.V4CIDR {
	return i.Addr.AsCIDR().(ip.V4CIDR)
}

func NewL3RouteResolver(hostname string, callbacks PipelineCallbacks, useNodeResourceUpdates bool, routeSource string) *L3RouteResolver {
	logrus.Info("Creating L3 route resolver")
	return &L3RouteResolver{
		myNodeName: hostname,
		callbacks:  callbacks,

		trie: NewRouteTrie(),

		nodeNameToNodeInfo:     map[string]l3rrNodeInfo{},
		blockToRoutes:          map[string]set.Set{},
		allPools:               map[string]model.IPPool{},
		workloadIDToCIDRs:      map[model.WorkloadEndpointKey][]cnet.IPNet{},
		useNodeResourceUpdates: useNodeResourceUpdates,
		routeSource:            routeSource,
	}
}

func (c *L3RouteResolver) RegisterWith(allUpdDispatcher, localDispatcher *dispatcher.Dispatcher) {
	if c.useNodeResourceUpdates {
		logrus.Info("Registering L3 route resolver (node resources on)")
		allUpdDispatcher.Register(model.ResourceKey{}, c.OnResourceUpdate)
	} else {
		logrus.Info("Registering L3 route resolver (node resources off)")
		allUpdDispatcher.Register(model.HostIPKey{}, c.OnHostIPUpdate)
	}

	allUpdDispatcher.Register(model.IPPoolKey{}, c.OnPoolUpdate)

	// Depending on if we're using workload endpoints for routing information, we may
	// need all WEPs, or only local WEPs.
	logrus.WithField("routeSource", c.routeSource).Info("Registering for L3 route updates")
	if c.routeSource == "WorkloadIPs" {
		// Driven off of workload IP addressess. Register for all WEP udpates.
		allUpdDispatcher.Register(model.WorkloadEndpointKey{}, c.OnWorkloadUpdate)
	} else {
		// Driven off of IPAM data. Register for blocks and local WEP updates.
		allUpdDispatcher.Register(model.BlockKey{}, c.OnBlockUpdate)
		localDispatcher.Register(model.WorkloadEndpointKey{}, c.OnWorkloadUpdate)
	}
}

func (c *L3RouteResolver) OnWorkloadUpdate(update api.Update) (_ bool) {
	defer c.flush()

	key := update.Key.(model.WorkloadEndpointKey)

	// Look up the (possibly nil) old CIDRs.
	oldCIDRs := c.workloadIDToCIDRs[key]

	// Get the new CIDRs (again, may be nil if this is a deletion).
	var newCIDRs []cnet.IPNet
	if update.Value != nil {
		newWorkload := update.Value.(*model.WorkloadEndpoint)
		newCIDRs = newWorkload.IPv4Nets
		logrus.WithField("workload", key).WithField("newCIDRs", newCIDRs).Debug("Workload update")
	}

	if reflect.DeepEqual(oldCIDRs, newCIDRs) {
		// No change, ignore.
		logrus.Debug("No change to CIDRs, ignore.")
		return
	}

	// Incref the new CIDRs.
	for _, newCIDR := range newCIDRs {
		c.trie.AddWEP(ip.CIDRFromCalicoNet(newCIDR).(ip.V4CIDR), key.Hostname)
	}

	// Decref the old.
	for _, oldCIDR := range oldCIDRs {
		c.trie.RemoveWEP(ip.CIDRFromCalicoNet(oldCIDR).(ip.V4CIDR), key.Hostname)
	}

	if len(newCIDRs) > 0 {
		// Only store an entry if there are some CIDRs.
		c.workloadIDToCIDRs[key] = newCIDRs
	} else {
		delete(c.workloadIDToCIDRs, key)
	}

	return
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

	logCxt := logrus.WithField("node", nodeName).WithField("update", update)
	logCxt.Debug("OnResourceUpdate triggered")

	// Update our tracking data structures.
	var nodeInfo *l3rrNodeInfo
	if update.Value != nil {
		node := update.Value.(*apiv3.Node)
		if node.Spec.BGP != nil && node.Spec.BGP.IPv4Address != "" {
			bgp := node.Spec.BGP
			// Use cnet.ParseCIDROrIP so we get the IP and the CIDR.  The parse functions in the ip package
			// throw away one or the other.
			ipv4, caliNodeCIDR, err := cnet.ParseCIDROrIP(bgp.IPv4Address)
			if err != nil {
				logrus.WithError(err).Panic("Failed to parse already-validated IP address")
			}
			nodeInfo = &l3rrNodeInfo{
				Addr: ip.FromCalicoIP(*ipv4).(ip.V4Addr),
				CIDR: ip.CIDRFromCalicoNet(*caliNodeCIDR).(ip.V4CIDR),
			}
		}
	}

	c.onNodeUpdate(nodeName, nodeInfo)

	return
}

// OnHostIPUpdate gets called whenever a node IP address changes.
func (c *L3RouteResolver) OnHostIPUpdate(update api.Update) (_ bool) {
	// Queue up a flush.
	defer c.flush()

	nodeName := update.Key.(model.HostIPKey).Hostname
	logrus.WithField("node", nodeName).Debug("OnHostIPUpdate triggered")

	var newNodeInfo *l3rrNodeInfo
	if update.Value != nil {
		newCaliIP := update.Value.(*cnet.IP)
		v4Addr, ok := ip.FromCalicoIP(*newCaliIP).(ip.V4Addr)
		if ok { // Defensive; we only expect an IPv4.
			newNodeInfo = &l3rrNodeInfo{
				Addr: v4Addr,
				CIDR: v4Addr.AsCIDR().(ip.V4CIDR), // Don't know the CIDR so use the /32.
			}
		}
	}
	c.onNodeUpdate(nodeName, newNodeInfo)

	return
}

// onNodeUpdate updates our cache of node information as well add adding/removing the node's CIDR from the trie.
// Passing newCIDR==nil cleans up the entry in the trie.
func (c *L3RouteResolver) onNodeUpdate(nodeName string, newNodeInfo *l3rrNodeInfo) {
	oldNodeInfo, nodeExisted := c.nodeNameToNodeInfo[nodeName]

	if (newNodeInfo == nil && !nodeExisted) || (newNodeInfo != nil && nodeExisted && oldNodeInfo == *newNodeInfo) {
		// No change.
		return
	}

	if nodeName == c.myNodeName {
		// Check if our CIDR has changed and if so recalculate the "same subnet" tracking.
		var myNewCIDR ip.V4CIDR
		var myNewCIDRKnown bool
		if newNodeInfo != nil {
			myNewCIDR = newNodeInfo.CIDR
			myNewCIDRKnown = true
		}
		if oldNodeInfo.CIDR != myNewCIDR {
			// This node's CIDR has changed; some routes may now have an incorrect value for same-subnet.
			c.visitAllRoutes(func(r nodenameRoute) {
				if r.nodeName == c.myNodeName {
					return // Ignore self.
				}
				otherNodeInfo, known := c.nodeNameToNodeInfo[r.nodeName]
				if !known {
					return // Don't know other node's CIDR so ignore for now.
				}
				otherNodesIPv4 := otherNodeInfo.Addr
				wasSameSubnet := nodeExisted && oldNodeInfo.CIDR.ContainsV4(otherNodesIPv4)
				nowSameSubnet := myNewCIDRKnown && myNewCIDR.ContainsV4(otherNodesIPv4)
				if wasSameSubnet != nowSameSubnet {
					logrus.WithField("route", r).Debug("Update to our subnet invalidated route")
					c.trie.MarkCIDRDirty(r.dst)
				}
			})
		}
	}

	if nodeExisted {
		delete(c.nodeNameToNodeInfo, nodeName)
		c.trie.RemoveHost(oldNodeInfo.AddrAsCIDR(), nodeName)
	}
	if newNodeInfo != nil {
		c.nodeNameToNodeInfo[nodeName] = *newNodeInfo
		c.trie.AddHost(newNodeInfo.AddrAsCIDR(), nodeName)
	}

	c.markAllNodeRoutesDirty(nodeName)
}

func (c *L3RouteResolver) markAllNodeRoutesDirty(nodeName string) {
	// TODO: Remove need to iterate all routes here.
	c.visitAllRoutes(func(route nodenameRoute) {
		if route.nodeName != nodeName {
			return
		}
		c.trie.MarkCIDRDirty(route.dst)
	})
}

func (c *L3RouteResolver) visitAllRoutes(v func(route nodenameRoute)) {
	c.trie.t.Visit(func(cidr ip.V4CIDR, data interface{}) bool {
		// Construct a nodenameRoute to pass to the visiting function.
		ri := c.trie.t.Get(cidr).(RouteInfo)
		nnr := nodenameRoute{dst: cidr}
		if len(ri.WEPs) > 0 {
			// From a WEP.
			nnr.nodeName = ri.WEPs[0].NodeName
		} else if ri.Block.NodeName != "" {
			// From IPAM.
			nnr.nodeName = ri.Block.NodeName
		} else {
			// No host associated with route.
			return true
		}

		v(nnr)
		return true
	})
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
		if ri.WasSent && !ri.IsValidRoute() {
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
				if rt.DstNodeName == c.myNodeName {
					logCxt.Debug("Local workload route.")
					rt.Type = proto.RouteType_LOCAL_WORKLOAD
				} else {
					logCxt.Debug("Remote workload route.")
					rt.Type = proto.RouteType_REMOTE_WORKLOAD
				}
			}
			if len(ri.Host.NodeNames) > 0 {
				rt.DstNodeName = ri.Host.NodeNames[0]

				if rt.DstNodeName == c.myNodeName {
					logCxt.Debug("Local host route.")
					rt.Type = proto.RouteType_LOCAL_HOST
				} else {
					logCxt.Debug("Remote host route.")
					rt.Type = proto.RouteType_REMOTE_HOST
				}
			}

			if len(ri.WEPs) > 0 {
				// At least one WEP exists with this IP. It may be on this node, or a remote node.
				// In steady state we only ever expect a single WEP for this CIDR. However there are rare transient
				// cases we must handle where we may have two WEPs with the same IP. Since this will be transient,
				// we can always just use the first entry.
				rt.DstNodeName = ri.WEPs[0].NodeName
				if ri.WEPs[0].NodeName == c.myNodeName {
					rt.Type = proto.RouteType_LOCAL_WORKLOAD
					rt.LocalWorkload = true
				} else {
					rt.Type = proto.RouteType_REMOTE_WORKLOAD
				}
			}
		}

		if rt.DstNodeName != "" {
			dstNodeInfo, exists := c.nodeNameToNodeInfo[rt.DstNodeName]
			if exists {
				rt.DstNodeIp = dstNodeInfo.Addr.String()
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
	localNodeInfo, exists := c.nodeNameToNodeInfo[c.myNodeName]
	if !exists {
		return false
	}

	nodeInfo, exists := c.nodeNameToNodeInfo[name]
	if !exists {
		return false
	}

	return localNodeInfo.CIDR.ContainsV4(nodeInfo.Addr)
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

// RouteTrie stores the information that we've gleaned from various resources in a way that allows us to
//
// - Look up a CIDR and find all the information that we know about the containing CIDRs.
//   Example: if we look up a workload /32 CIDR then we'll also find the IP pool that contains it.
// - Deal with collisions where resources from different sources share the same CIDR.
//   Example: an IP pool and an IPAM block can share the same CIDR.  When we do a lookup, we want to know
//   about both the pool and the block.
//
// More examples of nesting and collisions to be aware of:
//
// - Disabled IPAM pools that contain no blocks, which are used for tagging "external" IPs as safe destinations that
//   don't require SNAT and for adding IP ranges for BIRD to export.
// - IPAM blocks that are /32s so they overlap with the pod IP inside them (and potentially with a
//   misconfigured host IP).
// - Transient misconfigurations during a resync where we may see things out of order (for example, two hosts
//   sharing an IP).
// - In future, /32s that we've learned from workload endpoints that are not contained within IP pools.
//
// Approach: for each CIDR in the trie, we store a RouteInfo struct, which has a disjoint nested struct for
// tracking data from each source.  All updates are done via the updateCIDR method, which handles cleaning up
// RouteInfo structs that are empty.
//
// The RouteTrie maintains a set of dirty CIDRs.  When an IPAM pool is updated, all the CIDRs under it are
// marked dirty.
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

func (r *RouteTrie) AddHost(cidr ip.V4CIDR, nodeName string) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.Host.NodeNames = append(ri.Host.NodeNames, nodeName)
		if len(ri.Host.NodeNames) > 1 {
			logrus.WithFields(logrus.Fields{
				"cidr":  cidr,
				"nodes": ri.Host.NodeNames,
			}).Warn("Some nodes share IP address, route calculation may choose wrong node.")
			// For determinism in case we have two hosts sharing an IP, sort the entries.
			sort.Strings(ri.Host.NodeNames)
		}
	})
}

func (r *RouteTrie) RemoveHost(cidr ip.V4CIDR, nodeName string) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		var ns []string
		for _, n := range ri.Host.NodeNames {
			if n == nodeName {
				continue
			}
			ns = append(ns, n)
		}
		ri.Host.NodeNames = ns
	})
}

func (r *RouteTrie) AddWEP(cidr ip.V4CIDR, nodename string) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		// Find the WEP in the list for this nodename,
		// if it exists. If it doesn't, we'll add it below.
		for i := range ri.WEPs {
			if ri.WEPs[i].NodeName == nodename {
				// Found an existing WEP. Just increment the RefCount
				// and return.
				ri.WEPs[i].RefCount++
				return
			}
		}

		// If it doesn't already exist, add it to the slice and
		// sort the slice based on nodename to make sure we are not dependent
		// on event ordering.
		wep := WEP{NodeName: nodename, RefCount: 1}
		ri.WEPs = append(ri.WEPs, wep)
		sort.Slice(ri.WEPs, func(i, j int) bool {
			return ri.WEPs[i].NodeName < ri.WEPs[j].NodeName
		})
	})
}

func (r *RouteTrie) RemoveWEP(cidr ip.V4CIDR, nodename string) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		for i := range ri.WEPs {
			if ri.WEPs[i].NodeName == nodename {
				// Decref the WEP.
				ri.WEPs[i].RefCount--
				if ri.WEPs[i].RefCount < 0 {
					logrus.WithField("cidr", cidr).Panic("BUG: Asked to decref a workload past 0.")
				} else if ri.WEPs[i].RefCount == 0 {
					// Remove it from the list.
					ri.WEPs = append(ri.WEPs[:i], ri.WEPs[i+1:]...)
				}
				if len(ri.WEPs) == 0 {
					ri.WEPs = nil
				}
				return
			}
		}

		// Unable to find the requested WEP.
		logrus.WithField("cidr", cidr).Panic("BUG: Asked to decref a workload that doesn't exist.")
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
	riCopy := ri.Copy()

	// Apply the update, whatever that is.
	updateFn(&ri)

	// Check if the update was a no-op.
	if riCopy.Equals(ri) {
		// Change was a no-op, ignore.
		logrus.WithField("cidr", cidr).Debug("Ignoring no-op change")
		return false
	}

	// Not a no-op; mark CIDR as dirty.
	logrus.WithFields(logrus.Fields{"old": riCopy, "new": ri}).Debug("Route updated, marking dirty.")
	r.MarkCIDRDirty(cidr)
	if ri.IsZero() {
		// No longer have *anything* to track about this CIDR, clean it up.
		logrus.WithField("cidr", cidr).Debug("RouteInfo is zero, cleaning up.")
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
		NodeNames []string // set if this CIDR _is_ a node's own IP.
	}

	// WEPs contains information extracted from workload endpoints.
	WEPs []WEP

	// WasSent is set to true when the route is sent downstream.
	WasSent bool
}

type WEP struct {
	// Count of WEPs that have this CIDR.  Normally, this will be 0 or 1 but Felix has to be tolerant
	// to bad data (two WEPs with the same CIDR) so we do ref counting.
	RefCount int

	// NodeName contains the nodename for this WEP / CIDR.
	NodeName string
}

// IsValidRoute returns true if the RouteInfo contains some information about a CIDR, i.e. if this route
// should be sent downstream.  This _excludes_ the WasSent flag, which we use to track whether a route with
// this CIDR was previously sent.  If IsValidRoute() returns false but WasSent is true then we need to withdraw
// the route.
func (r RouteInfo) IsValidRoute() bool {
	return r.Pool.Type != proto.IPPoolType_NONE ||
		r.Block.NodeName != "" ||
		len(r.Host.NodeNames) > 0 ||
		r.Pool.NATOutgoing ||
		len(r.WEPs) > 0
}

// Copy returns a copy of the RouteInfo. Since some fields are pointers, we need to
// explicitly copy them so that they are not shared between the copies.
func (r RouteInfo) Copy() RouteInfo {
	cp := r
	if len(r.WEPs) != 0 {
		cp.WEPs = make([]WEP, len(r.WEPs))
		copy(cp.WEPs, r.WEPs)
	}
	return cp
}

// IsZero() returns true if this node in the trie now contains no tracking information at all and is
// ready for deletion.
func (r RouteInfo) IsZero() bool {
	return !r.WasSent && !r.IsValidRoute()
}

func (r RouteInfo) Equals(other RouteInfo) bool {
	return reflect.DeepEqual(r, other)
}
