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
	"fmt"
	"reflect"
	"sort"

	"github.com/sirupsen/logrus"

	apiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	cresources "github.com/projectcalico/calico/libcalico-go/lib/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/set"

	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/proto"
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
	nodeRoutes             nodeRoutes
	allPools               map[string]model.IPPool
	workloadIDToCIDRs      map[model.WorkloadEndpointKey][]cnet.IPNet
	useNodeResourceUpdates bool
	routeSource            string
}

type l3rrNodeInfo struct {
	V4Addr ip.V4Addr
	V4CIDR ip.V4CIDR

	V6Addr ip.V6Addr
	V6CIDR ip.V6CIDR

	// Tunnel IP addresses
	IPIPAddr        ip.Addr
	VXLANAddr       ip.Addr
	VXLANV6Addr     ip.Addr
	WireguardAddr   ip.Addr
	WireguardV6Addr ip.Addr

	Addresses []ip.Addr
}

func (i l3rrNodeInfo) Equal(b l3rrNodeInfo) bool {
	if i.V4Addr == b.V4Addr &&
		i.V4CIDR == b.V4CIDR &&
		i.V6Addr == b.V6Addr &&
		i.V6CIDR == b.V6CIDR &&
		i.IPIPAddr == b.IPIPAddr &&
		i.VXLANAddr == b.VXLANAddr &&
		i.WireguardAddr == b.WireguardAddr {

		if len(i.Addresses) != len(b.Addresses) {
			return false
		}

		// We expect a small single number of addresses in single digits and
		// mostly in the same order.
		l := len(i.Addresses)
		for ia, a := range i.Addresses {
			found := false
			for j := 0; j < l; j++ {
				if a == b.Addresses[(ia+j)%l] {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}

		return true
	}

	return false
}

func (i l3rrNodeInfo) V4AddrAsCIDR() ip.V4CIDR {
	return i.V4Addr.AsCIDR().(ip.V4CIDR)
}

func (i l3rrNodeInfo) AddressesAsCIDRs() []ip.CIDR {
	addrs := make(map[ip.Addr]struct{})

	addrs[i.V4Addr] = struct{}{}
	addrs[i.V6Addr] = struct{}{}

	for _, a := range i.Addresses {
		addrs[a] = struct{}{}
	}

	cidrs := make([]ip.CIDR, len(addrs))
	idx := 0
	for a := range addrs {
		cidrs[idx] = a.AsCIDR()
		idx++
	}

	return cidrs
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
		nodeRoutes:             newNodeRoutes(),
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
		// Driven off of workload IP addresses. Register for all WEP updates.
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
		newCIDRs = append(newWorkload.IPv4Nets, newWorkload.IPv6Nets...)
		logrus.WithField("workload", key).WithField("newCIDRs", newCIDRs).Debug("Workload update")
	}

	if reflect.DeepEqual(oldCIDRs, newCIDRs) {
		// No change, ignore.
		logrus.Debug("No change to CIDRs, ignore.")
		return
	}

	// Incref the new CIDRs.
	for _, newCIDR := range newCIDRs {
		cidr := ip.CIDRFromCalicoNet(newCIDR)
		c.trie.AddRef(cidr, key.Hostname, RefTypeWEP)
		c.nodeRoutes.Add(nodenameRoute{key.Hostname, cidr})
	}

	// Decref the old.
	for _, oldCIDR := range oldCIDRs {
		cidr := ip.CIDRFromCalicoNet(oldCIDR)
		c.trie.RemoveRef(cidr, key.Hostname, RefTypeWEP)
		c.nodeRoutes.Remove(nodenameRoute{key.Hostname, cidr})
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
		newRoutes := c.routesFromBlock(update.Value.(*model.AllocationBlock))
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
			c.nodeRoutes.Remove(nr)
			return nil
		})
		adds.Iter(func(item interface{}) error {
			nr := item.(nodenameRoute)
			c.trie.UpdateBlockRoute(nr.dst, nr.nodeName)
			c.nodeRoutes.Add(nr)
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
		if node.Spec.BGP != nil && (node.Spec.BGP.IPv4Address != "" || node.Spec.BGP.IPv6Address != "") {
			bgp := node.Spec.BGP
			nodeInfo = &l3rrNodeInfo{}
			if bgp.IPv4Address != "" {
				// Use cnet.ParseCIDROrIP so we get the IP and the CIDR.  The parse functions in the ip package
				// throw away one or the other.
				ipv4, caliNodeCIDR, err := cnet.ParseCIDROrIP(bgp.IPv4Address)
				if err != nil {
					logrus.WithError(err).Panic("Failed to parse already-validated IPv4 address")
				}
				nodeInfo.V4Addr = ip.FromCalicoIP(*ipv4).(ip.V4Addr)
				nodeInfo.V4CIDR = ip.CIDRFromCalicoNet(*caliNodeCIDR).(ip.V4CIDR)
			}
			if bgp.IPv6Address != "" {
				ipv6, caliNodeCIDRV6, err := cnet.ParseCIDROrIP(bgp.IPv6Address)
				if err != nil {
					logrus.WithError(err).Panic("Failed to parse already-validated IPv6 address")
				}
				nodeInfo.V6Addr = ip.FromCalicoIP(*ipv6).(ip.V6Addr)
				nodeInfo.V6CIDR = ip.CIDRFromCalicoNet(*caliNodeCIDRV6).(ip.V6CIDR)
			}
		} else {
			ipv4, caliNodeCIDR := cresources.FindNodeAddress(node, apiv3.InternalIP, 4)
			if ipv4 == nil {
				ipv4, caliNodeCIDR = cresources.FindNodeAddress(node, apiv3.ExternalIP, 4)
			}
			ipv6, caliNodeCIDRV6 := cresources.FindNodeAddress(node, apiv3.InternalIP, 6)
			if ipv6 == nil {
				ipv6, caliNodeCIDRV6 = cresources.FindNodeAddress(node, apiv3.ExternalIP, 6)
			}
			hasIPv4 := (ipv4 != nil && caliNodeCIDR != nil)
			hasIPv6 := (ipv6 != nil && caliNodeCIDRV6 != nil)
			if hasIPv4 || hasIPv6 {
				nodeInfo = &l3rrNodeInfo{}
				if hasIPv4 {
					nodeInfo.V4Addr = ip.FromCalicoIP(*ipv4).(ip.V4Addr)
					nodeInfo.V4CIDR = ip.CIDRFromCalicoNet(*caliNodeCIDR).(ip.V4CIDR)
				}
				if hasIPv6 {
					nodeInfo.V6Addr = ip.FromCalicoIP(*ipv6).(ip.V6Addr)
					nodeInfo.V6CIDR = ip.CIDRFromCalicoNet(*caliNodeCIDRV6).(ip.V6CIDR)
				}
			}
		}

		if nodeInfo != nil {
			if node.Spec.Wireguard != nil && node.Spec.Wireguard.InterfaceIPv4Address != "" {
				nodeInfo.WireguardAddr = ip.FromString(node.Spec.Wireguard.InterfaceIPv4Address)
			}

			if node.Spec.BGP != nil && node.Spec.BGP.IPv4IPIPTunnelAddr != "" {
				nodeInfo.IPIPAddr = ip.FromString(node.Spec.BGP.IPv4IPIPTunnelAddr)
			}

			if node.Spec.IPv4VXLANTunnelAddr != "" {
				nodeInfo.VXLANAddr = ip.FromString(node.Spec.IPv4VXLANTunnelAddr)
			}

			if node.Spec.IPv6VXLANTunnelAddr != "" {
				nodeInfo.VXLANV6Addr = ip.FromString(node.Spec.IPv6VXLANTunnelAddr)
			}

			for _, a := range node.Spec.Addresses {
				parsed, _, err := cnet.ParseCIDROrIP(a.Address)
				if err == nil && parsed != nil {
					nodeInfo.Addresses = append(nodeInfo.Addresses, ip.FromCalicoIP(*parsed))
				} else {
					logrus.WithError(err).WithField("addr", a.Address).Warn("not an IP")
				}
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
				V4Addr: v4Addr,
				V4CIDR: v4Addr.AsCIDR().(ip.V4CIDR), // Don't know the CIDR so use the /32.
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

	if (newNodeInfo == nil && !nodeExisted) || (newNodeInfo != nil && nodeExisted && oldNodeInfo.Equal(*newNodeInfo)) {
		// No change.
		return
	}

	if nodeName == c.myNodeName {
		// Check if our CIDR has changed and if so recalculate the "same subnet" tracking.
		var (
			myNewNodeInfoKnown bool
			myNewV4CIDR        ip.V4CIDR
			myNewV6CIDR        ip.V6CIDR
		)
		if newNodeInfo != nil {
			myNewNodeInfoKnown = true
			myNewV4CIDR = newNodeInfo.V4CIDR
			myNewV6CIDR = newNodeInfo.V6CIDR
		}
		if oldNodeInfo.V4CIDR != myNewV4CIDR {
			// This node's CIDR has changed; some routes may now have an incorrect value for same-subnet.
			c.visitAllRoutes(c.trie.v4T, func(r nodenameRoute) {
				if r.nodeName == c.myNodeName {
					return // Ignore self.
				}
				otherNodeInfo, known := c.nodeNameToNodeInfo[r.nodeName]
				if !known {
					return // Don't know other node's CIDR so ignore for now.
				}
				otherNodesIPv4 := otherNodeInfo.V4Addr
				wasSameSubnet := nodeExisted && oldNodeInfo.V4CIDR.ContainsV4(otherNodesIPv4)
				nowSameSubnet := myNewNodeInfoKnown && myNewV4CIDR.ContainsV4(otherNodesIPv4)
				if wasSameSubnet != nowSameSubnet {
					logrus.WithField("route", r).Debug("Update to our subnet invalidated route")
					c.trie.MarkCIDRDirty(r.dst)
				}
			})
		}
		if oldNodeInfo.V6CIDR != myNewV6CIDR {
			// This node's CIDR has changed; some routes may now have an incorrect value for same-subnet.
			c.visitAllRoutes(c.trie.v4T, func(r nodenameRoute) {
				if r.nodeName == c.myNodeName {
					return // Ignore self.
				}
				otherNodeInfo, known := c.nodeNameToNodeInfo[r.nodeName]
				if !known {
					return // Don't know other node's CIDR so ignore for now.
				}
				otherNodesIPv6 := otherNodeInfo.V6Addr
				wasSameSubnet := nodeExisted && oldNodeInfo.V6CIDR.ContainsV6(otherNodesIPv6)
				nowSameSubnet := myNewNodeInfoKnown && myNewV6CIDR.ContainsV6(otherNodesIPv6)
				if wasSameSubnet != nowSameSubnet {
					logrus.WithField("route", r).Debug("Update to our subnet invalidated route")
					c.trie.MarkCIDRDirty(r.dst)
				}
			})
		}
	}

	// Process the tunnel addresses. These are reference counted, so handle adds followed by deletes to minimize churn.
	if newNodeInfo != nil {
		if newNodeInfo.IPIPAddr != nil {
			c.trie.AddRef(newNodeInfo.IPIPAddr.AsCIDR(), nodeName, RefTypeIPIP)
		}
		if newNodeInfo.VXLANAddr != nil {
			c.trie.AddRef(newNodeInfo.VXLANAddr.AsCIDR(), nodeName, RefTypeVXLAN)
		}
		if newNodeInfo.VXLANV6Addr != nil {
			c.trie.AddRef(newNodeInfo.VXLANV6Addr.AsCIDR(), nodeName, RefTypeVXLAN)
		}
		if newNodeInfo.WireguardAddr != nil {
			c.trie.AddRef(newNodeInfo.WireguardAddr.AsCIDR(), nodeName, RefTypeWireguard)
		}
	}
	if nodeExisted {
		if oldNodeInfo.IPIPAddr != nil {
			c.trie.RemoveRef(oldNodeInfo.IPIPAddr.AsCIDR(), nodeName, RefTypeIPIP)
		}
		if oldNodeInfo.VXLANAddr != nil {
			c.trie.RemoveRef(oldNodeInfo.VXLANAddr.AsCIDR(), nodeName, RefTypeVXLAN)
		}
		if oldNodeInfo.VXLANV6Addr != nil {
			c.trie.RemoveRef(oldNodeInfo.VXLANV6Addr.AsCIDR(), nodeName, RefTypeVXLAN)
		}
		if oldNodeInfo.WireguardAddr != nil {
			c.trie.RemoveRef(oldNodeInfo.WireguardAddr.AsCIDR(), nodeName, RefTypeWireguard)
		}
	}

	// Process the node CIDR and cache the node info.
	if nodeExisted {
		delete(c.nodeNameToNodeInfo, nodeName)
		for _, a := range oldNodeInfo.AddressesAsCIDRs() {
			c.trie.RemoveHost(a, nodeName)
		}
	}
	if newNodeInfo != nil {
		c.nodeNameToNodeInfo[nodeName] = *newNodeInfo
		for _, a := range newNodeInfo.AddressesAsCIDRs() {
			c.trie.AddHost(a, nodeName)
		}
	}

	c.markAllNodeRoutesDirty(nodeName)
}

func (c *L3RouteResolver) markAllNodeRoutesDirty(nodeName string) {
	c.nodeRoutes.visitRoutesForNode(nodeName, func(route nodenameRoute) {
		c.trie.MarkCIDRDirty(route.dst)
	})
}

func (c *L3RouteResolver) visitAllRoutes(trie *ip.CIDRTrie, v func(route nodenameRoute)) {
	trie.Visit(func(cidr ip.CIDR, data interface{}) bool {
		// Construct a nodenameRoute to pass to the visiting function.
		ri := trie.Get(cidr).(RouteInfo)
		nnr := nodenameRoute{dst: cidr}
		if len(ri.Refs) > 0 {
			// From a Ref.
			nnr.nodeName = ri.Refs[0].NodeName
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
	var poolCIDR ip.CIDR
	if oldPoolExists {
		// Need explicit oldPoolExists check so that we don't pass a zero-struct to poolTypeForPool.
		oldPoolType = c.poolTypeForPool(&oldPool)
		poolCIDR = ip.CIDRFromCalicoNet(oldPool.CIDR)
	}
	var newPool *model.IPPool
	if update.Value != nil {
		newPool = update.Value.(*model.IPPool)
	}
	newPoolType := c.poolTypeForPool(newPool)
	logCxt := logrus.WithFields(logrus.Fields{"oldType": oldPoolType, "newType": newPoolType})
	if newPool != nil && newPoolType != proto.IPPoolType_NONE {
		logCxt.Info("Pool is active")
		c.allPools[poolKey] = *newPool
		poolCIDR = ip.CIDRFromCalicoNet(newPool.CIDR)
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

// routesFromBlock returns a list of routes which should exist based on the provided
// allocation block.
func (c *L3RouteResolver) routesFromBlock(b *model.AllocationBlock) map[string]nodenameRoute {
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
	if host != "" {
		logrus.WithField("host", host).Debug("Block has a host, including block-via-host route")
		r := nodenameRoute{
			dst:      ip.CIDRFromCalicoNet(b.CIDR),
			nodeName: host,
		}
		routes[r.Key()] = r
	}

	return routes
}

// flush() iterates over the CIDRs that are marked dirty in the trie and sends any route updates
// that it finds.
func (c *L3RouteResolver) flush() {
	var buf []ip.CIDRTrieEntry
	c.trie.dirtyCIDRs.Iter(func(item interface{}) error {
		logCxt := logrus.WithField("cidr", item)
		logCxt.Debug("Flushing dirty route")

		cidr := item.(ip.CIDR)
		trie := c.trie.trieForCIDR(cidr)

		// We know the CIDR may be dirty, look up the path through the trie to the CIDR.  This will
		// give us the information about the enclosing CIDRs.  For example, if we have:
		// - IP pool     10.0.0.0/16 VXLAN
		// - IPAM block  10.0.1.0/26 node x
		// - IP          10.0.0.1/32 node y
		// Then, we'll see the pool, block and IP in turn on the lookup path allowing us to collect the
		// relevant information from each.
		buf = trie.LookupPath(buf, cidr)

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

			if len(ri.Refs) > 0 {
				// At least one Ref exists with this IP. It may be on this node, or a remote node.
				// In steady state we only ever expect a single workload Ref for this CIDR, or multiple tunnel Refs
				// sharing the same CIDR. However, there are rare transient cases we must handle where we may have
				// multiple workload, or workload and tunnel, or multiple node Refs with the same IP. Since this will be
				// transient, we can always just use the first entry (and related tunnel entries)
				rt.DstNodeName = ri.Refs[0].NodeName
				if ri.Refs[0].RefType == RefTypeWEP {
					// This is not a tunnel ref, so must be a workload.
					if ri.Refs[0].NodeName == c.myNodeName {
						rt.Type = proto.RouteType_LOCAL_WORKLOAD
						rt.LocalWorkload = true
					} else {
						rt.Type = proto.RouteType_REMOTE_WORKLOAD
					}
				} else {
					// This is a tunnel ref, set type and also store the tunnel type in the route. It is possible for
					// multiple tunnels to have the same IP, so collate all tunnel types on the same node.
					if ri.Refs[0].NodeName == c.myNodeName {
						rt.Type = proto.RouteType_LOCAL_TUNNEL
					} else {
						rt.Type = proto.RouteType_REMOTE_TUNNEL
					}

					rt.TunnelType = &proto.TunnelType{}
					for _, ref := range ri.Refs {
						if ref.NodeName != ri.Refs[0].NodeName {
							// This reference is on a different node to entry 0, so don't include.
							continue
						}

						switch ref.RefType {
						case RefTypeIPIP:
							rt.TunnelType.Ipip = true
						case RefTypeVXLAN:
							rt.TunnelType.Vxlan = true
						case RefTypeWireguard:
							rt.TunnelType.Wireguard = true
						}
					}
				}
			}
		}

		var emptyV4Addr ip.V4Addr
		var emptyV6Addr ip.V6Addr

		if rt.DstNodeName != "" {
			dstNodeInfo, exists := c.nodeNameToNodeInfo[rt.DstNodeName]
			if exists {
				switch cidr.Version() {
				case 4:
					if dstNodeInfo.V4Addr != emptyV4Addr {
						rt.DstNodeIp = dstNodeInfo.V4Addr.String()
					}
				case 6:
					if dstNodeInfo.V6Addr != emptyV6Addr {
						rt.DstNodeIp = dstNodeInfo.V6Addr.String()
					}
				default:
					logrus.WithField("cidr", cidr).Panic("Invalid IP version")
				}
			}
		}
		rt.SameSubnet = poolAllowsCrossSubnet && c.nodeInOurSubnet(rt.DstNodeName)

		if rt.Dst != emptyV4Addr.AsCIDR().String() && rt.Dst != emptyV6Addr.AsCIDR().String() {
			// Skip sending a route for an empty CIDR
			logrus.WithField("route", rt).Debug("Sending route")
			c.callbacks.OnRouteUpdate(rt)
			c.trie.SetRouteSent(cidr, true)
		}

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

	sameV4 := localNodeInfo.V4CIDR.ContainsV4(nodeInfo.V4Addr)
	sameV6 := localNodeInfo.V6CIDR != ip.V6CIDR{} && nodeInfo.V6Addr != ip.V6Addr{} && localNodeInfo.V6CIDR.ContainsV6(nodeInfo.V6Addr)

	return sameV4 || sameV6
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
	v4T        *ip.CIDRTrie
	v6T        *ip.CIDRTrie
	dirtyCIDRs set.Set
}

func NewRouteTrie() *RouteTrie {
	return &RouteTrie{
		v4T:        &ip.CIDRTrie{},
		v6T:        &ip.CIDRTrie{},
		dirtyCIDRs: set.New(),
	}
}

func (r *RouteTrie) UpdatePool(cidr ip.CIDR, poolType proto.IPPoolType, natOutgoing bool, crossSubnet bool) {
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

func (r *RouteTrie) markChildrenDirty(cidr ip.CIDR) {
	// TODO: avoid full scan to mark children dirty
	trie := r.trieForCIDR(cidr)
	trie.Visit(func(c ip.CIDR, data interface{}) bool {
		if cidr.Contains(c.Addr()) {
			r.MarkCIDRDirty(c)
		}
		return true
	})
}

func (r *RouteTrie) MarkCIDRDirty(cidr ip.CIDR) {
	r.dirtyCIDRs.Add(cidr)
}

func (r *RouteTrie) RemovePool(cidr ip.CIDR) {
	r.UpdatePool(cidr, proto.IPPoolType_NONE, false, false)
}

func (r *RouteTrie) UpdateBlockRoute(cidr ip.CIDR, nodeName string) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.Block.NodeName = nodeName
	})
}

func (r *RouteTrie) RemoveBlockRoute(cidr ip.CIDR) {
	r.UpdateBlockRoute(cidr, "")
}

func (r *RouteTrie) AddHost(cidr ip.CIDR, nodeName string) {
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

func (r *RouteTrie) RemoveHost(cidr ip.CIDR, nodeName string) {
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

func (r *RouteTrie) AddRef(cidr ip.CIDR, nodename string, rt RefType) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		// Find the ref in the list for this nodename,
		// if it exists. If it doesn't, we'll add it below.
		for i := range ri.Refs {
			// Reference count
			if ri.Refs[i].NodeName == nodename && ri.Refs[i].RefType == rt {
				// Found an existing ref. Just increment the RefCount
				// and return.
				ri.Refs[i].RefCount++
				return
			}
		}

		// If it doesn't already exist, add it to the slice and
		// sort the slice based on nodename and ref type to make sure we are not dependent
		// on event ordering.
		ref := Ref{NodeName: nodename, RefCount: 1, RefType: rt}
		ri.Refs = append(ri.Refs, ref)
		sort.Slice(ri.Refs, func(i, j int) bool {
			if ri.Refs[i].NodeName == ri.Refs[j].NodeName {
				return ri.Refs[i].RefType < ri.Refs[j].RefType
			}
			return ri.Refs[i].NodeName < ri.Refs[j].NodeName
		})
	})
}

func (r *RouteTrie) RemoveRef(cidr ip.CIDR, nodename string, rt RefType) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		for i := range ri.Refs {
			if ri.Refs[i].NodeName == nodename && ri.Refs[i].RefType == rt {
				// Decref the Ref.
				ri.Refs[i].RefCount--
				if ri.Refs[i].RefCount < 0 {
					logrus.WithField("cidr", cidr).Panic("BUG: Asked to decref a workload past 0.")
				} else if ri.Refs[i].RefCount == 0 {
					// Remove it from the list.
					ri.Refs = append(ri.Refs[:i], ri.Refs[i+1:]...)
				}
				if len(ri.Refs) == 0 {
					ri.Refs = nil
				}
				return
			}
		}

		// Unable to find the requested Ref.
		logrus.WithField("cidr", cidr).Panic("BUG: Asked to decref a workload that doesn't exist.")
	})
}

func (r *RouteTrie) SetRouteSent(cidr ip.CIDR, sent bool) {
	r.updateCIDR(cidr, func(ri *RouteInfo) {
		ri.WasSent = sent
	})
}

func (r RouteTrie) updateCIDR(cidr ip.CIDR, updateFn func(info *RouteInfo)) bool {
	if cidr == nil {
		logrus.WithField("cidr", cidr).Debug("Ignoring nil CIDR update")
		return false
	}

	trie := r.trieForCIDR(cidr)

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
		trie.Delete(cidr)
		return true
	}
	trie.Update(cidr, ri)
	return true
}

func (r RouteTrie) Get(cidr ip.CIDR) RouteInfo {
	trie := r.trieForCIDR(cidr)
	ri := trie.Get(cidr)

	if ri == nil {
		return RouteInfo{}
	}

	return ri.(RouteInfo)
}

func (r RouteTrie) trieForCIDR(cidr ip.CIDR) *ip.CIDRTrie {
	var trie *ip.CIDRTrie
	switch cidr.(type) {
	case ip.V4CIDR:
		trie = r.v4T
	case ip.V6CIDR:
		trie = r.v6T
	default:
		logrus.WithField("cidr", cidr).Panic("Invalid CIDR type")
	}
	return trie
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

	// Refs contains information extracted from workload endpoints, or tunnel addresses extracted from the node.
	Refs []Ref

	// WasSent is set to true when the route is sent downstream.
	WasSent bool
}

type RefType byte

const (
	RefTypeWEP RefType = iota
	RefTypeWireguard
	RefTypeIPIP
	RefTypeVXLAN
)

type Ref struct {
	// Count of Refs that have this CIDR.  Normally, for WEPs this will be 0 or 1 but Felix has to be tolerant
	// to bad data (two Refs with the same CIDR) so we do ref counting. For tunnel IPs, multiple tunnels may share the
	// same IP, so again ref counting is necessary here.
	RefCount int

	// The type of reference.
	RefType RefType

	// NodeName contains the nodename for this Ref / CIDR.
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
		len(r.Refs) > 0
}

// Copy returns a copy of the RouteInfo. Since some fields are pointers, we need to
// explicitly copy them so that they are not shared between the copies.
func (r RouteInfo) Copy() RouteInfo {
	cp := r
	if len(r.Refs) != 0 {
		cp.Refs = make([]Ref, len(r.Refs))
		copy(cp.Refs, r.Refs)
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

// nodeRoutes is used for efficiently looking up routes associated with a node.
// It uses a reference counter so that we can properly handle intermediate cases where
// the same CIDR might appear twice.
type nodeRoutes struct {
	cache map[string]map[ip.CIDR]int
}

func newNodeRoutes() nodeRoutes {
	return nodeRoutes{
		cache: map[string]map[ip.CIDR]int{},
	}
}

func (nr *nodeRoutes) Add(r nodenameRoute) {
	if _, ok := nr.cache[r.nodeName]; !ok {
		nr.cache[r.nodeName] = map[ip.CIDR]int{r.dst: 0}
	}
	nr.cache[r.nodeName][r.dst]++
}

func (nr *nodeRoutes) Remove(r nodenameRoute) {
	_, ok := nr.cache[r.nodeName]
	if !ok {
		logrus.WithField("route", r).Panic("BUG: Asked to decref for node that doesn't exist")
	}
	nr.cache[r.nodeName][r.dst]--
	if nr.cache[r.nodeName][r.dst] == 0 {
		delete(nr.cache[r.nodeName], r.dst)
	} else if nr.cache[r.nodeName][r.dst] < 0 {
		logrus.WithField("route", r).Panic("BUG: Asked to decref a route past 0.")
	}
	if len(nr.cache[r.nodeName]) == 0 {
		delete(nr.cache, r.nodeName)
	}
}

func (nr *nodeRoutes) visitRoutesForNode(nodename string, v func(nodenameRoute)) {
	for cidr := range nr.cache[nodename] {
		v(nodenameRoute{nodeName: nodename, dst: cidr})
	}
}
