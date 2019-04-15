package calc

import (
	"crypto/sha1"
	"fmt"
	gonet "net"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/dispatcher"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/net"
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
	blockToRoutes             map[string]set.Set
	vxlanPools                map[string]model.IPPool
}

func NewVXLANResolver(hostname string, callbacks PipelineCallbacks) *VXLANResolver {
	return &VXLANResolver{
		hostname:                  hostname,
		callbacks:                 callbacks,
		nodeNameToVXLANTunnelAddr: map[string]string{},
		nodeNameToIPAddr:          map[string]string{},
		blockToRoutes:             map[string]set.Set{},
		vxlanPools:                map[string]model.IPPool{},
	}
}

func (c *VXLANResolver) RegisterWith(allUpdDispatcher *dispatcher.Dispatcher) {
	allUpdDispatcher.Register(model.HostIPKey{}, c.OnHostIPUpdate)
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
		currentRoutes, ok := c.blockToRoutes[key]
		if !ok {
			currentRoutes = set.New()
			c.blockToRoutes[key] = currentRoutes
		}

		for _, r := range newRoutes {
			logCxt := logrus.WithField("newRoute", r)
			if currentRoutes.Contains(r) {
				logCxt.Debug("Desired VXLAN route already exists, skip")
				continue
			}

			c.blockToRoutes[key].Add(r)
			adds.Add(r)
		}

		currentRoutes.Iter(func(item interface{}) error {
			r := item.(vxlanRoute)

			// For each existing route which is no longer present, we need to delete it.
			if _, ok := newRoutes[r.Key()]; ok {
				// Exists, and we want it to - nothing to do.
				return nil
			}

			// Current route is not in new set - we need to withdraw the route, and also
			// remove it from internal state.
			deletes.Add(r)
			c.blockToRoutes[key].Discard(r)
			return nil
		})

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

// OnHostIPUpdate gets called whenever a node IP address changes. On an add/update,
// we need to check if there are VTEPs or routes which are now valid, and trigger programming
// of them to the data plane. On a delete, we need to withdraw any routes and VTEPs associated
// with the node.
func (c *VXLANResolver) OnHostIPUpdate(update api.Update) (_ bool) {
	nodeName := update.Key.(model.HostIPKey).Hostname
	logCxt := logrus.WithField("node", nodeName)
	pendingSet, sentSet := c.routeSets()
	vtepSent := c.vtepSent(nodeName)
	if update.Value != nil {
		// Host IP updated or added. If it was added, we should check to see if we're ready
		// to send a VTEP and associated routes. If we already knew about this one, we need to
		// see if it has changed. If it has, we should remove and reprogram the VTEP and routes.
		newIP := update.Value.(*net.IP).String()
		currIP := c.nodeNameToIPAddr[nodeName]
		logCxt = logCxt.WithFields(logrus.Fields{"newIP": newIP, "currIP": currIP})
		if vtepSent {
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

	} else {
		// Withdraw any routes which target this VTEP, followed by the VTEP itself.
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
	return
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
			// We already know about this IP pool. Check to see if the CIDR has changed.
			// While this isn't possible directly in the user-facing API, it's possible that
			// we see a delete/recreate as an update over the Syncer in rare cases.
			if curr.CIDR.String() == update.Value.(*model.IPPool).CIDR.String() {
				return
			}

			// If the CIDR has changed, treat this as a delete followed by a re-create
			// with the new CIDR. Iterate through sent routes and withdraw any within
			// the old CIDR.
			delete(c.vxlanPools, k.String())
			sentSet.Iter(func(item interface{}) error {
				r := item.(vxlanRoute)
				if !c.containsRoute(curr, r) {
					c.withdrawRoute(r)
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
	gw := c.determineGatewayForRoute(r)
	if gw == "" {
		logCxt.Debug("No gateway yet for VXLAN route, skip")
		return false
	}
	if !c.routeWithinVXLANPool(r) {
		logCxt.Debug("Route not within VXLAN IP pool")
		return false
	}
	if !c.vtepSent(r.node) {
		logCxt.Debug("Don't yet know the VTEP for this route")
		return false
	}
	return true
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
		c.callbacks.OnRouteUpdate(&proto.RouteUpdate{
			Type: proto.RouteType_VXLAN,
			Node: r.node,
			Dst:  r.dst.String(),
			Gw:   c.determineGatewayForRoute(r),
		})
		return nil
	})
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

// routesFromBlock returns a list of routes which should exist based on the provided
// allocation block. Right now, we only support strict affinity so this will always
// be the block's CIDR.
func (c *VXLANResolver) routesFromBlock(blockKey string, b *model.AllocationBlock) map[string]vxlanRoute {
	if b.Host() == c.hostname {
		logrus.Debug("Skipping VXLAN routes for local node")
		return nil
	}

	r := vxlanRoute{
		dst:  ip.CIDRFromCalicoNet(b.CIDR),
		node: b.Host(),
	}
	return map[string]vxlanRoute{r.Key(): r}
}

// determineGatewayForRoute determines which gateway to use for this route. For VXLAN routes, the
// gateway is the remote node's IPv4VXLANTunnelAddr. If we don't know the remote node's tunnel
// address, this function will return an empty string.
func (c *VXLANResolver) determineGatewayForRoute(r vxlanRoute) string {
	return c.nodeNameToVXLANTunnelAddr[r.node]
}

// vtepMACForHost calculates a deterministic MAC address based on the provided host.
// The returned address matches the address assigned to the VXLAN device on that node.
func (c *VXLANResolver) vtepMACForHost(nodename string) string {
	hasher := sha1.New()
	hasher.Write([]byte(nodename))
	sha := hasher.Sum(nil)
	var hw gonet.HardwareAddr
	hw = gonet.HardwareAddr(append([]byte("f"), sha[0:5]...))
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
