// Copyright (c) 2016-2019 Tigera, Inc. All rights reserved.
//
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

package wireguard

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/projectcalico/felix/ifacemonitor"
	"github.com/projectcalico/felix/ip"
	netlinkshim "github.com/projectcalico/felix/netlink"
	"github.com/projectcalico/felix/routerule"
	"github.com/projectcalico/felix/routetable"
	timeshim "github.com/projectcalico/felix/time"
	"github.com/projectcalico/libcalico-go/lib/set"
)

const (
	// The number of netlink connection retries before we either panic (for standard link operations) or back-off (for
	// wireguard operations).
	maxConnFailures = 3

	// For wireguard client connections we back off retries and only try to actually connect once every
	// <wireguardClientRetryInterval> requests.
	wireguardClientRetryInterval = 10
)

var (
	ErrUpdateFailed                = errors.New("netlink update operation failed")
	ErrNotSupportedTooManyFailures = errors.New("operation not supported (too many failures)")

	// Internal types
	errWrongInterfaceType = errors.New("incorrect interface type for wireguard")

	zeroKey = wgtypes.Key{}
)

const (
	wireguardType = "wireguard"
	ipVersion     = 4
	ipPrefixLen   = 32
)

type noOpConnTrack struct{}

func (*noOpConnTrack) RemoveConntrackFlows(ipVersion uint8, ipAddr net.IP) {}

type peerData struct {
	ipv4EndpointAddr      ip.Addr
	publicKey             wgtypes.Key
	cidrs                 set.Set
	programmedInWireguard bool
	routingToWireguard    bool
}

func newPeerData() *peerData {
	return &peerData{
		cidrs: set.New(),
	}
}

func (n *peerData) allowedCidrsForWireguard() []net.IPNet {
	cidrs := make([]net.IPNet, 0, n.cidrs.Len())
	n.cidrs.Iter(func(item interface{}) error {
		cidrs = append(cidrs, item.(ip.CIDR).ToIPNet())
		return nil
	})
	return cidrs
}

type peerUpdateData struct {
	deleted             bool
	ipv4EndpointAddr    *ip.Addr
	publicKey           *wgtypes.Key
	allowedCidrsAdded   set.Set
	allowedCidrsDeleted set.Set
}

func newPeerUpdateData() *peerUpdateData {
	return &peerUpdateData{
		allowedCidrsDeleted: set.New(),
		allowedCidrsAdded:   set.New(),
	}
}

type Wireguard struct {
	// Wireguard configuration (this will not change without a restart).
	hostname string
	config   *Config
	logCxt   *logrus.Entry

	// Clients, client factories and testing shims.
	newNetlinkClient                     func() (netlinkshim.Netlink, error)
	newWireguardClient                   func() (netlinkshim.Wireguard, error)
	cachedNetlinkClient                  netlinkshim.Netlink
	cachedWireguardClient                netlinkshim.Wireguard
	numConsistentNetlinkClientFailures   int
	numConsistentWireguardClientFailures int
	time                                 timeshim.Time

	// State information.
	inSyncWireguard                    bool
	inSyncLink                         bool
	inSyncInterfaceAddr                bool
	ifaceUp                            bool
	wireguardNotSupported              bool
	ourPublicKey                       *wgtypes.Key
	ourIPv4InterfaceAddr               ip.Addr
	ourPublicKeyAgreesWithDataplaneMsg bool

	// Local workload information
	localCIDRsFiltered set.Set
	localIPs           set.Set
	localCIDRs         set.Set
	localCIDRsUpdated  bool

	// Current configuration
	// - all peerData information
	// - mapping between CIDRs and peerData
	// - mapping between public key and peers - this does not include the "zero" key.
	peers                map[string]*peerData
	publicKeyToNodeNames map[wgtypes.Key]set.Set

	// Pending updates
	peerUpdates map[string]*peerUpdateData

	// CIDR to node mappings - this is updated synchronously.
	cidrToNodeName map[ip.CIDR]string

	// Wireguard routing table and rule managers
	routetable *routetable.RouteTable
	routerule  *routerule.RouteRules

	// Callback function used to notify of public key updates for the local peerData
	statusCallback func(publicKey wgtypes.Key) error
}

func New(
	hostname string,
	config *Config,
	netlinkTimeout time.Duration,
	deviceRouteProtocol int,
	statusCallback func(publicKey wgtypes.Key) error,
) *Wireguard {
	return NewWithShims(
		hostname,
		config,
		netlinkshim.NewRealNetlink,
		netlinkshim.NewRealNetlink,
		netlinkshim.NewRealNetlink,
		netlinkshim.NewRealWireguard,
		netlinkTimeout,
		timeshim.NewRealTime(),
		deviceRouteProtocol,
		statusCallback,
	)
}

// NewWithShims is a test constructor, which allows linkClient, arp and time to be replaced by shims.
func NewWithShims(
	hostname string,
	config *Config,
	newRoutetableNetlink func() (netlinkshim.Netlink, error),
	newRouteRuleNetlink func() (netlinkshim.Netlink, error),
	newWireguardNetlink func() (netlinkshim.Netlink, error),
	newWireguardDevice func() (netlinkshim.Wireguard, error),
	netlinkTimeout time.Duration,
	timeShim timeshim.Time,
	deviceRouteProtocol int,
	statusCallback func(publicKey wgtypes.Key) error,
) *Wireguard {
	// Create routetable. We provide dummy callbacks for ARP and conntrack processing.
	rt := routetable.NewWithShims(
		[]string{"^" + config.InterfaceName + "$", routetable.InterfaceNone},
		ipVersion,
		newRoutetableNetlink,
		false, // vxlan
		netlinkTimeout,
		func(cidr ip.CIDR, destMAC net.HardwareAddr, ifaceName string) error { return nil }, // addStaticARPEntry
		&noOpConnTrack{},
		timeShim,
		nil, //deviceRouteSourceAddress
		deviceRouteProtocol,
		true, //removeExternalRoutes
		config.RoutingTableIndex,
	)
	// Create routerule.
	rr, err := routerule.NewWithShims(
		ipVersion,
		config.RoutingRulePriority,
		set.From(config.RoutingTableIndex),
		routerule.RulesMatchSrcFWMarkTable,
		routerule.RulesMatchSrcFWMarkTable,
		netlinkTimeout,
		func() (routerule.HandleIface, error) {
			return newRouteRuleNetlink()
		},
	)
	if err != nil && config.Enabled {
		// Wireguard is enabled, but could not create a routerule manager. This is unexpected.
		logrus.WithError(err).Panic("Unexpected error creating rule manager")
	}

	return &Wireguard{
		hostname:             hostname,
		config:               config,
		logCxt:               logrus.WithFields(logrus.Fields{"enabled": config.Enabled, "wgIfaceName": config.InterfaceName}),
		newNetlinkClient:     newWireguardNetlink,
		newWireguardClient:   newWireguardDevice,
		time:                 timeShim,
		peers:                map[string]*peerData{},
		cidrToNodeName:       map[ip.CIDR]string{},
		publicKeyToNodeNames: map[wgtypes.Key]set.Set{},
		peerUpdates:          map[string]*peerUpdateData{},
		routetable:           rt,
		routerule:            rr,
		statusCallback:       statusCallback,
		localCIDRsFiltered:   set.New(),
		localIPs:             set.New(),
		localCIDRs:           set.New(),
	}
}

func (w *Wireguard) OnIfaceStateChanged(ifaceName string, state ifacemonitor.State) {
	if w.config.InterfaceName != ifaceName {
		w.logCxt.WithField("ifaceName", ifaceName).Debug("Ignoring interface state change, not the wireguard interface.")
		return
	}
	switch state {
	case ifacemonitor.StateUp:
		w.logCxt.Debug("Interface up, marking for route sync")
		if !w.ifaceUp {
			w.ifaceUp = true
			w.inSyncWireguard = false
		}
	case ifacemonitor.StateDown:
		w.logCxt.Debug("Interface down")
		w.ifaceUp = false
	}

	// Notify the wireguard routetable module.
	w.routetable.OnIfaceStateChanged(ifaceName, state)
}

func (w *Wireguard) EndpointUpdate(name string, ipv4Addr ip.Addr) {
	w.logCxt.Debugf("EndpointUpdate: name=%s; ipv4Addr=%v", name, ipv4Addr)
	if !w.config.Enabled {
		w.logCxt.Debug("Not enabled - ignoring")
		return
	} else if name == w.hostname {
		// We don't need our own IP address, just interested in the peers.
		return
	}

	update := w.getOrInitPeerUpdate(name)
	if existing, ok := w.peers[name]; ok && existing.ipv4EndpointAddr == ipv4Addr {
		w.logCxt.Debug("Update contains unchanged IPv4 address")
		update.ipv4EndpointAddr = nil
	} else {
		w.logCxt.Debug("Update contains new IPv4 address")
		update.ipv4EndpointAddr = &ipv4Addr
	}
	w.setPeerUpdate(name, update)
}

func (w *Wireguard) EndpointRemove(name string) {
	w.logCxt.Debugf("EndpointRemove: name=%s", name)
	if !w.config.Enabled {
		w.logCxt.Debug("Not enabled - ignoring")
		return
	} else if name == w.hostname {
		w.logCxt.Debug("Local update - ignoring")
		return
	}

	if _, ok := w.peers[name]; ok {
		// Node data exists, so store a blank update with a deleted flag. The delete will be applied first, and then any
		// subsequent updates. There is no need to remove the pending CIDR to node mappings since the route resolver
		// provides self consistent route updates (i.e. we will get route removes or updates for these CIDRs).
		w.logCxt.Debug("Existing node is flagged for removal")
		nu := newPeerUpdateData()
		nu.deleted = true
		w.setPeerUpdate(name, nu)
	} else {
		// Node data is not yet programmed so just delete the pending update.
		w.logCxt.Debug("Node removed which has not yet been programmed - remove any pending update")
		delete(w.peerUpdates, name)
	}
}

func (w *Wireguard) RouteUpdate(name string, cidr ip.CIDR) {
	w.logCxt.Debugf("RouteUpdate: name=%s; cidr=%v", name, cidr)
	if !w.config.Enabled {
		w.logCxt.Debug("Not enabled - ignoring")
		return
	}

	// Determine which node this CIDR belongs to.
	if existing, ok := w.cidrToNodeName[cidr]; ok {
		if name == existing {
			// Update for the same CIDR and node - this is a no-op.
			return
		}
		// Update is moving CIDR to a different node. Do the delete first.
		w.routeRemove(existing, cidr)
	}

	// Update the CIDR->node mapping.
	w.cidrToNodeName[cidr] = name

	// If this is the local node then store as a local workload CIDR, otherwise store as a peer CIDR.
	if name == w.hostname {
		w.localWorkloadCIDRAdd(cidr)
	} else {
		w.peerAllowedCIDRAdd(name, cidr)
	}
}

func (w *Wireguard) RouteRemove(cidr ip.CIDR) {
	w.logCxt.Debugf("RouteRemove: cidr=%v", cidr)
	if !w.config.Enabled {
		w.logCxt.Debug("Not enabled - ignoring")
		return
	}

	// Determine which node this CIDR belongs to. Check the updates first and then the processed.
	name, ok := w.cidrToNodeName[cidr]
	if !ok {
		// The wireguard manager filters out some of the CIDR updates, but not the removes, so it's possible to get
		// CIDR removes for which we have seen no corresponding add.
		w.logCxt.Debugf("CIDR remove update but not associated with a node: %v", cidr)
		return
	}
	w.logCxt.Debugf("CIDR found for node %s", name)
	w.routeRemove(name, cidr)
}

func (w *Wireguard) routeRemove(name string, cidr ip.CIDR) {
	// Remove the CIDR->node mapping.
	delete(w.cidrToNodeName, cidr)

	// If this is the local node then remove as a local workload CIDR, otherwise remove as a peer CIDR.
	if name == w.hostname {
		w.localWorkloadCIDRRemove(cidr)
	} else {
		w.peerAllowedCIDRRemove(name, cidr)
	}
}

// Add a local workload CIDR. These CIDRs are used for the source-matched wireguard routes to limit wireguard encryption
// to traffic to/from local workloads. The workload CIDRs may overlap, in which case the updateAndApplyRouteRules
// method will determine the minimal set of non-overlapping CIDRs.
func (w *Wireguard) localWorkloadCIDRAdd(cidr ip.CIDR) {
	w.logCxt.Debugf("localWorkloadCIDRAdd: cidr=%v", cidr)
	// Split the local CIDRs into actual /32 workload IPs and the CIDR blocks for the node. We assume the CIDR blocks
	// are not overlapping, and so we add rules for each CIDR to route to wireguard, and only include the /32 workload
	// IPs if not covered by the CIDR blocks.
	if cidr.Prefix() == ipPrefixLen {
		w.localIPs.Add(cidr.Addr())
	} else {
		w.localCIDRs.Add(cidr)
	}
	// Only flag the CIDRs for update if it not wholly covered by the already filtered local CIDRs.
	contained := false
	w.localCIDRsFiltered.Iter(func(item interface{}) error {
		filtered := item.(ip.CIDR)
		filteredIPNet := filtered.ToIPNet()
		if filteredIPNet.Contains(cidr.ToIPNet().IP) && filtered.Prefix() >= cidr.Prefix() {
			contained = true
			return set.StopIteration
		}
		return nil
	})
	if !contained {
		w.localCIDRsUpdated = true
	}
}

// Remove a local workload CIDR. These CIDRs are used for the source-matched wireguard routes to limit wireguard
// encryption to traffic to/from local workloads.
func (w *Wireguard) localWorkloadCIDRRemove(cidr ip.CIDR) {
	w.logCxt.Debugf("localWorkloadCIDRRemove: cidr=%v", cidr)
	if cidr.Prefix() == ipPrefixLen {
		w.localIPs.Discard(cidr.Addr())
	} else {
		w.localCIDRs.Discard(cidr)
	}
	// Only flag the CIDRs for update if this CIDR is one of the filtered CIDRs.
	if w.localCIDRsFiltered.Contains(cidr) {
		w.localCIDRsUpdated = true
	}
}

// Add a peer allowed CIDR.  These CIDRs are used for the destination-matched wireguard routes to limit wireguard
// encryption to traffic to/from remote workloads.
func (w *Wireguard) peerAllowedCIDRAdd(name string, cidr ip.CIDR) {
	w.logCxt.Debugf("peerAllowedCIDRAdd: cidr=%v", cidr)
	update := w.getOrInitPeerUpdate(name)
	if existing, ok := w.peers[name]; ok && existing.cidrs.Contains(cidr) {
		// Adding the CIDR to a node that already has it. This may happen if there is a pending CIDR deletion for the
		// node, so discard the deletion update.
		w.logCxt.Debug("Node CIDR added which is already programmed - remove any pending delete")
		update.allowedCidrsDeleted.Discard(cidr)
	} else {
		// Adding the CIDR to a node that does not already have it.
		w.logCxt.Debug("Node CIDR added which is not programmed")
		update.allowedCidrsAdded.Add(cidr)
	}
	w.setPeerUpdate(name, update)
}

// Remove a peer allowed CIDR.  These CIDRs are used for the destination-matched wireguard routes to limit wireguard
// encryption to traffic to/from remote workloads.
func (w *Wireguard) peerAllowedCIDRRemove(name string, cidr ip.CIDR) {
	w.logCxt.Debugf("peerAllowedCIDRRemove: cidr=%v", cidr)
	update := w.getOrInitPeerUpdate(name)
	if existing, ok := w.peers[name]; ok && existing.cidrs.Contains(cidr) {
		// Remove the CIDR from a node that already has the CIDR configured.
		w.logCxt.Debug("Node CIDR removed")
		update.allowedCidrsDeleted.Add(cidr)
	} else {
		// Deleting the CIDR from a node that already doesn't have it configured. This may happen if there is a pending
		// CIDR addition for the node, so discard the addition update.
		w.logCxt.Debug("Node CIDR removed but is not programmed - remove any pending add")
		update.allowedCidrsAdded.Discard(cidr)
	}
	w.setPeerUpdate(name, update)
}

func (w *Wireguard) EndpointWireguardUpdate(name string, publicKey wgtypes.Key, ipv4InterfaceAddr ip.Addr) {
	w.logCxt.Debugf("EndpointWireguardUpdate: name=%s; key=%s, ipv4Addr=%v", name, publicKey, ipv4InterfaceAddr)
	if !w.config.Enabled {
		w.logCxt.Debug("Not enabled - ignoring")
		return
	}

	if name == w.hostname {
		w.logCxt.Debug("Local wireguard info updated")
		if w.ourPublicKey == nil || *w.ourPublicKey != publicKey {
			// Public key does not match that stored. Flag as not in-sync, we will update the value from the dataplane
			// and publish.
			w.logCxt.Debug("Stored public key does not match key queried from dataplane")
			w.ourPublicKeyAgreesWithDataplaneMsg = false
		}
		if w.ourIPv4InterfaceAddr != ipv4InterfaceAddr {
			w.logCxt.Debug("Local interface addr updated")
			w.ourIPv4InterfaceAddr = ipv4InterfaceAddr
			w.inSyncInterfaceAddr = false
		}
		return
	}

	update := w.getOrInitPeerUpdate(name)
	if existing, ok := w.peers[name]; ok && existing.publicKey == publicKey {
		// Public key not updated
		w.logCxt.Debug("Public key unchanged from programmed")
		update.publicKey = nil
	} else {
		// Public key updated (or this is a previously unseen node)
		w.logCxt.Debug("Storing updated public key")
		update.publicKey = &publicKey
	}
	w.setPeerUpdate(name, update)
}

func (w *Wireguard) EndpointWireguardRemove(name string) {
	w.logCxt.Debugf("EndpointWireguardRemove: name=%s", name)
	if !w.config.Enabled {
		w.logCxt.Debug("Not enabled - ignoring")
		return
	}
	if name == w.hostname {
		w.EndpointWireguardUpdate(name, zeroKey, nil)
	}

	// If there is no existing peer and no existing update then exit.
	if _, ok := w.peers[name]; ok {
		w.logCxt.Debugf("Peer %s is programmed", name)
	} else if _, ok := w.peerUpdates[name]; !ok {
		w.logCxt.Debugf("Peer %s is not programmed, and there are no updates", name)
		return
	}

	// Create update to remove the public key.
	update := w.getOrInitPeerUpdate(name)
	update.publicKey = &zeroKey
	w.setPeerUpdate(name, update)
}

func (w *Wireguard) QueueResync() {
	w.logCxt.Info("Queueing a resync of wireguard configuration")

	// Flag for resync to ensure everything is still configured correctly.
	// No need to resync the key. This will happen if the dataplane resync detects an inconsistency.
	w.setAllInSync(false)

	// Assume wireguard is supported unless we determine otherwise. If we determine unsupported then we'll short-circuit
	// the Apply processing until the next resync.
	w.wireguardNotSupported = false

	// Flag the routetable for resync.
	w.routetable.QueueResync()

	// Flag the routerule for resync.
	if w.routerule != nil {
		w.routerule.QueueResync()
	}
}

func (w *Wireguard) Apply() (err error) {
	// If the key is not in-sync and is known then send as a status update.
	defer func() {
		// If we need to send the key then send on the callback method.
		if !w.ourPublicKeyAgreesWithDataplaneMsg && w.ourPublicKey != nil {
			w.logCxt.Infof("Public key out of sync or updated: %s", *w.ourPublicKey)
			if errKey := w.statusCallback(*w.ourPublicKey); errKey != nil {
				err = errKey
				return
			}

			// We have sent the key status update.
			w.ourPublicKeyAgreesWithDataplaneMsg = true
		}
	}()

	// Get the netlink client - we should always be able to get this client.
	netlinkClient, err := w.getNetlinkClient()
	if err != nil {
		w.logCxt.Errorf("error obtaining link client: %v", err)
		return err
	}

	// If wireguard is not enabled, then short-circuit the processing - ensure config is deleted.
	if !w.config.Enabled {
		w.logCxt.Info("Wireguard is not enabled")
		if !w.inSyncWireguard {
			w.logCxt.Debug("Wireguard is not in-sync - verifying wireguard configuration is removed")
			if err := w.ensureDisabled(netlinkClient); err != nil {
				return err
			}

			// Zero out the public key.
			w.ourPublicKey = &zeroKey
			w.inSyncWireguard = true
		}
		return nil
	}

	if w.wireguardNotSupported {
		w.logCxt.Info("Wireguard is not supported")
		return
	}

	// --- Wireguard is enabled ---

	// We scan the updates multiple times to perform the following ordered updates:
	// 1. Deletion of peers and wireguard peers (we handle these separately from other updates because it is easier
	//    to handle a delete/re-add this way without needing to calculate delta configs.
	// 2. Update of cached node configuration (we cannot be certain exactly what is programmable until updated)
	// 3. Update of route table routes.
	// 4. Construction of wireguard delta (if performing deltas, or re-sync of wireguard configuration)
	// 5. Simultaneous updates of wireguard, routes and rules.
	var conflictingKeys = set.New()
	wireguardPeerDelete := w.handlePeerAndRouteDeletionFromPeerUpdates(conflictingKeys)
	w.updateCacheFromPeerUpdates(conflictingKeys)
	w.updateRouteTableFromPeerUpdates()

	defer func() {
		// Flag the programmed state to be the same as the expected state for each peer. We do this even if we failed to
		// apply the update because the routetable processing also uses this to maintain details about whether or not it
		// has routed to wireguard. In the event of a failed update or wireguard config, a full resync will be performed
		// next iteration which ignores the programmedInWireguard flag.
		if len(w.peerUpdates) > 0 {
			for name, node := range w.peers {
				if w.shouldProgramWireguardPeer(name, node) {
					w.logCxt.Debugf("Flag node %s as programmed", name)
					node.programmedInWireguard = true
				} else {
					w.logCxt.Debugf("Flag node %s as not programmed", name)
					node.programmedInWireguard = false
				}
			}
		}

		// All updates have been applied. Make sure we delete them after we exit - we will either have applied the deltas,
		// or we'll need to do a full resync, in either case no need to keep the deltas.  Don't do this immediately because
		// we may need them to calculate the wireguard config delta.
		w.peerUpdates = map[string]*peerUpdateData{}
	}()

	// If necessary ensure the wireguard device is configured. If this errors or if it is not yet oper up then no point
	// doing anything else.
	if !w.inSyncLink {
		w.logCxt.Debug("Ensure wireguard link is created and up")
		linkUp, err := w.ensureLink(netlinkClient)
		if netlinkshim.IsNotSupported(err) {
			// Wireguard is not supported, set everything to "in-sync" since there is not a lot of point doing anything
			// else. We don't return an error in this case, instead we'll retry every resync period.
			w.logCxt.Info("Wireguard is not supported - publishing no public key")
			w.setNotSupported()
			return nil
		} else if err != nil {
			// Error configuring link, pass up the stack. Close the netlink client as a precaution.
			w.logCxt.WithError(err).Info("Unable to create wireguard link, retrying...")
			w.closeNetlinkClient()
			return ErrUpdateFailed
		} else if !linkUp {
			// Wait for oper up notification.
			w.logCxt.Info("Waiting for wireguard link to come up...")
			return nil
		}
	}

	// Get the wireguard client. This may not always be possible.
	wireguardClient, err := w.getWireguardClient()
	if netlinkshim.IsNotSupported(err) {
		w.logCxt.Info("Wireguard is not supported - send zero-key status")
		w.setNotSupported()
		return nil
	} else if err != nil {
		w.logCxt.WithError(err).Error("error obtaining wireguard client")
		return ErrUpdateFailed
	}

	// The following can be done in parallel:
	// - Update the link address
	// - Update the routetable
	// - Update the wireguard device.
	var wg sync.WaitGroup
	var errLink, errWireguard, errRoutes error

	// Update link address if out of sync.
	if !w.inSyncInterfaceAddr {
		w.logCxt.Info("Ensure wireguard interface address is correct")
		wg.Add(1)
		go func() {
			defer wg.Done()
			if errLink = w.ensureLinkAddressV4(netlinkClient); errLink == nil {
				w.inSyncInterfaceAddr = true
			}
		}()
	}

	// Apply routetable updates.
	w.logCxt.Debug("Apply routing table updates for wireguard")
	wg.Add(1)
	go func() {
		defer wg.Done()
		errRoutes = w.routetable.Apply()
	}()

	// Apply wireguard configuration.
	wg.Add(1)
	var wireguardPeerUpdate *wgtypes.Config
	var publicKey wgtypes.Key
	go func() {
		defer wg.Done()

		// Update wireguard so that we are in-sync.
		if w.inSyncWireguard {
			// Wireguard configuration is in-sync, perform a delta update. First do the delete that was constructed
			// earlier, then construct and apply the update. Flag as not in-sync until we have finished processing.
			w.logCxt.Debug("Apply wireguard crypto routing delta update")
			if errWireguard = w.applyWireguardConfig(wireguardClient, wireguardPeerDelete); errWireguard != nil {
				w.logCxt.WithError(errWireguard).Info("Failed to delete wireguard peers")
				return
			}
			wireguardPeerUpdate = w.constructWireguardDeltaFromPeerUpdates(conflictingKeys)
			if errWireguard = w.applyWireguardConfig(wireguardClient, wireguardPeerUpdate); errWireguard != nil {
				w.logCxt.WithError(errWireguard).Info("Failed to create or update wireguard peers")
				return
			}
		} else {
			// Wireguard configuration is not in-sync. Construct and apply the wireguard configuration required to
			// synchronize with our cached data.
			w.logCxt.Debug("Apply wireguard crypto routing resync")
			if publicKey, wireguardPeerUpdate, errWireguard = w.constructWireguardDeltaForResync(wireguardClient); errWireguard != nil {
				w.logCxt.WithError(errWireguard).Info("Failed to construct a full wireguard delta for resync")
				return
			} else if errWireguard = w.applyWireguardConfig(wireguardClient, wireguardPeerUpdate); errWireguard != nil {
				w.logCxt.WithError(errWireguard).Info("Failed to update wireguard peers for resync")
				return
			} else if w.ourPublicKey == nil || *w.ourPublicKey != publicKey {
				// The public key differs from the one we previously queried or this is the first time we queried it.
				// Store and flag our key is not in sync so that a status update will be sent.
				w.logCxt.Infof("Public key has been updated to %s, send status notification", publicKey)
				w.ourPublicKey = &publicKey
				w.ourPublicKeyAgreesWithDataplaneMsg = false
			}
		}
		w.inSyncWireguard = true
	}()

	// Wait for the updates to complete.
	wg.Wait()

	if errWireguard != nil {
		// Error applying the wireguard config. Close the wireguard client as a precaution - this will force us to open
		// a new client on the next apply.
		w.logCxt.Info("Wireguard programming failed, ensure full resync is performed next")
		w.closeWireguardClient()
		w.inSyncWireguard = false
	}
	if errLink != nil {
		// Error applying the link configuration. Close the netlink client as a precaution - this will force us to open
		// a new client on the next apply.
		w.closeNetlinkClient()
	}

	if errLink != nil || errRoutes != nil || errWireguard != nil {
		return ErrUpdateFailed
	}

	// Once the wireguard and routing configuration is in place we can add the routing rules to start using the new
	// routing table.
	w.logCxt.Debug("Ensure routing rules are configured")
	if err = w.updateAndApplyRouteRules(netlinkClient); err != nil {
		// Error updating the ip rule - close the netlink client as a precaution.
		w.closeNetlinkClient()
		return ErrUpdateFailed
	}

	return nil
}

// setNotSupported is called when we determine wireguard is not supported.
func (w *Wireguard) setNotSupported() {
	// Publish a zero-key back to the calc graph.
	w.ourPublicKey = &zeroKey

	// Indicate that we are now fully in-sync to prevent further queries/updates to the dataplane (until next resync).
	w.setAllInSync(true)

	// And flag wireguard is not supported to short circuit some of the Apply processing.
	w.wireguardNotSupported = true
}

func (w *Wireguard) getOrInitPeer(name string) *peerData {
	if n := w.peers[name]; n != nil {
		return n
	}
	return newPeerData()
}

func (w *Wireguard) setPeer(name string, node *peerData) {
	w.peers[name] = node
}

func (w *Wireguard) getOrInitPeerUpdate(name string) *peerUpdateData {
	if nu := w.peerUpdates[name]; nu != nil {
		return nu
	}
	return newPeerUpdateData()
}

func (w *Wireguard) setPeerUpdate(name string, update *peerUpdateData) {
	w.peerUpdates[name] = update
}

// handlePeerAndRouteDeletionFromPeerUpdates handles wireguard peer deletion preparation:
// -  Updates routing table to remove routes for permantently deleted peers
// -  Creates a wireguard config update for deleted peers, or for peers whose public key has changed (which for
//    wireguard is effectively a different peer)
//
// This method does not perform any dataplane updates.
func (w *Wireguard) handlePeerAndRouteDeletionFromPeerUpdates(conflictingKeys set.Set) *wgtypes.Config {
	var wireguardPeerDelete wgtypes.Config
	for name, update := range w.peerUpdates {
		// Get existing peer configuration. If peer not seen before then no deletion processing is required.
		w.logCxt.Debugf("Handle peer and route deletion for node %s", name)
		node := w.peers[name]
		if node == nil {
			w.logCxt.Debugf("No wireguard configuration for node %s", name)
			continue
		}

		if update.deleted {
			// Node is deleted, so remove the node configuration and the associated routes.
			w.logCxt.Infof("Node %s is deleted, remove associated routes and wireguard peer", name)
			delete(w.peers, name)

			// Delete all of the node routes for the peerData and remove CIDR->node association. Note that we always
			// update the routing table routes using delta updates even during a full resync. The routetable component
			// takes care of its own kernel-cache synchronization.
			node.cidrs.Iter(func(item interface{}) error {
				cidr := item.(ip.CIDR)
				w.routetable.RouteRemove(w.config.InterfaceName, cidr)
				delete(w.cidrToNodeName, cidr)
				w.logCxt.Debugf("Deleting route for %s", cidr)
				return nil
			})
		} else if update.publicKey == nil || *update.publicKey == node.publicKey {
			// It's not a delete, and the public key hasn't changed so no key deletion processing required.
			w.logCxt.Debugf("Node %s updated, but public key is the same, no wireguard peer deletion required", name)
			continue
		}

		if node.publicKey == zeroKey {
			// The node did not have a key assigned, so no peer tidy-up required.
			w.logCxt.Debugf("Node %s had no public key assigned, so no deletion of wireguard peer necessary", name)
			continue
		}

		// If we aren't doing a full re-sync then delete the associated peer if it was previously configured.
		if node.programmedInWireguard && w.inSyncWireguard {
			w.logCxt.Debugf("Adding peer deletion config update for key %s", node.publicKey)
			wireguardPeerDelete.Peers = append(wireguardPeerDelete.Peers, wgtypes.PeerConfig{
				PublicKey: node.publicKey,
				Remove:    true,
			})
			node.programmedInWireguard = false
		}

		// Remove the key to node reference.
		nodenames := w.publicKeyToNodeNames[node.publicKey]
		nodenames.Discard(name)
		if nodenames.Len() == 0 {
			// This was the only node with its public key
			w.logCxt.Debugf("Removed the only node %s claiming public key %s", name, node.publicKey)
			delete(w.publicKeyToNodeNames, node.publicKey)
		} else {
			// This is or was a conflicting key. Recheck the peers associated with this key at the end.
			w.logCxt.Infof("Removed node %s which claimed the same public key %s to at least one other node", name, node.publicKey)
			conflictingKeys.Add(node.publicKey)
		}
		node.publicKey = zeroKey
	}

	if len(wireguardPeerDelete.Peers) > 0 {
		w.logCxt.Debug("There are wireguard peers to delete")
		return &wireguardPeerDelete
	}
	return nil
}

// updateCacheFromPeerUpdates updates the cache from the node update configuration.
//
// This method applies the current set of node updates on top of the current cache. It removes updates that are no
// ops so that they are not re-processed further down the pipeline.
func (w *Wireguard) updateCacheFromPeerUpdates(conflictingKeys set.Set) {
	for name, update := range w.peerUpdates {
		node := w.getOrInitPeer(name)

		// This is a remote node configuration. Update the node data and the key to node mappings.
		w.logCxt.Debugf("Updating cache from update for peer %s", name)
		updated := false
		if update.ipv4EndpointAddr != nil {
			w.logCxt.Debugf("Store IPv4 address %s", *update.ipv4EndpointAddr)
			node.ipv4EndpointAddr = *update.ipv4EndpointAddr
			updated = true
		}
		if update.publicKey != nil {
			w.logCxt.Debugf("Store public key %s", *update.publicKey)
			node.publicKey = *update.publicKey
			if node.publicKey != zeroKey {
				if nodenames := w.publicKeyToNodeNames[node.publicKey]; nodenames == nil {
					w.logCxt.Debug("Public key not associated with a node")
					w.publicKeyToNodeNames[node.publicKey] = set.From(name)
				} else {
					w.logCxt.Info("Public key already associated with a node")
					conflictingKeys.Add(node.publicKey)
					nodenames.Add(name)
				}
			}
			updated = true
		}
		update.allowedCidrsDeleted.Iter(func(item interface{}) error {
			cidr := item.(ip.CIDR)
			w.logCxt.Debugf("Discarding CIDR %s", cidr)
			node.cidrs.Discard(cidr)
			updated = true
			return nil
		})
		update.allowedCidrsAdded.Iter(func(item interface{}) error {
			cidr := item.(ip.CIDR)
			w.logCxt.Debugf("Adding CIDR %s", cidr)
			node.cidrs.Add(cidr)
			updated = true
			return nil
		})

		if updated {
			// Node configuration updated. Store node data.
			w.logCxt.Debug("Node updated")
			w.setPeer(name, node)
		} else {
			// No further update, delete update so it's not processed again.
			w.logCxt.Debug("No updates for the node - remove node update to remove additional processing")
			delete(w.peerUpdates, name)
		}
	}
}

// updateRouteTable updates the route table from the node updates.
func (w *Wireguard) updateRouteTableFromPeerUpdates() {
	// Do all deletes first. Then adds or updates separarately. This ensures a CIDR that has been deleted from one node
	// and added to another will not add first then delete (which will remove the route, since the route table does not
	// care about destination node).
	for name, update := range w.peerUpdates {
		// Delete routes that are no longer required in routing.
		node := w.getOrInitPeer(name)
		ifaceName := routetable.InterfaceNone
		if node != nil && node.programmedInWireguard {
			ifaceName = w.config.InterfaceName
		}
		update.allowedCidrsDeleted.Iter(func(item interface{}) error {
			w.logCxt.Debugf("Removing CIDR %s (node %s) from routetable interface %s", item, name, ifaceName)
			cidr := item.(ip.CIDR)
			w.routetable.RouteRemove(ifaceName, cidr)
			return nil
		})
	}

	// Now do the adds or updates. The routetable component will take care of routes that don't actually change and
	// effectively no-op the delta.
	for name, update := range w.peerUpdates {
		w.logCxt.Debugf("Add/update routing for peer %s", name)
		node := w.getOrInitPeer(name)

		// If the node routing to wireguard does not match with whether we should route then we need to do a full
		// route update, otherwise do an incremental update.
		var updateSet set.Set
		shouldRouteToWireguard := w.shouldProgramWireguardPeer(name, node)
		if node.routingToWireguard != shouldRouteToWireguard {
			w.logCxt.Debugf("Wireguard routing has changed from %v to %v - need to update full set of CIDRs", node.routingToWireguard, shouldRouteToWireguard)
			updateSet = node.cidrs
		} else {
			w.logCxt.Debugf("Wireguard routing has not changed from %v - only need to update added CIDRs", node.routingToWireguard)
			updateSet = update.allowedCidrsAdded
		}

		var targetType routetable.TargetType
		var ifaceName, deleteIfaceName string
		if !shouldRouteToWireguard {
			// If we should not route to wireguard then we need to use a throw directive to skip wireguard routing and
			// return to normal routing. We may also need to delete the existing route to wireguard.
			w.logCxt.Debug("Not routing to wireguard - set route type to throw")
			targetType = routetable.TargetTypeThrow
			ifaceName = routetable.InterfaceNone
			deleteIfaceName = w.config.InterfaceName
		} else {
			// If we should route to wireguard then route to the wireguard interface. We may also need to delete the
			// existing throw route that was used to circumvent wireguard routing.
			w.logCxt.Debug("Routing to wireguard interface")
			ifaceName = w.config.InterfaceName
			deleteIfaceName = routetable.InterfaceNone
		}

		updateSet.Iter(func(item interface{}) error {
			cidr := item.(ip.CIDR)
			w.logCxt.Debugf("Updating route for CIDR %s", cidr)
			if node.routingToWireguard != shouldRouteToWireguard {
				// The wireguard setting has changed. It is possible that some of the entries we are "removing" were
				// never added - the routetable component handles that gracefully. We need to do these deletes because
				// routetable component groups by interface and we are essentially moving routes between the wireguard
				// interface and the "none" interface.
				w.logCxt.Debugf("Wireguard routing has changed - delete previous route for %s", deleteIfaceName)
				w.routetable.RouteRemove(deleteIfaceName, cidr)
			}
			w.routetable.RouteUpdate(ifaceName, routetable.Target{
				Type: targetType,
				CIDR: cidr,
			})
			return nil
		})
		node.routingToWireguard = shouldRouteToWireguard
	}
}

// constructWireguardDeltaFromPeerUpdates constructs a wireguard delta update from the set of peer updates.
func (w *Wireguard) constructWireguardDeltaFromPeerUpdates(conflictingKeys set.Set) *wgtypes.Config {
	// 4. If we are performing a wireguard delta update then construct the delta now.
	var wireguardUpdate wgtypes.Config
	if w.inSyncWireguard {
		// Construct a wireguard delta update
		for name, update := range w.peerUpdates {
			logCxt := w.logCxt.WithField("peer", name)
			logCxt.Debug("Constructing wireguard delta")
			peer := w.peers[name]
			if peer == nil {
				w.logCxt.Warning("internal error: peer data is nil")
				continue
			}

			if w.shouldProgramWireguardPeer(name, peer) {
				// The wgpeer should be programmed in wireguard. We need to do a full CIDR re-sync if either:
				// -  A CIDR was deleted (there is no API directive for deleting an allowed CIDR), or
				// -  The wgpeer has not been programmed.
				logCxt.Debug("Constructing update for peer")
				wgpeer := wgtypes.PeerConfig{
					UpdateOnly: peer.programmedInWireguard,
					PublicKey:  peer.publicKey,
				}
				updatePeer := false
				if !peer.programmedInWireguard || update.allowedCidrsDeleted.Len() > 0 {
					logCxt.Debug("Peer not programmed or CIDRs were deleted - need to replace full set of CIDRs")
					wgpeer.ReplaceAllowedIPs = true
					wgpeer.AllowedIPs = peer.allowedCidrsForWireguard()
					updatePeer = true
				} else if update.allowedCidrsAdded.Len() > 0 {
					logCxt.Debug("Peer programmmed, no CIDRs deleted and CIDRs added")
					wgpeer.AllowedIPs = make([]net.IPNet, 0, update.allowedCidrsAdded.Len())
					update.allowedCidrsAdded.Iter(func(item interface{}) error {
						wgpeer.AllowedIPs = append(wgpeer.AllowedIPs, item.(ip.CIDR).ToIPNet())
						return nil
					})
					updatePeer = true
				}

				if update.ipv4EndpointAddr != nil || !peer.programmedInWireguard {
					logCxt.Infof("Peer endpoint address is updated: %v", update.ipv4EndpointAddr)
					wgpeer.Endpoint = w.endpointUDPAddr(peer.ipv4EndpointAddr.AsNetIP())
					updatePeer = true
				}

				if updatePeer {
					logCxt.Debugf("Peer needs updating")
					wireguardUpdate.Peers = append(wireguardUpdate.Peers, wgpeer)
				}
			} else if peer.programmedInWireguard {
				// This peer is programmed in wireguard and it should not be. Add a delta delete.
				logCxt.Debug("Constructing peer removal update")
				wireguardUpdate.Peers = append(wireguardUpdate.Peers, wgtypes.PeerConfig{
					Remove:    true,
					PublicKey: peer.publicKey,
				})
			}
		}

		// Finally loop through any conflicting public keys and check each of the peers is now handled correctly.
		conflictingKeys.Iter(func(item interface{}) error {
			w.logCxt.Debugf("Processing public key with conflicting peers: %s", item)
			nodenames := w.publicKeyToNodeNames[item.(wgtypes.Key)]
			if nodenames == nil {
				return nil
			}
			nodenames.Iter(func(item interface{}) error {
				nodename := item.(string)
				w.logCxt.Debugf("Processing peer %s", nodename)
				peer := w.peers[nodename]
				if peer == nil || peer.programmedInWireguard == w.shouldProgramWireguardPeer(nodename, peer) {
					// The peer programming matches the expected value, so nothing to do.
					w.logCxt.Debug("Programming state has not changed")
					return nil
				} else if peer.programmedInWireguard {
					// The peer is programmed and shouldn't be. Add a delta delete.
					w.logCxt.Debug("Programmed in wireguard, need to delete")
					wireguardUpdate.Peers = append(wireguardUpdate.Peers, wgtypes.PeerConfig{
						Remove:    true,
						PublicKey: peer.publicKey,
					})
				} else {
					// The peer is not programmed and should be.  Add a delta create.
					w.logCxt.Debug("Not programmed in wireguard, needs to be added now")
					wireguardUpdate.Peers = append(wireguardUpdate.Peers, wgtypes.PeerConfig{
						PublicKey:  peer.publicKey,
						Endpoint:   w.endpointUDPAddr(peer.ipv4EndpointAddr.AsNetIP()),
						AllowedIPs: peer.allowedCidrsForWireguard(),
					})
				}
				return nil
			})
			return nil
		})
	}

	// Delta updates only include updates to peer config, so if no peer updates, just return nil.
	if len(wireguardUpdate.Peers) > 0 {
		w.logCxt.Debug("There are peers to update")
		return &wireguardUpdate
	}
	return nil
}

// constructWireguardDeltaForResync checks the wireguard configuration matches the cached data and creates a delta
// update to correct any discrepancies.
func (w *Wireguard) constructWireguardDeltaForResync(wireguardClient netlinkshim.Wireguard) (wgtypes.Key, *wgtypes.Config, error) {
	// Get the wireguard device configuration.
	device, err := wireguardClient.DeviceByName(w.config.InterfaceName)
	if err != nil {
		w.logCxt.Errorf("error querying wireguard configuration: %v", err)
		return zeroKey, nil, err
	}

	// Determine if any configuration on the device needs updating
	wireguardUpdate := wgtypes.Config{}
	wireguardUpdateRequired := false
	if device.FirewallMark != w.config.FirewallMark {
		w.logCxt.Infof("Update firewall mark from %d to %d", device.FirewallMark, w.config.FirewallMark)
		wireguardUpdate.FirewallMark = &w.config.FirewallMark
		wireguardUpdateRequired = true
	}
	if device.ListenPort != w.config.ListeningPort {
		w.logCxt.Infof("Update listening port from %d to %d", device.ListenPort, w.config.ListeningPort)
		wireguardUpdate.ListenPort = &w.config.ListeningPort
		wireguardUpdateRequired = true
	}

	publicKey := device.PublicKey
	if device.PrivateKey == zeroKey || device.PublicKey == zeroKey {
		// One of the private or public key is not set. Generate a new private key and return the corresponding
		// public key.
		w.logCxt.Info("Generate new private/public keypair")
		pkey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			w.logCxt.Errorf("error generating private-key: %v", err)
			return zeroKey, nil, err
		}
		wireguardUpdate.PrivateKey = &pkey
		wireguardUpdateRequired = true

		publicKey = pkey.PublicKey()
	}

	// Track which keys we have processed. The value indicates whether the data should be programmed in wireguard or
	// not.
	processedKeys := set.New()

	// Handle peers that are configured
	for peerIdx := range device.Peers {
		key := device.Peers[peerIdx].PublicKey
		node := w.getNodeFromKey(key)
		if node == nil {
			w.logCxt.Infof("Peer key is not expected or associated with multiple peers: %v", key)
			wireguardUpdate.Peers = append(wireguardUpdate.Peers, wgtypes.PeerConfig{
				PublicKey: key,
				Remove:    true,
			})
			processedKeys.Add(key)
			wireguardUpdateRequired = true
			continue
		}

		w.logCxt.Debugf("Checking allowed CIDRs for node with key %v", key)
		configuredCidrs := device.Peers[peerIdx].AllowedIPs
		configuredAddr := device.Peers[peerIdx].Endpoint
		replaceCidrs := false

		// Need to check programmed CIDRs against expected to see if any need deleting.
		w.logCxt.Debug("Check programmed CIDRs for required deletions")
		for _, netCidr := range configuredCidrs {
			cidr := ip.CIDRFromIPNet(&netCidr)
			if !node.cidrs.Contains(cidr) {
				// Need to delete an entry, so just replace
				w.logCxt.Debugf("Unexpected CIDR configured: %s", cidr)
				replaceCidrs = true
				break
			}
		}

		// If the CIDRs need replacing or the endpoint address needs updating then wireguardUpdate the entry.
		expectedEndpointIP := node.ipv4EndpointAddr.AsNetIP()
		replaceEndpointAddr := expectedEndpointIP != nil &&
			(configuredAddr == nil || configuredAddr.Port != w.config.ListeningPort || !configuredAddr.IP.Equal(expectedEndpointIP))
		if replaceCidrs || replaceEndpointAddr {
			peer := wgtypes.PeerConfig{
				PublicKey:         key,
				UpdateOnly:        true,
				ReplaceAllowedIPs: replaceCidrs,
			}

			if replaceEndpointAddr {
				w.logCxt.Info("Endpoint address needs updating")
				peer.Endpoint = w.endpointUDPAddr(expectedEndpointIP)
			}

			if replaceCidrs {
				w.logCxt.Info("AllowedIPs need replacing")
				peer.AllowedIPs = node.allowedCidrsForWireguard()
			}

			wireguardUpdate.Peers = append(wireguardUpdate.Peers, peer)
			wireguardUpdateRequired = true
		}
	}

	// Handle peers that are not configured at all.
	for name, node := range w.peers {
		if processedKeys.Contains(node.publicKey) {
			w.logCxt.Debugf("Peer key already handled: node %s; key %v", name, node.publicKey)
			continue
		}
		if !w.shouldProgramWireguardPeer(name, node) {
			w.logCxt.Debugf("Peer should not be programmed: node %s", name)
			continue
		}

		w.logCxt.Infof("Add peer to wireguard: node %s; key %v; ip: %v", name, node.publicKey, node.ipv4EndpointAddr)
		wireguardUpdate.Peers = append(wireguardUpdate.Peers, wgtypes.PeerConfig{
			PublicKey:  node.publicKey,
			Endpoint:   w.endpointUDPAddr(node.ipv4EndpointAddr.AsNetIP()),
			AllowedIPs: node.allowedCidrsForWireguard(),
		})
		wireguardUpdateRequired = true
	}

	w.logCxt.Debugf("Wireguard device configured with public key %v", publicKey)

	if wireguardUpdateRequired {
		return publicKey, &wireguardUpdate, nil
	}

	return publicKey, nil, nil
}

// ensureLink checks that the wireguard link is configured correctly. Returns true if the link is oper up.
func (w *Wireguard) ensureLink(netlinkClient netlinkshim.Netlink) (bool, error) {
	link, err := netlinkClient.LinkByName(w.config.InterfaceName)
	if netlinkshim.IsNotExist(err) {
		// Create the wireguard device.
		w.logCxt.Info("Wireguard device needs to be created")
		attr := netlink.NewLinkAttrs()
		attr.Name = w.config.InterfaceName
		lwg := netlink.GenericLink{
			LinkAttrs: attr,
			LinkType:  wireguardType,
		}

		if err := netlinkClient.LinkAdd(&lwg); err != nil {
			return false, err
		}

		link, err = netlinkClient.LinkByName(w.config.InterfaceName)
		if err != nil {
			w.logCxt.Errorf("error querying wireguard device: %v", err)
			return false, err
		}

		w.logCxt.Info("Created wireguard device")
	} else if err != nil {
		w.logCxt.Errorf("unable to determine if wireguard device exists: %v", err)
		return false, err
	}

	if link.Type() != wireguardType {
		w.logCxt.Errorf("interface %s is of type %s, not wireguard", w.config.InterfaceName, link.Type())
		return false, errWrongInterfaceType
	}

	// If necessary, update the MTU and admin status of the device.
	w.logCxt.Debug("Wireguard device exists, checking settings")
	attrs := link.Attrs()
	oldMTU := attrs.MTU
	if w.config.MTU != 0 && oldMTU != w.config.MTU {
		w.logCxt.WithField("oldMTU", oldMTU).Info("Wireguard device MTU needs to be updated")
		if err := netlinkClient.LinkSetMTU(link, w.config.MTU); err != nil {
			w.logCxt.WithError(err).Warn("failed to set tunnel device MTU")
			return false, err
		}
		w.logCxt.Info("Updated wireguard device MTU")
	}
	if attrs.Flags&net.FlagUp == 0 {
		w.logCxt.WithField("flags", attrs.Flags).Info("Wireguard interface wasn't admin up, enabling it")
		if err := netlinkClient.LinkSetUp(link); err != nil {
			w.logCxt.WithError(err).Warn("failed to set wireguard device up")
			return false, err
		}
		w.logCxt.Info("Set wireguard admin up")

		if link, err = netlinkClient.LinkByName(w.config.InterfaceName); err != nil {
			w.logCxt.WithError(err).Warn("failed to get link device after creating link")
			return false, err
		}
	}

	// Track whether the interface is oper up or not. We halt programming when it is down.
	return link.Attrs().Flags&net.FlagUp != 0, nil
}

// ensureNoLink checks that the wireguard link is not present.
func (w *Wireguard) ensureNoLink(netlinkClient netlinkshim.Netlink) error {
	link, err := netlinkClient.LinkByName(w.config.InterfaceName)
	if err == nil {
		// Wireguard device exists.
		w.logCxt.Info("Wireguard is disabled, deleting device")
		if err := netlinkClient.LinkDel(link); err != nil {
			w.logCxt.Errorf("error deleting wireguard type link: %v", err)
			return err
		}
		w.logCxt.Info("Deleted wireguard device")
	} else if netlinkshim.IsNotExist(err) {
		w.logCxt.Debug("Wireguard is disabled and does not exist")
	} else if err != nil {
		w.logCxt.Errorf("unable to determine if wireguard device exists: %v", err)
		return err
	}
	return nil
}

// ensureLinkAddressV4 ensures the wireguard link to set to the required local IP address.  It removes any other
// addresses.
func (w *Wireguard) ensureLinkAddressV4(netlinkClient netlinkshim.Netlink) error {
	w.logCxt.Debug("Setting local IPv4 address on link.")
	link, err := netlinkClient.LinkByName(w.config.InterfaceName)
	if err != nil {
		w.logCxt.WithError(err).Warning("Failed to get device")
		return err
	}

	addrs, err := netlinkClient.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		w.logCxt.WithError(err).Warn("failed to list interface addresses")
		return err
	}

	var address net.IP
	if w.ourIPv4InterfaceAddr != nil {
		address = w.ourIPv4InterfaceAddr.AsNetIP()
	}

	found := false
	for _, oldAddr := range addrs {
		if address != nil && oldAddr.IP.Equal(address) {
			w.logCxt.Debug("Address already present.")
			found = true
			continue
		}
		w.logCxt.WithField("oldAddr", oldAddr).Info("Removing old address")
		if err := netlinkClient.AddrDel(link, &oldAddr); err != nil {
			w.logCxt.WithError(err).Warn("failed to delete address from wireguard device")
			return err
		}
	}

	if !found && address != nil {
		w.logCxt.Info("address not present on wireguard device, adding it")
		mask := net.CIDRMask(32, 32)
		ipNet := net.IPNet{
			IP:   address.Mask(mask), // Mask the IP to match ParseCIDR()'s behaviour.
			Mask: mask,
		}
		addr := &netlink.Addr{
			IPNet: &ipNet,
		}
		if err := netlinkClient.AddrAdd(link, addr); err != nil {
			w.logCxt.WithError(err).WithField("addr", address).Warn("failed to add address")
			return err
		}
	}
	w.logCxt.Debug("Address set.")

	return nil
}

// updateAndApplyRouteRules updates the route rule manager and applies the changes.
func (w *Wireguard) updateAndApplyRouteRules(netlinkClient netlinkshim.Netlink) error {
	if w.routerule == nil {
		return nil
	}

	// If there are local CIDR updates we'll need to recalculate the minimal set of non-overlapping CIDRs and send
	// deltas to the routeule manager. The local CIDRs are split into IPs and (presumably) non-overlapping CIDRs. Just
	// add all of the CIDRs and any IPs that are not covered by the CIDRs.
	if w.localCIDRsUpdated {
		oldFiltered := w.localCIDRsFiltered
		newFiltered := set.New()
		w.localCIDRs.Iter(func(itemCIDR interface{}) error {
			cidr := itemCIDR.(ip.CIDR)
			newFiltered.Add(cidr)
			if oldFiltered.Contains(cidr) {
				oldFiltered.Discard(cidr)
			} else {
				w.routerule.SetRule(w.createRouteRule(cidr))
			}
			return nil
		})
		w.localIPs.Iter(func(itemAddr interface{}) error {
			addr := itemAddr.(ip.Addr)
			overlaps := false
			w.localCIDRs.Iter(func(itemCIDR interface{}) error {
				cidr := itemCIDR.(ip.CIDR).ToIPNet()
				if cidr.Contains(addr.AsNetIP()) {
					overlaps = true
					return set.StopIteration
				}
				return nil
			})
			if !overlaps {
				ipAsCidr := addr.AsCIDR()
				newFiltered.Add(ipAsCidr)
				if oldFiltered.Contains(ipAsCidr) {
					oldFiltered.Discard(ipAsCidr)
				} else {
					w.routerule.SetRule(w.createRouteRule(ipAsCidr))
				}
			}
			return nil
		})
		oldFiltered.Iter(func(itemCIDR interface{}) error {
			cidr := itemCIDR.(ip.CIDR)
			w.routerule.RemoveRule(w.createRouteRule(cidr))
			return nil
		})

		w.localCIDRsFiltered = newFiltered
		w.localCIDRsUpdated = false
	}

	// Apply the routing rule updates.
	return w.routerule.Apply()
}

// createRouteRule creates a routing rule to route a local source CIDR to the wireguard table (if wireguard firewall
// mark is not set).
func (w *Wireguard) createRouteRule(cidr ip.CIDR) *routerule.Rule {
	rule := routerule.NewRule(ipVersion, w.config.RoutingRulePriority).
		GoToTable(w.config.RoutingTableIndex).
		MatchFWMarkWithMask(0, uint32(w.config.FirewallMark)).
		MatchSrcAddress(cidr.ToIPNet())
	return rule
}

// ensureDisabled ensures all calico-installed wireguard configuration is removed.
func (w *Wireguard) ensureDisabled(netlinkClient netlinkshim.Netlink) error {
	var errRule, errLink, errRoutes error
	wg := sync.WaitGroup{}

	if w.routerule != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errRule = w.routerule.Apply()
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		errLink = w.ensureNoLink(netlinkClient)
	}()
	if w.config.RoutingTableIndex > 0 {
		// Only attempt automatic cleanup of the routing table if it is not the default table.
		wg.Add(1)
		go func() {
			defer wg.Done()
			// The routetable configuration will be empty since we will not send updates, so applying this will remove the
			// old routes if so configured.
			errRoutes = w.routetable.Apply()
		}()
		wg.Wait()
	}

	if errRule != nil || errLink != nil {
		// Failed to delete the rule or link.  Close the netlink client as a precaution.
		w.closeNetlinkClient()
		return ErrUpdateFailed
	} else if errRoutes != nil {
		// Routes are handled by a separate module which takes care of its own netlink client lifecycle.
		return ErrUpdateFailed
	}

	return nil
}

// shouldProgramWireguardPeer returns true if the peer configuration indicates the peer should be programmed in
// wireguard. This requires:
// -  A peer to have an IPv4 endpoint address
// -  A peer to have a valid public key, and
// -  Only a single peer to be claiming that public key
func (w *Wireguard) shouldProgramWireguardPeer(name string, node *peerData) bool {
	if node.ipv4EndpointAddr == nil {
		w.logCxt.Debugf("Peer %s should not be programmed, no endpoint address", name)
		return false
	} else if node.publicKey == zeroKey {
		w.logCxt.Debugf("Peer %s should not be programmed, no valid public key", name)
		return false
	} else if w.publicKeyToNodeNames[node.publicKey].Len() != 1 {
		w.logCxt.Debugf("Peer %s should not be programmed, multiple nodes are claiming the same key", name)
		return false
	}
	w.logCxt.Debugf("Peer %s should be programmed", name)
	return true
}

// getWireguardClient returns a wireguard client for managing wireguard devices.
func (w *Wireguard) getWireguardClient() (netlinkshim.Wireguard, error) {
	if w.cachedWireguardClient == nil {
		if w.numConsistentWireguardClientFailures >= maxConnFailures && w.numConsistentWireguardClientFailures%wireguardClientRetryInterval != 0 {
			// It is a valid condition that we cannot connect to the wireguard client, so just log.
			w.logCxt.WithField("numFailures", w.numConsistentWireguardClientFailures).Debug(
				"Repeatedly failed to connect to wireguard client.")
			return nil, ErrNotSupportedTooManyFailures
		}
		w.logCxt.Info("Trying to connect to wireguard client")
		client, err := w.newWireguardClient()
		if err != nil {
			w.numConsistentWireguardClientFailures++
			w.logCxt.WithError(err).WithField("numFailures", w.numConsistentWireguardClientFailures).Info(
				"Failed to connect to wireguard client")
			return nil, err
		}
		w.cachedWireguardClient = client
	}
	if w.numConsistentWireguardClientFailures > 0 {
		w.logCxt.WithField("numFailures", w.numConsistentWireguardClientFailures).Info(
			"Connected to linkClient after previous failures.")
		w.numConsistentWireguardClientFailures = 0
	}
	return w.cachedWireguardClient, nil
}

// closeWireguardClient closes the current wireguard client. This forces a wireguard client reconnect next call to
// getWireguardClient.
func (w *Wireguard) closeWireguardClient() {
	if w.cachedWireguardClient == nil {
		return
	}
	if err := w.cachedWireguardClient.Close(); err != nil {
		w.logCxt.WithError(err).Error("Failed to close wireguard client, ignoring.")
	}
	w.cachedWireguardClient = nil
}

// getNetlinkClient returns a netlink client for managing device links.
func (w *Wireguard) getNetlinkClient() (netlinkshim.Netlink, error) {
	if w.cachedNetlinkClient == nil {
		// We do not expect the standard netlink client to fail, so panic after a set number of failed attempts.
		if w.numConsistentNetlinkClientFailures >= maxConnFailures {
			w.logCxt.WithField("numFailures", w.numConsistentNetlinkClientFailures).Panic(
				"Repeatedly failed to connect to netlink.")
		}
		w.logCxt.Info("Trying to connect to linkClient")
		client, err := w.newNetlinkClient()
		if err != nil {
			w.numConsistentNetlinkClientFailures++
			w.logCxt.WithError(err).WithField("numFailures", w.numConsistentNetlinkClientFailures).Error(
				"Failed to connect to linkClient")
			return nil, err
		}
		w.cachedNetlinkClient = client
	}
	if w.numConsistentNetlinkClientFailures > 0 {
		w.logCxt.WithField("numFailures", w.numConsistentNetlinkClientFailures).Info(
			"Connected to linkClient after previous failures.")
		w.numConsistentNetlinkClientFailures = 0
	}
	return w.cachedNetlinkClient, nil
}

// closeNetlinkClient deletes the netlink client handle. This forces a netlink reconnect next call to getNetlinkClient.
func (w *Wireguard) closeNetlinkClient() {
	if w.cachedNetlinkClient == nil {
		return
	}
	w.cachedNetlinkClient.Delete()
	w.cachedNetlinkClient = nil
}

// getNodeFromKey returns the node data associated with a key. If there is no node, or if multiple peers have claimed the
// same key, this returns nil.
func (w *Wireguard) getNodeFromKey(key wgtypes.Key) *peerData {
	if item := getOnlyItemInSet(w.publicKeyToNodeNames[key]); item != nil {
		return w.peers[item.(string)]
	}
	return nil
}

// applyWireguardConfig applies the wireguard configuration.
func (w *Wireguard) applyWireguardConfig(wireguardClient netlinkshim.Wireguard, c *wgtypes.Config) error {
	w.logCxt.Debugf("Apply wireguard config update: %#v", c)
	if c == nil {
		// No config to apply.
		return nil
	}
	return wireguardClient.ConfigureDevice(w.config.InterfaceName, *c)
}

// endpointUDPAddr converts the net IP and the configured listening port to a net UDP address.
func (w *Wireguard) endpointUDPAddr(ip net.IP) *net.UDPAddr {
	if ip == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   ip,
		Port: w.config.ListeningPort,
	}
}

// setAllInSync updates all of the internal "in-sync" markers.
func (w *Wireguard) setAllInSync(inSync bool) {
	w.inSyncWireguard = inSync
	w.inSyncLink = inSync
	w.inSyncInterfaceAddr = inSync
}

// getOnlyItemInSet returns the only item in the set, or nil if the set is nil or the set does not contain only one
// item.
func getOnlyItemInSet(s set.Set) interface{} {
	if s == nil || s.Len() != 1 {
		return nil
	}
	var i interface{}
	s.Iter(func(item interface{}) error {
		i = item
		return set.StopIteration
	})
	return i
}
