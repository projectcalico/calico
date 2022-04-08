// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.
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
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/projectcalico/calico/libcalico-go/lib/set"

	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/routerule"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/timeshim"
)

const (
	// The number of netlink connection retries before we either panic (for standard link operations) or back-off (for
	// wireguard operations).
	maxConnFailures = 3

	// For wireguard client connections we back off retries and only try to actually connect once every
	// <wireguardClientRetryInterval> requests.
	wireguardClientRetryInterval = 10

	wireguardType       = "wireguard"
	ipVersion           = 4
	ipPrefixLen         = 32
	allSrcValidMarkPath = "/proc/sys/net/ipv4/conf/all/src_valid_mark"
)

var (
	ErrUpdateFailed                = errors.New("netlink update operation failed")
	ErrNotSupportedTooManyFailures = errors.New("operation not supported (too many failures)")

	// Internal types
	errWrongInterfaceType = errors.New("incorrect interface type for wireguard")

	zeroKey = wgtypes.Key{}
)

type noOpConnTrack struct{}

func (*noOpConnTrack) RemoveConntrackFlows(ipVersion uint8, ipAddr net.IP) {}

type nodeData struct {
	ipv4EndpointAddr      ip.Addr
	publicKey             wgtypes.Key
	cidrs                 set.Set
	programmedInWireguard bool
	routingToWireguard    bool
}

func newNodeData() *nodeData {
	return &nodeData{
		cidrs: set.New(),
	}
}

func (n *nodeData) allowedCidrsForWireguard() []net.IPNet {
	cidrs := make([]net.IPNet, 0, n.cidrs.Len())
	n.cidrs.Iter(func(item interface{}) error {
		cidrs = append(cidrs, item.(ip.CIDR).ToIPNet())
		return nil
	})
	return cidrs
}

type nodeUpdateData struct {
	// Used for nodes *and* the local node.
	cidrsAdded   set.Set
	cidrsDeleted set.Set

	// Only used for nodes.
	deleted          bool
	ipv4EndpointAddr *ip.Addr
	publicKey        *wgtypes.Key
}

func newNodeUpdateData() *nodeUpdateData {
	return &nodeUpdateData{
		cidrsDeleted: set.New(),
		cidrsAdded:   set.New(),
	}
}

type Wireguard struct {
	// Wireguard configuration (this will not change without a restart).
	hostname string
	config   *Config

	// Clients, client factories and testing shims.
	newNetlinkClient                     func() (netlinkshim.Interface, error)
	newWireguardClient                   func() (netlinkshim.Wireguard, error)
	cachedNetlinkClient                  netlinkshim.Interface
	cachedWireguardClient                netlinkshim.Wireguard
	numConsistentNetlinkClientFailures   int
	numConsistentWireguardClientFailures int
	time                                 timeshim.Interface

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
	localIPs          set.Set
	localCIDRs        set.Set
	localCIDRsUpdated bool

	// Current configuration
	// - all nodeData information
	// - mapping between CIDRs and nodeData
	// - mapping between public key and nodes - this does not include the "zero" key, and will not include the local
	//   node.
	nodes                map[string]*nodeData
	publicKeyToNodeNames map[wgtypes.Key]set.Set

	// Pending updates
	nodeUpdates map[string]*nodeUpdateData

	// CIDR to node mappings - this is updated synchronously.
	cidrToNodeName map[ip.CIDR]string

	// Wireguard routing table and rule managers
	routetable *routetable.RouteTable
	routerule  *routerule.RouteRules

	// Callback function used to notify of public key updates for the local nodeData
	statusCallback func(publicKey wgtypes.Key) error
	opRecorder     logutils.OpRecorder
}

func New(
	hostname string,
	config *Config,
	netlinkTimeout time.Duration,
	deviceRouteProtocol netlink.RouteProtocol,
	statusCallback func(publicKey wgtypes.Key) error,
	opRecorder logutils.OpRecorder,
) *Wireguard {
	return NewWithShims(
		hostname,
		config,
		netlinkshim.NewRealNetlink,
		netlinkshim.NewRealNetlink,
		netlinkshim.NewRealNetlink,
		netlinkshim.NewRealWireguard,
		netlinkTimeout,
		timeshim.RealTime(),
		deviceRouteProtocol,
		statusCallback,
		opRecorder,
	)
}

// NewWithShims is a test constructor, which allows linkClient, arp and time to be replaced by shims.
func NewWithShims(
	hostname string,
	config *Config,
	newRoutetableNetlink func() (netlinkshim.Interface, error),
	newRouteRuleNetlink func() (netlinkshim.Interface, error),
	newWireguardNetlink func() (netlinkshim.Interface, error),
	newWireguardDevice func() (netlinkshim.Wireguard, error),
	netlinkTimeout time.Duration,
	timeShim timeshim.Interface,
	deviceRouteProtocol netlink.RouteProtocol,
	statusCallback func(publicKey wgtypes.Key) error,
	opRecorder logutils.OpRecorder,
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
		nil, // deviceRouteSourceAddress
		deviceRouteProtocol,
		true, // removeExternalRoutes
		config.RoutingTableIndex,
		opRecorder,
	)
	// Create routerule.
	rr, err := routerule.New(
		ipVersion,
		config.RoutingRulePriority,
		set.From(config.RoutingTableIndex),
		routerule.RulesMatchSrcFWMarkTable,
		routerule.RulesMatchSrcFWMarkTable,
		netlinkTimeout,
		func() (routerule.HandleIface, error) {
			return newRouteRuleNetlink()
		},
		opRecorder,
	)
	if err != nil && config.Enabled {
		// Wireguard is enabled, but could not create a routerule manager. This is unexpected.
		log.WithError(err).Panic("Unexpected error creating rule manager")
	}

	return &Wireguard{
		hostname:             hostname,
		config:               config,
		newNetlinkClient:     newWireguardNetlink,
		newWireguardClient:   newWireguardDevice,
		time:                 timeShim,
		nodes:                map[string]*nodeData{},
		cidrToNodeName:       map[ip.CIDR]string{},
		publicKeyToNodeNames: map[wgtypes.Key]set.Set{},
		nodeUpdates:          map[string]*nodeUpdateData{},
		routetable:           rt,
		routerule:            rr,
		statusCallback:       statusCallback,
		localIPs:             set.New(),
		localCIDRs:           set.New(),
		opRecorder:           opRecorder,
	}
}

func (w *Wireguard) OnIfaceStateChanged(ifaceName string, state ifacemonitor.State) {
	logCxt := log.WithField("wireguardIfaceName", w.config.InterfaceName)
	if w.config.InterfaceName != ifaceName {
		logCxt.WithField("ifaceName", ifaceName).Debug("Ignoring interface state change, not the wireguard interface.")
		return
	}
	switch state {
	case ifacemonitor.StateUp:
		logCxt.Debug("Interface up, marking for route sync")
		if !w.ifaceUp {
			w.ifaceUp = true
			w.inSyncWireguard = false
		}
	case ifacemonitor.StateDown:
		logCxt.Debug("Interface down")
		w.ifaceUp = false
	}

	// Notify the wireguard routetable module.
	w.routetable.OnIfaceStateChanged(ifaceName, state)
}

func (w *Wireguard) EndpointUpdate(name string, ipv4Addr ip.Addr) {
	logCxt := log.WithFields(log.Fields{"name": name, "ipv4Addr": ipv4Addr})
	logCxt.Debug("EndpointUpdate")
	if !w.config.Enabled {
		logCxt.Debug("Not enabled - ignoring")
		return
	} else if name == w.hostname {
		// We don't need our own IP address, just interested in the nodes.
		return
	}

	update := w.getOrInitNodeUpdateData(name)
	if existing, ok := w.nodes[name]; ok && existing.ipv4EndpointAddr == ipv4Addr {
		logCxt.Debug("Update contains unchanged IPv4 address")
		update.ipv4EndpointAddr = nil
	} else {
		logCxt.Debug("Update contains new IPv4 address")
		update.ipv4EndpointAddr = &ipv4Addr
	}
	w.setNodeUpdate(name, update)
}

func (w *Wireguard) EndpointRemove(name string) {
	logCxt := log.WithField("name", name)
	logCxt.Debug("EndpointRemove")
	if !w.config.Enabled {
		logCxt.Debug("Not enabled - ignoring")
		return
	} else if name == w.hostname {
		logCxt.Debug("Local update - ignoring")
		return
	}

	if _, ok := w.nodes[name]; ok {
		// Node data exists, so store a blank update with a deleted flag. The delete will be applied first, and then any
		// subsequent updates. There is no need to remove the pending CIDR to node mappings since the route resolver
		// provides self consistent route updates (i.e. we will get route removes or updates for these CIDRs).
		logCxt.Debug("Existing node is flagged for removal")
		nu := newNodeUpdateData()
		nu.deleted = true
		w.setNodeUpdate(name, nu)
	} else {
		// Node data is not yet programmed so just delete the pending update.
		logCxt.Debug("Node removed which has not yet been programmed - remove any pending update")
		delete(w.nodeUpdates, name)
	}
}

func (w *Wireguard) RouteUpdate(name string, cidr ip.CIDR) {
	logCxt := log.WithFields(log.Fields{"name": name, "cidr": cidr})
	logCxt.Debug("RouteUpdate")
	if !w.config.Enabled {
		logCxt.Debug("Not enabled - ignoring")
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
	logCxt := log.WithField("cidr", cidr)
	logCxt.Debug("RouteRemove")
	if !w.config.Enabled {
		log.Debug("Not enabled - ignoring")
		return
	}

	// Determine which node this CIDR belongs to. Check the updates first and then the processed.
	name, ok := w.cidrToNodeName[cidr]
	if !ok {
		// The wireguard manager filters out some of the CIDR updates, but not the removes, so it's possible to get
		// CIDR removes for which we have seen no corresponding add.
		logCxt.Debug("CIDR remove update but not associated with a node")
		return
	}
	logCxt.WithField("node", name).Debug("CIDR associated with node")
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

// Add a local workload CIDR. These CIDRs are used for:
// - the source-matched wireguard routing rules to limit wireguard encryption to traffic to/from local workloads.
// - add throw routes to the wireguard route table to ensure we throw to the main table for local routing.
//
// Note that the workload CIDRs may overlap. This method determines if the added CIDR is wholly covered by one already
// programmed - if it is then no further update is required.
func (w *Wireguard) localWorkloadCIDRAdd(cidr ip.CIDR) {
	log.WithField("cidr", cidr).Debug("localWorkloadCIDRAdd")
	// Split the local CIDRs into actual /32 workload IPs and the CIDR blocks for the node. We assume the CIDR blocks
	// are not overlapping, and so we add rules for each CIDR to route to wireguard, and only include the /32 workload
	// IPs if not covered by the CIDR blocks.
	if cidr.Prefix() == ipPrefixLen {
		w.localIPs.Add(cidr.Addr())
	} else {
		w.localCIDRs.Add(cidr)
	}
	// Only flag the CIDRs for update if it not wholly covered by the already filtered local CIDRs.
	if !w.localCIDRsUpdated {
		contained := false
		if node, ok := w.nodes[w.hostname]; ok {
			node.cidrs.Iter(func(item interface{}) error {
				filtered := item.(ip.CIDR)
				filteredIPNet := filtered.ToIPNet()
				if filteredIPNet.Contains(cidr.ToIPNet().IP) && filtered.Prefix() >= cidr.Prefix() {
					contained = true
					return set.StopIteration
				}
				return nil
			})
		}
		if !contained {
			w.localCIDRsUpdated = true
		}
	}
}

// Remove a local workload CIDR. These CIDRs are used for:
// - the source-matched wireguard routing rules to limit wireguard encryption to traffic to/from local workloads.
// - add throw routes to the wireguard route table to ensure we throw to the main table for local routing.
//
// Note that the workload CIDRs may overlap so the minimal overlapping set of routes needs to be recalculated, so
// we only need to update the local CIDRs if the CIDR being removed is one of the ones programmed.
func (w *Wireguard) localWorkloadCIDRRemove(cidr ip.CIDR) {
	log.WithField("cidr", cidr).Debug("localWorkloadCIDRRemove")
	if cidr.Prefix() == ipPrefixLen {
		w.localIPs.Discard(cidr.Addr())
	} else {
		w.localCIDRs.Discard(cidr)
	}
	// Only flag the CIDRs for update if this CIDR is one of the filtered CIDRs.
	if !w.localCIDRsUpdated {
		if node, ok := w.nodes[w.hostname]; ok {
			w.localCIDRsUpdated = node.cidrs.Contains(cidr)
		}
	}
}

// Add a peer allowed CIDR.  These CIDRs are used for the destination-matched wireguard routes to limit wireguard
// encryption to traffic to/from remote workloads.
func (w *Wireguard) peerAllowedCIDRAdd(name string, cidr ip.CIDR) {
	logCxt := log.WithFields(log.Fields{"node": name, "cidr": cidr})
	logCxt.Debug("peerAllowedCIDRAdd")
	update := w.getOrInitNodeUpdateData(name)
	if existing, ok := w.nodes[name]; ok && existing.cidrs.Contains(cidr) {
		// Adding the CIDR to a node that already has it. This may happen if there is a pending CIDR deletion for the
		// node, so discard the deletion update.
		logCxt.Debug("Peer CIDR added which is already programmed - remove any pending delete")
		update.cidrsDeleted.Discard(cidr)
	} else {
		// Adding the CIDR to a node that does not already have it.
		logCxt.Debug("Peer CIDR added which is not programmed")
		update.cidrsAdded.Add(cidr)
	}
	w.setNodeUpdate(name, update)
}

// Remove a peer allowed CIDR.  These CIDRs are used for the destination-matched wireguard routes to limit wireguard
// encryption to traffic to/from remote workloads.
func (w *Wireguard) peerAllowedCIDRRemove(name string, cidr ip.CIDR) {
	logCxt := log.WithFields(log.Fields{"node": name, "cidr": cidr})
	logCxt.Debug("peerAllowedCIDRRemove")
	update := w.getOrInitNodeUpdateData(name)
	if existing, ok := w.nodes[name]; ok && existing.cidrs.Contains(cidr) {
		// Remove the CIDR from a node that already has the CIDR configured.
		logCxt.Debug("Node CIDR removed")
		update.cidrsDeleted.Add(cidr)
	} else {
		// Deleting the CIDR from a node that already doesn't have it configured. This may happen if there is a pending
		// CIDR addition for the node, so discard the addition update.
		logCxt.Debug("Node CIDR removed but is not programmed - remove any pending add")
		update.cidrsAdded.Discard(cidr)
	}
	w.setNodeUpdate(name, update)
}

func (w *Wireguard) EndpointWireguardUpdate(name string, publicKey wgtypes.Key, ipv4InterfaceAddr ip.Addr) {
	logCxt := log.WithFields(log.Fields{"node": name, "publicKey": publicKey, "ipv4InterfaceAddr": ipv4InterfaceAddr})
	logCxt.Debug("EndpointWireguardUpdate")
	if !w.config.Enabled {
		log.Debug("Not enabled - ignoring")
		return
	}

	if name == w.hostname {
		logCxt.Debug("Local wireguard info updated")
		if w.ourPublicKey == nil || *w.ourPublicKey != publicKey {
			// Public key does not match that stored. Flag as not in-sync, we will update the value from the dataplane
			// and publish.
			logCxt.Debug("Stored public key does not match key queried from dataplane")
			w.ourPublicKeyAgreesWithDataplaneMsg = false
		}
		if w.ourIPv4InterfaceAddr != ipv4InterfaceAddr {
			logCxt.Debug("Local interface addr updated")
			w.ourIPv4InterfaceAddr = ipv4InterfaceAddr
			w.inSyncInterfaceAddr = false
		}
		return
	}

	// Only update the public key in the node data for nodes.  The local node will not have this set, this prevents the
	// wireguard config processing from attempting to add the local node as a peer.
	update := w.getOrInitNodeUpdateData(name)
	if existing, ok := w.nodes[name]; ok && existing.publicKey == publicKey {
		// Public key not updated
		logCxt.Debug("Public key unchanged from programmed")
		update.publicKey = nil
	} else {
		// Public key updated (or this is a previously unseen node)
		logCxt.Debug("Storing updated public key")
		update.publicKey = &publicKey
	}
	w.setNodeUpdate(name, update)
}

func (w *Wireguard) EndpointWireguardRemove(name string) {
	logCxt := log.WithField("node", name)
	logCxt.Debug("EndpointWireguardRemove")
	if !w.config.Enabled {
		logCxt.Debug("Not enabled - ignoring")
		return
	}
	if name == w.hostname {
		w.EndpointWireguardUpdate(name, zeroKey, nil)
		return
	}

	// If there is no existing peer and no existing update then exit.
	if _, ok := w.nodes[name]; ok {
		logCxt.Debug("Peer is programmed")
	} else if _, ok := w.nodeUpdates[name]; !ok {
		logCxt.Debug("Peer is not programmed, and there are no updates")
		return
	}

	// Create update to remove the public key.
	update := w.getOrInitNodeUpdateData(name)
	update.publicKey = &zeroKey
	w.setNodeUpdate(name, update)
}

func (w *Wireguard) QueueResync() {
	log.Debug("Queueing a resync of wireguard configuration")
	if w.opRecorder != nil {
		w.opRecorder.RecordOperation("resync-wg")
	}

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
			log.WithField("ourPublicKey", *w.ourPublicKey).Info("Public key out of sync or updated")
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
		log.WithError(err).Error("error obtaining link client")
		return err
	}

	// If wireguard is not enabled, then short-circuit the processing - ensure config is deleted.
	if !w.config.Enabled {
		log.Debug("Wireguard is not enabled, skipping sync")
		if !w.inSyncWireguard {
			log.Debug("Wireguard is not in-sync - verifying wireguard configuration is removed")
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
		log.Info("Wireguard is not supported")
		return
	}

	// --- Wireguard is enabled ---

	// Process local CIDR updates. This may result in node deltas for the local node.
	if w.localCIDRsUpdated {
		w.nodeUpdates[w.hostname] = w.getLocalNodeCIDRUpdates()
		w.localCIDRsUpdated = false
	}

	// We scan the updates multiple times to perform the following ordered updates:
	// 1. Deletion of nodes and wireguard nodes (we handle these separately from other updates because it is easier
	//    to handle a delete/re-add this way without needing to calculate delta configs.
	// 2. Update of cached node configuration (we cannot be certain exactly what is programmable until updated)
	// 3. Update of route table routes.
	// 4. Construction of wireguard delta (if performing deltas, or re-sync of wireguard configuration)
	// 5. Simultaneous updates of wireguard and routes.
	var conflictingKeys = set.New()
	wireguardPeerDelete := w.handlePeerAndRouteDeletionFromNodeUpdates(conflictingKeys)
	w.updateCacheFromNodeUpdates(conflictingKeys)
	w.updateRouteTableFromNodeUpdates()

	defer func() {
		// Flag the programmed state to be the same as the expected state for each peer. We do this even if we failed to
		// apply the update because the routetable processing also uses this to maintain details about whether or not it
		// has routed to wireguard. In the event of a failed update or wireguard config, a full resync will be performed
		// next iteration which ignores the programmedInWireguard flag.
		if len(w.nodeUpdates) > 0 {
			for name, node := range w.nodes {
				if w.shouldProgramWireguardPeer(name, node) {
					log.WithField("node", name).Debug("Flag node as programmed")
					node.programmedInWireguard = true
				} else {
					log.WithField("node", name).Debug("Flag node as not programmed")
					node.programmedInWireguard = false
				}
			}
		}

		// All updates have been applied. Make sure we delete them after we exit - we will either have applied the deltas,
		// or we'll need to do a full resync, in either case no need to keep the deltas.  Don't do this immediately because
		// we may need them to calculate the wireguard config delta.
		w.nodeUpdates = map[string]*nodeUpdateData{}
	}()

	// If necessary ensure the wireguard device is configured. If this errors or if it is not yet oper up then no point
	// doing anything else.
	if !w.inSyncLink {
		log.Debug("Ensure wireguard link is created and up")
		linkUp, err := w.ensureLink(netlinkClient)
		if netlinkshim.IsNotSupported(err) {
			// Wireguard is not supported, set everything to "in-sync" since there is not a lot of point doing anything
			// else. We don't return an error in this case, instead we'll retry every resync period.
			log.Info("Wireguard is not supported - publishing no public key")
			w.setNotSupported()
			return nil
		} else if err != nil {
			// Error configuring link, pass up the stack. Close the netlink client as a precaution.
			log.WithError(err).Info("Unable to create wireguard link, retrying...")
			w.closeNetlinkClient()
			return ErrUpdateFailed
		} else if !linkUp {
			// Wait for oper up notification.
			log.Info("Waiting for wireguard link to come up...")
			return nil
		}

		// The link is now sync'd.
		w.inSyncLink = true
	}

	// Get the wireguard client. This may not always be possible.
	wireguardClient, err := w.getWireguardClient()
	if netlinkshim.IsNotSupported(err) {
		log.Info("Wireguard is not supported - send zero-key status")
		w.setNotSupported()
		return nil
	} else if err != nil {
		log.WithError(err).Error("error obtaining wireguard client")
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
		log.Info("Ensure wireguard interface address is correct")
		wg.Add(1)
		go func() {
			defer wg.Done()
			if errLink = w.ensureLinkAddressV4(netlinkClient); errLink == nil {
				w.inSyncInterfaceAddr = true
			}
		}()
	}

	// Apply routetable updates.
	log.Debug("Apply routing table updates for wireguard")
	wg.Add(1)
	go func() {
		defer wg.Done()
		errRoutes = w.routetable.Apply()
	}()

	// Apply wireguard configuration.
	wg.Add(1)
	var wireguardNodeUpdate *wgtypes.Config
	var publicKey wgtypes.Key
	go func() {
		defer wg.Done()

		// Update wireguard so that we are in-sync.
		if w.inSyncWireguard {
			// Wireguard configuration is in-sync, perform a delta update. First do the delete that was constructed
			// earlier, then construct and apply the update. Flag as not in-sync until we have finished processing.
			log.Debug("Apply wireguard crypto routing delta update")
			if errWireguard = w.applyWireguardConfig(wireguardClient, wireguardPeerDelete); errWireguard != nil {
				log.WithError(errWireguard).Info("Failed to delete wireguard nodes")
				return
			}
			wireguardNodeUpdate = w.constructWireguardDeltaFromNodeUpdates(conflictingKeys)
			if errWireguard = w.applyWireguardConfig(wireguardClient, wireguardNodeUpdate); errWireguard != nil {
				log.WithError(errWireguard).Info("Failed to create or update wireguard nodes")
				return
			}
		} else {
			// Wireguard configuration is not in-sync. Construct and apply the wireguard configuration required to
			// synchronize with our cached data.
			log.Debug("Apply wireguard crypto routing resync")
			if publicKey, wireguardNodeUpdate, errWireguard = w.constructWireguardDeltaForResync(wireguardClient); errWireguard != nil {
				log.WithError(errWireguard).Info("Failed to construct a full wireguard delta for resync")
				return
			} else if errWireguard = w.applyWireguardConfig(wireguardClient, wireguardNodeUpdate); errWireguard != nil {
				log.WithError(errWireguard).Info("Failed to update wireguard nodes for resync")
				return
			} else if w.ourPublicKey == nil || *w.ourPublicKey != publicKey {
				// The public key differs from the one we previously queried or this is the first time we queried it.
				// Store and flag our key is not in sync so that a status update will be sent.
				log.WithField("publicKey", publicKey).Info("Public key has been updated, send status notification")
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
		log.Info("Wireguard programming failed, ensure full resync is performed next")
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
	log.Debug("Ensure routing rules are configured")
	w.addRouteRule()
	if err = w.routerule.Apply(); err != nil {
		// Error updating the ip rule.
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

func (w *Wireguard) getOrInitNodeData(name string) *nodeData {
	if n := w.nodes[name]; n != nil {
		return n
	}
	return newNodeData()
}

func (w *Wireguard) setNode(name string, node *nodeData) {
	w.nodes[name] = node
}

func (w *Wireguard) getOrInitNodeUpdateData(name string) *nodeUpdateData {
	if nu := w.nodeUpdates[name]; nu != nil {
		return nu
	}
	return newNodeUpdateData()
}

func (w *Wireguard) setNodeUpdate(name string, update *nodeUpdateData) {
	w.nodeUpdates[name] = update
}

// getLocalNodeCIDRUpdates gets a nodeUpdateData to handle any deltas to the set of local CIDRs.
func (w *Wireguard) getLocalNodeCIDRUpdates() *nodeUpdateData {
	node := w.getOrInitNodeData(w.hostname)

	// Node updates for the local node should only consist of CIDR updates - since we are calculating the set in full
	// here, no need to modify any existing data.
	nodeUpdate := newNodeUpdateData()

	// Include all local CIDRs, update the cidrsAdded with any missing.
	oldFiltered := node.cidrs.Copy()
	w.localCIDRs.Iter(func(itemCIDR interface{}) error {
		cidr := itemCIDR.(ip.CIDR)
		if oldFiltered.Contains(cidr) {
			oldFiltered.Discard(cidr)
		} else {
			nodeUpdate.cidrsAdded.Add(cidr)
		}
		return nil
	})
	// Include all local IPs that are not covered by the local CIDRs, update the cidrsAdded with any missing.
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
			if oldFiltered.Contains(ipAsCidr) {
				oldFiltered.Discard(ipAsCidr)
			} else {
				nodeUpdate.cidrsAdded.Add(ipAsCidr)
			}
		}
		return nil
	})
	// Remove any existing entry that is now no longer required.
	oldFiltered.Iter(func(itemCIDR interface{}) error {
		cidr := itemCIDR.(ip.CIDR)
		nodeUpdate.cidrsDeleted.Add(cidr)
		return nil
	})

	// Return the node update
	return nodeUpdate
}

// handlePeerAndRouteDeletionFromNodeUpdates handles wireguard peer deletion preparation:
// -  Updates routing table to remove routes for permantently deleted nodes
// -  Creates a wireguard config update for deleted nodes, or for nodes whose public key has changed (which for
//    wireguard is effectively a different peer)
//
// This method does not perform any dataplane updates.
func (w *Wireguard) handlePeerAndRouteDeletionFromNodeUpdates(conflictingKeys set.Set) *wgtypes.Config {
	var wireguardPeerDelete wgtypes.Config
	for name, update := range w.nodeUpdates {
		// Get existing peer configuration. If peer not seen before then no deletion processing is required.
		logCxt := log.WithField("node", name)
		logCxt.Debug("Handle peer and route deletion for node")
		node := w.nodes[name]
		if node == nil {
			logCxt.Debug("No wireguard configuration for node")
			continue
		}

		if update.deleted {
			// Node is deleted, so remove the node configuration and the associated routes.
			logCxt.Info("Node is deleted, remove associated routes and wireguard peer")
			delete(w.nodes, name)

			// Delete all of the node routes for the nodeData and remove CIDR->node association. Note that we always
			// update the routing table routes using delta updates even during a full resync. The routetable component
			// takes care of its own kernel-cache synchronization.
			node.cidrs.Iter(func(item interface{}) error {
				cidr := item.(ip.CIDR)
				w.routetable.RouteRemove(w.config.InterfaceName, cidr)
				delete(w.cidrToNodeName, cidr)
				logCxt.WithField("cidr", cidr).Debug("Deleting route")
				return nil
			})
		} else if update.publicKey == nil || *update.publicKey == node.publicKey {
			// It's not a delete, and the public key hasn't changed so no key deletion processing required.
			logCxt.Debug("Node updated, but public key is the same - no wireguard peer deletion required")
			continue
		}

		if node.publicKey == zeroKey {
			// The node did not have a key assigned, so no peer tidy-up required.
			logCxt.Debug("Node had no public key assigned - no deletion of wireguard peer necessary")
			continue
		}

		// If we aren't doing a full re-sync then delete the associated peer if it was previously configured.
		if node.programmedInWireguard && w.inSyncWireguard {
			logCxt.WithField("publicKey", node.publicKey).Debug("Adding peer deletion config update for key")
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
			logCxt.WithField("publicKey", node.publicKey).Debug("Removed the only node claiming public key")
			delete(w.publicKeyToNodeNames, node.publicKey)
		} else {
			// This is or was a conflicting key. Recheck the nodes associated with this key at the end.
			log.WithField("publicKey", node.publicKey).Info("Removed node which claimed the same public key as at least one other node")
			conflictingKeys.Add(node.publicKey)
		}
		node.publicKey = zeroKey
	}

	if len(wireguardPeerDelete.Peers) > 0 {
		log.Debug("There are wireguard nodes to delete")
		return &wireguardPeerDelete
	}
	return nil
}

// updateCacheFromNodeUpdates updates the cache from the node update configuration.
//
// This method applies the current set of node updates on top of the current cache. It removes updates that are no
// ops so that they are not re-processed further down the pipeline.
func (w *Wireguard) updateCacheFromNodeUpdates(conflictingKeys set.Set) {
	for name, update := range w.nodeUpdates {
		node := w.getOrInitNodeData(name)

		// This is a remote node configuration. Update the node data and the key to node mappings.
		logCxt := log.WithField("node", name)
		logCxt.Debug("Updating cache from update for peer")
		updated := false
		if update.ipv4EndpointAddr != nil {
			logCxt.WithField("ipv4EndpointAddr", *update.ipv4EndpointAddr).Debug("Store IPv4 address")
			node.ipv4EndpointAddr = *update.ipv4EndpointAddr
			updated = true
		}
		if update.publicKey != nil {
			logCxt.WithField("publicKey", *update.publicKey).Debug("Store public key")
			node.publicKey = *update.publicKey
			if node.publicKey != zeroKey {
				if nodenames := w.publicKeyToNodeNames[node.publicKey]; nodenames == nil {
					log.Debug("Public key not associated with a node")
					w.publicKeyToNodeNames[node.publicKey] = set.From(name)
				} else {
					log.Info("Public key already associated with a node")
					conflictingKeys.Add(node.publicKey)
					nodenames.Add(name)
				}
			}
			updated = true
		}
		update.cidrsDeleted.Iter(func(item interface{}) error {
			cidr := item.(ip.CIDR)
			logCxt.WithField("cidr", cidr).Debug("Discarding CIDR")
			node.cidrs.Discard(cidr)
			updated = true
			return nil
		})
		update.cidrsAdded.Iter(func(item interface{}) error {
			cidr := item.(ip.CIDR)
			logCxt.WithField("cidr", cidr).Debug("Adding CIDR")
			node.cidrs.Add(cidr)
			updated = true
			return nil
		})

		if updated {
			// Node configuration updated. Store node data.
			log.Debug("Node updated")
			w.setNode(name, node)
		} else {
			// No further update, delete update so it's not processed again.
			log.Debug("No updates for the node - remove node update to remove additional processing")
			delete(w.nodeUpdates, name)
		}
	}
}

// updateRouteTable updates the route table from the node updates.
func (w *Wireguard) updateRouteTableFromNodeUpdates() {
	// Do all deletes first. Then adds or updates separarately. This ensures a CIDR that has been deleted from one node
	// and added to another will not add first then delete (which will remove the route, since the route table does not
	// care about destination node).
	for name, update := range w.nodeUpdates {
		// Delete routes that are no longer required in routing.
		node := w.getOrInitNodeData(name)
		ifaceName := routetable.InterfaceNone
		if node != nil && node.programmedInWireguard {
			ifaceName = w.config.InterfaceName
		}
		logCxt := log.WithFields(log.Fields{"node": name, "ifaceName": ifaceName})
		update.cidrsDeleted.Iter(func(item interface{}) error {
			cidr := item.(ip.CIDR)
			logCxt.WithField("cidr", cidr).Debug("Removing CIDR from routetable interface")
			w.routetable.RouteRemove(ifaceName, cidr)
			return nil
		})
	}

	// Now do the adds or updates. The routetable component will take care of routes that don't actually change and
	// effectively no-op the delta.
	for name, update := range w.nodeUpdates {
		logCxt := log.WithField("node", name)
		logCxt.Debug("Add/update routing for peer")
		node := w.getOrInitNodeData(name)

		// If the node routing to wireguard does not match with whether we should route then we need to do a full
		// route update, otherwise do an incremental update.
		var updateSet set.Set
		shouldRouteToWireguard := w.shouldProgramWireguardPeer(name, node)
		if node.routingToWireguard != shouldRouteToWireguard {
			logCxt.WithField("shouldNowRouteToWireguard", shouldRouteToWireguard).Debug("Wireguard routing decision has changed - need to update full set of CIDRs")
			updateSet = node.cidrs
		} else {
			logCxt.WithField("shouldNowRouteToWireguard", shouldRouteToWireguard).Debug("Wireguard routing decision has not changed - only need to update added CIDRs")
			updateSet = update.cidrsAdded
		}

		var targetType routetable.TargetType
		var ifaceName, deleteIfaceName string
		if !shouldRouteToWireguard {
			// If we should not route to wireguard then we need to use a throw directive to skip wireguard routing and
			// return to normal routing. We may also need to delete the existing route to wireguard.
			logCxt.Debug("Not routing to wireguard - set route type to throw")
			targetType = routetable.TargetTypeThrow
			ifaceName = routetable.InterfaceNone
			deleteIfaceName = w.config.InterfaceName
		} else {
			// If we should route to wireguard then route to the wireguard interface. We may also need to delete the
			// existing throw route that was used to circumvent wireguard routing.
			logCxt.Debug("Routing to wireguard interface")
			ifaceName = w.config.InterfaceName
			deleteIfaceName = routetable.InterfaceNone
		}

		updateSet.Iter(func(item interface{}) error {
			cidr := item.(ip.CIDR)
			updateLogCxt := logCxt.WithField("cidr", cidr)
			updateLogCxt.Debug("Updating route for CIDR")
			if node.routingToWireguard != shouldRouteToWireguard {
				// The wireguard setting has changed. It is possible that some of the entries we are "removing" were
				// never added - the routetable component handles that gracefully. We need to do these deletes because
				// routetable component groups by interface and we are essentially moving routes between the wireguard
				// interface and the "none" interface.
				updateLogCxt.WithField("ifacename", deleteIfaceName).Debug("Wireguard routing has changed - delete previous route for interface")
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

// constructWireguardDeltaFromNodeUpdates constructs a wireguard delta update from the set of peer updates.
func (w *Wireguard) constructWireguardDeltaFromNodeUpdates(conflictingKeys set.Set) *wgtypes.Config {
	// 4. If we are performing a wireguard delta update then construct the delta now.
	var wireguardUpdate wgtypes.Config
	if w.inSyncWireguard {
		// Construct a wireguard delta update
		for name, update := range w.nodeUpdates {
			logCxt := log.WithField("peer", name)
			logCxt.Debug("Constructing wireguard delta")
			peer := w.nodes[name]
			if peer == nil {
				log.Warn("internal error: peer data is nil")
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
				if !peer.programmedInWireguard || update.cidrsDeleted.Len() > 0 {
					logCxt.Debug("Peer not programmed or CIDRs were deleted - need to replace full set of CIDRs")
					wgpeer.ReplaceAllowedIPs = true
					wgpeer.AllowedIPs = peer.allowedCidrsForWireguard()
					updatePeer = true
				} else if update.cidrsAdded.Len() > 0 {
					logCxt.Debug("Peer programmmed, no CIDRs deleted and CIDRs added")
					wgpeer.AllowedIPs = make([]net.IPNet, 0, update.cidrsAdded.Len())
					update.cidrsAdded.Iter(func(item interface{}) error {
						wgpeer.AllowedIPs = append(wgpeer.AllowedIPs, item.(ip.CIDR).ToIPNet())
						return nil
					})
					updatePeer = true
				}

				if update.ipv4EndpointAddr != nil || !peer.programmedInWireguard {
					logCxt.WithField("ipv4EndpointAddr", update.ipv4EndpointAddr).Info("Peer endpoint address is updated")
					wgpeer.Endpoint = w.endpointUDPAddr(peer.ipv4EndpointAddr.AsNetIP())
					updatePeer = true
				}

				if updatePeer {
					logCxt.Debug("Peer needs updating")
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

		// Finally loop through any conflicting public keys and check each of the nodes is now handled correctly.
		conflictingKeys.Iter(func(item interface{}) error {
			key := item.(wgtypes.Key)
			logCxt := log.WithField("publicKey", key)
			logCxt.Debug("Processing public key with conflicting nodes")
			nodenames := w.publicKeyToNodeNames[key]
			if nodenames == nil {
				return nil
			}
			nodenames.Iter(func(item interface{}) error {
				nodename := item.(string)
				nodeLogCxt := logCxt.WithField("node", nodename)
				nodeLogCxt.Debug("Processing peer")
				peer := w.nodes[nodename]
				if peer == nil || peer.programmedInWireguard == w.shouldProgramWireguardPeer(nodename, peer) {
					// The peer programming matches the expected value, so nothing to do.
					nodeLogCxt.Debug("Programming state has not changed")
					return nil
				} else if peer.programmedInWireguard {
					// The peer is programmed and shouldn't be. Add a delta delete.
					nodeLogCxt.Debug("Programmed in wireguard, need to delete")
					wireguardUpdate.Peers = append(wireguardUpdate.Peers, wgtypes.PeerConfig{
						Remove:    true,
						PublicKey: peer.publicKey,
					})
				} else {
					// The peer is not programmed and should be.  Add a delta create.
					nodeLogCxt.Debug("Not programmed in wireguard, needs to be added now")
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
		log.Debug("There are nodes to update")
		return &wireguardUpdate
	}
	return nil
}

// constructWireguardDeltaForResync checks the wireguard configuration matches the cached data and creates a delta
// update to correct any discrepancies.
func (w *Wireguard) constructWireguardDeltaForResync(wireguardClient netlinkshim.Wireguard) (wgtypes.Key, *wgtypes.Config, error) {
	// Get the wireguard device configuration.
	logCxt := log.WithField("ifaceName", w.config.InterfaceName)
	device, err := wireguardClient.DeviceByName(w.config.InterfaceName)
	if err != nil {
		logCxt.WithError(err).Error("error querying wireguard configuration")
		return zeroKey, nil, err
	}

	// Determine if any configuration on the device needs updating
	wireguardUpdate := wgtypes.Config{}
	wireguardUpdateRequired := false
	if device.FirewallMark != w.config.FirewallMark {
		logCxt.WithFields(log.Fields{"existing": device.FirewallMark, "required": w.config.FirewallMark}).Info("Update firewall mark")
		wireguardUpdate.FirewallMark = &w.config.FirewallMark
		wireguardUpdateRequired = true
	}
	if device.ListenPort != w.config.ListeningPort {
		logCxt.WithFields(log.Fields{"existing": device.ListenPort, "required": w.config.ListeningPort}).Info("Update listening port")
		wireguardUpdate.ListenPort = &w.config.ListeningPort
		wireguardUpdateRequired = true
	}

	publicKey := device.PublicKey
	if device.PrivateKey == zeroKey || device.PublicKey == zeroKey {
		// One of the private or public key is not set. Generate a new private key and return the corresponding
		// public key.
		log.Info("Generate new private/public keypair")
		pkey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			log.WithError(err).Error("error generating private-key")
			return zeroKey, nil, err
		}
		wireguardUpdate.PrivateKey = &pkey
		wireguardUpdateRequired = true

		publicKey = pkey.PublicKey()
		log.WithField("publicKey", publicKey).Debug("Generated new public key")
	}

	// Track which keys we have processed.
	processedKeys := set.New()

	// Handle nodes that are configured
	for peerIdx := range device.Peers {
		key := device.Peers[peerIdx].PublicKey
		node := w.getNodeFromKey(key)

		// Track each node that we process. Any nodes in our cache that were not processed here indicates a node that
		// is not programmed in the dataplane. This is handled below
		processedKeys.Add(key)

		logCxt := log.WithFields(log.Fields{"publicKey": key, "node": node})
		if node == nil {
			logCxt.Info("Peer key is not expected or is associated with multiple nodes")
			wireguardUpdate.Peers = append(wireguardUpdate.Peers, wgtypes.PeerConfig{
				PublicKey: key,
				Remove:    true,
			})
			wireguardUpdateRequired = true
			continue
		}

		configuredCidrs := device.Peers[peerIdx].AllowedIPs
		configuredAddr := device.Peers[peerIdx].Endpoint
		replaceCidrs := false

		// Need to check programmed CIDRs against expected to see if any need deleting.
		logCxt.Debug("Check programmed CIDRs for required deletions")
		expectedAllowedCidrs := node.allowedCidrsForWireguard()
		configuredCidrsAsSet := set.New()
		var allowedCidrsForUpdateMsg []net.IPNet
		for _, netCidr := range configuredCidrs {
			cidr := ip.CIDRFromIPNet(&netCidr)
			configuredCidrsAsSet.Add(cidr)
			if !node.cidrs.Contains(cidr) {
				// Need to delete an entry, so just replace.
				logCxt.WithField("cidr", cidr).Info("Unexpected CIDR configured - replace full set of CIDRs")
				replaceCidrs = true
				allowedCidrsForUpdateMsg = expectedAllowedCidrs
				break
			}
		}

		// If we aren't replacing the CIDRs, check to see if there are any missing, and if so determine which ones.
		if !replaceCidrs && len(expectedAllowedCidrs) != len(configuredCidrs) {
			logCxt.Info("Adding missing CIDRs configured for peer")
			for _, netCidr := range expectedAllowedCidrs {
				cidr := ip.CIDRFromIPNet(&netCidr)
				if !configuredCidrsAsSet.Contains(cidr) {
					allowedCidrsForUpdateMsg = append(allowedCidrsForUpdateMsg, netCidr)
				}
			}
		}

		// If the CIDRs need replacing or the endpoint address needs updating then update the entry.
		expectedEndpointIP := node.ipv4EndpointAddr.AsNetIP()
		replaceEndpointAddr := expectedEndpointIP != nil &&
			(configuredAddr == nil || configuredAddr.Port != w.config.ListeningPort || !configuredAddr.IP.Equal(expectedEndpointIP))
		if replaceEndpointAddr || allowedCidrsForUpdateMsg != nil {
			peer := wgtypes.PeerConfig{
				PublicKey:         key,
				UpdateOnly:        true,
				ReplaceAllowedIPs: replaceCidrs,
				AllowedIPs:        allowedCidrsForUpdateMsg,
			}

			if replaceEndpointAddr {
				logCxt.Info("Endpoint address needs updating")
				peer.Endpoint = w.endpointUDPAddr(expectedEndpointIP)
			}

			wireguardUpdate.Peers = append(wireguardUpdate.Peers, peer)
			wireguardUpdateRequired = true
		}
	}

	// Handle nodes that are not configured at all.
	for name, node := range w.nodes {
		logCxt := log.WithFields(log.Fields{"publicKey": node.publicKey, "node": name})
		if processedKeys.Contains(node.publicKey) {
			logCxt.Debug("Peer key already handled")
			continue
		}
		if !w.shouldProgramWireguardPeer(name, node) {
			logCxt.Debug("Peer should not be programmed")
			continue
		}

		logCxt.WithField("ipv4EndpointAddr", node.ipv4EndpointAddr).Info("Add peer to wireguard")
		wireguardUpdate.Peers = append(wireguardUpdate.Peers, wgtypes.PeerConfig{
			PublicKey:  node.publicKey,
			Endpoint:   w.endpointUDPAddr(node.ipv4EndpointAddr.AsNetIP()),
			AllowedIPs: node.allowedCidrsForWireguard(),
		})
		wireguardUpdateRequired = true
	}

	if wireguardUpdateRequired {
		return publicKey, &wireguardUpdate, nil
	}

	return publicKey, nil, nil
}

// ensureLink checks that the wireguard link is configured correctly. Returns true if the link is oper up.
func (w *Wireguard) ensureLink(netlinkClient netlinkshim.Interface) (bool, error) {
	logCxt := log.WithField("ifaceName", w.config.InterfaceName)

	if w.config.EncryptHostTraffic {
		log.Info("Enabling src valid mark for WireGuard")
		if err := writeProcSys(allSrcValidMarkPath, "1"); err != nil {
			return false, err
		}
	}

	link, err := netlinkClient.LinkByName(w.config.InterfaceName)
	if netlinkshim.IsNotExist(err) {
		// Create the wireguard device.
		logCxt.Info("Wireguard device needs to be created")
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
			log.WithError(err).Error("error querying wireguard device")
			return false, err
		}

		logCxt.Info("Created wireguard device")
	} else if err != nil {
		logCxt.WithError(err).Error("unable to determine if wireguard device exists")
		return false, err
	}

	if link.Type() != wireguardType {
		logCxt.WithField("type", link.Type()).Error("interface is not of type wireguard")
		return false, errWrongInterfaceType
	}

	// If necessary, update the MTU and admin status of the device.
	logCxt.Debug("Wireguard device exists, checking settings")
	attrs := link.Attrs()
	oldMTU := attrs.MTU
	if w.config.MTU != 0 && oldMTU != w.config.MTU {
		logCxt.WithField("oldMTU", oldMTU).Info("Wireguard device MTU needs to be updated")
		if err := netlinkClient.LinkSetMTU(link, w.config.MTU); err != nil {
			log.WithError(err).Warn("failed to set tunnel device MTU")
			return false, err
		}
		log.Info("Updated wireguard device MTU")
	}
	if attrs.Flags&net.FlagUp == 0 {
		log.WithField("flags", attrs.Flags).Info("Wireguard interface wasn't admin up, enabling it")
		if err := netlinkClient.LinkSetUp(link); err != nil {
			log.WithError(err).Warn("failed to set wireguard device up")
			return false, err
		}
		log.Info("Set wireguard admin up")

		if link, err = netlinkClient.LinkByName(w.config.InterfaceName); err != nil {
			log.WithError(err).Warn("failed to get link device after creating link")
			return false, err
		}
	}

	// Track whether the interface is oper up or not. We halt programming when it is down.
	return link.Attrs().Flags&net.FlagUp != 0, nil
}

// ensureNoLink checks that the wireguard link is not present.
func (w *Wireguard) ensureNoLink(netlinkClient netlinkshim.Interface) error {
	logCxt := log.WithField("ifaceName", w.config.InterfaceName)
	link, err := netlinkClient.LinkByName(w.config.InterfaceName)
	if err == nil {
		// Wireguard device exists.
		logCxt.Info("Wireguard is disabled, deleting device")
		if err := netlinkClient.LinkDel(link); err != nil {
			log.WithError(err).Error("error deleting wireguard type link")
			return err
		}
		logCxt.Info("Deleted wireguard device")
	} else if netlinkshim.IsNotExist(err) {
		logCxt.Debug("Wireguard is disabled and does not exist")
	} else if err != nil {
		logCxt.WithError(err).Error("unable to determine if wireguard device exists")
		return err
	}
	return nil
}

// ensureLinkAddressV4 ensures the wireguard link to set to the required local IP address.  It removes any other
// addresses.
func (w *Wireguard) ensureLinkAddressV4(netlinkClient netlinkshim.Interface) error {
	logCxt := log.WithField("ifaceName", w.config.InterfaceName)
	logCxt.Debug("Setting local IPv4 address on link.")
	link, err := netlinkClient.LinkByName(w.config.InterfaceName)
	if err != nil {
		logCxt.WithError(err).Warn("Failed to get device")
		return err
	}

	addrs, err := netlinkClient.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		logCxt.WithError(err).Warn("failed to list interface addresses")
		return err
	}

	var address net.IP
	if w.ourIPv4InterfaceAddr != nil {
		address = w.ourIPv4InterfaceAddr.AsNetIP()
	}

	found := false
	for _, oldAddr := range addrs {
		addrLogCxt := logCxt.WithField("addr", oldAddr)
		if address != nil && oldAddr.IP.Equal(address) {
			addrLogCxt.Debug("Address already present.")
			found = true
			continue
		}
		addrLogCxt.Info("Removing old address")
		if err := netlinkClient.AddrDel(link, &oldAddr); err != nil {
			addrLogCxt.WithError(err).Warn("failed to delete address from wireguard device")
			return err
		}
	}

	if address != nil {
		addrLogCxt := logCxt.WithField("addr", address)
		if !found {
			addrLogCxt.Info("address not present on wireguard device, adding it")
			mask := net.CIDRMask(32, 32)
			ipNet := net.IPNet{
				IP:   address.Mask(mask), // Mask the IP to match ParseCIDR()'s behaviour.
				Mask: mask,
			}
			addr := &netlink.Addr{
				IPNet: &ipNet,
			}
			if err := netlinkClient.AddrAdd(link, addr); err != nil {
				addrLogCxt.WithError(err).Warn("failed to add address")
				return err
			}
		}
		logCxt.Debug("Address set on wireguard device")
	} else {
		logCxt.Debug("Address not set on wireguard device")
	}
	return nil
}

// addRouteRule adds a routing rule to use the wireguard table.
func (w *Wireguard) addRouteRule() {
	// The netlink library has a bug where it returns -1 for the mark on a rule instead of 0.
	// To work around this issue, the rule below was re-written to no longer use a mark of 0x0,
	// instead matching the NOT of the actual wireguard mark.
	w.routerule.SetRule(routerule.NewRule(ipVersion, w.config.RoutingRulePriority).
		GoToTable(w.config.RoutingTableIndex).
		Not().MatchFWMarkWithMask(uint32(w.config.FirewallMark), uint32(w.config.FirewallMark)))
}

// ensureDisabled ensures all calico-installed wireguard configuration is removed.
func (w *Wireguard) ensureDisabled(netlinkClient netlinkshim.Interface) error {
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
func (w *Wireguard) shouldProgramWireguardPeer(name string, node *nodeData) bool {
	logCxt := log.WithField("node", name)
	if node.ipv4EndpointAddr == nil {
		logCxt.Debug("Peer should not be programmed, no endpoint address")
		return false
	} else if node.publicKey == zeroKey {
		logCxt.Debug("Peer should not be programmed, no valid public key")
		return false
	} else if w.publicKeyToNodeNames[node.publicKey].Len() != 1 {
		logCxt.Debug("Peer should not be programmed, multiple nodes are claiming the same key")
		return false
	}
	logCxt.Debug("Peer should be programmed")
	return true
}

// getWireguardClient returns a wireguard client for managing wireguard devices.
func (w *Wireguard) getWireguardClient() (netlinkshim.Wireguard, error) {
	if w.cachedWireguardClient == nil {
		if w.numConsistentWireguardClientFailures >= maxConnFailures && w.numConsistentWireguardClientFailures%wireguardClientRetryInterval != 0 {
			// It is a valid condition that we cannot connect to the wireguard client, so just log.
			log.WithField("numFailures", w.numConsistentWireguardClientFailures).Debug(
				"Repeatedly failed to connect to wireguard client.")
			return nil, ErrNotSupportedTooManyFailures
		}
		log.Info("Trying to connect to wireguard client")
		client, err := w.newWireguardClient()
		if err != nil {
			w.numConsistentWireguardClientFailures++
			log.WithError(err).WithField("numFailures", w.numConsistentWireguardClientFailures).Info(
				"Failed to connect to wireguard client")
			return nil, err
		}
		w.cachedWireguardClient = client
	}
	if w.numConsistentWireguardClientFailures > 0 {
		log.WithField("numFailures", w.numConsistentWireguardClientFailures).Info(
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
		log.WithError(err).Error("Failed to close wireguard client, ignoring.")
	}
	w.cachedWireguardClient = nil
}

// getNetlinkClient returns a netlink client for managing device links.
func (w *Wireguard) getNetlinkClient() (netlinkshim.Interface, error) {
	if w.cachedNetlinkClient == nil {
		// We do not expect the standard netlink client to fail, so panic after a set number of failed attempts.
		if w.numConsistentNetlinkClientFailures >= maxConnFailures {
			log.WithField("numFailures", w.numConsistentNetlinkClientFailures).Panic(
				"Repeatedly failed to connect to netlink.")
		}
		log.Info("Trying to connect to linkClient")
		client, err := w.newNetlinkClient()
		if err != nil {
			w.numConsistentNetlinkClientFailures++
			log.WithError(err).WithField("numFailures", w.numConsistentNetlinkClientFailures).Error(
				"Failed to connect to linkClient")
			return nil, err
		}
		w.cachedNetlinkClient = client
	}
	if w.numConsistentNetlinkClientFailures > 0 {
		log.WithField("numFailures", w.numConsistentNetlinkClientFailures).Info(
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

// getNodeFromKey returns the node data associated with a key. If there is no node, or if multiple nodes have claimed the
// same key, this returns nil.
func (w *Wireguard) getNodeFromKey(key wgtypes.Key) *nodeData {
	if item := getOnlyItemInSet(w.publicKeyToNodeNames[key]); item != nil {
		return w.nodes[item.(string)]
	}
	return nil
}

// applyWireguardConfig applies the wireguard configuration.
func (w *Wireguard) applyWireguardConfig(wireguardClient netlinkshim.Wireguard, c *wgtypes.Config) error {
	log.Debugf("Apply wireguard config update: %#v", c)
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

// writeProcSys writes the value to the given sysctl path
func writeProcSys(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err = f.Write([]byte(value)); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return nil
}
