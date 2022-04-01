// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

package calc

import (
	"strings"

	log "github.com/sirupsen/logrus"

	"fmt"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/labelindex"
	"github.com/projectcalico/calico/felix/multidict"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type EventHandler func(message interface{})

type configInterface interface {
	UpdateFrom(map[string]string, config.Source) (changed bool, err error)
	RawValues() map[string]string
}

// EventSequencer buffers and coalesces updates from the calculation graph then flushes them
// when Flush() is called.  It flushed updates in a dependency-safe order.
type EventSequencer struct {
	config configInterface

	// Buffers used to hold data that we haven't flushed yet so we can coalesce multiple
	// updates and generate updates in dependency order.
	pendingAddedIPSets           map[string]proto.IPSetUpdate_IPSetType
	pendingRemovedIPSets         set.Set
	pendingAddedIPSetMembers     multidict.StringToIface
	pendingRemovedIPSetMembers   multidict.StringToIface
	pendingPolicyUpdates         map[model.PolicyKey]*ParsedRules
	pendingPolicyDeletes         set.Set
	pendingProfileUpdates        map[model.ProfileRulesKey]*ParsedRules
	pendingProfileDeletes        set.Set
	pendingEncapUpdate           *config.Encapsulation
	pendingEndpointUpdates       map[model.Key]interface{}
	pendingEndpointTierUpdates   map[model.Key][]tierInfo
	pendingEndpointDeletes       set.Set
	pendingHostIPUpdates         map[string]*net.IP
	pendingHostIPDeletes         set.Set
	pendingIPPoolUpdates         map[ip.CIDR]*model.IPPool
	pendingIPPoolDeletes         set.Set
	pendingNotReady              bool
	pendingGlobalConfig          map[string]string
	pendingHostConfig            map[string]string
	pendingServiceAccountUpdates map[proto.ServiceAccountID]*proto.ServiceAccountUpdate
	pendingServiceAccountDeletes set.Set
	pendingNamespaceUpdates      map[proto.NamespaceID]*proto.NamespaceUpdate
	pendingNamespaceDeletes      set.Set
	pendingRouteUpdates          map[routeID]*proto.RouteUpdate
	pendingRouteDeletes          set.Set
	pendingVTEPUpdates           map[string]*proto.VXLANTunnelEndpointUpdate
	pendingVTEPDeletes           set.Set
	pendingWireguardUpdates      map[string]*model.Wireguard
	pendingWireguardDeletes      set.Set
	pendingGlobalBGPConfig       *proto.GlobalBGPConfigUpdate
	pendingServiceUpdates        map[serviceID]*proto.ServiceUpdate
	pendingServiceDeletes        set.Set

	// Sets to record what we've sent downstream. Updated whenever we flush.
	sentIPSets          set.Set
	sentPolicies        set.Set
	sentProfiles        set.Set
	sentEndpoints       set.Set
	sentHostIPs         set.Set
	sentIPPools         set.Set
	sentServiceAccounts set.Set
	sentNamespaces      set.Set
	sentRoutes          set.Set
	sentVTEPs           set.Set
	sentWireguard       set.Set
	sentServices        set.Set

	Callback EventHandler
}

type serviceID struct {
	Name      string
	Namespace string
}

//func (buf *EventSequencer) HasPendingUpdates() {
//	return buf.pendingAddedIPSets.Len() > 0 ||
//		buf.pendingRemovedIPSets.Len() > 0 ||
//		buf.pendingAddedIPSetMembers.Len() > 0 ||
//		buf.pendingRemovedIPSetMembers.Len() > 0 ||
//		len(buf.pendingPolicyUpdates) > 0 ||
//		buf.pendingPolicyDeletes.Len() > 0 ||
//
//}

func NewEventSequencer(conf configInterface) *EventSequencer {
	buf := &EventSequencer{
		config:                     conf,
		pendingAddedIPSets:         map[string]proto.IPSetUpdate_IPSetType{},
		pendingRemovedIPSets:       set.New(),
		pendingAddedIPSetMembers:   multidict.NewStringToIface(),
		pendingRemovedIPSetMembers: multidict.NewStringToIface(),

		pendingPolicyUpdates:         map[model.PolicyKey]*ParsedRules{},
		pendingPolicyDeletes:         set.New(),
		pendingProfileUpdates:        map[model.ProfileRulesKey]*ParsedRules{},
		pendingProfileDeletes:        set.New(),
		pendingEndpointUpdates:       map[model.Key]interface{}{},
		pendingEndpointTierUpdates:   map[model.Key][]tierInfo{},
		pendingEndpointDeletes:       set.New(),
		pendingHostIPUpdates:         map[string]*net.IP{},
		pendingHostIPDeletes:         set.New(),
		pendingIPPoolUpdates:         map[ip.CIDR]*model.IPPool{},
		pendingIPPoolDeletes:         set.New(),
		pendingServiceAccountUpdates: map[proto.ServiceAccountID]*proto.ServiceAccountUpdate{},
		pendingServiceAccountDeletes: set.New(),
		pendingNamespaceUpdates:      map[proto.NamespaceID]*proto.NamespaceUpdate{},
		pendingNamespaceDeletes:      set.New(),
		pendingRouteUpdates:          map[routeID]*proto.RouteUpdate{},
		pendingRouteDeletes:          set.New(),
		pendingVTEPUpdates:           map[string]*proto.VXLANTunnelEndpointUpdate{},
		pendingVTEPDeletes:           set.New(),
		pendingWireguardUpdates:      map[string]*model.Wireguard{},
		pendingWireguardDeletes:      set.New(),
		pendingServiceUpdates:        map[serviceID]*proto.ServiceUpdate{},
		pendingServiceDeletes:        set.New(),

		// Sets to record what we've sent downstream. Updated whenever we flush.
		sentIPSets:          set.New(),
		sentPolicies:        set.New(),
		sentProfiles:        set.New(),
		sentEndpoints:       set.New(),
		sentHostIPs:         set.New(),
		sentIPPools:         set.New(),
		sentServiceAccounts: set.New(),
		sentNamespaces:      set.New(),
		sentRoutes:          set.New(),
		sentVTEPs:           set.New(),
		sentWireguard:       set.New(),
		sentServices:        set.New(),
	}
	return buf
}

type routeID struct {
	dst string
}

func (buf *EventSequencer) OnIPSetAdded(setID string, ipSetType proto.IPSetUpdate_IPSetType) {
	log.Debugf("IP set %v now active", setID)
	sent := buf.sentIPSets.Contains(setID)
	removePending := buf.pendingRemovedIPSets.Contains(setID)
	if sent && !removePending {
		log.Panic("OnIPSetAdded called for existing IP set")
	}
	buf.pendingAddedIPSets[setID] = ipSetType
	buf.pendingRemovedIPSets.Discard(setID)
	// An add implicitly means that the set is now empty.
	buf.pendingAddedIPSetMembers.DiscardKey(setID)
	buf.pendingRemovedIPSetMembers.DiscardKey(setID)
}

func (buf *EventSequencer) OnIPSetRemoved(setID string) {
	log.Debugf("IP set %v no longer active", setID)
	sent := buf.sentIPSets.Contains(setID)
	_, updatePending := buf.pendingAddedIPSets[setID]
	if !sent && !updatePending {
		log.WithField("setID", setID).Panic("IPSetRemoved called for unknown IP set")
	}
	if sent {
		buf.pendingRemovedIPSets.Add(setID)
	}
	delete(buf.pendingAddedIPSets, setID)
	buf.pendingAddedIPSetMembers.DiscardKey(setID)
	buf.pendingRemovedIPSetMembers.DiscardKey(setID)
}

func (buf *EventSequencer) OnIPSetMemberAdded(setID string, member labelindex.IPSetMember) {
	log.Debugf("IP set %v now contains %v", setID, member)
	sent := buf.sentIPSets.Contains(setID)
	_, updatePending := buf.pendingAddedIPSets[setID]
	if !sent && !updatePending {
		log.WithField("setID", setID).Panic("Member added to unknown IP set")
	}
	if buf.pendingRemovedIPSetMembers.Contains(setID, member) {
		buf.pendingRemovedIPSetMembers.Discard(setID, member)
	} else {
		buf.pendingAddedIPSetMembers.Put(setID, member)
	}
}

func (buf *EventSequencer) OnIPSetMemberRemoved(setID string, member labelindex.IPSetMember) {
	log.Debugf("IP set %v no longer contains %v", setID, member)
	sent := buf.sentIPSets.Contains(setID)
	_, updatePending := buf.pendingAddedIPSets[setID]
	if !sent && !updatePending {
		log.WithField("setID", setID).Panic("Member removed from unknown IP set")
	}
	if buf.pendingAddedIPSetMembers.Contains(setID, member) {
		buf.pendingAddedIPSetMembers.Discard(setID, member)
	} else {
		buf.pendingRemovedIPSetMembers.Put(setID, member)
	}
}

func (buf *EventSequencer) OnDatastoreNotReady() {
	buf.pendingNotReady = true
}

func (buf *EventSequencer) flushReadyFlag() {
	if !buf.pendingNotReady {
		return
	}
	buf.pendingNotReady = false
	buf.Callback(&DatastoreNotReady{})
}

type DatastoreNotReady struct{}

func (buf *EventSequencer) OnConfigUpdate(globalConfig, hostConfig map[string]string) {
	buf.pendingGlobalConfig = globalConfig
	buf.pendingHostConfig = hostConfig
}

func (buf *EventSequencer) flushConfigUpdate() {
	if buf.pendingGlobalConfig == nil {
		return
	}
	logCxt := log.WithFields(log.Fields{
		"global": buf.pendingGlobalConfig,
		"host":   buf.pendingHostConfig,
	})
	logCxt.Info("Possible config update.")
	globalChanged, err := buf.config.UpdateFrom(buf.pendingGlobalConfig, config.DatastoreGlobal)
	if err != nil {
		logCxt.WithError(err).Panic("Failed to parse config update")
	}
	hostChanged, err := buf.config.UpdateFrom(buf.pendingHostConfig, config.DatastorePerHost)
	if err != nil {
		logCxt.WithError(err).Panic("Failed to parse config update")
	}
	if globalChanged || hostChanged {
		rawConfig := buf.config.RawValues()
		log.WithField("merged", rawConfig).Info("Config changed. Sending ConfigUpdate message.")
		buf.Callback(&proto.ConfigUpdate{
			Config: rawConfig,
		})
	}
	buf.pendingGlobalConfig = nil
	buf.pendingHostConfig = nil
}

func (buf *EventSequencer) OnPolicyActive(key model.PolicyKey, rules *ParsedRules) {
	buf.pendingPolicyDeletes.Discard(key)
	buf.pendingPolicyUpdates[key] = rules
}

func (buf *EventSequencer) flushPolicyUpdates() {
	for key, rules := range buf.pendingPolicyUpdates {
		buf.Callback(ParsedRulesToActivePolicyUpdate(key, rules))
		buf.sentPolicies.Add(key)
		delete(buf.pendingPolicyUpdates, key)
	}
}

func ParsedRulesToActivePolicyUpdate(key model.PolicyKey, rules *ParsedRules) *proto.ActivePolicyUpdate {
	return &proto.ActivePolicyUpdate{
		Id: &proto.PolicyID{
			Tier: "default",
			Name: key.Name,
		},
		Policy: &proto.Policy{
			Namespace: rules.Namespace,
			InboundRules: parsedRulesToProtoRules(
				rules.InboundRules,
				"pol-in-default/"+key.Name,
			),
			OutboundRules: parsedRulesToProtoRules(
				rules.OutboundRules,
				"pol-out-default/"+key.Name,
			),
			Untracked: rules.Untracked,
			PreDnat:   rules.PreDNAT,
		},
	}
}

func (buf *EventSequencer) OnPolicyInactive(key model.PolicyKey) {
	delete(buf.pendingPolicyUpdates, key)
	if buf.sentPolicies.Contains(key) {
		buf.pendingPolicyDeletes.Add(key)
	}
}
func (buf *EventSequencer) flushPolicyDeletes() {
	buf.pendingPolicyDeletes.Iter(func(item interface{}) error {
		buf.Callback(&proto.ActivePolicyRemove{
			Id: &proto.PolicyID{
				Tier: "default",
				Name: item.(model.PolicyKey).Name,
			},
		})
		buf.sentPolicies.Discard(item)
		return set.RemoveItem
	})
}

func (buf *EventSequencer) OnProfileActive(key model.ProfileRulesKey, rules *ParsedRules) {
	buf.pendingProfileDeletes.Discard(key)
	buf.pendingProfileUpdates[key] = rules
}

func (buf *EventSequencer) flushProfileUpdates() {
	for key, rulesOrNil := range buf.pendingProfileUpdates {
		buf.Callback(&proto.ActiveProfileUpdate{
			Id: &proto.ProfileID{
				Name: key.Name,
			},
			Profile: &proto.Profile{
				InboundRules: parsedRulesToProtoRules(
					rulesOrNil.InboundRules,
					"prof-in-"+key.Name,
				),
				OutboundRules: parsedRulesToProtoRules(
					rulesOrNil.OutboundRules,
					"prof-out-"+key.Name,
				),
			},
		})
		buf.sentProfiles.Add(key)
		delete(buf.pendingProfileUpdates, key)
	}
}

func (buf *EventSequencer) OnProfileInactive(key model.ProfileRulesKey) {
	delete(buf.pendingProfileUpdates, key)
	if buf.sentProfiles.Contains(key) {
		buf.pendingProfileDeletes.Add(key)
	}
}

func (buf *EventSequencer) flushProfileDeletes() {
	buf.pendingProfileDeletes.Iter(func(item interface{}) error {
		buf.Callback(&proto.ActiveProfileRemove{
			Id: &proto.ProfileID{
				Name: item.(model.ProfileRulesKey).Name,
			},
		})
		buf.sentProfiles.Discard(item)
		return set.RemoveItem
	})
}

func ModelWorkloadEndpointToProto(ep *model.WorkloadEndpoint, tiers []*proto.TierInfo) *proto.WorkloadEndpoint {
	mac := ""
	if ep.Mac != nil {
		mac = ep.Mac.String()
	}
	return &proto.WorkloadEndpoint{
		State:      ep.State,
		Name:       ep.Name,
		Mac:        mac,
		ProfileIds: ep.ProfileIDs,
		Ipv4Nets:   netsToStrings(ep.IPv4Nets),
		Ipv6Nets:   netsToStrings(ep.IPv6Nets),
		Tiers:      tiers,
		Ipv4Nat:    natsToProtoNatInfo(ep.IPv4NAT),
		Ipv6Nat:    natsToProtoNatInfo(ep.IPv6NAT),
	}
}

func ModelHostEndpointToProto(ep *model.HostEndpoint, tiers, untrackedTiers, preDNATTiers []*proto.TierInfo, forwardTiers []*proto.TierInfo) *proto.HostEndpoint {
	return &proto.HostEndpoint{
		Name:              ep.Name,
		ExpectedIpv4Addrs: ipsToStrings(ep.ExpectedIPv4Addrs),
		ExpectedIpv6Addrs: ipsToStrings(ep.ExpectedIPv6Addrs),
		ProfileIds:        ep.ProfileIDs,
		Tiers:             tiers,
		UntrackedTiers:    untrackedTiers,
		PreDnatTiers:      preDNATTiers,
		ForwardTiers:      forwardTiers,
	}
}

func (buf *EventSequencer) OnEndpointTierUpdate(key model.Key,
	endpoint interface{},
	filteredTiers []tierInfo,
) {
	if endpoint == nil {
		// Deletion. Squash any queued updates.
		delete(buf.pendingEndpointUpdates, key)
		delete(buf.pendingEndpointTierUpdates, key)
		if buf.sentEndpoints.Contains(key) {
			// We'd previously sent an update, so we need to send a deletion.
			buf.pendingEndpointDeletes.Add(key)
		}
	} else {
		// Update.
		buf.pendingEndpointDeletes.Discard(key)
		buf.pendingEndpointUpdates[key] = endpoint
		buf.pendingEndpointTierUpdates[key] = filteredTiers
	}
}

func (buf *EventSequencer) flushEndpointTierUpdates() {
	for key, endpoint := range buf.pendingEndpointUpdates {
		tiers, untrackedTiers, preDNATTiers, forwardTiers := tierInfoToProtoTierInfo(buf.pendingEndpointTierUpdates[key])
		switch key := key.(type) {
		case model.WorkloadEndpointKey:
			wlep := endpoint.(*model.WorkloadEndpoint)
			buf.Callback(&proto.WorkloadEndpointUpdate{
				Id: &proto.WorkloadEndpointID{
					OrchestratorId: key.OrchestratorID,
					WorkloadId:     key.WorkloadID,
					EndpointId:     key.EndpointID,
				},
				Endpoint: ModelWorkloadEndpointToProto(wlep, tiers),
			})
		case model.HostEndpointKey:
			hep := endpoint.(*model.HostEndpoint)
			buf.Callback(&proto.HostEndpointUpdate{
				Id: &proto.HostEndpointID{
					EndpointId: key.EndpointID,
				},
				Endpoint: ModelHostEndpointToProto(hep, tiers, untrackedTiers, preDNATTiers, forwardTiers),
			})
		}
		// Record that we've sent this endpoint.
		buf.sentEndpoints.Add(key)
		// And clean up the pending buffer.
		delete(buf.pendingEndpointUpdates, key)
		delete(buf.pendingEndpointTierUpdates, key)
	}
}

func (buf *EventSequencer) flushEndpointTierDeletes() {
	buf.pendingEndpointDeletes.Iter(func(item interface{}) error {
		switch key := item.(type) {
		case model.WorkloadEndpointKey:
			buf.Callback(&proto.WorkloadEndpointRemove{
				Id: &proto.WorkloadEndpointID{
					OrchestratorId: key.OrchestratorID,
					WorkloadId:     key.WorkloadID,
					EndpointId:     key.EndpointID,
				},
			})
		case model.HostEndpointKey:
			buf.Callback(&proto.HostEndpointRemove{
				Id: &proto.HostEndpointID{
					EndpointId: key.EndpointID,
				},
			})
		}
		buf.sentEndpoints.Discard(item)
		return set.RemoveItem
	})
}

func (buf *EventSequencer) OnEncapUpdate(encap config.Encapsulation) {
	log.WithFields(log.Fields{
		"IPIPEnabled":  encap.IPIPEnabled,
		"VXLANEnabled": encap.VXLANEnabled,
	}).Debug("Encapsulation update")
	buf.pendingEncapUpdate = &encap
}

func (buf *EventSequencer) flushEncapUpdate() {
	if buf.pendingEncapUpdate != nil {
		buf.Callback(&proto.Encapsulation{
			IpipEnabled:  buf.pendingEncapUpdate.IPIPEnabled,
			VxlanEnabled: buf.pendingEncapUpdate.VXLANEnabled,
		})
		buf.pendingEncapUpdate = nil
	}
}

func (buf *EventSequencer) OnHostIPUpdate(hostname string, ip *net.IP) {
	log.WithFields(log.Fields{
		"hostname": hostname,
		"ip":       ip,
	}).Debug("HostIP update")
	buf.pendingHostIPDeletes.Discard(hostname)
	buf.pendingHostIPUpdates[hostname] = ip
}

func (buf *EventSequencer) flushHostIPUpdates() {
	for hostname, hostIP := range buf.pendingHostIPUpdates {
		buf.Callback(&proto.HostMetadataUpdate{
			Hostname: hostname,
			Ipv4Addr: hostIP.IP.String(),
		})
		buf.sentHostIPs.Add(hostname)
		delete(buf.pendingHostIPUpdates, hostname)
	}
}

func (buf *EventSequencer) OnHostIPRemove(hostname string) {
	log.WithField("hostname", hostname).Debug("HostIP removed")
	delete(buf.pendingHostIPUpdates, hostname)
	if buf.sentHostIPs.Contains(hostname) {
		buf.pendingHostIPDeletes.Add(hostname)
	}
}
func (buf *EventSequencer) flushHostIPDeletes() {
	buf.pendingHostIPDeletes.Iter(func(item interface{}) error {
		buf.Callback(&proto.HostMetadataRemove{
			Hostname: item.(string),
		})
		buf.sentHostIPs.Discard(item)
		return set.RemoveItem
	})
}

func (buf *EventSequencer) OnIPPoolUpdate(key model.IPPoolKey, pool *model.IPPool) {
	log.WithFields(log.Fields{
		"key":  key,
		"pool": pool,
	}).Debug("IPPool update")
	cidr := ip.CIDRFromCalicoNet(key.CIDR)
	buf.pendingIPPoolDeletes.Discard(cidr)
	buf.pendingIPPoolUpdates[cidr] = pool
}

func (buf *EventSequencer) flushIPPoolUpdates() {
	for key, pool := range buf.pendingIPPoolUpdates {
		buf.Callback(&proto.IPAMPoolUpdate{
			Id: cidrToIPPoolID(key),
			Pool: &proto.IPAMPool{
				Cidr:       pool.CIDR.String(),
				Masquerade: pool.Masquerade,
			},
		})
		buf.sentIPPools.Add(key)
		delete(buf.pendingIPPoolUpdates, key)
	}
}

func (buf *EventSequencer) flushHostWireguardUpdates() {
	for nodename, wg := range buf.pendingWireguardUpdates {
		var ipstr string
		if wg.InterfaceIPv4Addr != nil {
			ipstr = wg.InterfaceIPv4Addr.String()
		}
		buf.Callback(&proto.WireguardEndpointUpdate{
			Hostname:          nodename,
			PublicKey:         wg.PublicKey,
			InterfaceIpv4Addr: ipstr,
		})
		buf.sentWireguard.Add(nodename)
		delete(buf.pendingWireguardUpdates, nodename)
	}
}

func (buf *EventSequencer) OnIPPoolRemove(key model.IPPoolKey) {
	log.WithField("key", key).Debug("IPPool removed")
	cidr := ip.CIDRFromCalicoNet(key.CIDR)
	delete(buf.pendingIPPoolUpdates, cidr)
	if buf.sentIPPools.Contains(cidr) {
		buf.pendingIPPoolDeletes.Add(cidr)
	}
}

func (buf *EventSequencer) flushIPPoolDeletes() {
	buf.pendingIPPoolDeletes.Iter(func(item interface{}) error {
		key := item.(ip.CIDR)
		buf.Callback(&proto.IPAMPoolRemove{
			Id: cidrToIPPoolID(key),
		})
		buf.sentIPPools.Discard(key)
		return set.RemoveItem
	})
}

func (buf *EventSequencer) flushHostWireguardDeletes() {
	buf.pendingWireguardDeletes.Iter(func(item interface{}) error {
		key := item.(string)
		if buf.sentWireguard.Contains(key) {
			buf.Callback(&proto.WireguardEndpointRemove{
				Hostname: key,
			})
			buf.sentWireguard.Discard(key)
		}
		return set.RemoveItem
	})
}

func (buf *EventSequencer) flushAddedIPSets() {
	for setID, setType := range buf.pendingAddedIPSets {
		log.WithField("setID", setID).Debug("Flushing added IP set")
		members := make([]string, 0)
		buf.pendingAddedIPSetMembers.Iter(setID, func(value interface{}) {
			member := value.(labelindex.IPSetMember)
			members = append(members, memberToProto(member))
		})
		buf.pendingAddedIPSetMembers.DiscardKey(setID)
		buf.Callback(&proto.IPSetUpdate{
			Id:      setID,
			Members: members,
			Type:    setType,
		})
		buf.sentIPSets.Add(setID)
		delete(buf.pendingAddedIPSets, setID)
	}
}

func memberToProto(member labelindex.IPSetMember) string {
	switch member.Protocol {
	case labelindex.ProtocolNone:
		return member.CIDR.String()
	case labelindex.ProtocolTCP:
		return fmt.Sprintf("%s,tcp:%d", member.CIDR.Addr(), member.PortNumber)
	case labelindex.ProtocolUDP:
		return fmt.Sprintf("%s,udp:%d", member.CIDR.Addr(), member.PortNumber)
	case labelindex.ProtocolSCTP:
		return fmt.Sprintf("%s,sctp:%d", member.CIDR.Addr(), member.PortNumber)
	}
	log.WithField("member", member).Panic("Unknown IP set member type")
	return ""
}

func (buf *EventSequencer) Flush() {
	// Flush (rare) config changes first, since they may trigger a restart of the process.
	buf.flushReadyFlag()
	buf.flushConfigUpdate()

	// Flush mainline additions/updates in dependency order (IP sets, policy, endpoints) so
	// that later updates always have their dependencies in place.
	buf.flushAddedIPSets()
	buf.flushIPSetDeltas()
	buf.flushPolicyUpdates()
	buf.flushProfileUpdates()
	buf.flushEndpointTierUpdates()

	// Then flush removals in reverse order.
	buf.flushEndpointTierDeletes()
	buf.flushProfileDeletes()
	buf.flushPolicyDeletes()
	buf.flushRemovedIPSets()

	// Flush ServiceAccount and Namespace updates. These have no particular ordering compared with other updates.
	buf.flushServiceAccounts()
	buf.flushNamespaces()

	// Flush VXLAN data. Order such that no routes are present in the data plane unless
	// they have a corresponding VTEP in the data plane as well. Do this by sending VTEP adds
	// before flushsing route adds, and route removes before flushing VTEP removes. We also send
	// route removes before route adds in order to minimize maximum occupancy.
	buf.flushRouteRemoves()
	buf.flushVTEPRemoves()
	buf.flushVTEPAdds()
	buf.flushRouteAdds()

	// Flush (rare) cluster-wide updates.  There's no particular ordering to these so we might
	// as well do deletions first to minimise occupancy.
	buf.flushHostWireguardDeletes()
	buf.flushHostWireguardUpdates()
	buf.flushHostIPDeletes()
	buf.flushHostIPUpdates()
	buf.flushIPPoolDeletes()
	buf.flushIPPoolUpdates()
	buf.flushEncapUpdate()

	// Flush global BGPConfiguration updates.
	if buf.pendingGlobalBGPConfig != nil {
		buf.Callback(buf.pendingGlobalBGPConfig)
		buf.pendingGlobalBGPConfig = nil
	}

	buf.flushServices()
}

func (buf *EventSequencer) flushRemovedIPSets() {
	buf.pendingRemovedIPSets.Iter(func(item interface{}) (err error) {
		setID := item.(string)
		log.Debugf("Flushing IP set remove: %v", setID)
		buf.Callback(&proto.IPSetRemove{
			Id: setID,
		})
		buf.pendingRemovedIPSetMembers.DiscardKey(setID)
		buf.pendingAddedIPSetMembers.DiscardKey(setID)
		buf.pendingRemovedIPSets.Discard(item)
		buf.sentIPSets.Discard(item)
		return
	})
	log.Debugf("Done flushing IP set removes")
}

func (buf *EventSequencer) flushIPSetDeltas() {
	buf.pendingRemovedIPSetMembers.IterKeys(buf.flushAddsOrRemoves)
	buf.pendingAddedIPSetMembers.IterKeys(buf.flushAddsOrRemoves)
	log.Debugf("Done flushing IP address deltas")
}

func (buf *EventSequencer) flushAddsOrRemoves(setID string) {
	log.Debugf("Flushing IP set deltas: %v", setID)
	deltaUpdate := proto.IPSetDeltaUpdate{
		Id: setID,
	}
	buf.pendingAddedIPSetMembers.Iter(setID, func(item interface{}) {
		member := item.(labelindex.IPSetMember)
		deltaUpdate.AddedMembers = append(deltaUpdate.AddedMembers, memberToProto(member))
	})
	buf.pendingRemovedIPSetMembers.Iter(setID, func(item interface{}) {
		member := item.(labelindex.IPSetMember)
		deltaUpdate.RemovedMembers = append(deltaUpdate.RemovedMembers, memberToProto(member))
	})
	buf.pendingAddedIPSetMembers.DiscardKey(setID)
	buf.pendingRemovedIPSetMembers.DiscardKey(setID)
	buf.Callback(&deltaUpdate)
}

func (buf *EventSequencer) OnServiceAccountUpdate(update *proto.ServiceAccountUpdate) {
	// We trust the caller not to send us an update with nil ID, so safe to dereference.
	id := *update.Id
	log.WithFields(log.Fields{
		"key":    id,
		"labels": update.GetLabels(),
	}).Debug("ServiceAccount update")
	buf.pendingServiceAccountDeletes.Discard(id)
	buf.pendingServiceAccountUpdates[id] = update
}

func (buf *EventSequencer) OnServiceAccountRemove(id proto.ServiceAccountID) {
	log.WithFields(log.Fields{
		"key": id,
	}).Debug("ServiceAccount removed")
	delete(buf.pendingServiceAccountUpdates, id)
	if buf.sentServiceAccounts.Contains(id) {
		buf.pendingServiceAccountDeletes.Add(id)
	}
}

func (buf *EventSequencer) flushServiceAccounts() {
	// Order doesn't matter, but send removes first to reduce max occupancy
	buf.pendingServiceAccountDeletes.Iter(func(item interface{}) error {
		id := item.(proto.ServiceAccountID)
		msg := proto.ServiceAccountRemove{Id: &id}
		buf.Callback(&msg)
		buf.sentServiceAccounts.Discard(id)
		return nil
	})
	buf.pendingServiceAccountDeletes.Clear()
	for _, msg := range buf.pendingServiceAccountUpdates {
		buf.Callback(msg)
		id := msg.Id
		// We safely dereferenced the Id in OnServiceAccountUpdate before adding it to the pending updates map, so
		// it is safe to do so here.
		buf.sentServiceAccounts.Add(*id)
	}
	buf.pendingServiceAccountUpdates = make(map[proto.ServiceAccountID]*proto.ServiceAccountUpdate)
	log.Debug("Done flushing Service Accounts")
}

func (buf *EventSequencer) OnNamespaceUpdate(update *proto.NamespaceUpdate) {
	// We trust the caller not to send us an update with nil ID, so safe to dereference.
	id := *update.Id
	log.WithFields(log.Fields{
		"key":    id,
		"labels": update.GetLabels(),
	}).Debug("Namespace update")
	buf.pendingNamespaceDeletes.Discard(id)
	buf.pendingNamespaceUpdates[id] = update
}

func (buf *EventSequencer) OnNamespaceRemove(id proto.NamespaceID) {
	log.WithFields(log.Fields{
		"key": id,
	}).Debug("Namespace removed")
	delete(buf.pendingNamespaceUpdates, id)
	if buf.sentNamespaces.Contains(id) {
		buf.pendingNamespaceDeletes.Add(id)
	}
}

func (buf *EventSequencer) OnWireguardUpdate(nodename string, wg *model.Wireguard) {
	log.WithFields(log.Fields{
		"nodename": nodename,
	}).Debug("Wireguard updated")
	buf.pendingWireguardDeletes.Discard(nodename)
	buf.pendingWireguardUpdates[nodename] = wg
}

func (buf *EventSequencer) OnWireguardRemove(nodename string) {
	log.WithFields(log.Fields{
		"nodename": nodename,
	}).Debug("Wireguard removed")
	delete(buf.pendingWireguardUpdates, nodename)
	buf.pendingWireguardDeletes.Add(nodename)
}

func (buf *EventSequencer) OnGlobalBGPConfigUpdate(cfg *v3.BGPConfiguration) {
	log.WithField("cfg", cfg).Debug("Global BGPConfiguration updated")
	buf.pendingGlobalBGPConfig = &proto.GlobalBGPConfigUpdate{}
	if cfg != nil {
		for _, block := range cfg.Spec.ServiceClusterIPs {
			buf.pendingGlobalBGPConfig.ServiceClusterCidrs = append(buf.pendingGlobalBGPConfig.ServiceClusterCidrs, block.CIDR)
		}
		for _, block := range cfg.Spec.ServiceExternalIPs {
			buf.pendingGlobalBGPConfig.ServiceExternalCidrs = append(buf.pendingGlobalBGPConfig.ServiceExternalCidrs, block.CIDR)
		}
		for _, block := range cfg.Spec.ServiceLoadBalancerIPs {
			buf.pendingGlobalBGPConfig.ServiceLoadbalancerCidrs = append(buf.pendingGlobalBGPConfig.ServiceLoadbalancerCidrs, block.CIDR)
		}
	}
}

func (buf *EventSequencer) flushNamespaces() {
	// Order doesn't matter, but send removes first to reduce max occupancy
	buf.pendingNamespaceDeletes.Iter(func(item interface{}) error {
		id := item.(proto.NamespaceID)
		msg := proto.NamespaceRemove{Id: &id}
		buf.Callback(&msg)
		buf.sentNamespaces.Discard(id)
		return nil
	})
	buf.pendingNamespaceDeletes.Clear()
	for _, msg := range buf.pendingNamespaceUpdates {
		buf.Callback(msg)
		id := msg.Id
		// We safely dereferenced the Id in OnNamespaceUpdate before adding it to the pending updates map, so
		// it is safe to do so here.
		buf.sentNamespaces.Add(*id)
	}
	buf.pendingNamespaceUpdates = make(map[proto.NamespaceID]*proto.NamespaceUpdate)
	log.Debug("Done flushing Namespaces")
}

func (buf *EventSequencer) OnVTEPUpdate(update *proto.VXLANTunnelEndpointUpdate) {
	node := update.Node
	log.WithFields(log.Fields{"id": node}).Debug("VTEP update")
	buf.pendingVTEPDeletes.Discard(node)
	buf.pendingVTEPUpdates[node] = update
}

func (buf *EventSequencer) OnVTEPRemove(dst string) {
	log.WithFields(log.Fields{"dst": dst}).Debug("VTEP removed")
	delete(buf.pendingVTEPUpdates, dst)
	if buf.sentVTEPs.Contains(dst) {
		buf.pendingVTEPDeletes.Add(dst)
	}
}

func (buf *EventSequencer) flushVTEPRemoves() {
	buf.pendingVTEPDeletes.Iter(func(item interface{}) error {
		node := item.(string)
		msg := proto.VXLANTunnelEndpointRemove{Node: node}
		buf.Callback(&msg)
		buf.sentVTEPs.Discard(node)
		return nil
	})
	buf.pendingVTEPDeletes.Clear()
	log.Debug("Done flushing VTEP removes")
}

func (buf *EventSequencer) flushVTEPAdds() {
	for _, msg := range buf.pendingVTEPUpdates {
		buf.Callback(msg)
		buf.sentVTEPs.Add(msg.Node)
	}
	buf.pendingVTEPUpdates = make(map[string]*proto.VXLANTunnelEndpointUpdate)
	log.Debug("Done flushing VTEP adds")
}

func (buf *EventSequencer) OnRouteUpdate(update *proto.RouteUpdate) {
	routeID := routeID{
		dst: update.Dst,
	}
	log.WithFields(log.Fields{"id": routeID}).Debug("Route update")
	buf.pendingRouteDeletes.Discard(routeID)
	buf.pendingRouteUpdates[routeID] = update
}

func (buf *EventSequencer) OnRouteRemove(dst string) {
	routeID := routeID{
		dst: dst,
	}
	log.WithFields(log.Fields{"id": routeID}).Debug("Route update")
	delete(buf.pendingRouteUpdates, routeID)
	if buf.sentRoutes.Contains(routeID) {
		buf.pendingRouteDeletes.Add(routeID)
	}
}

func (buf *EventSequencer) flushRouteAdds() {
	for id, msg := range buf.pendingRouteUpdates {
		buf.Callback(msg)
		buf.sentRoutes.Add(id)
	}
	buf.pendingRouteUpdates = make(map[routeID]*proto.RouteUpdate)
	log.Debug("Done flushing route adds")
}

func (buf *EventSequencer) flushRouteRemoves() {
	buf.pendingRouteDeletes.Iter(func(item interface{}) error {
		id := item.(routeID)
		msg := proto.RouteRemove{Dst: id.dst}
		buf.Callback(&msg)
		buf.sentRoutes.Discard(id)
		return nil
	})
	buf.pendingRouteDeletes.Clear()
	log.Debug("Done flushing route deletes")
}

func (buf *EventSequencer) OnServiceUpdate(update *proto.ServiceUpdate) {
	log.WithFields(log.Fields{
		"name":      update.Name,
		"namespace": update.Namespace,
	}).Debug("Service update")
	id := serviceID{
		Name:      update.Name,
		Namespace: update.Namespace,
	}
	buf.pendingServiceDeletes.Discard(id)
	buf.pendingServiceUpdates[id] = update
}

func (buf *EventSequencer) OnServiceRemove(update *proto.ServiceRemove) {
	log.WithFields(log.Fields{
		"name":      update.Name,
		"namespace": update.Namespace,
	}).Debug("Service delete")
	id := serviceID{
		Name:      update.Name,
		Namespace: update.Namespace,
	}
	delete(buf.pendingServiceUpdates, id)
	if buf.sentServices.Contains(id) {
		buf.pendingServiceDeletes.Add(id)
	}
}

func (buf *EventSequencer) flushServices() {
	// Order doesn't matter, but send removes first to reduce max occupancy
	buf.pendingServiceDeletes.Iter(func(item interface{}) error {
		id := item.(serviceID)
		msg := &proto.ServiceRemove{
			Name:      id.Name,
			Namespace: id.Namespace,
		}
		buf.Callback(&msg)
		buf.sentServices.Discard(id)
		return nil
	})
	buf.pendingServiceDeletes.Clear()
	for _, msg := range buf.pendingServiceUpdates {
		buf.Callback(msg)
		id := &proto.ServiceRemove{
			Name:      msg.Name,
			Namespace: msg.Namespace,
		}
		// We safely dereferenced the Id in OnServiceUpdate before adding it to the pending updates map, so
		// it is safe to do so here.
		buf.sentServices.Add(id)
	}
	buf.pendingServiceUpdates = make(map[serviceID]*proto.ServiceUpdate)
	log.Debug("Done flushing Services")
}

func cidrToIPPoolID(cidr ip.CIDR) string {
	return strings.Replace(cidr.String(), "/", "-", 1)
}

func addPolicyToTierInfo(pol *PolKV, tierInfo *proto.TierInfo, egressAllowed bool) {
	if pol.GovernsIngress() {
		tierInfo.IngressPolicies = append(tierInfo.IngressPolicies, pol.Key.Name)
	}
	if egressAllowed && pol.GovernsEgress() {
		tierInfo.EgressPolicies = append(tierInfo.EgressPolicies, pol.Key.Name)
	}
}

func tierInfoToProtoTierInfo(filteredTiers []tierInfo) (normalTiers, untrackedTiers, preDNATTiers, forwardTiers []*proto.TierInfo) {
	if len(filteredTiers) > 0 {
		for _, ti := range filteredTiers {
			untrackedTierInfo := &proto.TierInfo{Name: ti.Name}
			preDNATTierInfo := &proto.TierInfo{Name: ti.Name}
			forwardTierInfo := &proto.TierInfo{Name: ti.Name}
			normalTierInfo := &proto.TierInfo{Name: ti.Name}
			for _, pol := range ti.OrderedPolicies {
				if pol.Value.DoNotTrack {
					addPolicyToTierInfo(&pol, untrackedTierInfo, true)
				} else if pol.Value.PreDNAT {
					addPolicyToTierInfo(&pol, preDNATTierInfo, false)
				} else {
					if pol.Value.ApplyOnForward {
						addPolicyToTierInfo(&pol, forwardTierInfo, true)
					}
					addPolicyToTierInfo(&pol, normalTierInfo, true)
				}
			}

			if len(untrackedTierInfo.IngressPolicies) > 0 || len(untrackedTierInfo.EgressPolicies) > 0 {
				untrackedTiers = append(untrackedTiers, untrackedTierInfo)
			}
			if len(preDNATTierInfo.IngressPolicies) > 0 || len(preDNATTierInfo.EgressPolicies) > 0 {
				preDNATTiers = append(preDNATTiers, preDNATTierInfo)
			}
			if len(forwardTierInfo.IngressPolicies) > 0 || len(forwardTierInfo.EgressPolicies) > 0 {
				forwardTiers = append(forwardTiers, forwardTierInfo)
			}
			if len(normalTierInfo.IngressPolicies) > 0 || len(normalTierInfo.EgressPolicies) > 0 {
				normalTiers = append(normalTiers, normalTierInfo)
			}
		}
	}
	return
}

func netsToStrings(nets []net.IPNet) []string {
	output := make([]string, len(nets))
	for ii, ipNet := range nets {
		output[ii] = ipNet.String()
	}
	return output
}

func ipsToStrings(ips []net.IP) []string {
	output := make([]string, len(ips))
	for ii, netIP := range ips {
		output[ii] = netIP.String()
	}
	return output
}

func natsToProtoNatInfo(nats []model.IPNAT) []*proto.NatInfo {
	protoNats := make([]*proto.NatInfo, len(nats))
	for ii, nat := range nats {
		protoNats[ii] = &proto.NatInfo{
			ExtIp: nat.ExtIP.String(),
			IntIp: nat.IntIP.String(),
		}
	}
	return protoNats
}
