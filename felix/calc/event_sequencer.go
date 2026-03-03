// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.
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

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/labelindex/ipsetmember"
	"github.com/projectcalico/calico/felix/multidict"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type EventHandler func(message any)

type configInterface interface {
	UpdateFrom(map[string]string, config.Source) (changed bool, err error)
	RawValues() map[string]string
	ToConfigUpdate() *proto.ConfigUpdate
}

// Struct for additional data that feeds into proto.WorkloadEndpoint but is computed rather
// than stored on resource's database.
type EndpointComputedDataKind string
type EndpointComputedData interface {
	ApplyTo(*proto.WorkloadEndpoint)
}

// EndpointUpdate contains information about updates applied to the endpoint.
type endpointUpdate struct {
	endpoint     any
	computedData []EndpointComputedData
	peerData     *EndpointBGPPeer
	tierInfo     []TierInfo
}

// EventSequencer buffers and coalesces updates from the calculation graph then flushes them
// when Flush() is called.  It flushed updates in a dependency-safe order.
type EventSequencer struct {
	config configInterface

	// Buffers used to hold data that we haven't flushed yet so we can coalesce multiple
	// updates and generate updates in dependency order.
	pendingAddedIPSets           map[string]proto.IPSetUpdate_IPSetType
	pendingRemovedIPSets         set.Set[string]
	pendingAddedIPSetMembers     multidict.Multidict[string, ipsetmember.IPSetMember]
	pendingRemovedIPSetMembers   multidict.Multidict[string, ipsetmember.IPSetMember]
	pendingPolicyUpdates         map[model.PolicyKey]*ParsedRules
	pendingPolicyDeletes         set.Set[model.PolicyKey]
	pendingProfileUpdates        map[model.ProfileRulesKey]*ParsedRules
	pendingProfileDeletes        set.Set[model.ProfileRulesKey]
	pendingEncapUpdate           *config.Encapsulation
	pendingEndpointUpdates       map[model.Key]endpointUpdate
	pendingEndpointDeletes       set.Set[model.Key]
	pendingHostIPUpdates         map[string]*net.IP
	pendingHostIPDeletes         set.Set[string]
	pendingHostIPv6Updates       map[string]*net.IP
	pendingHostIPv6Deletes       set.Set[string]
	pendingHostMetadataUpdates   map[string]*hostInfo
	pendingHostMetadataDeletes   set.Set[string]
	pendingIPPoolUpdates         map[ip.CIDR]*model.IPPool
	pendingIPPoolDeletes         set.Set[ip.CIDR]
	pendingNotReady              bool
	pendingGlobalConfig          map[string]string
	pendingHostConfig            map[string]string
	pendingServiceAccountUpdates map[types.ServiceAccountID]*proto.ServiceAccountUpdate
	pendingServiceAccountDeletes set.Set[types.ServiceAccountID]
	pendingNamespaceUpdates      map[types.NamespaceID]*proto.NamespaceUpdate
	pendingNamespaceDeletes      set.Set[types.NamespaceID]
	pendingRouteUpdates          map[routeID]*proto.RouteUpdate
	pendingRouteDeletes          set.Set[routeID]
	pendingVTEPUpdates           map[string]*proto.VXLANTunnelEndpointUpdate
	pendingVTEPDeletes           set.Set[string]
	pendingWireguardUpdates      map[string]*model.Wireguard
	pendingWireguardDeletes      set.Set[string]
	pendingGlobalBGPConfig       *proto.GlobalBGPConfigUpdate
	pendingServiceUpdates        map[serviceID]*proto.ServiceUpdate
	pendingServiceDeletes        set.Set[serviceID]

	// Sets to record what we've sent downstream. Updated whenever we flush.
	sentIPSets          set.Set[string]
	sentPolicies        set.Set[model.PolicyKey]
	sentProfiles        set.Set[model.ProfileRulesKey]
	sentEndpoints       set.Set[model.Key]
	sentHostIPs         set.Set[string]
	sentHostIPv6s       set.Set[string]
	sentHosts           set.Set[string]
	sentIPPools         set.Set[ip.CIDR]
	sentServiceAccounts set.Set[types.ServiceAccountID]
	sentNamespaces      set.Set[types.NamespaceID]
	sentRoutes          set.Set[routeID]
	sentVTEPs           set.Set[string]
	sentWireguard       set.Set[string]
	sentWireguardV6     set.Set[string]
	sentServices        set.Set[serviceID]

	Callback EventHandler
}

type hostInfo struct {
	ip4Addr  *net.IPNet
	ip6Addr  *net.IPNet
	labels   map[string]string
	asnumber string
}

type serviceID struct {
	Name      string
	Namespace string
}

// func (buf *EventSequencer) HasPendingUpdates() {
//	return buf.pendingAddedIPSets.Len() > 0 ||
//		buf.pendingRemovedIPSets.Len() > 0 ||
//		buf.pendingAddedIPSetMembers.Len() > 0 ||
//		buf.pendingRemovedIPSetMembers.Len() > 0 ||
//		len(buf.pendingPolicyUpdates) > 0 ||
//		buf.pendingPolicyDeletes.Len() > 0 ||
//
// }

func NewEventSequencer(conf configInterface) *EventSequencer {
	buf := &EventSequencer{
		config:                     conf,
		pendingAddedIPSets:         map[string]proto.IPSetUpdate_IPSetType{},
		pendingRemovedIPSets:       set.New[string](),
		pendingAddedIPSetMembers:   multidict.New[string, ipsetmember.IPSetMember](),
		pendingRemovedIPSetMembers: multidict.New[string, ipsetmember.IPSetMember](),

		pendingPolicyUpdates:         map[model.PolicyKey]*ParsedRules{},
		pendingPolicyDeletes:         set.New[model.PolicyKey](),
		pendingProfileUpdates:        map[model.ProfileRulesKey]*ParsedRules{},
		pendingProfileDeletes:        set.New[model.ProfileRulesKey](),
		pendingEndpointUpdates:       map[model.Key]endpointUpdate{},
		pendingEndpointDeletes:       set.New[model.Key](),
		pendingHostIPUpdates:         map[string]*net.IP{},
		pendingHostIPDeletes:         set.New[string](),
		pendingHostIPv6Updates:       map[string]*net.IP{},
		pendingHostIPv6Deletes:       set.New[string](),
		pendingHostMetadataUpdates:   map[string]*hostInfo{},
		pendingHostMetadataDeletes:   set.New[string](),
		pendingIPPoolUpdates:         map[ip.CIDR]*model.IPPool{},
		pendingIPPoolDeletes:         set.New[ip.CIDR](),
		pendingServiceAccountUpdates: map[types.ServiceAccountID]*proto.ServiceAccountUpdate{},
		pendingServiceAccountDeletes: set.New[types.ServiceAccountID](),
		pendingNamespaceUpdates:      map[types.NamespaceID]*proto.NamespaceUpdate{},
		pendingNamespaceDeletes:      set.New[types.NamespaceID](),
		pendingRouteUpdates:          map[routeID]*proto.RouteUpdate{},
		pendingRouteDeletes:          set.New[routeID](),
		pendingVTEPUpdates:           map[string]*proto.VXLANTunnelEndpointUpdate{},
		pendingVTEPDeletes:           set.New[string](),
		pendingWireguardUpdates:      map[string]*model.Wireguard{},
		pendingWireguardDeletes:      set.New[string](),
		pendingServiceUpdates:        map[serviceID]*proto.ServiceUpdate{},
		pendingServiceDeletes:        set.New[serviceID](),

		// Sets to record what we've sent downstream. Updated whenever we flush.
		sentIPSets:          set.New[string](),
		sentPolicies:        set.New[model.PolicyKey](),
		sentProfiles:        set.New[model.ProfileRulesKey](),
		sentEndpoints:       set.New[model.Key](),
		sentHostIPs:         set.New[string](),
		sentHostIPv6s:       set.New[string](),
		sentHosts:           set.New[string](),
		sentIPPools:         set.New[ip.CIDR](),
		sentServiceAccounts: set.New[types.ServiceAccountID](),
		sentNamespaces:      set.New[types.NamespaceID](),
		sentRoutes:          set.New[routeID](),
		sentVTEPs:           set.New[string](),
		sentWireguard:       set.New[string](),
		sentWireguardV6:     set.New[string](),
		sentServices:        set.New[serviceID](),
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

func (buf *EventSequencer) OnIPSetMemberAdded(setID string, member ipsetmember.IPSetMember) {
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

func (buf *EventSequencer) OnIPSetMemberRemoved(setID string, member ipsetmember.IPSetMember) {
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
		buf.Callback(buf.config.ToConfigUpdate())
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
	var perfHints []string
	for _, hint := range rules.PerformanceHints {
		perfHints = append(perfHints, string(hint))
	}
	return &proto.ActivePolicyUpdate{
		Id: &proto.PolicyID{
			Name:      key.Name,
			Namespace: key.Namespace,
			Kind:      key.Kind,
		},
		Policy: &proto.Policy{
			Tier:      rules.Tier,
			Namespace: rules.Namespace,
			InboundRules: parsedRulesToProtoRules(
				rules.InboundRules,
				"pol-in-default/"+key.Name,
			),
			OutboundRules: parsedRulesToProtoRules(
				rules.OutboundRules,
				"pol-out-default/"+key.Name,
			),
			Untracked:        rules.Untracked,
			PreDnat:          rules.PreDNAT,
			OriginalSelector: rules.OriginalSelector,
			PerfHints:        perfHints,
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
	for item := range buf.pendingPolicyDeletes.All() {
		buf.Callback(&proto.ActivePolicyRemove{
			Id: &proto.PolicyID{
				Name:      item.Name,
				Namespace: item.Namespace,
				Kind:      item.Kind,
			},
		})
		buf.sentPolicies.Discard(item)
		buf.pendingPolicyDeletes.Discard(item)
	}
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
	for item := range buf.pendingProfileDeletes.All() {
		buf.Callback(&proto.ActiveProfileRemove{
			Id: &proto.ProfileID{
				Name: item.Name,
			},
		})
		buf.sentProfiles.Discard(item)
		buf.pendingProfileDeletes.Discard(item)
	}
}

func ModelWorkloadEndpointToProto(ep *model.WorkloadEndpoint, computedData []EndpointComputedData, peerData *EndpointBGPPeer, tiers []*proto.TierInfo) *proto.WorkloadEndpoint {
	mac := ""
	if ep.Mac != nil {
		mac = ep.Mac.String()
	}
	var (
		qosControls *proto.QoSControls
		qosPolicies []*proto.QoSPolicy
	)
	if ep.QoSControls != nil {
		qosControls = &proto.QoSControls{
			IngressBandwidth:      ep.QoSControls.IngressBandwidth,
			EgressBandwidth:       ep.QoSControls.EgressBandwidth,
			IngressBurst:          ep.QoSControls.IngressBurst,
			EgressBurst:           ep.QoSControls.EgressBurst,
			IngressPeakrate:       ep.QoSControls.IngressPeakrate,
			EgressPeakrate:        ep.QoSControls.EgressPeakrate,
			IngressMinburst:       ep.QoSControls.IngressMinburst,
			EgressMinburst:        ep.QoSControls.EgressMinburst,
			IngressPacketRate:     ep.QoSControls.IngressPacketRate,
			EgressPacketRate:      ep.QoSControls.EgressPacketRate,
			IngressPacketBurst:    ep.QoSControls.IngressPacketBurst,
			EgressPacketBurst:     ep.QoSControls.EgressPacketBurst,
			IngressMaxConnections: ep.QoSControls.IngressMaxConnections,
			EgressMaxConnections:  ep.QoSControls.EgressMaxConnections,
		}

		if ep.QoSControls.DSCP != nil {
			qosPolicies = append(qosPolicies, &proto.QoSPolicy{
				Dscp: int32(ep.QoSControls.DSCP.ToUint8()),
			})
		}
	}

	var localBGPPeer *proto.LocalBGPPeer
	if peerData != nil {
		localBGPPeer = &proto.LocalBGPPeer{
			BgpPeerName: peerData.v3PeerName,
		}
	}

	var skipRedir *proto.WorkloadBpfSkipRedir
	// BPF ingress redirect should be skipped for VM workloads and workloads that have ingress BW QoS configured
	if isVMWorkload(ep.Labels) || (ep.QoSControls != nil && (ep.QoSControls.IngressBandwidth > 0 || ep.QoSControls.IngressPacketRate > 0)) {
		skipRedir = &proto.WorkloadBpfSkipRedir{Ingress: true}
	}
	if ep.QoSControls != nil && (ep.QoSControls.EgressBandwidth > 0 || ep.QoSControls.EgressPacketRate > 0) {
		if skipRedir == nil {
			skipRedir = &proto.WorkloadBpfSkipRedir{}
		}
		skipRedir.Egress = true
	}

	wep := &proto.WorkloadEndpoint{
		State:                      ep.State,
		Name:                       ep.Name,
		Mac:                        mac,
		ProfileIds:                 ep.ProfileIDs,
		Ipv4Nets:                   netsToStrings(ep.IPv4Nets),
		Ipv6Nets:                   netsToStrings(ep.IPv6Nets),
		Tiers:                      tiers,
		Ipv4Nat:                    natsToProtoNatInfo(ep.IPv4NAT),
		Ipv6Nat:                    natsToProtoNatInfo(ep.IPv6NAT),
		AllowSpoofedSourcePrefixes: netsToStrings(ep.AllowSpoofedSourcePrefixes),
		Annotations:                ep.Annotations,
		QosControls:                qosControls,
		LocalBgpPeer:               localBGPPeer,
		SkipRedir:                  skipRedir,
		QosPolicies:                qosPolicies,
	}

	for _, cd := range computedData {
		cd.ApplyTo(wep)
	}

	return wep
}

func ModelHostEndpointToProto(ep *model.HostEndpoint, tiers, untrackedTiers, preDNATTiers []*proto.TierInfo, forwardTiers []*proto.TierInfo) *proto.HostEndpoint {
	var qosPolicies []*proto.QoSPolicy
	if ep.QoSControls != nil && ep.QoSControls.DSCP != nil {
		qosPolicies = append(qosPolicies, &proto.QoSPolicy{
			Dscp: int32(ep.QoSControls.DSCP.ToUint8()),
		})
	}
	return &proto.HostEndpoint{
		Name:              ep.Name,
		ExpectedIpv4Addrs: ipsToStrings(ep.ExpectedIPv4Addrs),
		ExpectedIpv6Addrs: ipsToStrings(ep.ExpectedIPv6Addrs),
		ProfileIds:        ep.ProfileIDs,
		Tiers:             tiers,
		UntrackedTiers:    untrackedTiers,
		PreDnatTiers:      preDNATTiers,
		ForwardTiers:      forwardTiers,
		QosPolicies:       qosPolicies,
	}
}

func (buf *EventSequencer) OnEndpointTierUpdate(
	endpointKey model.EndpointKey,
	endpoint model.Endpoint,
	computedData []EndpointComputedData,
	peerData *EndpointBGPPeer,
	filteredTiers []TierInfo,
) {
	if endpoint == nil {
		// Deletion. Squash any queued updates.
		delete(buf.pendingEndpointUpdates, endpointKey)
		if buf.sentEndpoints.Contains(endpointKey) {
			// We'd previously sent an update, so we need to send a deletion.
			buf.pendingEndpointDeletes.Add(endpointKey)
		}
	} else {
		// Update.
		buf.pendingEndpointDeletes.Discard(endpointKey)
		buf.pendingEndpointUpdates[endpointKey] = endpointUpdate{
			endpoint:     endpoint,
			computedData: computedData,
			peerData:     peerData,
			tierInfo:     filteredTiers,
		}
	}
}

func (buf *EventSequencer) flushEndpointTierUpdates() {
	for key, endpointUpdate := range buf.pendingEndpointUpdates {
		endpoint := endpointUpdate.endpoint

		tiers, untrackedTiers, preDNATTiers, forwardTiers := tierInfoToProtoTierInfo(endpointUpdate.tierInfo)
		switch key := key.(type) {
		case model.WorkloadEndpointKey:
			wlep := endpoint.(*model.WorkloadEndpoint)

			buf.Callback(&proto.WorkloadEndpointUpdate{
				Id: &proto.WorkloadEndpointID{
					OrchestratorId: key.OrchestratorID,
					WorkloadId:     key.WorkloadID,
					EndpointId:     key.EndpointID,
				},
				Endpoint: ModelWorkloadEndpointToProto(wlep, endpointUpdate.computedData, endpointUpdate.peerData, tiers),
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
	}
}

func (buf *EventSequencer) flushEndpointTierDeletes() {
	for item := range buf.pendingEndpointDeletes.All() {
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
		buf.pendingEndpointDeletes.Discard(item)
	}
}

func (buf *EventSequencer) OnEncapUpdate(encap config.Encapsulation) {
	log.WithFields(log.Fields{
		"IPIPEnabled":    encap.IPIPEnabled,
		"VXLANEnabled":   encap.VXLANEnabled,
		"VXLANEnabledV6": encap.VXLANEnabledV6,
	}).Debug("Encapsulation update")
	buf.pendingEncapUpdate = &encap
}

func (buf *EventSequencer) flushEncapUpdate() {
	if buf.pendingEncapUpdate != nil {
		buf.Callback(&proto.Encapsulation{
			IpipEnabled:    buf.pendingEncapUpdate.IPIPEnabled,
			VxlanEnabled:   buf.pendingEncapUpdate.VXLANEnabled,
			VxlanEnabledV6: buf.pendingEncapUpdate.VXLANEnabledV6,
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
		hostAddr := ""
		if hostIP != nil {
			hostAddr = hostIP.String()
		}
		buf.Callback(&proto.HostMetadataUpdate{
			Hostname: hostname,
			Ipv4Addr: hostAddr,
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
	for item := range buf.pendingHostIPDeletes.All() {
		buf.Callback(&proto.HostMetadataRemove{
			Hostname: item,
		})
		buf.sentHostIPs.Discard(item)
		buf.pendingHostIPDeletes.Discard(item)
	}
}

func (buf *EventSequencer) OnHostIPv6Update(hostname string, ip *net.IP) {
	log.WithFields(log.Fields{
		"hostname": hostname,
		"ip":       ip,
	}).Debug("Host IPv6 update")
	buf.pendingHostIPv6Deletes.Discard(hostname)
	buf.pendingHostIPv6Updates[hostname] = ip
}

func (buf *EventSequencer) flushHostIPv6Updates() {
	for hostname, hostIP := range buf.pendingHostIPv6Updates {
		hostIPv6Addr := ""
		if hostIP != nil {
			hostIPv6Addr = hostIP.String()
		}
		buf.Callback(&proto.HostMetadataV6Update{
			Hostname: hostname,
			Ipv6Addr: hostIPv6Addr,
		})
		buf.sentHostIPv6s.Add(hostname)
		delete(buf.pendingHostIPv6Updates, hostname)
	}
}

func (buf *EventSequencer) OnHostIPv6Remove(hostname string) {
	log.WithField("hostname", hostname).Debug("Host IPv6 removed")
	delete(buf.pendingHostIPv6Updates, hostname)
	if buf.sentHostIPv6s.Contains(hostname) {
		buf.pendingHostIPv6Deletes.Add(hostname)
	}
}

func (buf *EventSequencer) flushHostIPv6Deletes() {
	for item := range buf.pendingHostIPv6Deletes.All() {
		buf.Callback(&proto.HostMetadataV6Remove{
			Hostname: item,
		})
		buf.sentHostIPv6s.Discard(item)
		buf.pendingHostIPv6Deletes.Discard(item)
	}
}

func (buf *EventSequencer) OnHostMetadataUpdate(hostname string, ip4 *net.IPNet, ip6 *net.IPNet, asnumber string, labels map[string]string) {
	log.WithFields(log.Fields{
		"hostname": hostname,
		"ip4":      ip4,
		"ip6":      ip6,
		"labels":   labels,
		"asnumber": asnumber,
	}).Debug("Host update")
	buf.pendingHostMetadataDeletes.Discard(hostname)
	buf.pendingHostMetadataUpdates[hostname] = &hostInfo{ip4Addr: ip4, ip6Addr: ip6, labels: labels, asnumber: asnumber}
}

func (buf *EventSequencer) flushHostUpdates() {
	for hostname, hostInfo := range buf.pendingHostMetadataUpdates {
		var ip4str, ip6str string
		if hostInfo.ip4Addr.IP != nil {
			ip4str = hostInfo.ip4Addr.String()
		}
		if hostInfo.ip6Addr.IP != nil {
			ip6str = hostInfo.ip6Addr.String()
		}
		buf.Callback(&proto.HostMetadataV4V6Update{
			Hostname: hostname,
			Ipv4Addr: ip4str,
			Ipv6Addr: ip6str,
			Asnumber: hostInfo.asnumber,
			Labels:   hostInfo.labels,
		})
		buf.sentHosts.Add(hostname)
		delete(buf.pendingHostMetadataUpdates, hostname)
	}
}

func (buf *EventSequencer) OnHostMetadataRemove(hostname string) {
	log.WithField("hostname", hostname).Debug("Host removed")
	delete(buf.pendingHostMetadataUpdates, hostname)
	if buf.sentHosts.Contains(hostname) {
		buf.pendingHostMetadataDeletes.Add(hostname)
	}
}

func (buf *EventSequencer) flushHostDeletes() {
	for item := range buf.pendingHostMetadataDeletes.All() {
		buf.Callback(&proto.HostMetadataV4V6Remove{
			Hostname: item,
		})
		buf.sentHosts.Discard(item)
		buf.pendingHostMetadataDeletes.Discard(item)
	}
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
				IpipMode:   string(pool.IPIPMode),
				VxlanMode:  string(pool.VXLANMode),
			},
		})
		buf.sentIPPools.Add(key)
		delete(buf.pendingIPPoolUpdates, key)
	}
}

func (buf *EventSequencer) flushHostWireguardUpdates() {
	for nodename, wg := range buf.pendingWireguardUpdates {
		log.WithFields(log.Fields{"nodename": nodename, "wg": wg}).Debug("Processing pending wireguard update")

		var ipv4Str, ipv6Str string

		if wg.PublicKey != "" {
			if wg.InterfaceIPv4Addr != nil {
				ipv4Str = wg.InterfaceIPv4Addr.String()
			}
			log.WithField("ipv4Str", ipv4Str).Debug("Sending IPv4 wireguard endpoint update")
			buf.Callback(&proto.WireguardEndpointUpdate{
				Hostname:          nodename,
				PublicKey:         wg.PublicKey,
				InterfaceIpv4Addr: ipv4Str,
			})
			buf.sentWireguard.Add(nodename)
		} else if buf.sentWireguard.Contains(nodename) {
			log.Debug("Sending IPv4 wireguard endpoint remove")
			buf.Callback(&proto.WireguardEndpointRemove{
				Hostname: nodename,
			})
			buf.sentWireguard.Discard(nodename)
		}

		if wg.PublicKeyV6 != "" {
			if wg.InterfaceIPv6Addr != nil {
				ipv6Str = wg.InterfaceIPv6Addr.String()
			}
			log.WithField("ipv6Str", ipv6Str).Debug("Sending IPv6 wireguard endpoint update")
			buf.Callback(&proto.WireguardEndpointV6Update{
				Hostname:          nodename,
				PublicKeyV6:       wg.PublicKeyV6,
				InterfaceIpv6Addr: ipv6Str,
			})
			buf.sentWireguardV6.Add(nodename)
		} else if buf.sentWireguardV6.Contains(nodename) {
			log.Debug("Sending IPv6 wireguard endpoint remove")
			buf.Callback(&proto.WireguardEndpointV6Remove{
				Hostname: nodename,
			})
			buf.sentWireguardV6.Discard(nodename)
		}

		delete(buf.pendingWireguardUpdates, nodename)
	}
	log.Debug("Done flushing wireguard updates")
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
	for key := range buf.pendingIPPoolDeletes.All() {
		buf.Callback(&proto.IPAMPoolRemove{
			Id: cidrToIPPoolID(key),
		})
		buf.sentIPPools.Discard(key)
		buf.pendingIPPoolDeletes.Discard(key)
	}
}

func (buf *EventSequencer) flushHostWireguardDeletes() {
	for key := range buf.pendingWireguardDeletes.All() {
		log.WithField("nodename", key).Debug("Processing pending wireguard delete")
		if buf.sentWireguard.Contains(key) {
			log.Debug("Sending IPv4 wireguard endpoint remove")
			buf.Callback(&proto.WireguardEndpointRemove{
				Hostname: key,
			})
			buf.sentWireguard.Discard(key)
		}
		if buf.sentWireguardV6.Contains(key) {
			log.Debug("Sending IPv6 wireguard endpoint remove")
			buf.Callback(&proto.WireguardEndpointV6Remove{
				Hostname: key,
			})
			buf.sentWireguardV6.Discard(key)
		}
		buf.pendingWireguardDeletes.Discard(key)
	}
	log.Debug("Done flushing wireguard removes")
}

func (buf *EventSequencer) flushAddedIPSets() {
	for setID, setType := range buf.pendingAddedIPSets {
		log.WithField("setID", setID).Debug("Flushing added IP set")
		members := make([]string, 0)
		buf.pendingAddedIPSetMembers.Iter(setID, func(member ipsetmember.IPSetMember) {
			members = append(members, member.ToProtobufFormat())
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
	// before flushing route adds, and route removes before flushing VTEP removes. We also send
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
	buf.flushHostIPv6Deletes()
	buf.flushHostIPv6Updates()
	buf.flushHostDeletes()
	buf.flushHostUpdates()
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
	for setID := range buf.pendingRemovedIPSets.All() {
		log.Debugf("Flushing IP set remove: %v", setID)
		buf.Callback(&proto.IPSetRemove{
			Id: setID,
		})
		buf.pendingRemovedIPSetMembers.DiscardKey(setID)
		buf.pendingAddedIPSetMembers.DiscardKey(setID)
		buf.pendingRemovedIPSets.Discard(setID)
		buf.sentIPSets.Discard(setID)
	}
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
	buf.pendingAddedIPSetMembers.Iter(setID, func(member ipsetmember.IPSetMember) {
		deltaUpdate.AddedMembers = append(deltaUpdate.AddedMembers, member.ToProtobufFormat())
	})
	buf.pendingRemovedIPSetMembers.Iter(setID, func(member ipsetmember.IPSetMember) {
		deltaUpdate.RemovedMembers = append(deltaUpdate.RemovedMembers, member.ToProtobufFormat())
	})
	buf.pendingAddedIPSetMembers.DiscardKey(setID)
	buf.pendingRemovedIPSetMembers.DiscardKey(setID)
	buf.Callback(&deltaUpdate)
}

func (buf *EventSequencer) OnServiceAccountUpdate(update *proto.ServiceAccountUpdate) {
	// We trust the caller not to send us an update with nil ID, so safe to dereference.
	id := types.ProtoToServiceAccountID(update.Id)
	log.WithFields(log.Fields{
		"key":    id,
		"labels": update.GetLabels(),
	}).Debug("ServiceAccount update")
	buf.pendingServiceAccountDeletes.Discard(id)
	buf.pendingServiceAccountUpdates[id] = update
}

func (buf *EventSequencer) OnServiceAccountRemove(id types.ServiceAccountID) {
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
	for id := range buf.pendingServiceAccountDeletes.All() {
		protoID := types.ServiceAccountIDToProto(id)
		msg := proto.ServiceAccountRemove{Id: protoID}
		buf.Callback(&msg)
		buf.sentServiceAccounts.Discard(id)
	}
	buf.pendingServiceAccountDeletes.Clear()
	for _, msg := range buf.pendingServiceAccountUpdates {
		buf.Callback(msg)
		id := types.ProtoToServiceAccountID(msg.GetId())
		// We safely dereferenced the Id in OnServiceAccountUpdate before adding it to the pending updates map, so
		// it is safe to do so here.
		buf.sentServiceAccounts.Add(id)
	}
	buf.pendingServiceAccountUpdates = make(map[types.ServiceAccountID]*proto.ServiceAccountUpdate)
	log.Debug("Done flushing Service Accounts")
}

func (buf *EventSequencer) OnNamespaceUpdate(update *proto.NamespaceUpdate) {
	// We trust the caller not to send us an update with nil ID, so safe to dereference.
	id := types.ProtoToNamespaceID(update.GetId())
	log.WithFields(log.Fields{
		"key":    id,
		"labels": update.GetLabels(),
	}).Debug("Namespace update")
	buf.pendingNamespaceDeletes.Discard(id)
	buf.pendingNamespaceUpdates[id] = update
}

func (buf *EventSequencer) OnNamespaceRemove(id types.NamespaceID) {
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
			if block.CIDR == "" {
				// When we defined the CRD we allowed this field to be optional
				// for extensibility, ignore empty CIDRs.
				continue
			}
			buf.pendingGlobalBGPConfig.ServiceClusterCidrs = append(buf.pendingGlobalBGPConfig.ServiceClusterCidrs, block.CIDR)
		}
		for _, block := range cfg.Spec.ServiceExternalIPs {
			if block.CIDR == "" {
				// When we defined the CRD we allowed this field to be optional
				// for extensibility, ignore empty CIDRs.
				continue
			}
			buf.pendingGlobalBGPConfig.ServiceExternalCidrs = append(buf.pendingGlobalBGPConfig.ServiceExternalCidrs, block.CIDR)
		}
		for _, block := range cfg.Spec.ServiceLoadBalancerIPs {
			if block.CIDR == "" {
				// When we defined the CRD we allowed this field to be optional
				// for extensibility, ignore empty CIDRs.
				continue
			}
			buf.pendingGlobalBGPConfig.ServiceLoadbalancerCidrs = append(buf.pendingGlobalBGPConfig.ServiceLoadbalancerCidrs, block.CIDR)
		}
		buf.pendingGlobalBGPConfig.LocalWorkloadPeeringIpV4 = cfg.Spec.LocalWorkloadPeeringIPV4
		buf.pendingGlobalBGPConfig.LocalWorkloadPeeringIpV6 = cfg.Spec.LocalWorkloadPeeringIPV6
	}
}

func (buf *EventSequencer) flushNamespaces() {
	// Order doesn't matter, but send removes first to reduce max occupancy
	for id := range buf.pendingNamespaceDeletes.All() {
		protoID := types.NamespaceIDToProto(id)
		msg := proto.NamespaceRemove{Id: protoID}
		buf.Callback(&msg)
		buf.sentNamespaces.Discard(id)
	}
	buf.pendingNamespaceDeletes.Clear()
	for _, msg := range buf.pendingNamespaceUpdates {
		buf.Callback(msg)
		id := types.ProtoToNamespaceID(msg.GetId())
		// We safely dereferenced the Id in OnNamespaceUpdate before adding it to the pending updates map, so
		// it is safe to do so here.
		buf.sentNamespaces.Add(id)
	}
	buf.pendingNamespaceUpdates = make(map[types.NamespaceID]*proto.NamespaceUpdate)
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
	for node := range buf.pendingVTEPDeletes.All() {
		msg := proto.VXLANTunnelEndpointRemove{Node: node}
		buf.Callback(&msg)
		buf.sentVTEPs.Discard(node)
	}
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
	for id := range buf.pendingRouteDeletes.All() {
		msg := proto.RouteRemove{Dst: id.dst}
		buf.Callback(&msg)
		buf.sentRoutes.Discard(id)
	}
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
	for id := range buf.pendingServiceDeletes.All() {
		msg := &proto.ServiceRemove{
			Name:      id.Name,
			Namespace: id.Namespace,
		}
		buf.Callback(msg)
		buf.sentServices.Discard(id)
	}
	buf.pendingServiceDeletes.Clear()
	for _, msg := range buf.pendingServiceUpdates {
		buf.Callback(msg)
		id := serviceID{
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
	id := proto.PolicyID{
		Name:      pol.Key.Name,
		Namespace: pol.Key.Namespace,
		Kind:      pol.Key.Kind,
	}
	if pol.GovernsIngress() {
		tierInfo.IngressPolicies = append(tierInfo.IngressPolicies, &id)
	}
	if egressAllowed && pol.GovernsEgress() {
		tierInfo.EgressPolicies = append(tierInfo.EgressPolicies, &id)
	}
}

func tierInfoToProtoTierInfo(filteredTiers []TierInfo) (normalTiers, untrackedTiers, preDNATTiers, forwardTiers []*proto.TierInfo) {
	if len(filteredTiers) > 0 {
		for _, ti := range filteredTiers {
			// For untracked and preDNAT tiers, DefautlAction must be Pass, to make sure policies in the normal tier
			// are also checked.
			untrackedTierInfo := &proto.TierInfo{Name: ti.Name, DefaultAction: string(v3.Pass)}
			preDNATTierInfo := &proto.TierInfo{Name: ti.Name, DefaultAction: string(v3.Pass)}
			forwardTierInfo := &proto.TierInfo{Name: ti.Name, DefaultAction: string(ti.DefaultAction)}
			normalTierInfo := &proto.TierInfo{Name: ti.Name, DefaultAction: string(ti.DefaultAction)}
			for _, pol := range ti.OrderedPolicies {
				if pol.Value.DoNotTrack() {
					addPolicyToTierInfo(&pol, untrackedTierInfo, true)
				} else if pol.Value.PreDNAT() {
					addPolicyToTierInfo(&pol, preDNATTierInfo, false)
				} else {
					if pol.Value.ApplyOnForward() {
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

func isVMWorkload(labels uniquelabels.Map) bool {
	if val, ok := labels.GetString("kubevirt.io"); ok {
		if val == "virt-launcher" {
			return true
		}
	}
	return false
}
