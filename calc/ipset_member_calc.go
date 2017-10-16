// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/dispatcher"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/multidict"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/set"
)

type IPAddRemoveCallbacks interface {
	OnCIDRAdded(ipSetID string, ip ip.CIDR)
	OnCIDRRemoved(ipSetID string, ip ip.CIDR)
}

// MemberCalculator calculates the actual IPs that should be in each IP set.  As input, it
// expects MatchStarted/Stopped events telling it which IP sets match which endpoints (by ID)
// along with OnUpdate calls for endpoints.  It then joins the match data with the endpoint
// data to calculate which IPs are in which IP set and generates events when IPs are added or
// removed.
//
// The complexity in the MemberCalculator comes from needing to deal with IPs being assigned
// to multiple endpoints at the same time.  If two endpoints are added with the same IP, we
// want to generate only one "IP added" event.  We also need to wait for both endpoints to be
// removed before generating the "IP removed" event.
type MemberCalculator struct {
	keyToCIDRs            map[model.Key][]ip.CIDR
	keyToMatchingIPSetIDs multidict.IfaceToString
	ipSetIDToCIDRToKey    map[string]map[ip.CIDR][]model.Key

	callbacks IPAddRemoveCallbacks
}

func NewMemberCalculator() *MemberCalculator {
	calc := &MemberCalculator{
		keyToCIDRs:            make(map[model.Key][]ip.CIDR),
		keyToMatchingIPSetIDs: multidict.NewIfaceToString(),
		ipSetIDToCIDRToKey:    make(map[string]map[ip.CIDR][]model.Key),
	}
	return calc
}

func (calc *MemberCalculator) RegisterWith(allUpdDispatcher *dispatcher.Dispatcher) {
	allUpdDispatcher.Register(model.WorkloadEndpointKey{}, calc.OnUpdate)
	allUpdDispatcher.Register(model.HostEndpointKey{}, calc.OnUpdate)
	allUpdDispatcher.Register(model.NetworkSetKey{}, calc.OnUpdate)
}

// MatchStarted tells this object that an endpoint now belongs to an IP set.
func (calc *MemberCalculator) MatchStarted(key model.Key, ipSetID string) {
	log.Debugf("Adding endpoint %v to IP set %v", key, ipSetID)
	calc.keyToMatchingIPSetIDs.Put(key, ipSetID)
	ips := calc.keyToCIDRs[key]
	calc.addMatchToIndex(ipSetID, key, ips)
}

// MatchStopped tells this object that an endpoint no longer belongs to an IP set.
func (calc *MemberCalculator) MatchStopped(key model.Key, ipSetID string) {
	log.Debugf("Removing endpoint %v from IP set %v", key, ipSetID)
	calc.keyToMatchingIPSetIDs.Discard(key, ipSetID)
	ips := calc.keyToCIDRs[key]
	calc.removeMatchFromIndex(ipSetID, key, ips)
}

func (calc *MemberCalculator) OnUpdate(update api.Update) (filterOut bool) {
	if update.Value == nil {
		calc.updateCIDRsForKey(update.Key, []ip.CIDR{})
		return
	}
	switch update.Key.(type) {
	case model.WorkloadEndpointKey:
		ep := update.Value.(*model.WorkloadEndpoint)
		cidrs := make([]ip.CIDR, 0, len(ep.IPv4Nets)+len(ep.IPv6Nets))
		for _, net := range ep.IPv4Nets {
			cidrs = append(cidrs, ip.CIDRFromCalicoNet(net))
		}
		for _, net := range ep.IPv6Nets {
			cidrs = append(cidrs, ip.CIDRFromCalicoNet(net))
		}
		calc.updateCIDRsForKey(update.Key, cidrs)
	case model.NetworkSetKey:
		ns := update.Value.(*model.NetworkSet)
		cidrs := make([]ip.CIDR, 0, len(ns.Nets))
		for _, net := range ns.Nets {
			cidrs = append(cidrs, ip.CIDRFromCalicoNet(net))
		}
		calc.updateCIDRsForKey(update.Key, cidrs)
	case model.HostEndpointKey:
		ep := update.Value.(*model.HostEndpoint)
		cidrs := make([]ip.CIDR, 0,
			len(ep.ExpectedIPv4Addrs)+len(ep.ExpectedIPv6Addrs))
		for _, netIP := range ep.ExpectedIPv4Addrs {
			cidrs = append(cidrs, ip.CIDRFromNetIP(netIP.IP))
		}
		for _, netIP := range ep.ExpectedIPv6Addrs {
			cidrs = append(cidrs, ip.CIDRFromNetIP(netIP.IP))
		}
		calc.updateCIDRsForKey(update.Key, cidrs)
	}
	return
}

// UpdateEndpointIPs tells this object that an endpoint has a new set of IP addresses.
func (calc *MemberCalculator) updateCIDRsForKey(key model.Key, cidrs []ip.CIDR) {
	log.Debugf("Endpoint %v CIDRs updated to %v", key, cidrs)
	oldCIDRs := calc.keyToCIDRs[key]
	if len(cidrs) == 0 {
		delete(calc.keyToCIDRs, key)
	} else {
		calc.keyToCIDRs[key] = cidrs
	}

	oldCIDRsSet := set.New()
	for _, cidr := range oldCIDRs {
		oldCIDRsSet.Add(cidr)
	}

	addedCIDRs := make([]ip.CIDR, 0)
	currentCIDRs := set.New()
	for _, cidr := range cidrs {
		if !oldCIDRsSet.Contains(cidr) {
			log.Debugf("Added CIDR: %v", cidr)
			addedCIDRs = append(addedCIDRs, cidr)
		}
		currentCIDRs.Add(cidr)
	}

	removedCIDRs := make([]ip.CIDR, 0)
	for _, cidr := range oldCIDRs {
		if !currentCIDRs.Contains(cidr) {
			log.Debugf("Removed CIDR: %v", cidr)
			removedCIDRs = append(removedCIDRs, cidr)
		}
	}

	calc.keyToMatchingIPSetIDs.Iter(key, func(ipSetID string) {
		log.Debugf("Updating matching IP set: %v", ipSetID)
		calc.addMatchToIndex(ipSetID, key, addedCIDRs)
		calc.removeMatchFromIndex(ipSetID, key, removedCIDRs)
	})
}

func (calc *MemberCalculator) addMatchToIndex(ipSetID string, key model.Key, cidrs []ip.CIDR) {
	log.Debugf("IP set %v now matches CIDRs %v via %v", ipSetID, cidrs, key)
	cidrToKeys, ok := calc.ipSetIDToCIDRToKey[ipSetID]
	if !ok {
		cidrToKeys = make(map[ip.CIDR][]model.Key, len(cidrs))
		calc.ipSetIDToCIDRToKey[ipSetID] = cidrToKeys
	}

cidrLoop:
	for _, cidr := range cidrs {
		keys := cidrToKeys[cidr]
		if keys == nil {
			log.Debugf("New CIDR in IP set %v: %v", ipSetID, cidr)
			calc.callbacks.OnCIDRAdded(ipSetID, cidr)
		} else {
			// Skip the append if the key is already present.
			for _, k := range keys {
				if key == k {
					continue cidrLoop
				}
			}
		}
		cidrToKeys[cidr] = append(keys, key)
	}
}

func (calc *MemberCalculator) removeMatchFromIndex(ipSetID string, key model.Key, cidrs []ip.CIDR) {
	log.Debugf("IP set %v no longer matches CIDRs %v via %v", ipSetID, cidrs, key)
	cidrToKeys := calc.ipSetIDToCIDRToKey[ipSetID]
	for _, cidr := range cidrs {
		keys := cidrToKeys[cidr]
		for i, k := range keys {
			if key == k {
				// found it,
				if len(keys) == 1 {
					// It was the only entry, clean it up.
					delete(cidrToKeys, cidr)
					calc.callbacks.OnCIDRRemoved(ipSetID, cidr)
				} else {
					keys[i] = keys[len(keys)-1]
					keys = keys[:len(keys)-1]
					cidrToKeys[cidr] = keys
				}
				break
			}
		}
	}
}
