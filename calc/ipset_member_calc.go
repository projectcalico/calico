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
	OnIPAdded(ipSetID string, ip ip.Addr)
	OnIPRemoved(ipSetID string, ip ip.Addr)
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
	keyToIPs              map[model.Key][]ip.Addr
	keyToMatchingIPSetIDs multidict.IfaceToString
	ipSetIDToIPToKey      map[string]map[ip.Addr][]model.Key

	callbacks IPAddRemoveCallbacks
}

func NewMemberCalculator() *MemberCalculator {
	calc := &MemberCalculator{
		keyToIPs:              make(map[model.Key][]ip.Addr),
		keyToMatchingIPSetIDs: multidict.NewIfaceToString(),
		ipSetIDToIPToKey:      make(map[string]map[ip.Addr][]model.Key),
	}
	return calc
}

func (calc *MemberCalculator) RegisterWith(allUpdDispatcher *dispatcher.Dispatcher) {
	allUpdDispatcher.Register(model.WorkloadEndpointKey{}, calc.OnUpdate)
	allUpdDispatcher.Register(model.HostEndpointKey{}, calc.OnUpdate)
}

// MatchStarted tells this object that an endpoint now belongs to an IP set.
func (calc *MemberCalculator) MatchStarted(key model.Key, ipSetID string) {
	log.Debugf("Adding endpoint %v to IP set %v", key, ipSetID)
	calc.keyToMatchingIPSetIDs.Put(key, ipSetID)
	ips := calc.keyToIPs[key]
	calc.addMatchToIndex(ipSetID, key, ips)
}

// MatchStopped tells this object that an endpoint no longer belongs to an IP set.
func (calc *MemberCalculator) MatchStopped(key model.Key, ipSetID string) {
	log.Debugf("Removing endpoint %v from IP set %v", key, ipSetID)
	calc.keyToMatchingIPSetIDs.Discard(key, ipSetID)
	ips := calc.keyToIPs[key]
	calc.removeMatchFromIndex(ipSetID, key, ips)
}

func (calc *MemberCalculator) OnUpdate(update api.Update) (filterOut bool) {
	if update.Value == nil {
		calc.updateEndpointIPs(update.Key, []ip.Addr{})
		return
	}
	switch update.Key.(type) {
	case model.WorkloadEndpointKey:
		ep := update.Value.(*model.WorkloadEndpoint)
		ips := make([]ip.Addr, 0, len(ep.IPv4Nets)+len(ep.IPv6Nets))
		for _, net := range ep.IPv4Nets {
			ips = append(ips, ip.FromNetIP(net.IP))
		}
		for _, net := range ep.IPv6Nets {
			ips = append(ips, ip.FromNetIP(net.IP))
		}
		calc.updateEndpointIPs(update.Key, ips)
	case model.HostEndpointKey:
		ep := update.Value.(*model.HostEndpoint)
		ips := make([]ip.Addr, 0,
			len(ep.ExpectedIPv4Addrs)+len(ep.ExpectedIPv6Addrs))
		for _, netIP := range ep.ExpectedIPv4Addrs {
			ips = append(ips, ip.FromNetIP(netIP.IP))
		}
		for _, netIP := range ep.ExpectedIPv6Addrs {
			ips = append(ips, ip.FromNetIP(netIP.IP))
		}
		calc.updateEndpointIPs(update.Key, ips)
	}
	return
}

// UpdateEndpointIPs tells this object that an endpoint has a new set of IP addresses.
func (calc *MemberCalculator) updateEndpointIPs(endpointKey model.Key, ips []ip.Addr) {
	log.Debugf("Endpoint %v IPs updated to %v", endpointKey, ips)
	oldIPs := calc.keyToIPs[endpointKey]
	if len(ips) == 0 {
		delete(calc.keyToIPs, endpointKey)
	} else {
		calc.keyToIPs[endpointKey] = ips
	}

	oldIPsSet := set.New()
	for _, ip := range oldIPs {
		oldIPsSet.Add(ip)
	}

	addedIPs := make([]ip.Addr, 0)
	currentIPs := set.New()
	for _, ip := range ips {
		if !oldIPsSet.Contains(ip) {
			log.Debugf("Added IP: %v", ip)
			addedIPs = append(addedIPs, ip)
		}
		currentIPs.Add(ip)
	}

	removedIPs := make([]ip.Addr, 0)
	for _, ip := range oldIPs {
		if !currentIPs.Contains(ip) {
			log.Debugf("Removed IP: %v", ip)
			removedIPs = append(removedIPs, ip)
		}
	}

	calc.keyToMatchingIPSetIDs.Iter(endpointKey, func(ipSetID string) {
		log.Debugf("Updating matching IP set: %v", ipSetID)
		calc.addMatchToIndex(ipSetID, endpointKey, addedIPs)
		calc.removeMatchFromIndex(ipSetID, endpointKey, removedIPs)
	})
}

func (calc *MemberCalculator) addMatchToIndex(ipSetID string, key model.Key, ips []ip.Addr) {
	log.Debugf("IP set %v now matches IPs %v via %v", ipSetID, ips, key)
	ipToKeys, ok := calc.ipSetIDToIPToKey[ipSetID]
	if !ok {
		ipToKeys = make(map[ip.Addr][]model.Key, len(ips))
		calc.ipSetIDToIPToKey[ipSetID] = ipToKeys
	}

ipLoop:
	for _, theIP := range ips {
		keys := ipToKeys[theIP]
		if keys == nil {
			log.Debugf("New IP in IP set %v: %v", ipSetID, theIP)
			calc.callbacks.OnIPAdded(ipSetID, theIP)
		} else {
			// Skip the append if the key is already present.
			for _, k := range keys {
				if key == k {
					continue ipLoop
				}
			}
		}
		ipToKeys[theIP] = append(keys, key)
	}
}

func (calc *MemberCalculator) removeMatchFromIndex(ipSetID string, key model.Key, ips []ip.Addr) {
	log.Debugf("IP set %v no longer matches IPs %v via %v", ipSetID, ips, key)
	ipToKeys := calc.ipSetIDToIPToKey[ipSetID]
	for _, theIP := range ips {
		keys := ipToKeys[theIP]
		for i, k := range keys {
			if key == k {
				// found it,
				if len(keys) == 1 {
					// It was the only entry, clean it up.
					delete(ipToKeys, theIP)
					calc.callbacks.OnIPRemoved(ipSetID, theIP)
				} else {
					keys[i] = keys[len(keys)-1]
					keys = keys[:len(keys)-1]
					ipToKeys[theIP] = keys
				}
				break
			}
		}
	}
}
