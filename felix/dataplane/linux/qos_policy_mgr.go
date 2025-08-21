// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	"sort"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
)

type qosPolicyManager struct {
	ipVersion    uint8
	ruleRenderer rules.RuleRenderer
	mangleTable  Table

	// QoS policies.
	wepPolicies map[types.WorkloadEndpointID]rules.QoSPolicy
	hepPolicies map[types.HostEndpointID]rules.QoSPolicy
	dirty       bool

	logCxt *logrus.Entry
}

func newQoSPolicyManager(
	mangleTable Table,
	ruleRenderer rules.RuleRenderer,
	ipVersion uint8,
) *qosPolicyManager {
	return &qosPolicyManager{
		mangleTable:  mangleTable,
		ruleRenderer: ruleRenderer,
		ipVersion:    ipVersion,
		wepPolicies:  map[types.WorkloadEndpointID]rules.QoSPolicy{},
		hepPolicies:  map[types.HostEndpointID]rules.QoSPolicy{},
		dirty:        true,
		logCxt:       logrus.WithField("ipVersion", ipVersion),
	}
}

func (m *qosPolicyManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *proto.HostEndpointUpdate:
		m.handleHEPUpdates(msg.GetId(), msg)
	case *proto.HostEndpointRemove:
		m.handleHEPUpdates(msg.GetId(), nil)
	case *proto.WorkloadEndpointUpdate:
		m.handleWEPUpdates(msg.GetId(), msg)
	case *proto.WorkloadEndpointRemove:
		m.handleWEPUpdates(msg.GetId(), nil)
	}
}

func (m *qosPolicyManager) handleHEPUpdates(hepID *proto.HostEndpointID, msg *proto.HostEndpointUpdate) {
	id := types.ProtoToHostEndpointID(hepID)
	if msg == nil || len(msg.Endpoint.QosPolicies) == 0 {
		_, exists := m.hepPolicies[id]
		if exists {
			delete(m.hepPolicies, id)
			m.dirty = true
		}
		return
	}

	// We only support one policy per endpoint at this point.
	dscp := msg.Endpoint.QosPolicies[0].Dscp

	// This situation must be handled earlier.
	if dscp > 63 || dscp < 0 {
		logrus.WithField("id", id).Panicf("Invalid DSCP value %v", dscp)
	}
	ips := msg.Endpoint.ExpectedIpv4Addrs
	if m.ipVersion == 6 {
		ips = msg.Endpoint.ExpectedIpv6Addrs
	}
	if len(ips) != 0 {
		m.hepPolicies[id] = rules.QoSPolicy{
			SrcAddrs: normaliseSourceAddr(ips),
			DSCP:     uint8(dscp),
		}
		m.dirty = true
	}
}

func (m *qosPolicyManager) handleWEPUpdates(wepID *proto.WorkloadEndpointID, msg *proto.WorkloadEndpointUpdate) {
	id := types.ProtoToWorkloadEndpointID(wepID)
	if msg == nil || len(msg.Endpoint.QosPolicies) == 0 {
		_, exists := m.wepPolicies[id]
		if exists {
			delete(m.wepPolicies, id)
			m.dirty = true
		}
		return
	}

	// We only support one policy per endpoint at this point.
	dscp := msg.Endpoint.QosPolicies[0].Dscp

	// This situation must be handled earlier.
	if dscp > 63 || dscp < 0 {
		logrus.WithField("id", id).Panicf("Invalid DSCP value %v", dscp)
	}
	ips := msg.Endpoint.Ipv4Nets
	if m.ipVersion == 6 {
		ips = msg.Endpoint.Ipv6Nets
	}
	if len(ips) != 0 {
		m.wepPolicies[id] = rules.QoSPolicy{
			SrcAddrs: normaliseSourceAddr(ips),
			DSCP:     uint8(dscp),
		}
		m.dirty = true
	}
}

func normaliseSourceAddr(addrs []string) string {
	var trimmedSources []string
	for _, addr := range addrs {
		parts := strings.Split(addr, "/")
		trimmedSources = append(trimmedSources, parts[0])
	}
	return strings.Join(trimmedSources, ",")
}

func (m *qosPolicyManager) CompleteDeferredWork() error {
	var policies []rules.QoSPolicy
	if m.dirty {
		for _, p := range m.wepPolicies {
			policies = append(policies, p)
		}
		for _, p := range m.hepPolicies {
			policies = append(policies, p)
		}
		sort.Slice(policies, func(i, j int) bool {
			return policies[i].SrcAddrs < policies[j].SrcAddrs
		})

		chain := m.ruleRenderer.EgressQoSPolicyChain(policies)
		m.mangleTable.UpdateChain(chain)
		m.dirty = false
	}

	return nil
}
