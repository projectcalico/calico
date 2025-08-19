// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.
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
	"strings"

	"github.com/sirupsen/logrus"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
)

// hostsIPSetManager manages the all-hosts IP set, which is used by some rules in our static chains.
// It doesn't actually program the rules, because they are part of the top-level static chains.
type hostsIPSetManager struct {
	// Our dependencies.
	hostname  string
	ipVersion uint8

	// activeHostnameToIP maps hostname to string IP address. We don't bother to parse into
	// net.IPs because we're going to pass them directly to the IPSet API.
	activeHostnameToIP map[string]string
	ipsetsDataplane    dpsets.IPSetsDataplane
	ipSetMetadata      ipsets.IPSetMetadata

	// Indicates if configuration has changed since the last apply.
	ipSetDirty bool
	dpConfig   Config

	// Log context
	logCtx *logrus.Entry
}

func newHostsIPSetManager(
	ipsetsDataplane dpsets.IPSetsDataplane,
	ipVersion uint8,
	dpConfig Config,
) *hostsIPSetManager {
	return &hostsIPSetManager{
		ipsetsDataplane: ipsetsDataplane,
		ipSetMetadata: ipsets.IPSetMetadata{
			MaxSize: dpConfig.MaxIPSetSize,
			SetID:   rules.IPSetIDAllHostNets,
			Type:    ipsets.IPSetTypeHashNet,
		},
		activeHostnameToIP: map[string]string{},
		hostname:           dpConfig.Hostname,
		ipVersion:          ipVersion,
		ipSetDirty:         true,
		dpConfig:           dpConfig,
		logCtx: logrus.WithFields(logrus.Fields{
			"ipVersion": ipVersion,
		}),
	}
}

func (m *hostsIPSetManager) OnUpdate(protoBufMsg interface{}) {
	switch msg := protoBufMsg.(type) {
	case *proto.HostMetadataV4V6Update:
		if (m.ipVersion == 4 && msg.Ipv4Addr == "") || (m.ipVersion == 6 && msg.Ipv6Addr == "") {
			// Skip since the update is for a mismatched IP version
			m.logCtx.WithField("msg", msg).Debug("Skipping mismatched IP version update")
			return
		}

		m.logCtx.WithField("hostname", msg.Hostname).Debug("Host update/create")
		addr := msg.Ipv4Addr
		if m.ipVersion == 6 {
			addr = msg.Ipv6Addr
		}
		// Remove subnet mask.
		parts := strings.Split(addr, "/")
		m.activeHostnameToIP[msg.Hostname] = parts[0]
		m.ipSetDirty = true
	case *proto.HostMetadataV4V6Remove:
		m.logCtx.WithField("hostname", msg.Hostname).Debug("Host removed")
		delete(m.activeHostnameToIP, msg.Hostname)
		m.ipSetDirty = true
	}
}

func (m *hostsIPSetManager) CompleteDeferredWork() error {
	if m.ipSetDirty {
		m.updateAllHostsIPSet()
		m.ipSetDirty = false
	}
	return nil
}

func (m *hostsIPSetManager) updateAllHostsIPSet() {
	var externalNodeCIDRs []string
	// We allow IPIP packets from configured external sources as well as
	// each Calico node. However, IPIP encapsulation is only supported with IPv4.
	if m.ipVersion == 4 {
		externalNodeCIDRs = m.dpConfig.ExternalNodesCidrs
	}

	// For simplicity (and on the assumption that host add/removes are rare) rewrite
	// the whole IP set whenever we get a change. To replace this with delta handling
	// would require reference counting the IPs because it's possible for two hosts
	// to (at least transiently) share an IP. That would add occupancy and make the
	// code more complex.
	m.logCtx.Info("All-hosts IP set out-of sync, refreshing it.")
	members := make([]string, 0, len(m.activeHostnameToIP)+len(externalNodeCIDRs))
	for _, ip := range m.activeHostnameToIP {
		members = append(members, ip)
	}
	members = append(members, externalNodeCIDRs...)
	m.ipsetsDataplane.AddOrReplaceIPSet(m.ipSetMetadata, members)
}
