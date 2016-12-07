// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

package rules

import (
	"github.com/Sirupsen/logrus"
	. "github.com/projectcalico/felix/go/felix/iptables"
	"strings"
)

func (r *ruleRenderer) StaticFilterTableChains(ipVersion uint8) (chains []*Chain) {
	chains = append(chains, r.StaticFilterForwardChains()...)
	chains = append(chains, r.StaticFilterInputChains(ipVersion)...)
	chains = append(chains, r.StaticFilterOutputChains()...)
	return
}

const (
	ProtoIPIP = 4
)

func (r *ruleRenderer) StaticFilterInputChains(ipVersion uint8) []*Chain {

	// TODO(smc) Metadata IP/port
	// TODO(smc) DHCP special case for OpenStack

	var rules []Rule

	if ipVersion == 4 && r.IPIPEnabled {
		// IPIP is enabled, filter incoming IPIP packets to ensure they come from a
		// recognised host.  We use the protocol number rather than its name because the
		// name is not guaranteed to be known by the kernel.
		match := Match().ProtocolNum(ProtoIPIP).
			NotSourceIPSet(r.IPSetConfigV4.NameForMainIPSet(AllHostIPsSetID))
		rules = append(rules,
			r.DropRules(match, "Drop IPIP packets from non-Calico hosts")...)
	}

	return []*Chain{
		{
			Name:  FilterInputChainName,
			Rules: rules,
		},
	}
}

func (r *ruleRenderer) StaticFilterForwardChains() []*Chain {
	rules := []Rule{}

	for _, prefix := range r.WorkloadIfacePrefixes {
		logrus.WithField("ifacePrefix", prefix).Debug("Adding workload match rules")
		ifaceMatch := prefix + "+"
		rules = append(rules, r.DropRules(Match().InInterface(ifaceMatch).ConntrackState("INVALID"))...)
		rules = append(rules,
			Rule{
				Match:  Match().InInterface(ifaceMatch).ConntrackState("RELATED,ESTABLISHED"),
				Action: AcceptAction{},
			},
			Rule{
				Match:  Match().OutInterface(ifaceMatch).ConntrackState("RELATED,ESTABLISHED"),
				Action: AcceptAction{},
			},
			Rule{
				Match:  Match().InInterface(ifaceMatch),
				Action: JumpAction{Target: DispatchFromWorkloadEndpoint},
			},
			Rule{
				Match:  Match().OutInterface(ifaceMatch),
				Action: JumpAction{Target: DispatchToWorkloadEndpoint},
			},
			Rule{
				Match:  Match().InInterface(ifaceMatch),
				Action: AcceptAction{},
			},
			Rule{
				Match:  Match().OutInterface(ifaceMatch),
				Action: AcceptAction{},
			})
	}

	return []*Chain{{
		Name:  FilterForwardChainName,
		Rules: rules,
	}}
}

func (r *ruleRenderer) StaticFilterOutputChains() []*Chain {
	// TODO(smc) filter output chain
	return []*Chain{}
}

func (r *ruleRenderer) StaticNATTableChains(ipVersion uint8) (chains []*Chain) {
	chains = append(chains, r.StaticNATPreroutingChains(ipVersion)...)
	chains = append(chains, r.StaticNATPostroutingChains(ipVersion)...)
	return
}

func (r *ruleRenderer) StaticNATPreroutingChains(ipVersion uint8) []*Chain {
	rules := []Rule{}

	if ipVersion == 4 && r.OpenStackMetadataIP != nil {
		rules = append(rules, Rule{
			Match: Match().
				Protocol("tcp").
				DestPorts(80).
				DestNet("169.254.169.254/32"),
			Action: DNATAction{
				DestAddr: r.OpenStackMetadataIP.String(),
				DestPort: r.OpenStackMetadataPort,
			},
		})
	}

	return []*Chain{{
		Name:  NATPreroutingChainName,
		Rules: rules,
	}}
}

func (r *ruleRenderer) StaticNATPostroutingChains(ipVersion uint8) []*Chain {
	rules := []Rule{
		{
			Action: JumpAction{Target: NATOutgoingChainName},
		},
	}
	if r.IPIPEnabled && len(r.IPIPTunnelAddress) > 0 {
		// Add a rule to catch packets that are being sent down the IPIP tunnel from an
		// incorrect local IP address of the host and NAT them to use the tunnel IP as its
		// source.  This happens if:
		//
		// - the user explicitly binds their socket to the wrong source IP accidentally
		// - the user sends traffic to, for example, a Kubernetes service IP, which is
		//   implemented via NAT instead of routing, leading the kernel to choose the
		//   wrong source IP.
		//
		// We NAT the source of the packet to use the tunnel IP.  We assume that
		// non-local IPs have been correctly routed.  Since Calico-assigned IPs are
		// non-local (because they're down a veth), they won't get caught by the rule.
		// Other remote sources will only reach the tunnel if they're being NATted
		// already (for example, a Kubernetes "NodePort").  The kernel will then
		// choose the correct source on its own.
		rules = append(rules, Rule{
			Match: Match().
				// Only match packets going out the tunnel.
				OutInterface("tunl0").
				// Match packets that don't have the correct source address.  This
				// matches local addresses (i.e. ones assigned to this host)
				// limiting the match to the output interface (which we matched
				// above as the tunnel).  Avoiding embedding the IP address lets
				// us use a static rule, which is easier to manage.
				NotSrcAddrType(AddrTypeLocal, true).
				// Only match if the IP is also some local IP on the box.  This
				// prevents us from matching packets from workloads, which are
				// remote as far as the routing table is concerned.
				SrcAddrType(AddrTypeLocal, false),
			Action: MasqAction{},
		})
	}
	return []*Chain{{
		Name:  NATPostroutingChainName,
		Rules: rules,
	}}
}

func (t ruleRenderer) DropRules(matchCriteria MatchCriteria, comments ...string) []Rule {
	return []Rule{
		{
			Match:   matchCriteria,
			Action:  DropAction{},
			Comment: strings.Join(comments, "; "),
		},
	}
}
