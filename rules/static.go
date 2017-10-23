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

package rules

import (
	log "github.com/sirupsen/logrus"

	. "github.com/projectcalico/felix/iptables"
)

func (r *DefaultRuleRenderer) StaticFilterTableChains(ipVersion uint8) (chains []*Chain) {
	chains = append(chains, r.StaticFilterForwardChains()...)
	chains = append(chains, r.StaticFilterInputChains(ipVersion)...)
	chains = append(chains, r.StaticFilterOutputChains()...)
	return
}

const (
	ProtoIPIP   = 4
	ProtoICMPv6 = 58
)

func (r *DefaultRuleRenderer) StaticFilterInputChains(ipVersion uint8) []*Chain {
	return []*Chain{
		r.filterInputChain(ipVersion),
		r.filterWorkloadToHostChain(ipVersion),
		r.failsafeInChain(),
	}
}

func (r *DefaultRuleRenderer) acceptAlreadyAccepted() []Rule {
	return []Rule{
		{
			Match:  Match().MarkSet(r.IptablesMarkAccept),
			Action: AcceptAction{},
		},
	}
}

func (r *DefaultRuleRenderer) filterInputChain(ipVersion uint8) *Chain {
	var inputRules []Rule

	// Accept immediately if we've already accepted this packet in the raw or mangle table.
	inputRules = append(inputRules, r.acceptAlreadyAccepted()...)

	if ipVersion == 4 && r.IPIPEnabled {
		// IPIP is enabled, filter incoming IPIP packets to ensure they come from a
		// recognised host.  We use the protocol number rather than its name because the
		// name is not guaranteed to be known by the kernel.
		match := Match().ProtocolNum(ProtoIPIP).
			NotSourceIPSet(r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllHostIPs))
		inputRules = append(inputRules, Rule{
			Match:   match,
			Action:  DropAction{},
			Comment: "Drop IPIP packets from non-Calico hosts",
		})
	}

	// Apply our policy to packets coming from workload endpoints.
	for _, prefix := range r.WorkloadIfacePrefixes {
		log.WithField("ifacePrefix", prefix).Debug("Adding workload match rules")
		ifaceMatch := prefix + "+"
		inputRules = append(inputRules, Rule{
			Match:  Match().InInterface(ifaceMatch),
			Action: GotoAction{Target: ChainWorkloadToHost},
		})
	}

	// Apply host endpoint policy.
	inputRules = append(inputRules,
		Rule{
			Action: ClearMarkAction{Mark: r.allCalicoMarkBits()},
		},
		Rule{
			Action: JumpAction{Target: ChainDispatchFromHostEndpoint},
		},
		Rule{
			Match:   Match().MarkSet(r.IptablesMarkAccept),
			Action:  r.filterAllowAction,
			Comment: "Host endpoint policy accepted packet.",
		},
	)

	return &Chain{
		Name:  ChainFilterInput,
		Rules: inputRules,
	}
}

func (r *DefaultRuleRenderer) filterWorkloadToHostChain(ipVersion uint8) *Chain {
	var rules []Rule

	// For IPv6, we need to white-list certain ICMP traffic from workloads in order to to act
	// as a router.  Note: we do this before the policy chains, so we're bypassing the egress
	// rules for this traffic.  While that might be unexpected, it makes sure that the user
	// doesn't cut off their own connectivity in subtle ways that they shouldn't have to worry
	// about.
	//
	// - 130: multicast listener query.
	// - 131: multicast listener report.
	// - 132: multicast listener done.
	// - 133: router solicitation, which an endpoint uses to request
	//        configuration information rather than waiting for an
	//        unsolicited router advertisement.
	// - 135: neighbor solicitation.
	// - 136: neighbor advertisement.
	if ipVersion == 6 {
		for _, icmpType := range []uint8{130, 131, 132, 133, 135, 136} {
			rules = append(rules, Rule{
				Match: Match().
					ProtocolNum(ProtoICMPv6).
					ICMPV6Type(icmpType),
				Action: AcceptAction{},
			})
		}
	}

	if r.OpenStackSpecialCasesEnabled {
		log.Info("Adding OpenStack special-case rules.")
		if ipVersion == 4 && r.OpenStackMetadataIP != nil {
			// For OpenStack compatibility, we support a special-case to allow incoming traffic
			// to the OpenStack metadata IP/port.
			// TODO(smc) Long-term, it'd be nice if the OpenStack plugin programmed a policy to
			// do this instead.
			log.WithField("ip", r.OpenStackMetadataIP).Info(
				"OpenStack metadata IP specified, installing whitelist rule.")
			rules = append(rules, Rule{
				Match: Match().
					Protocol("tcp").
					DestNet(r.OpenStackMetadataIP.String()).
					DestPorts(r.OpenStackMetadataPort),
				Action: AcceptAction{},
			})
		}

		// Again, for OpenStack compatibility, white-list certain protocols.
		// TODO(smc) Long-term, it'd be nice if the OpenStack plugin programmed a policy to
		// do this instead.
		dhcpSrcPort := uint16(68)
		dhcpDestPort := uint16(67)
		if ipVersion == 6 {
			dhcpSrcPort = uint16(546)
			dhcpDestPort = uint16(547)
		}
		dnsDestPort := uint16(53)
		rules = append(rules,
			Rule{
				Match: Match().
					Protocol("udp").
					SourcePorts(dhcpSrcPort).
					DestPorts(dhcpDestPort),
				Action: AcceptAction{},
			},
			Rule{
				Match: Match().
					Protocol("udp").
					DestPorts(dnsDestPort),
				Action: AcceptAction{},
			},
		)
	}

	// Now send traffic to the policy chains to apply the egress policy.
	rules = append(rules, Rule{
		Action: JumpAction{Target: ChainFromWorkloadDispatch},
	})

	// If the dispatch chain accepts the packet, it returns to us here.  Apply the configured
	// action.  Note: we may have done work above to allow the packet and then end up dropping
	// it here.  We can't optimize that away because there may be other rules (such as log
	// rules in the policy).
	for _, action := range r.inputAcceptActions {
		rules = append(rules, Rule{
			Action:  action,
			Comment: "Configured DefaultEndpointToHostAction",
		})
	}

	return &Chain{
		Name:  ChainWorkloadToHost,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) failsafeInChain() *Chain {
	rules := []Rule{}

	for _, protoPort := range r.Config.FailsafeInboundHostPorts {
		rules = append(rules, Rule{
			Match: Match().
				Protocol(protoPort.Protocol).
				DestPorts(protoPort.Port),
			Action: AcceptAction{},
		})
	}

	return &Chain{
		Name:  ChainFailsafeIn,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) failsafeOutChain() *Chain {
	rules := []Rule{}

	for _, protoPort := range r.Config.FailsafeOutboundHostPorts {
		rules = append(rules, Rule{
			Match: Match().
				Protocol(protoPort.Protocol).
				DestPorts(protoPort.Port),
			Action: AcceptAction{},
		})
	}

	return &Chain{
		Name:  ChainFailsafeOut,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) StaticFilterForwardChains() []*Chain {
	rules := []Rule{}

	// Rules for filter forward chains dispatches the packet to our dispatch chains if it is going
	// to/from an interface that we're responsible for.  Note: the dispatch chains represent "allow"
	// by returning to this chain for further processing; this is required to handle traffic that
	// is going between endpoints on the same host.  In that case we need to apply the egress policy
	// for one endpoint and the ingress policy for the other.
	//
	// Packets will be accepted if they passed through both workload and host endpoint policy
	// and were returned.

	// Jump to from-host-endpoint dispatch chains.
	rules = append(rules,
		Rule{
			// we're clearing all our mark bits to minimise non-determinism caused by rules in other chains.
			// We exclude the accept bit because we use that to communicate from the raw/pre-dnat chains.
			Action: ClearMarkAction{Mark: r.allCalicoMarkBits() &^ r.IptablesMarkAccept},
		},
		Rule{
			// Apply forward policy for the incoming Host endpoint if accept bit is clear which means the packet
			// was not accepted in a previous raw or pre-DNAT chain.
			Match:  Match().MarkClear(r.IptablesMarkAccept),
			Action: JumpAction{Target: ChainDispatchFromHostEndPointForward},
		},
	)

	// Jump to workload dispatch chains.
	for _, prefix := range r.WorkloadIfacePrefixes {
		log.WithField("ifacePrefix", prefix).Debug("Adding workload match rules")
		ifaceMatch := prefix + "+"
		rules = append(rules,
			Rule{
				Match:  Match().InInterface(ifaceMatch),
				Action: JumpAction{Target: ChainFromWorkloadDispatch},
			},
			Rule{
				Match:  Match().OutInterface(ifaceMatch),
				Action: JumpAction{Target: ChainToWorkloadDispatch},
			},
		)
	}

	// Jump to to-host-endpoint dispatch chains.
	rules = append(rules,
		Rule{
			// Apply forward policy for the outgoing host endpoint.
			Action: JumpAction{Target: ChainDispatchToHostEndpointForward},
		},
	)

	// Accept packet if policies above set ACCEPT mark.
	rules = append(rules,
		Rule{
			Match:   Match().MarkSet(r.IptablesMarkAccept),
			Action:  r.filterAllowAction,
			Comment: "Policy explicitly accepted packet.",
		},
	)

	return []*Chain{{
		Name:  ChainFilterForward,
		Rules: rules,
	}}
}

func (r *DefaultRuleRenderer) StaticFilterOutputChains() []*Chain {
	return []*Chain{
		r.filterOutputChain(),
		r.failsafeOutChain(),
	}
}

func (r *DefaultRuleRenderer) filterOutputChain() *Chain {
	rules := []Rule{}

	// Accept immediately if we've already accepted this packet in the raw or mangle table.
	rules = append(rules, r.acceptAlreadyAccepted()...)

	// We don't currently police host -> endpoint according to the endpoint's ingress policy.
	// That decision is based on pragmatism; it's generally very useful to be able to contact
	// any local workload from the host and policing the traffic doesn't really protect
	// against host compromise.  If a host is compromised, then the rules could be removed!
	// However, we do apply policy to workload ingress traffic if it belongs to an IPVS connection.
	for _, prefix := range r.WorkloadIfacePrefixes {
		// If the packet is going to a workload endpoint, apply workload ingress policy if traffic
		// belongs to an IPVS connection and return at the end.
		log.WithField("ifacePrefix", prefix).Debug("Adding workload match rules")
		ifaceMatch := prefix + "+"
		rules = append(rules,
			Rule{
				Match:  Match().OutInterface(ifaceMatch).IPVSConnection(),
				Action: JumpAction{Target: ChainToWorkloadDispatch},
			},
			Rule{
				Match:  Match().OutInterface(ifaceMatch),
				Action: ReturnAction{},
			},
		)
	}

	// If we reach here, the packet is not going to a workload so it must be going to a
	// host endpoint.

	// Apply host endpoint policy.
	rules = append(rules,
		Rule{
			Action: ClearMarkAction{Mark: r.allCalicoMarkBits()},
		},
		Rule{
			Action: JumpAction{Target: ChainDispatchToHostEndpoint},
		},
		Rule{
			Match:   Match().MarkSet(r.IptablesMarkAccept),
			Action:  r.filterAllowAction,
			Comment: "Host endpoint policy accepted packet.",
		},
	)

	return &Chain{
		Name:  ChainFilterOutput,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) StaticNATTableChains(ipVersion uint8) (chains []*Chain) {
	chains = append(chains, r.StaticNATPreroutingChains(ipVersion)...)
	chains = append(chains, r.StaticNATPostroutingChains(ipVersion)...)
	chains = append(chains, r.StaticNATOutputChains(ipVersion)...)
	return
}

func (r *DefaultRuleRenderer) StaticNATPreroutingChains(ipVersion uint8) []*Chain {
	rules := []Rule{
		{
			Action: JumpAction{Target: ChainFIPDnat},
		},
	}

	if ipVersion == 4 && r.OpenStackSpecialCasesEnabled && r.OpenStackMetadataIP != nil {
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
		Name:  ChainNATPrerouting,
		Rules: rules,
	}}
}

func (r *DefaultRuleRenderer) StaticNATPostroutingChains(ipVersion uint8) []*Chain {
	rules := []Rule{
		{
			Action: JumpAction{Target: ChainFIPSnat},
		},
		{
			Action: JumpAction{Target: ChainNATOutgoing},
		},
	}
	if ipVersion == 4 && r.IPIPEnabled && len(r.IPIPTunnelAddress) > 0 {
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
		Name:  ChainNATPostrouting,
		Rules: rules,
	}}
}

func (r *DefaultRuleRenderer) StaticNATOutputChains(ipVersion uint8) []*Chain {
	rules := []Rule{
		{
			Action: JumpAction{Target: ChainFIPDnat},
		},
	}

	return []*Chain{{
		Name:  ChainNATOutput,
		Rules: rules,
	}}
}

func (r *DefaultRuleRenderer) StaticMangleTableChains(ipVersion uint8) (chains []*Chain) {
	return []*Chain{
		r.failsafeInChain(),
		r.StaticManglePreroutingChain(ipVersion),
	}
}

func (r *DefaultRuleRenderer) StaticManglePreroutingChain(ipVersion uint8) *Chain {
	rules := []Rule{}

	// ACCEPT or RETURN immediately if packet matches an existing connection.  Note that we also
	// have a rule like this at the start of each pre-endpoint chain; the functional difference
	// with placing this rule here is that it will also apply to packets that may be unrelated
	// to Calico (i.e. not to or from Calico workloads, and not via Calico host endpoints).  We
	// think this is appropriate in the mangle table here - whereas we don't have a rule like
	// this in the filter table - because the mangle table is generally not used (except by us)
	// for dropping packets, so it is very unlikely that we would be circumventing someone
	// else's rule to drop a packet.  (And in that case, the user can configure
	// IptablesMangleAllowAction to be RETURN.)
	rules = append(rules,
		Rule{
			Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
			Action: r.mangleAllowAction,
		},
	)

	// Or if we've already accepted this packet in the raw table.
	rules = append(rules,
		Rule{
			Match:  Match().MarkSet(r.IptablesMarkAccept),
			Action: r.mangleAllowAction,
		},
	)

	// If packet is from a workload interface, ACCEPT or RETURN immediately according to
	// IptablesMangleAllowAction (because pre-DNAT policy is only for host endpoints).
	for _, ifacePrefix := range r.WorkloadIfacePrefixes {
		rules = append(rules, Rule{
			Match:  Match().InInterface(ifacePrefix + "+"),
			Action: r.mangleAllowAction,
		})
	}

	// Now (=> not from a workload) dispatch to host endpoint chain for the incoming interface.
	rules = append(rules,
		Rule{
			Action: JumpAction{Target: ChainDispatchFromHostEndpoint},
		},
		// Following that...  If the packet was explicitly allowed by a pre-DNAT policy, it
		// will have MarkAccept set.  If the packet was denied, it will have been dropped
		// already.  If the incoming interface isn't one that we're policing, or the packet
		// isn't governed by any pre-DNAT policy on that interface, it will fall through to
		// here without any Calico bits set.

		// In the MarkAccept case, we ACCEPT or RETURN according to
		// IptablesMangleAllowAction.
		Rule{
			Match:   Match().MarkSet(r.IptablesMarkAccept),
			Action:  r.mangleAllowAction,
			Comment: "Host endpoint policy accepted packet.",
		},
	)

	return &Chain{
		Name:  ChainManglePrerouting,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) StaticRawTableChains(ipVersion uint8) []*Chain {
	return []*Chain{
		r.failsafeInChain(),
		r.failsafeOutChain(),
		r.StaticRawPreroutingChain(ipVersion),
		r.StaticRawOutputChain(),
	}
}

func (r *DefaultRuleRenderer) StaticRawPreroutingChain(ipVersion uint8) *Chain {
	rules := []Rule{}

	// For safety, clear all our mark bits before we start.  (We could be in append mode and
	// another process' rules could have left the mark bit set.)
	rules = append(rules,
		Rule{Action: ClearMarkAction{Mark: r.allCalicoMarkBits()}},
	)

	// Set a mark on the packet if it's from a workload interface.
	markFromWorkload := r.IptablesMarkScratch0
	for _, ifacePrefix := range r.WorkloadIfacePrefixes {
		rules = append(rules, Rule{
			Match:  Match().InInterface(ifacePrefix + "+"),
			Action: SetMarkAction{Mark: markFromWorkload},
		})
	}

	if ipVersion == 6 {
		// Apply strict RPF check to packets from workload interfaces.  This prevents
		// workloads from spoofing their IPs.  Note: non-privileged containers can't
		// usually spoof but privileged containers and VMs can.
		//
		// We only do this for IPv6 because the IPv4 RPF check is handled via a sysctl.
		// In addition, the IPv4 check is complicated by the fact that we have special
		// case handling for DHCP to the host, which would require an exclusion.
		rules = append(rules, Rule{
			Match:  Match().MarkSet(markFromWorkload).RPFCheckFailed(),
			Action: DropAction{},
		})
	}

	rules = append(rules,
		// Send non-workload traffic to the untracked policy chains.
		Rule{Match: Match().MarkClear(markFromWorkload),
			Action: JumpAction{Target: ChainDispatchFromHostEndpoint}},
		// Then, if the packet was marked as allowed, accept it.  Packets also return here
		// without the mark bit set if the interface wasn't one that we're policing.  We
		// let those packets fall through to the user's policy.
		Rule{Match: Match().MarkSet(r.IptablesMarkAccept),
			Action: AcceptAction{}},
	)

	return &Chain{
		Name:  ChainRawPrerouting,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) allCalicoMarkBits() uint32 {
	return r.IptablesMarkAccept |
		r.IptablesMarkPass |
		r.IptablesMarkScratch0 |
		r.IptablesMarkScratch1
}

func (r *DefaultRuleRenderer) StaticRawOutputChain() *Chain {
	return &Chain{
		Name: ChainRawOutput,
		Rules: []Rule{
			// For safety, clear all our mark bits before we start.  (We could be in
			// append mode and another process' rules could have left the mark bit set.)
			{Action: ClearMarkAction{Mark: r.allCalicoMarkBits()}},
			// Then, jump to the untracked policy chains.
			{Action: JumpAction{Target: ChainDispatchToHostEndpoint}},
			// Then, if the packet was marked as allowed, accept it.  Packets also
			// return here without the mark bit set if the interface wasn't one that
			// we're policing.
			{Match: Match().MarkSet(r.IptablesMarkAccept),
				Action: AcceptAction{}},
		},
	}
}
