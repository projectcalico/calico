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

package rules

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	. "github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/proto"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

func (r *DefaultRuleRenderer) StaticFilterTableChains(ipVersion uint8) (chains []*Chain) {
	chains = append(chains, r.StaticFilterForwardChains()...)
	chains = append(chains, r.StaticFilterInputChains(ipVersion)...)
	chains = append(chains, r.StaticFilterOutputChains(ipVersion)...)
	return
}

const (
	ProtoIPIP   = 4
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
)

func (r *DefaultRuleRenderer) StaticFilterInputChains(ipVersion uint8) []*Chain {
	result := []*Chain{}
	result = append(result,
		r.filterInputChain(ipVersion),
		r.filterWorkloadToHostChain(ipVersion),
		r.failsafeInChain("filter", ipVersion),
	)
	if r.KubeIPVSSupportEnabled {
		result = append(result, r.StaticFilterInputForwardCheckChain(ipVersion))
	}
	return result
}

func (r *DefaultRuleRenderer) acceptAlreadyAccepted() []Rule {
	return []Rule{
		{
			Match:  Match().MarkSingleBitSet(r.IptablesMarkAccept),
			Action: r.filterAllowAction,
		},
	}
}

// Forward check chain is to check if a packet belongs to a forwarded traffic or not.
// With kube-proxy running in ipvs mode, both local or forwarded traffic goes through INPUT filter chain.
func (r *DefaultRuleRenderer) StaticFilterInputForwardCheckChain(ipVersion uint8) *Chain {
	var fwRules []Rule
	var portRanges []*proto.PortRange

	// Assembly port ranges for kubernetes node ports.
	for _, portRange := range r.KubeNodePortRanges {
		pr := &proto.PortRange{
			First: int32(portRange.MinPort),
			Last:  int32(portRange.MaxPort),
		}
		portRanges = append(portRanges, pr)
	}

	// Get ipsets name for local host ips.
	nameForIPSet := func(ipsetID string) string {
		if ipVersion == 4 {
			return r.IPSetConfigV4.NameForMainIPSet(ipsetID)
		} else {
			return r.IPSetConfigV6.NameForMainIPSet(ipsetID)
		}
	}
	hostIPSet := nameForIPSet(IPSetIDThisHostIPs)

	fwRules = append(fwRules,
		// If packet belongs to an existing conntrack connection, it does not belong to a forwarded traffic even destination ip is a
		// service ip. This could happen when pod send back response to a local host process accessing a service ip.
		Rule{
			Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
			Action: ReturnAction{},
		},
	)

	// If packet is accessing local host within kubernetes NodePort range, it belongs to a forwarded traffic.
	for _, portSplit := range SplitPortList(portRanges) {
		fwRules = append(fwRules,
			Rule{
				Match: Match().Protocol("tcp").
					DestPortRanges(portSplit).
					DestIPSet(hostIPSet),
				Action:  GotoAction{Target: ChainDispatchSetEndPointMark},
				Comment: []string{"To kubernetes NodePort service"},
			},
			Rule{
				Match: Match().Protocol("udp").
					DestPortRanges(portSplit).
					DestIPSet(hostIPSet),
				Action:  GotoAction{Target: ChainDispatchSetEndPointMark},
				Comment: []string{"To kubernetes NodePort service"},
			},
		)
	}

	fwRules = append(fwRules,
		// If packet is accessing non local host ip, it belongs to a forwarded traffic.
		Rule{
			Match:   Match().NotDestIPSet(hostIPSet),
			Action:  JumpAction{Target: ChainDispatchSetEndPointMark},
			Comment: []string{"To kubernetes service"},
		},
	)

	return &Chain{
		Name:  ChainForwardCheck,
		Rules: fwRules,
	}
}

// With kube-proxy running in ipvs mode, we categorise traffic going through OUTPUT chain into three classes.
// Class 1. forwarded packet originated from a calico workload or host endpoint --> INPUT filter --> OUTPUT filter
// Class 2. forwarded packet originated from a non calico endpoint              --> INPUT filter --> OUTPUT filter
// Class 3. local process originated packet --> OUTPUT filter
// This function handles traffic in Class 1 and Class 2.
func (r *DefaultRuleRenderer) StaticFilterOutputForwardEndpointMarkChain() *Chain {
	var fwRules []Rule

	fwRules = append(fwRules,
		// Only packets that we know are really being forwarded reach this chain. However, since
		// we're called from the OUTPUT chain, we're forbidden from using the input interface match.
		// Instead, we rely on the INPUT chain to mark the packet with a per-endpoint mark value
		// and do our dispatch on that mark value.  So that we don't touch "Class 2" packets, we
		// mark them with mark pattern IptablesMarkNonCaliEndpoint and exclude them here.  This
		// prevents the default drop at the end of the dispatch chain from dropping non-Calico
		// traffic.
		Rule{
			Match:  Match().NotMarkMatchesWithMask(r.IptablesMarkNonCaliEndpoint, r.IptablesMarkEndpoint),
			Action: JumpAction{Target: ChainDispatchFromEndPointMark},
		},
	)

	// The packet may be going to a workload interface.  Send any such packets to the normal,
	// interface-name-based dispatch chains.
	for _, prefix := range r.WorkloadIfacePrefixes {
		log.WithField("ifacePrefix", prefix).Debug("Adding workload match rules")
		ifaceMatch := prefix + "+"
		fwRules = append(fwRules,
			Rule{
				Match:  Match().OutInterface(ifaceMatch),
				Action: JumpAction{Target: ChainToWorkloadDispatch},
			},
		)
	}

	fwRules = append(fwRules,
		// The packet may be going to a host endpoint, send it to the host endpoint
		// apply-on-forward dispatch chain. That chain returns any packets that are not going to a
		// known host endpoint for further processing.
		Rule{
			Action: JumpAction{Target: ChainDispatchToHostEndpointForward},
		},

		// Before we ACCEPT the packet, clear the per-interface mark bit.  This is required because
		// the packet may get encapsulated and pass through iptables again.  Since the new encapped
		// packet would inherit the mark bits, it would be (incorrectly) treated as a forwarded
		// packet.
		Rule{
			Action: ClearMarkAction{Mark: r.IptablesMarkEndpoint},
		},

		// If a packet reaches here, one of the following must be true:
		//
		// - it is going to a workload endpoint and it has passed that endpoint's policy
		// - it is going to a host interface with a Calico host endpoint and it has passed that
		//   endpoint's policy
		// - it is going to a host interface with no Calico host endpoint.
		//
		// In the first two cases, the policy will have set the accept bit in the mark and we "own"
		// the packet so it's right for us to ACCEPT it here (unless configured otherwise).  In
		// the other case, we don't own the packet so we always return it to the OUTPUT chain
		// for further processing.
		Rule{
			Match:   Match().MarkSingleBitSet(r.IptablesMarkAccept),
			Action:  r.filterAllowAction,
			Comment: []string{"Policy explicitly accepted packet."},
		},
	)

	return &Chain{
		Name:  ChainForwardEndpointMark,
		Rules: fwRules,
	}
}

func (r *DefaultRuleRenderer) filterInputChain(ipVersion uint8) *Chain {
	var inputRules []Rule

	if ipVersion == 4 && r.IPIPEnabled {
		// IPIP is enabled, filter incoming IPIP packets to ensure they come from a
		// recognised host and are going to a local address on the host.  We use the protocol
		// number rather than its name because the name is not guaranteed to be known by the kernel.
		inputRules = append(inputRules,
			Rule{
				Match: Match().ProtocolNum(ProtoIPIP).
					SourceIPSet(r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllHostNets)).
					DestAddrType(AddrTypeLocal),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow IPIP packets from Calico hosts"},
			},
			Rule{
				Match:   Match().ProtocolNum(ProtoIPIP),
				Action:  DropAction{},
				Comment: []string{"Drop IPIP packets from non-Calico hosts"},
			},
		)
	}

	if ipVersion == 4 && r.VXLANEnabled {
		// IPv4 VXLAN is enabled, filter incoming VXLAN packets that match our VXLAN port to ensure they
		// come from a recognised host and are going to a local address on the host.
		inputRules = append(inputRules,
			Rule{
				Match: Match().ProtocolNum(ProtoUDP).
					DestPorts(uint16(r.Config.VXLANPort)).
					SourceIPSet(r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllVXLANSourceNets)).
					DestAddrType(AddrTypeLocal),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow IPv4 VXLAN packets from whitelisted hosts"},
			},
			Rule{
				Match: Match().ProtocolNum(ProtoUDP).
					DestPorts(uint16(r.Config.VXLANPort)).
					DestAddrType(AddrTypeLocal),
				Action:  DropAction{},
				Comment: []string{"Drop IPv4 VXLAN packets from non-whitelisted hosts"},
			},
		)
	}

	if ipVersion == 6 && r.VXLANEnabledV6 {
		// IPv6 VXLAN is enabled, filter incoming VXLAN packets that match our VXLAN port to ensure they
		// come from a recognised host and are going to a local address on the host.
		inputRules = append(inputRules,
			Rule{
				Match: Match().ProtocolNum(ProtoUDP).
					DestPorts(uint16(r.Config.VXLANPort)).
					SourceIPSet(r.IPSetConfigV6.NameForMainIPSet(IPSetIDAllVXLANSourceNets)).
					DestAddrType(AddrTypeLocal),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow IPv6 VXLAN packets from whitelisted hosts"},
			},
			Rule{
				Match: Match().ProtocolNum(ProtoUDP).
					DestPorts(uint16(r.Config.VXLANPort)).
					DestAddrType(AddrTypeLocal),
				Action:  DropAction{},
				Comment: []string{"Drop IPv6 VXLAN packets from non-whitelisted hosts"},
			},
		)
	}

	if (ipVersion == 4 && r.WireguardEnabled) || (ipVersion == 6 && r.WireguardEnabledV6) {
		// When Wireguard is enabled, auto-allow Wireguard traffic from other nodes.  Without this,
		// it's too easy to make a host policy that blocks Wireguard traffic, resulting in very confusing
		// connectivity problems.
		inputRules = append(inputRules,
			Rule{
				Match: Match().ProtocolNum(ProtoUDP).
					DestPorts(uint16(r.Config.WireguardListeningPort)).
					DestAddrType(AddrTypeLocal),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow incoming Wireguard packets"},
			},
			// Note that we do not need a drop rule for Wireguard because it already has the peering and allowed IPs
			// baked into the crypto routing table.
		)
	}

	if r.KubeIPVSSupportEnabled {
		// Check if packet belongs to forwarded traffic. (e.g. part of an ipvs connection).
		// If it is, set endpoint mark and skip "to local host" rules below.
		inputRules = append(inputRules,
			Rule{
				Action: ClearMarkAction{Mark: r.IptablesMarkEndpoint},
			},
			Rule{
				Action: JumpAction{Target: ChainForwardCheck},
			},
			Rule{
				Match:  Match().MarkNotClear(r.IptablesMarkEndpoint),
				Action: ReturnAction{},
			},
		)
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

	// Now we only have ingress host endpoint processing to do.  The ingress host endpoint may
	// have already accepted this packet in the raw or mangle table.  In that case, accept the
	// packet immediately here too.
	inputRules = append(inputRules, r.acceptAlreadyAccepted()...)

	// Apply host endpoint policy.
	inputRules = append(inputRules,
		Rule{
			Action: ClearMarkAction{Mark: r.allCalicoMarkBits()},
		},
		Rule{
			Action: JumpAction{Target: ChainDispatchFromHostEndpoint},
		},
		Rule{
			Match:   Match().MarkSingleBitSet(r.IptablesMarkAccept),
			Action:  r.filterAllowAction,
			Comment: []string{"Host endpoint policy accepted packet."},
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
				Action: r.filterAllowAction,
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
				Action: r.filterAllowAction,
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
				Action: r.filterAllowAction,
			},
			Rule{
				Match: Match().
					Protocol("udp").
					DestPorts(dnsDestPort),
				Action: r.filterAllowAction,
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
			Comment: []string{"Configured DefaultEndpointToHostAction"},
		})
	}

	return &Chain{
		Name:  ChainWorkloadToHost,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) failsafeInChain(table string, ipVersion uint8) *Chain {
	rules := []Rule{}

	for _, protoPort := range r.Config.FailsafeInboundHostPorts {
		rule := Rule{
			Match: Match().
				Protocol(protoPort.Protocol).
				DestPorts(protoPort.Port),
			Action: AcceptAction{},
		}

		if protoPort.Net != "" {
			ip, _, err := cnet.ParseCIDROrIP(protoPort.Net)
			if err != nil {
				log.WithError(err).Error("Failed to parse CIDR in inbound failsafe rule. Skipping failsafe rule")
				continue
			}
			if int(ipVersion) == ip.Version() {
				rule.Match = Match().
					Protocol(protoPort.Protocol).
					DestPorts(protoPort.Port).
					SourceNet(protoPort.Net)
			}
		}
		rules = append(rules, rule)
	}

	if table == "raw" {
		// We're in the raw table, before conntrack, so we need to whitelist response traffic.
		// Otherwise, it could fall through to some doNotTrack policy and half of the connection
		// would get untracked.  If we ACCEPT here then the traffic falls through to the filter
		// table, where it'll only be accepted if there's a conntrack entry.
		for _, protoPort := range r.Config.FailsafeOutboundHostPorts {
			rule := Rule{
				Match: Match().
					Protocol(protoPort.Protocol).
					SourcePorts(protoPort.Port),
				Action: AcceptAction{},
			}

			if protoPort.Net != "" {
				ip, _, err := cnet.ParseCIDROrIP(protoPort.Net)
				if err != nil {
					log.WithError(err).Error("Failed to parse CIDR in inbound failsafe rule. Skipping failsafe rule")
					continue
				}
				if int(ipVersion) == ip.Version() {
					rule.Match = Match().
						Protocol(protoPort.Protocol).
						SourcePorts(protoPort.Port).
						SourceNet(protoPort.Net)
				}
			}
			rules = append(rules, rule)
		}
	}

	return &Chain{
		Name:  ChainFailsafeIn,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) failsafeOutChain(table string, ipVersion uint8) *Chain {
	rules := []Rule{}

	for _, protoPort := range r.Config.FailsafeOutboundHostPorts {
		rule := Rule{
			Match: Match().
				Protocol(protoPort.Protocol).
				DestPorts(protoPort.Port),
			Action: AcceptAction{},
		}

		if protoPort.Net != "" {
			ip, _, err := cnet.ParseCIDROrIP(protoPort.Net)
			if err != nil {
				log.WithError(err).Error("Failed to parse CIDR in outbound failsafe rule. Skipping failsafe rule")
				continue
			}
			if int(ipVersion) == ip.Version() {
				rule.Match = Match().
					Protocol(protoPort.Protocol).
					DestPorts(protoPort.Port).
					DestNet(protoPort.Net)
			}
		}
		rules = append(rules, rule)
	}

	if table == "raw" {
		// We're in the raw table, before conntrack, so we need to whitelist response traffic.
		// Otherwise, it could fall through to some doNotTrack policy and half of the connection
		// would get untracked.  If we ACCEPT here then the traffic falls through to the filter
		// table, where it'll only be accepted if there's a conntrack entry.
		for _, protoPort := range r.Config.FailsafeInboundHostPorts {
			rule := Rule{
				Match: Match().
					Protocol(protoPort.Protocol).
					SourcePorts(protoPort.Port),
				Action: AcceptAction{},
			}

			if protoPort.Net != "" {
				ip, _, err := cnet.ParseCIDROrIP(protoPort.Net)
				if err != nil {
					log.WithError(err).Error("Failed to parse CIDR in outbound failsafe rule. Skipping failsafe rule")
					continue
				}
				if int(ipVersion) == ip.Version() {
					rule.Match = Match().
						Protocol(protoPort.Protocol).
						SourcePorts(protoPort.Port).
						SourceNet(protoPort.Net)
				}
			}
			rules = append(rules, rule)
		}
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

	// Jump to chain for blocking service CIDR loops.
	rules = append(rules,
		Rule{
			Action: JumpAction{Target: ChainCIDRBlock},
		},
	)

	return []*Chain{{
		Name:  ChainFilterForward,
		Rules: rules,
	}}
}

// StaticFilterForwardAppendRules returns rules which should be statically appended to the end of the filter
// table's forward chain.
func (r *DefaultRuleRenderer) StaticFilterForwardAppendRules() []Rule {
	return []Rule{
		{
			Match:   Match().MarkSingleBitSet(r.IptablesMarkAccept),
			Action:  r.filterAllowAction,
			Comment: []string{"Policy explicitly accepted packet."},
		},

		// Set IptablesMarkAccept bit here, to indicate to our mangle-POSTROUTING chain that this is
		// forwarded traffic and should not be subject to normal host endpoint policy.
		{
			Action: SetMarkAction{Mark: r.IptablesMarkAccept},
		},
	}
}

func (r *DefaultRuleRenderer) StaticFilterOutputChains(ipVersion uint8) []*Chain {
	result := []*Chain{}
	result = append(result,
		r.filterOutputChain(ipVersion),
		r.failsafeOutChain("filter", ipVersion),
	)

	if r.KubeIPVSSupportEnabled {
		result = append(result, r.StaticFilterOutputForwardEndpointMarkChain())
	}

	return result
}

func (r *DefaultRuleRenderer) filterOutputChain(ipVersion uint8) *Chain {
	var rules []Rule

	// Accept immediately if we've already accepted this packet in the raw or mangle table.
	rules = append(rules, r.acceptAlreadyAccepted()...)

	if r.KubeIPVSSupportEnabled {
		// Special case: packets that are forwarded through IPVS hit the INPUT and OUTPUT chains
		// instead of FORWARD.  In the INPUT chain, we mark such packets with a per-interface ID.
		// Divert those packets to a chain that handles them as we would if they had hit the FORWARD
		// chain.
		//
		// We use a goto so that a RETURN from that chain will skip the rest of this chain
		// and continue execution in the parent chain (OUTPUT).
		rules = append(rules,
			Rule{
				Match:  Match().MarkNotClear(r.IptablesMarkEndpoint),
				Action: GotoAction{Target: ChainForwardEndpointMark},
			},
		)
	}

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
				// if packet goes to a workload endpoint. set return action properly.
				Match:  Match().OutInterface(ifaceMatch),
				Action: ReturnAction{},
			},
		)
	}

	// If we reach here, the packet is not going to a workload so it must be going to a
	// host endpoint. It also has no endpoint mark so it must be going from a process.

	if ipVersion == 4 && r.IPIPEnabled {
		// When IPIP is enabled, auto-allow IPIP traffic to other Calico nodes.  Without this,
		// it's too easy to make a host policy that blocks IPIP traffic, resulting in very confusing
		// connectivity problems.
		rules = append(rules,
			Rule{
				Match: Match().ProtocolNum(ProtoIPIP).
					DestIPSet(r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllHostNets)).
					SrcAddrType(AddrTypeLocal, false),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow IPIP packets to other Calico hosts"},
			},
		)
	}

	if ipVersion == 4 && r.VXLANEnabled {
		// When IPv4 VXLAN is enabled, auto-allow VXLAN traffic to other Calico nodes.  Without this,
		// it's too easy to make a host policy that blocks VXLAN traffic, resulting in very confusing
		// connectivity problems.
		rules = append(rules,
			Rule{
				Match: Match().ProtocolNum(ProtoUDP).
					DestPorts(uint16(r.Config.VXLANPort)).
					SrcAddrType(AddrTypeLocal, false).
					DestIPSet(r.IPSetConfigV4.NameForMainIPSet(IPSetIDAllVXLANSourceNets)),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow IPv4 VXLAN packets to other whitelisted hosts"},
			},
		)
	}

	if ipVersion == 6 && r.VXLANEnabledV6 {
		// When IPv6 VXLAN is enabled, auto-allow VXLAN traffic to other Calico nodes.  Without this,
		// it's too easy to make a host policy that blocks VXLAN traffic, resulting in very confusing
		// connectivity problems.
		rules = append(rules,
			Rule{
				Match: Match().ProtocolNum(ProtoUDP).
					DestPorts(uint16(r.Config.VXLANPort)).
					SrcAddrType(AddrTypeLocal, false).
					DestIPSet(r.IPSetConfigV6.NameForMainIPSet(IPSetIDAllVXLANSourceNets)),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow IPv6 VXLAN packets to other whitelisted hosts"},
			},
		)
	}

	if (ipVersion == 4 && r.WireguardEnabled) || (ipVersion == 6 && r.WireguardEnabledV6) {
		// When Wireguard is enabled, auto-allow Wireguard traffic to other Calico nodes.  Without this,
		// it's too easy to make a host policy that blocks Wireguard traffic, resulting in very confusing
		// connectivity problems.
		rules = append(rules,
			Rule{
				Match: Match().ProtocolNum(ProtoUDP).
					DestPorts(uint16(r.Config.WireguardListeningPort)).
					// Note that we do not need to limit the destination hosts to Calico nodes because allowed peers are
					// programmed separately
					SrcAddrType(AddrTypeLocal, false),
				Action:  r.filterAllowAction,
				Comment: []string{"Allow outgoing Wireguard packets"},
			},
		)
	}

	// Apply host endpoint policy to traffic that has not been DNAT'd.  In the DNAT case we
	// can't correctly apply policy here because the packet's OIF is still the OIF from a
	// routing lookup based on the pre-DNAT destination IP; Linux will shortly update it based
	// on the new destination IP, but that hasn't happened yet.  Instead, in the DNAT case, we
	// apply host endpoint in the mangle POSTROUTING chain; see StaticManglePostroutingChain for
	// that.
	rules = append(rules,
		Rule{
			Action: ClearMarkAction{Mark: r.allCalicoMarkBits()},
		},
		Rule{
			Match:  Match().NotConntrackState("DNAT"),
			Action: JumpAction{Target: ChainDispatchToHostEndpoint},
		},
		Rule{
			Match:   Match().MarkSingleBitSet(r.IptablesMarkAccept),
			Action:  r.filterAllowAction,
			Comment: []string{"Host endpoint policy accepted packet."},
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

	chains := []*Chain{{
		Name:  ChainNATPrerouting,
		Rules: rules,
	}}

	return chains
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

	if r.BPFEnabled {
		// Prepend a BPF SNAT rule.
		rules = append([]Rule{
			{
				Comment: []string{"BPF loopback SNAT"},
				Match:   Match().MarkMatchesWithMask(tcdefs.MarkSeenMASQ, tcdefs.MarkSeenMASQMask),
				Action:  MasqAction{},
			},
		}, rules...)
	}

	var tunnelIfaces []string

	if ipVersion == 4 && r.IPIPEnabled && len(r.IPIPTunnelAddress) > 0 {
		tunnelIfaces = append(tunnelIfaces, "tunl0")
	}
	if ipVersion == 4 && r.VXLANEnabled && len(r.VXLANTunnelAddress) > 0 {
		tunnelIfaces = append(tunnelIfaces, "vxlan.calico")
	}
	if ipVersion == 6 && r.VXLANEnabledV6 && len(r.VXLANTunnelAddressV6) > 0 {
		tunnelIfaces = append(tunnelIfaces, "vxlan-v6.calico")
	}
	if ipVersion == 4 && r.WireguardEnabled && len(r.WireguardInterfaceName) > 0 {
		// Wireguard is assigned an IP dynamically and without restarting Felix. Just add the interface if we have
		// wireguard enabled.
		tunnelIfaces = append(tunnelIfaces, r.WireguardInterfaceName)
	}
	if ipVersion == 6 && r.WireguardEnabledV6 && len(r.WireguardInterfaceNameV6) > 0 {
		// Wireguard is assigned an IP dynamically and without restarting Felix. Just add the interface if we have
		// wireguard enabled.
		tunnelIfaces = append(tunnelIfaces, r.WireguardInterfaceNameV6)
	}

	for _, tunnel := range tunnelIfaces {
		// Add a rule to catch packets that are being sent down a tunnel from an
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
				OutInterface(tunnel).
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

func (r *DefaultRuleRenderer) StaticMangleTableChains(ipVersion uint8) []*Chain {
	var chains []*Chain

	chains = append(chains,
		r.failsafeInChain("mangle", ipVersion),
		r.failsafeOutChain("mangle", ipVersion),
		r.StaticManglePreroutingChain(ipVersion),
		r.StaticManglePostroutingChain(ipVersion),
	)

	return chains
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
			Match:  Match().MarkSingleBitSet(r.IptablesMarkAccept),
			Action: r.mangleAllowAction,
		},
	)

	// Now dispatch to host endpoint chain for the incoming interface.
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
			Match:   Match().MarkSingleBitSet(r.IptablesMarkAccept),
			Action:  r.mangleAllowAction,
			Comment: []string{"Host endpoint policy accepted packet."},
		},
	)

	return &Chain{
		Name:  ChainManglePrerouting,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) StaticManglePostroutingChain(ipVersion uint8) *Chain {
	rules := []Rule{}

	// Note, we use RETURN as the Allow action in this chain, rather than ACCEPT because the
	// mangle table is typically used, if at all, for packet manipulations that might need to
	// apply to our allowed traffic.

	// Allow immediately if IptablesMarkAccept is set.  Our filter-FORWARD chain sets this for
	// any packets that reach the end of that chain.  The principle is that we don't want to
	// apply normal host endpoint policy to forwarded traffic.
	rules = append(rules, Rule{
		Match:  Match().MarkSingleBitSet(r.IptablesMarkAccept),
		Action: ReturnAction{},
	})

	// Similarly, avoid applying normal host endpoint policy to IPVS-forwarded traffic.
	// IPVS-forwarded traffic is identified by having a non-zero endpoint ID in the
	// IptablesMarkEndpoint bits.  Note: we only need this check for when net.ipv4.vs.conntrack
	// is enabled.  When net.ipv4.vs.conntrack is disabled (which is the default),
	// IPVS-forwarded traffic will fail the ConntrackState("DNAT") match below, and so would
	// avoid normal host endpoint policy anyway.  But it doesn't hurt to have this additional
	// check even when not strictly needed.
	if r.KubeIPVSSupportEnabled {
		rules = append(rules,
			Rule{
				Match:  Match().MarkNotClear(r.IptablesMarkEndpoint),
				Action: ReturnAction{},
			},
		)
	}

	// At this point we know that the packet is not forwarded, so it must be originated by a
	// host-based process or host-networked pod.

	// The similar sequence in filterOutputChain has rules here to allow IPIP and VXLAN traffic.
	// We don't need those rules here because the encapsulated traffic won't match `--ctstate
	// DNAT` and so we won't try applying HEP policy to it anyway.

	// The similar sequence in filterOutputChain has rules here to detect traffic to local
	// workloads, and to return early in that case.  We don't need those rules here because
	// ChainDispatchToHostEndpoint also checks for traffic to a local workload, and avoids
	// applying any host endpoint policy in that case.  Search for "Skip egress WHEP" in
	// dispatch.go, to see that.

	// Apply host endpoint policy to non-forwarded traffic that has been DNAT'd.  We do this
	// here, rather than in filter-OUTPUT, because Linux is weird: when a host-originated packet
	// is DNAT'd (typically in nat-OUTPUT), its destination IP is changed immediately, but Linux
	// does not recalculate the outgoing interface (OIF) until AFTER the filter-OUTPUT chain.
	// The OIF has been recalculated by the time we hit THIS chain (mangle-POSTROUTING), so we
	// can reliably apply host endpoint policy here.
	rules = append(rules,
		Rule{
			Action: ClearMarkAction{Mark: r.allCalicoMarkBits()},
		},
		Rule{
			Match:  Match().ConntrackState("DNAT"),
			Action: JumpAction{Target: ChainDispatchToHostEndpoint},
		},
		Rule{
			Match:   Match().MarkSingleBitSet(r.IptablesMarkAccept),
			Action:  ReturnAction{},
			Comment: []string{"Host endpoint policy accepted packet."},
		},
	)

	return &Chain{
		Name:  ChainManglePostrouting,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) StaticRawTableChains(ipVersion uint8) []*Chain {
	return []*Chain{
		r.failsafeInChain("raw", ipVersion),
		r.failsafeOutChain("raw", ipVersion),
		r.StaticRawPreroutingChain(ipVersion),
		r.WireguardIncomingMarkChain(),
		r.StaticRawOutputChain(0),
	}
}

func (r *DefaultRuleRenderer) StaticBPFModeRawChains(ipVersion uint8,
	wgEncryptHost, bypassHostConntrack bool) []*Chain {

	var rawRules []Rule

	if ((r.WireguardEnabled && len(r.WireguardInterfaceName) > 0) || (r.WireguardEnabledV6 && len(r.WireguardInterfaceNameV6) > 0)) && wgEncryptHost {
		// Set a mark on packets coming from any interface except for lo, wireguard, or pod veths to ensure the RPF
		// check allows it.
		log.Debug("Adding Wireguard iptables rule chain")
		rawRules = append(rawRules, Rule{
			Match:  nil,
			Action: JumpAction{Target: ChainSetWireguardIncomingMark},
		})
	}

	rawRules = append(rawRules,
		Rule{
			Match:  Match().NotDestAddrType(AddrTypeLocal),
			Action: GotoAction{Target: ChainRawUntrackedFlows},
		},
		Rule{
			// Return, i.e. no-op, if bypass mark is not set.
			Match:   Match().MarkMatchesWithMask(tcdefs.MarkSeenBypass, 0xffffffff),
			Action:  GotoAction{Target: ChainRawBPFUntrackedPolicy},
			Comment: []string{"Jump to target for packets with Bypass mark"},
		},
	)

	rawPreroutingChain := &Chain{
		Name:  ChainRawPrerouting,
		Rules: rawRules,
	}

	bpfUntrackedFlowChain := &Chain{
		Name:  ChainRawUntrackedFlows,
		Rules: []Rule{},
	}

	if bypassHostConntrack {
		bpfUntrackedFlowChain = &Chain{
			Name: ChainRawUntrackedFlows,
			Rules: []Rule{
				Rule{
					Match:   Match().MarkMatchesWithMask(tcdefs.MarkSeenSkipFIB, tcdefs.MarkSeenSkipFIB),
					Action:  ReturnAction{},
					Comment: []string{"MarkSeenSkipFIB Mark"},
				},
				Rule{
					Match:   Match().MarkMatchesWithMask(tcdefs.MarkSeenFallThrough, tcdefs.MarkSeenFallThroughMask),
					Action:  ReturnAction{},
					Comment: []string{"MarkSeenFallThrough Mark"},
				},
				Rule{
					Match:   Match().MarkMatchesWithMask(tcdefs.MarkSeenMASQ, tcdefs.MarkSeenMASQMask),
					Action:  ReturnAction{},
					Comment: []string{"MarkSeenMASQ Mark"},
				},
				Rule{
					Match:   Match().MarkMatchesWithMask(tcdefs.MarkSeenNATOutgoing, tcdefs.MarkSeenNATOutgoingMask),
					Action:  ReturnAction{},
					Comment: []string{"MarkSeenNATOutgoing Mark"},
				},
				Rule{
					Action: NoTrackAction{},
				},
			},
		}
	}

	xdpUntrakedPoliciesChain := &Chain{
		Name: ChainRawBPFUntrackedPolicy,
		Rules: []Rule{
			// At this point we know bypass mark is set, which means that the packet has
			// been explicitly allowed by untracked ingress policy (XDP).  We should
			// clear the mark so as not to affect any FROM_HOST processing.  (There
			// shouldn't be any FROM_HOST processing, because untracked policy is only
			// intended for traffic to/from the host.  But if the traffic is in fact
			// forwarded and goes to or through another endpoint, it's better to enforce
			// that endpoint's policy than to accidentally skip it because of the BYPASS
			// mark.  Note that we can clear the mark without stomping on anyone else's
			// logic because no one else's iptables should have had a chance to execute
			// yet.
			Rule{
				Action: SetMarkAction{Mark: 0},
			},
			// Now ensure that the packet is not tracked.
			Rule{
				Action: NoTrackAction{},
			},
		},
	}

	chains := []*Chain{
		rawPreroutingChain,
		xdpUntrakedPoliciesChain,
		bpfUntrackedFlowChain,
		r.failsafeOutChain("raw", ipVersion),
		r.WireguardIncomingMarkChain(),
	}

	if ipVersion == 4 {
		chains = append(chains,
			r.StaticRawOutputChain(tcdefs.MarkSeenBypass))
	}

	return chains
}

func (r *DefaultRuleRenderer) StaticRawPreroutingChain(ipVersion uint8) *Chain {
	rules := []Rule{}

	// For safety, clear all our mark bits before we start.  (We could be in append mode and
	// another process' rules could have left the mark bit set.)
	rules = append(rules,
		Rule{Action: ClearMarkAction{Mark: r.allCalicoMarkBits()}},
	)

	// Set a mark on encapsulated packets coming from WireGuard to ensure the RPF check allows it
	if ((r.WireguardEnabled && len(r.WireguardInterfaceName) > 0) || (r.WireguardEnabledV6 && len(r.WireguardInterfaceNameV6) > 0)) && r.Config.WireguardEncryptHostTraffic {
		log.Debug("Adding Wireguard iptables rule")
		rules = append(rules, Rule{
			Match:  nil,
			Action: JumpAction{Target: ChainSetWireguardIncomingMark},
		})
	}

	// Set a mark on the packet if it's from a workload interface.
	markFromWorkload := r.IptablesMarkScratch0
	for _, ifacePrefix := range r.WorkloadIfacePrefixes {
		rules = append(rules, Rule{
			Match:  Match().InInterface(ifacePrefix + "+"),
			Action: SetMarkAction{Mark: markFromWorkload},
		})
	}

	// Send workload traffic to a specific chain to skip the rpf check for some workloads
	rules = append(rules,
		Rule{
			Match:  Match().MarkMatchesWithMask(markFromWorkload, markFromWorkload),
			Action: JumpAction{Target: ChainRpfSkip},
		})

	// Apply strict RPF check to packets from workload interfaces.  This prevents
	// workloads from spoofing their IPs.  Note: non-privileged containers can't
	// usually spoof but privileged containers and VMs can.
	//
	rules = append(rules,
		RPFilter(ipVersion, markFromWorkload, markFromWorkload, r.OpenStackSpecialCasesEnabled, false)...)

	rules = append(rules,
		// Send non-workload traffic to the untracked policy chains.
		Rule{Match: Match().MarkClear(markFromWorkload),
			Action: JumpAction{Target: ChainDispatchFromHostEndpoint}},
		// Then, if the packet was marked as allowed, accept it.  Packets also return here
		// without the mark bit set if the interface wasn't one that we're policing.  We
		// let those packets fall through to the user's policy.
		Rule{Match: Match().MarkSingleBitSet(r.IptablesMarkAccept),
			Action: AcceptAction{}},
	)

	return &Chain{
		Name:  ChainRawPrerouting,
		Rules: rules,
	}
}

// RPFilter returns rules that implement RPF
func RPFilter(ipVersion uint8, mark, mask uint32, openStackSpecialCasesEnabled, acceptLocal bool) []Rule {
	rules := make([]Rule, 0, 2)

	// For OpenStack, allow DHCP v4 packets with source 0.0.0.0.  These must be allowed before
	// checking against the iptables rp_filter module, because the rp_filter module in some
	// kernel versions does not allow for DHCP with source 0.0.0.0 (whereas the rp_filter sysctl
	// setting _did_).
	//
	// Initial DHCP requests (DHCPDISCOVER) have source 0.0.0.0, and so will be allowed through
	// by the specific rule just following.  Later DHCP requests (DHCPREQUEST) may have source
	// 0.0.0.0, or the client's actual IP (as discovered through the DHCP process).  The 0.0.0.0
	// case will again be allowed by the following specific rule; the actual IP case should be
	// allowed by the general RPF check.  (Ref: https://www.ietf.org/rfc/rfc2131.txt page 37)
	//
	// Note: in DHCPv6, the initial request is sent with a link-local IPv6 address, which should
	// pass RPF, hence no special case is needed for DHCPv6.
	//
	// Here we are only focussing on anti-spoofing, and note that we ACCEPT a correct packet for
	// the current raw table, but don't mark it (with our Accept bit) as automatically accepted
	// for later tables.  Hence - for the policy level - we still have an OpenStack DHCP special
	// case again in filterWorkloadToHostChain.
	if openStackSpecialCasesEnabled && ipVersion == 4 {
		log.Info("Add OpenStack special-case rule for DHCP with source 0.0.0.0")
		rules = append(rules,
			Rule{
				Match: Match().
					Protocol("udp").
					SourceNet("0.0.0.0").
					SourcePorts(68).
					DestPorts(67),
				Action: AcceptAction{},
			},
		)
	}

	rules = append(rules, Rule{
		Match:  Match().MarkMatchesWithMask(mark, mask).RPFCheckFailed(acceptLocal),
		Action: DropAction{},
	})

	return rules
}

func (r *DefaultRuleRenderer) allCalicoMarkBits() uint32 {
	return r.IptablesMarkAccept |
		r.IptablesMarkPass |
		r.IptablesMarkScratch0 |
		r.IptablesMarkScratch1
}

func (r *DefaultRuleRenderer) WireguardIncomingMarkChain() *Chain {
	rules := []Rule{
		{
			Match:  Match().InInterface("lo"),
			Action: ReturnAction{},
		},
		{
			Match:  Match().InInterface(r.WireguardInterfaceName),
			Action: ReturnAction{},
		},
		{
			Match:  Match().InInterface(r.WireguardInterfaceNameV6),
			Action: ReturnAction{},
		},
	}

	for _, ifacePrefix := range r.WorkloadIfacePrefixes {
		rules = append(rules, Rule{
			Match:  Match().InInterface(fmt.Sprintf("%s+", ifacePrefix)),
			Action: ReturnAction{},
		})
	}

	rules = append(rules, Rule{Match: nil, Action: SetMarkAction{Mark: r.WireguardIptablesMark}})

	return &Chain{
		Name:  ChainSetWireguardIncomingMark,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) StaticRawOutputChain(tcBypassMark uint32) *Chain {
	rules := []Rule{
		// For safety, clear all our mark bits before we start.  (We could be in
		// append mode and another process' rules could have left the mark bit set.)
		{Action: ClearMarkAction{Mark: r.allCalicoMarkBits()}},
		// Then, jump to the untracked policy chains.
		{Action: JumpAction{Target: ChainDispatchToHostEndpoint}},
		// Then, if the packet was marked as allowed, accept it.  Packets also
		// return here without the mark bit set if the interface wasn't one that
		// we're policing.
	}
	if tcBypassMark == 0 {
		rules = append(rules, []Rule{
			{Match: Match().MarkSingleBitSet(r.IptablesMarkAccept),
				Action: AcceptAction{}},
		}...)
	} else {
		rules = append(rules, []Rule{
			{Match: Match().MarkSingleBitSet(r.IptablesMarkAccept),
				Action: SetMaskedMarkAction{Mark: tcBypassMark, Mask: 0xffffffff}},
			{Match: Match().MarkMatchesWithMask(tcBypassMark, 0xffffffff),
				Action: AcceptAction{}},
		}...)
	}
	return &Chain{
		Name:  ChainRawOutput,
		Rules: rules,
	}
}
