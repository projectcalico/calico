// Copyright (c) 2016-2021 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/calico/felix/hashutils"
	. "github.com/projectcalico/calico/felix/iptables"
	"github.com/projectcalico/calico/felix/proto"
)

const (
	alwaysAllowVXLANEncap = true
	alwaysAllowIPIPEncap  = true
)

func (r *DefaultRuleRenderer) WorkloadEndpointToIptablesChains(
	ifaceName string,
	epMarkMapper EndpointMarkMapper,
	adminUp bool,
	ingressPolicies []string,
	egressPolicies []string,
	profileIDs []string,
) []*Chain {
	allowVXLANEncapFromWorkloads := r.Config.AllowVXLANPacketsFromWorkloads
	allowIPIPEncapFromWorkloads := r.Config.AllowIPIPPacketsFromWorkloads
	result := []*Chain{}
	result = append(result,
		// Chain for traffic _to_ the endpoint.
		r.endpointIptablesChain(
			ingressPolicies,
			profileIDs,
			ifaceName,
			PolicyInboundPfx,
			ProfileInboundPfx,
			WorkloadToEndpointPfx,
			"", // No fail-safe chains for workloads.
			chainTypeNormal,
			adminUp,
			r.filterAllowAction, // Workload endpoint chains are only used in the filter table
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
		),
		// Chain for traffic _from_ the endpoint.
		// Encap traffic is blocked by default from workload endpoints
		// unless explicitly overridden.
		r.endpointIptablesChain(
			egressPolicies,
			profileIDs,
			ifaceName,
			PolicyOutboundPfx,
			ProfileOutboundPfx,
			WorkloadFromEndpointPfx,
			"", // No fail-safe chains for workloads.
			chainTypeNormal,
			adminUp,
			r.filterAllowAction, // Workload endpoint chains are only used in the filter table
			allowVXLANEncapFromWorkloads,
			allowIPIPEncapFromWorkloads,
		),
	)

	if r.KubeIPVSSupportEnabled {
		// Chain for setting endpoint mark of an endpoint.
		result = append(result,
			r.endpointSetMarkChain(
				ifaceName,
				epMarkMapper,
				SetEndPointMarkPfx,
			),
		)
	}

	return result
}

func (r *DefaultRuleRenderer) HostEndpointToFilterChains(
	ifaceName string,
	epMarkMapper EndpointMarkMapper,
	ingressPolicyNames []string,
	egressPolicyNames []string,
	ingressForwardPolicyNames []string,
	egressForwardPolicyNames []string,
	profileIDs []string,
) []*Chain {
	log.WithField("ifaceName", ifaceName).Debug("Rendering filter host endpoint chain.")
	result := []*Chain{}
	result = append(result,
		// Chain for output traffic _to_ the endpoint.
		r.endpointIptablesChain(
			egressPolicyNames,
			profileIDs,
			ifaceName,
			PolicyOutboundPfx,
			ProfileOutboundPfx,
			HostToEndpointPfx,
			ChainFailsafeOut,
			chainTypeNormal,
			true, // Host endpoints are always admin up.
			r.filterAllowAction,
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
		),
		// Chain for input traffic _from_ the endpoint.
		r.endpointIptablesChain(
			ingressPolicyNames,
			profileIDs,
			ifaceName,
			PolicyInboundPfx,
			ProfileInboundPfx,
			HostFromEndpointPfx,
			ChainFailsafeIn,
			chainTypeNormal,
			true, // Host endpoints are always admin up.
			r.filterAllowAction,
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
		),
		// Chain for forward traffic _to_ the endpoint.
		r.endpointIptablesChain(
			egressForwardPolicyNames,
			profileIDs,
			ifaceName,
			PolicyOutboundPfx,
			ProfileOutboundPfx,
			HostToEndpointForwardPfx,
			"", // No fail-safe chains for forward traffic.
			chainTypeForward,
			true, // Host endpoints are always admin up.
			r.filterAllowAction,
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
		),
		// Chain for forward traffic _from_ the endpoint.
		r.endpointIptablesChain(
			ingressForwardPolicyNames,
			profileIDs,
			ifaceName,
			PolicyInboundPfx,
			ProfileInboundPfx,
			HostFromEndpointForwardPfx,
			"", // No fail-safe chains for forward traffic.
			chainTypeForward,
			true, // Host endpoints are always admin up.
			r.filterAllowAction,
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
		),
	)

	if r.KubeIPVSSupportEnabled {
		// Chain for setting endpoint mark of an endpoint.
		result = append(result,
			r.endpointSetMarkChain(
				ifaceName,
				epMarkMapper,
				SetEndPointMarkPfx,
			),
		)
	}

	return result
}

func (r *DefaultRuleRenderer) HostEndpointToMangleEgressChains(
	ifaceName string,
	egressPolicyNames []string,
	profileIDs []string,
) []*Chain {
	log.WithField("ifaceName", ifaceName).Debug("Render host endpoint mangle egress chain.")
	return []*Chain{
		// Chain for output traffic _to_ the endpoint.  Note, we use RETURN here rather than
		// ACCEPT because the mangle table is typically used, if at all, for packet
		// manipulations that might need to apply to our allowed traffic.
		r.endpointIptablesChain(
			egressPolicyNames,
			profileIDs,
			ifaceName,
			PolicyOutboundPfx,
			ProfileOutboundPfx,
			HostToEndpointPfx,
			ChainFailsafeOut,
			chainTypeNormal,
			true, // Host endpoints are always admin up.
			ReturnAction{},
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
		),
	}
}

func (r *DefaultRuleRenderer) HostEndpointToRawEgressChain(
	ifaceName string,
	egressPolicyNames []string,
) *Chain {
	log.WithField("ifaceName", ifaceName).Debug("Rendering raw (untracked) host endpoint egress chain.")
	return r.endpointIptablesChain(
		egressPolicyNames,
		nil, // We don't render profiles into the raw table.
		ifaceName,
		PolicyOutboundPfx,
		ProfileOutboundPfx,
		HostToEndpointPfx,
		ChainFailsafeOut,
		chainTypeUntracked,
		true, // Host endpoints are always admin up.
		AcceptAction{},
		alwaysAllowVXLANEncap,
		alwaysAllowIPIPEncap,
	)
}

func (r *DefaultRuleRenderer) HostEndpointToRawChains(
	ifaceName string,
	ingressPolicyNames []string,
	egressPolicyNames []string,
) []*Chain {
	log.WithField("ifaceName", ifaceName).Debug("Rendering raw (untracked) host endpoint chain.")
	return []*Chain{
		// Chain for traffic _to_ the endpoint.
		r.HostEndpointToRawEgressChain(ifaceName, egressPolicyNames),
		// Chain for traffic _from_ the endpoint.
		r.endpointIptablesChain(
			ingressPolicyNames,
			nil, // We don't render profiles into the raw table.
			ifaceName,
			PolicyInboundPfx,
			ProfileInboundPfx,
			HostFromEndpointPfx,
			ChainFailsafeIn,
			chainTypeUntracked,
			true, // Host endpoints are always admin up.
			AcceptAction{},
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
		),
	}
}

func (r *DefaultRuleRenderer) HostEndpointToMangleIngressChains(
	ifaceName string,
	preDNATPolicyNames []string,
) []*Chain {
	log.WithField("ifaceName", ifaceName).Debug("Rendering pre-DNAT host endpoint chain.")
	return []*Chain{
		// Chain for traffic _from_ the endpoint.  Pre-DNAT policy does not apply to
		// outgoing traffic through a host endpoint.
		r.endpointIptablesChain(
			preDNATPolicyNames,
			nil, // We don't render profiles into the raw table.
			ifaceName,
			PolicyInboundPfx,
			ProfileInboundPfx,
			HostFromEndpointPfx,
			ChainFailsafeIn,
			chainTypePreDNAT,
			true, // Host endpoints are always admin up.
			r.mangleAllowAction,
			alwaysAllowVXLANEncap,
			alwaysAllowIPIPEncap,
		),
	}
}

type endpointChainType int

const (
	chainTypeNormal endpointChainType = iota
	chainTypeUntracked
	chainTypePreDNAT
	chainTypeForward
)

func (r *DefaultRuleRenderer) endpointSetMarkChain(
	name string,
	epMarkMapper EndpointMarkMapper,
	endpointPrefix string,
) *Chain {
	rules := []Rule{}
	chainName := EndpointChainName(endpointPrefix, name)

	if endPointMark, err := epMarkMapper.GetEndpointMark(name); err == nil {
		// Set endpoint mark.
		rules = append(rules, Rule{
			Action: SetMaskedMarkAction{
				Mark: endPointMark,
				Mask: epMarkMapper.GetMask()},
		})
	}
	return &Chain{
		Name:  chainName,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) endpointIptablesChain(
	policyNames []string,
	profileIds []string,
	name string,
	policyPrefix PolicyChainNamePrefix,
	profilePrefix ProfileChainNamePrefix,
	endpointPrefix string,
	failsafeChain string,
	chainType endpointChainType,
	adminUp bool,
	allowAction Action,
	allowVXLANEncap bool,
	allowIPIPEncap bool,
) *Chain {
	rules := []Rule{}
	chainName := EndpointChainName(endpointPrefix, name)

	if !adminUp {
		// Endpoint is admin-down, drop all traffic to/from it.
		rules = append(rules, Rule{
			Match:   Match(),
			Action:  r.DropActionOverride,
			Comment: []string{"Endpoint admin disabled"},
		})
		return &Chain{
			Name:  chainName,
			Rules: rules,
		}
	}

	if chainType != chainTypeUntracked {
		// Tracked chain: install conntrack rules, which implement our stateful connections.
		// This allows return traffic associated with a previously-permitted request.
		rules = r.appendConntrackRules(rules, allowAction)
	}

	// First set up failsafes.
	if failsafeChain != "" {
		rules = append(rules, Rule{
			Action: JumpAction{Target: failsafeChain},
		})
	}

	// Start by ensuring that the accept mark bit is clear, policies set that bit to indicate
	// that they accepted the packet.
	rules = append(rules, Rule{
		Action: ClearMarkAction{
			Mark: r.IptablesMarkAccept,
		},
	})

	if !allowVXLANEncap {
		rules = append(rules, Rule{
			Match: Match().ProtocolNum(ProtoUDP).
				DestPorts(uint16(r.Config.VXLANPort)),
			Action:  r.DropActionOverride,
			Comment: []string{fmt.Sprintf("%s VXLAN encapped packets originating in workloads", r.DropActionOverride)},
		})
	}
	if !allowIPIPEncap {
		rules = append(rules, Rule{
			Match:   Match().ProtocolNum(ProtoIPIP),
			Action:  r.DropActionOverride,
			Comment: []string{fmt.Sprintf("%s IPinIP encapped packets originating in workloads", r.DropActionOverride)},
		})
	}

	if len(policyNames) > 0 {
		// Clear the "pass" mark.  If a policy sets that mark, we'll skip the rest of the policies and
		// continue processing the profiles, if there are any.
		rules = append(rules, Rule{
			Comment: []string{"Start of policies"},
			Action: ClearMarkAction{
				Mark: r.IptablesMarkPass,
			},
		})

		// Then, jump to each policy in turn.
		for _, polID := range policyNames {
			polChainName := PolicyChainName(
				policyPrefix,
				&proto.PolicyID{Name: polID},
			)

			// If a previous policy didn't set the "pass" mark, jump to the policy.
			rules = append(rules, Rule{
				Match:  Match().MarkClear(r.IptablesMarkPass),
				Action: JumpAction{Target: polChainName},
			})
			// If policy marked packet as accepted, it returns, setting the accept
			// mark bit.
			if chainType == chainTypeUntracked {
				// For an untracked policy, map allow to "NOTRACK and ALLOW".
				rules = append(rules, Rule{
					Match:  Match().MarkSingleBitSet(r.IptablesMarkAccept),
					Action: NoTrackAction{},
				})
			}
			// If accept bit is set, return from this chain.  We don't immediately
			// accept because there may be other policy still to apply.
			rules = append(rules, Rule{
				Match:   Match().MarkSingleBitSet(r.IptablesMarkAccept),
				Action:  ReturnAction{},
				Comment: []string{"Return if policy accepted"},
			})
		}

		if chainType == chainTypeNormal || chainType == chainTypeForward {
			// When rendering normal and forward rules, if no policy marked the packet as "pass", drop
			// or reject the packet.
			//
			// For untracked and pre-DNAT rules, we don't do that because there may be
			// normal rules still to be applied to the packet in the filter table.
			rules = append(rules, Rule{
				Match:   Match().MarkClear(r.IptablesMarkPass),
				Action:  r.DropActionOverride,
				Comment: []string{fmt.Sprintf("%s if no policies passed packet", r.DropActionOverride)},
			})
		}

	} else if chainType == chainTypeForward {
		// Forwarded traffic is allowed when there are no policies with
		// applyOnForward that apply to this endpoint (and in this direction).
		rules = append(rules, Rule{
			Action:  SetMarkAction{Mark: r.IptablesMarkAccept},
			Comment: []string{"Allow forwarded traffic by default"},
		})
		rules = append(rules, Rule{
			Action:  ReturnAction{},
			Comment: []string{"Return for accepted forward traffic"},
		})
	}

	if chainType == chainTypeNormal {
		// Then, jump to each profile in turn.
		for _, profileID := range profileIds {
			profChainName := ProfileChainName(profilePrefix, &proto.ProfileID{Name: profileID})
			rules = append(rules,
				Rule{Action: JumpAction{Target: profChainName}},
				// If policy marked packet as accepted, it returns, setting the
				// accept mark bit.  If that is set, return from this chain.
				Rule{
					Match:   Match().MarkSingleBitSet(r.IptablesMarkAccept),
					Action:  ReturnAction{},
					Comment: []string{"Return if profile accepted"},
				})
		}

		// When rendering normal rules, if no profile marked the packet as accepted, drop
		// the packet.
		//
		// For untracked rules, we don't do that because there may be tracked rules
		// still to be applied to the packet in the filter table.
		//if dropIfNoProfilesMatched {
		rules = append(rules, Rule{
			Match:   Match(),
			Action:  r.DropActionOverride,
			Comment: []string{fmt.Sprintf("%s if no profiles matched", r.DropActionOverride)},
		})
		//}
	}

	return &Chain{
		Name:  chainName,
		Rules: rules,
	}
}

func (r *DefaultRuleRenderer) appendConntrackRules(rules []Rule, allowAction Action) []Rule {
	// Allow return packets for established connections.
	if allowAction != (AcceptAction{}) {
		// If we've been asked to return instead of accept the packet immediately,
		// make sure we flag the packet as allowed.
		rules = append(rules,
			Rule{
				Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
				Action: SetMarkAction{Mark: r.IptablesMarkAccept},
			},
		)
	}
	rules = append(rules,
		Rule{
			Match:  Match().ConntrackState("RELATED,ESTABLISHED"),
			Action: allowAction,
		},
	)
	if !r.Config.DisableConntrackInvalid {
		// Drop packets that aren't either a valid handshake or part of an established
		// connection.
		rules = append(rules, Rule{
			Match:  Match().ConntrackState("INVALID"),
			Action: r.DropActionOverride,
		})
	}
	return rules
}

func EndpointChainName(prefix string, ifaceName string) string {
	return hashutils.GetLengthLimitedID(
		prefix,
		ifaceName,
		MaxChainNameLength,
	)
}
