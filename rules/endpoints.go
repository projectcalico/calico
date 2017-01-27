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
	"github.com/projectcalico/felix/hashutils"
	. "github.com/projectcalico/felix/iptables"
	"github.com/projectcalico/felix/proto"
)

func (r *DefaultRuleRenderer) WorkloadEndpointToIptablesChains(epID *proto.WorkloadEndpointID, endpoint *proto.WorkloadEndpoint) []*Chain {
	return r.endpointToIptablesChains(
		endpoint.Tiers,
		endpoint.ProfileIds,
		endpoint.Name,
		PolicyInboundPfx,
		PolicyOutboundPfx,
		WorkloadToEndpointPfx,
		WorkloadFromEndpointPfx,
		"", // No fail-safe chains for workloads.
		"", // No fail-safe chains for workloads.
		chainTypeTracked,
	)
}

func (r *DefaultRuleRenderer) HostEndpointToFilterChains(ifaceName string, endpoint *proto.HostEndpoint) []*Chain {
	return r.endpointToIptablesChains(
		endpoint.Tiers,
		endpoint.ProfileIds,
		ifaceName,
		PolicyOutboundPfx,
		PolicyInboundPfx,
		HostToEndpointPfx,
		HostFromEndpointPfx,
		ChainFailsafeOut,
		ChainFailsafeIn,
		chainTypeTracked,
	)
}

func (r *DefaultRuleRenderer) HostEndpointToRawChains(ifaceName string, endpoint *proto.HostEndpoint) []*Chain {
	return r.endpointToIptablesChains(
		endpoint.UntrackedTiers,
		endpoint.ProfileIds,
		ifaceName,
		PolicyOutboundPfx,
		PolicyInboundPfx,
		HostToEndpointPfx,
		HostFromEndpointPfx,
		ChainFailsafeOut,
		ChainFailsafeIn,
		chainTypeUntracked, // Render "untracked" version of chain for the raw table.
	)
}

type endpointChainType int

const (
	chainTypeTracked endpointChainType = iota
	chainTypeUntracked
)

func (r *DefaultRuleRenderer) endpointToIptablesChains(
	tiers []*proto.TierInfo,
	profileIds []string,
	name string,
	toPolicyPrefix string,
	fromPolicyPrefix string,
	toEndpointPrefix string,
	fromEndpointPrefix string,
	toFailsafeChain string,
	fromFailsafeChain string,
	chainType endpointChainType,
) []*Chain {
	toRules := []Rule{}
	fromRules := []Rule{}

	// First set up failsafes.
	if toFailsafeChain != "" {
		toRules = append(toRules, Rule{
			Action: JumpAction{Target: toFailsafeChain},
		})
	}
	if fromFailsafeChain != "" {
		fromRules = append(fromRules, Rule{
			Action: JumpAction{Target: fromFailsafeChain},
		})
	}

	// Start by ensuring that the accept mark bit is clear, policies set that bit to indicate
	// that they accepted the packet.
	toRules = append(toRules, Rule{
		Action: ClearMarkAction{
			Mark: r.IptablesMarkAccept,
		},
	})
	fromRules = append(fromRules, Rule{
		Action: ClearMarkAction{
			Mark: r.IptablesMarkAccept,
		},
	})

	// TODO(smc) Police the MAC?
	// TODO(neil) If so, add an arg to this function and only police in the workload case.

	for _, tier := range tiers {
		// For each tier,  clear the "accepted by tier" mark.
		toRules = append(toRules, Rule{
			Comment: "Start of tier " + tier.Name,
			Action: ClearMarkAction{
				Mark: r.IptablesMarkNextTier,
			},
		})
		fromRules = append(fromRules, Rule{
			Comment: "Start of tier " + tier.Name,
			Action: ClearMarkAction{
				Mark: r.IptablesMarkNextTier,
			},
		})
		// Then, jump to each policy in turn.
		for _, polID := range tier.Policies {
			toPolChainName := PolicyChainName(
				toPolicyPrefix,
				&proto.PolicyID{Tier: tier.Name, Name: polID},
			)
			// If a previous policy didn't set the "next-tier" mark, jump to the policy.
			toRules = append(toRules, Rule{
				Match:  Match().MarkClear(r.IptablesMarkNextTier),
				Action: JumpAction{Target: toPolChainName},
			})
			// If policy marked packet as accepted, it returns, setting the accept
			// mark bit.
			if chainType == chainTypeUntracked {
				// For an untracked policy, map allow to "NOTRACK and ALLOW".
				toRules = append(toRules, Rule{
					Match:  Match().MarkSet(r.IptablesMarkAccept),
					Action: NoTrackAction{},
				})
			}
			// If accept bit is set, return from this chain.  We don't immediately
			// accept because there may be other policy still to apply.
			toRules = append(toRules, Rule{
				Match:   Match().MarkSet(r.IptablesMarkAccept),
				Action:  ReturnAction{},
				Comment: "Return if policy accepted",
			})

			fromPolChainName := PolicyChainName(
				fromPolicyPrefix,
				&proto.PolicyID{Tier: tier.Name, Name: polID},
			)
			// If a previous policy didn't set the "next-tier" mark, jump to the policy.
			fromRules = append(fromRules, Rule{
				Match:  Match().MarkClear(r.IptablesMarkNextTier),
				Action: JumpAction{Target: fromPolChainName},
			})
			// If policy marked packet as accepted, it returns, setting the accept
			// mark bit.
			if chainType == chainTypeUntracked {
				// For an untracked policy, map allow to "NOTRACK and ALLOW".
				fromRules = append(fromRules, Rule{
					Match:  Match().MarkSet(r.IptablesMarkAccept),
					Action: NoTrackAction{},
				})
			}
			// If accept bit is set, return from this chain.  We don't immediately
			// accept because there may be other policy still to apply.
			fromRules = append(fromRules, Rule{
				Match:   Match().MarkSet(r.IptablesMarkAccept),
				Action:  ReturnAction{},
				Comment: "Return if policy accepted",
			})
		}

		if chainType == chainTypeTracked {
			// When rendering normal rules, if no policy in the tier marked the packet
			// as next-tier, drop the packet.
			//
			// For untracked rules, we don't do that because there may be tracked rules
			// still to be applied to the packet in the filter table.
			toRules = append(toRules, r.DropRules(
				Match().MarkClear(r.IptablesMarkNextTier),
				"Drop if no policies passed packet")...)
			fromRules = append(fromRules, r.DropRules(
				Match().MarkClear(r.IptablesMarkNextTier),
				"Drop if no policies passed packet")...)
		}
	}

	if chainType == chainTypeTracked {
		// Then, jump to each profile in turn.
		for _, profileID := range profileIds {
			toProfChainName := ProfileChainName(toPolicyPrefix, &proto.ProfileID{Name: profileID})
			fromProfChainName := ProfileChainName(fromPolicyPrefix, &proto.ProfileID{Name: profileID})
			toRules = append(toRules,
				Rule{Action: JumpAction{Target: toProfChainName}},
				// If policy marked packet as accepted, it returns, setting the
				// accept mark bit.  If that is set, return from this chain.
				Rule{
					Match:   Match().MarkSet(r.IptablesMarkAccept),
					Action:  ReturnAction{},
					Comment: "Return if profile accepted",
				})
			fromRules = append(fromRules,
				Rule{Action: JumpAction{Target: fromProfChainName}},
				// If policy marked packet as accepted, it returns, setting the
				// accept mark bit.  If that is set, return from this chain.
				Rule{
					Match:   Match().MarkSet(r.IptablesMarkAccept),
					Action:  ReturnAction{},
					Comment: "Return if profile accepted",
				})
		}

		// When rendering normal rules, if no profile marked the packet as accepted, drop
		// the packet.
		//
		// For untracked rules, we don't do that because there may be tracked rules
		// still to be applied to the packet in the filter table.
		toRules = append(toRules, r.DropRules(Match(), "Drop if no profiles matched")...)
		fromRules = append(fromRules, r.DropRules(Match(), "Drop if no profiles matched")...)
	}

	toEndpointChain := Chain{
		Name:  EndpointChainName(toEndpointPrefix, name),
		Rules: toRules,
	}
	fromEndpointChain := Chain{
		Name:  EndpointChainName(fromEndpointPrefix, name),
		Rules: fromRules,
	}
	return []*Chain{&toEndpointChain, &fromEndpointChain}
}

func EndpointChainName(prefix string, ifaceName string) string {
	return hashutils.GetLengthLimitedID(
		prefix,
		ifaceName,
		MaxChainNameLength,
	)
}
