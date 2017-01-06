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
	"github.com/projectcalico/felix/go/felix/hashutils"
	. "github.com/projectcalico/felix/go/felix/iptables"
	"github.com/projectcalico/felix/go/felix/proto"
)

func (r *ruleRenderer) WorkloadDispatchChains(endpoints map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint) []*Chain {

	// Extract endpoint names.
	names := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		names = append(names, endpoint.Name)
	}

	return r.dispatchChains(
		names,
		WorkloadFromEndpointPfx,
		WorkloadToEndpointPfx,
		ChainFromWorkloadDispatch,
		ChainToWorkloadDispatch,
		true,
	)
}

func (r *ruleRenderer) HostDispatchChains(endpoints map[string]proto.HostEndpointID) []*Chain {

	// Extract endpoint names.
	names := make([]string, 0, len(endpoints))
	for ifaceName, _ := range endpoints {
		names = append(names, ifaceName)
	}

	return r.dispatchChains(
		names,
		HostFromEndpointPfx,
		HostToEndpointPfx,
		ChainDispatchFromHostEndpoint,
		ChainDispatchToHostEndpoint,
		false,
	)
}

func (r *ruleRenderer) dispatchChains(
	names []string,
	fromEndpointPfx,
	toEndpointPfx,
	dispatchFromEndpoint,
	dispatchToEndpoint string,
	dropAtEndOfChain bool,
) []*Chain {
	toEndpointRules := make([]Rule, 0, len(names)+1)
	fromEndpointRules := make([]Rule, 0, len(names)+1)
	for _, name := range names {
		fromEndpointRules = append(fromEndpointRules, Rule{
			Match: Match().InInterface(name),
			Action: GotoAction{
				Target: EndpointChainName(fromEndpointPfx, name),
			},
		})
		toEndpointRules = append(toEndpointRules, Rule{
			Match: Match().OutInterface(name),
			Action: GotoAction{
				Target: EndpointChainName(toEndpointPfx, name),
			},
		})
	}

	if dropAtEndOfChain {
		fromEndpointRules = append(fromEndpointRules,
			r.DropRules(Match(), "Unknown interface")...)
		toEndpointRules = append(toEndpointRules,
			r.DropRules(Match(), "Unknown interface")...)
	}

	fromEndpointDispatchChain := Chain{
		Name:  dispatchFromEndpoint,
		Rules: fromEndpointRules,
	}
	toEndpointDispatchChain := Chain{
		Name:  dispatchToEndpoint,
		Rules: toEndpointRules,
	}

	return []*Chain{&toEndpointDispatchChain, &fromEndpointDispatchChain}
}

func (r *ruleRenderer) WorkloadEndpointToIptablesChains(epID *proto.WorkloadEndpointID, endpoint *proto.WorkloadEndpoint) []*Chain {
	return r.endpointToIptablesChains(
		endpoint.Tiers,
		endpoint.ProfileIds,
		endpoint.Name,
		PolicyInboundPfx,
		PolicyOutboundPfx,
		WorkloadToEndpointPfx,
		WorkloadFromEndpointPfx,
		"",
		"",
	)
}

func (r *ruleRenderer) endpointToIptablesChains(
	tiers []*proto.TierInfo,
	profileIds []string,
	name string,
	toPolicyPrefix string,
	fromPolicyPrefix string,
	toEndpointPrefix string,
	fromEndpointPrefix string,
	toFailsafeChain string,
	fromFailsafeChain string,
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
			toRules = append(toRules,
				Rule{
					Match:  Match().MarkClear(r.IptablesMarkNextTier),
					Action: JumpAction{Target: toPolChainName},
				},
				// If policy marked packet as accepted, it returns, setting the
				// accept mark bit.  If that is set, return from this chain.
				Rule{
					Match:   Match().MarkSet(r.IptablesMarkAccept),
					Action:  ReturnAction{},
					Comment: "Return if policy accepted",
				})
			fromPolChainName := PolicyChainName(
				fromPolicyPrefix,
				&proto.PolicyID{Tier: tier.Name, Name: polID},
			)
			fromRules = append(fromRules,
				Rule{
					Match:  Match().MarkClear(r.IptablesMarkNextTier),
					Action: JumpAction{Target: fromPolChainName},
				},
				// If policy marked packet as accepted, it returns, setting the
				// accept mark bit.  If that is set, return from this chain.
				Rule{
					Match:   Match().MarkSet(r.IptablesMarkAccept),
					Action:  ReturnAction{},
					Comment: "Return if policy accepted",
				})
		}
		// If no policy in the tier marked the packet as next-tier, drop the packet.
		toRules = append(toRules, r.DropRules(Match().MarkClear(r.IptablesMarkNextTier), "Drop if no policies passed packet")...)
		fromRules = append(fromRules, r.DropRules(Match().MarkClear(r.IptablesMarkNextTier), "Drop if no policies passed packet")...)
	}

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

	toRules = append(toRules, r.DropRules(Match(), "Drop if no profiles matched")...)
	fromRules = append(fromRules, r.DropRules(Match(), "Drop if no profiles matched")...)

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

func (r *ruleRenderer) HostEndpointToIptablesChains(ifaceName string, endpoint *proto.HostEndpoint) []*Chain {
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
	)
}

func EndpointChainName(prefix string, ifaceName string) string {
	return hashutils.GetLengthLimitedID(
		prefix,
		ifaceName,
		MaxChainNameLength,
	)
}
