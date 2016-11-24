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
	"github.com/projectcalico/felix/go/felix/hashutils"
	. "github.com/projectcalico/felix/go/felix/iptables"
	"github.com/projectcalico/felix/go/felix/proto"
)

func (r *ruleRenderer) WorkloadDispatchChains(endpoints map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint) []*Chain {
	toEndpointRules := make([]Rule, 0, len(endpoints)+1)
	fromEndpointRules := make([]Rule, 0, len(endpoints)+1)
	for _, endpoint := range endpoints {
		fromEndpointRules = append(fromEndpointRules, Rule{
			Match: Match().InInterface(endpoint.Name),
			Action: GotoAction{
				Target: WorkloadEndpointChainName(WorkloadFromEndpointPfx, endpoint),
			},
		})
		toEndpointRules = append(toEndpointRules, Rule{
			Match: Match().OutInterface(endpoint.Name),
			Action: GotoAction{
				Target: WorkloadEndpointChainName(WorkloadToEndpointPfx, endpoint),
			},
		})
	}

	toEndpointRules = append(fromEndpointRules, Rule{
		Action: DropAction{},
	})
	fromEndpointRules = append(fromEndpointRules, Rule{
		Action: DropAction{},
	})

	toEndpointDispatchChain := Chain{
		Name:  DispatchToWorkloadEndpoint,
		Rules: toEndpointRules,
	}
	fromEndpointDispatchChain := Chain{
		Name:  DispatchFromWorkloadEndpoint,
		Rules: fromEndpointRules,
	}

	return []*Chain{&toEndpointDispatchChain, &fromEndpointDispatchChain}
}

func (r *ruleRenderer) WorkloadEndpointToIptablesChains(epID *proto.WorkloadEndpointID, endpoint *proto.WorkloadEndpoint) []*Chain {
	inRules := []Rule{}
	outRules := []Rule{}

	// Start by ensuring that the accept mark bit is clear, policies set that bit to indicate
	// that they accepted the packet.
	inRules = append(inRules, Rule{
		Action: ClearMarkAction{
			Mark: r.IptablesMarkAccept,
		},
	})
	outRules = append(outRules, Rule{
		Action: ClearMarkAction{
			Mark: r.IptablesMarkAccept,
		},
	})

	// TODO(smc) Police the MAC?

	for _, tier := range endpoint.Tiers {
		// For each tier,  clear the "accepted by tier" mark.
		inRules = append(inRules, Rule{
			Comment: "Start of tier " + tier.Name,
			Action: ClearMarkAction{
				Mark: r.IptablesMarkNextTier,
			},
		})
		outRules = append(outRules, Rule{
			Comment: "Start of tier " + tier.Name,
			Action: ClearMarkAction{
				Mark: r.IptablesMarkNextTier,
			},
		})
		// Then, jump to each policy in turn.
		for _, polID := range tier.Policies {
			inPolChainName := PolicyChainName(
				PolicyInboundPfx,
				&proto.PolicyID{Tier: tier.Name, Name: polID},
			)
			inRules = append(inRules,
				Rule{
					Match:  Match().MarkClear(r.IptablesMarkNextTier),
					Action: JumpAction{Target: inPolChainName},
				},
				// If policy marked packet as accepted, it returns, setting the
				// accept mark bit.  If that is set, return from this chain.
				Rule{
					Match:   Match().MarkSet(r.IptablesMarkAccept),
					Action:  ReturnAction{},
					Comment: "Return if policy accepted",
				})
			outPolChainName := PolicyChainName(
				PolicyOutboundPfx,
				&proto.PolicyID{Tier: tier.Name, Name: polID},
			)
			outRules = append(outRules,
				Rule{
					Match:  Match().MarkClear(r.IptablesMarkNextTier),
					Action: JumpAction{Target: outPolChainName},
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
		inRules = append(inRules, r.DropRules(Match().MarkClear(r.IptablesMarkNextTier), "Drop if no policies passed packet")...)
		outRules = append(outRules, r.DropRules(Match().MarkClear(r.IptablesMarkNextTier), "Drop if no policies passed packet")...)
	}

	// Then, jump to each profile in turn.
	for _, profileID := range endpoint.ProfileIds {
		inProfChainName := ProfileChainName(PolicyInboundPfx, &proto.ProfileID{Name: profileID})
		outProfChainName := ProfileChainName(PolicyOutboundPfx, &proto.ProfileID{Name: profileID})
		inRules = append(inRules,
			Rule{Action: JumpAction{Target: inProfChainName}},
			// If policy marked packet as accepted, it returns, setting the
			// accept mark bit.  If that is set, return from this chain.
			Rule{
				Match:   Match().MarkSet(r.IptablesMarkAccept),
				Action:  ReturnAction{},
				Comment: "Return if profile accepted",
			})
		outRules = append(outRules,
			Rule{Action: JumpAction{Target: outProfChainName}},
			// If policy marked packet as accepted, it returns, setting the
			// accept mark bit.  If that is set, return from this chain.
			Rule{
				Match:   Match().MarkSet(r.IptablesMarkAccept),
				Action:  ReturnAction{},
				Comment: "Return if profile accepted",
			})
	}

	inRules = append(inRules, r.DropRules(Match(), "Drop if no profiles matched")...)
	outRules = append(outRules, r.DropRules(Match(), "Drop if no profiles matched")...)

	toEndpointChain := Chain{
		Name:  WorkloadEndpointChainName(WorkloadToEndpointPfx, endpoint),
		Rules: inRules,
	}
	fromEndpointChain := Chain{
		Name:  WorkloadEndpointChainName(WorkloadFromEndpointPfx, endpoint),
		Rules: outRules,
	}
	return []*Chain{&toEndpointChain, &fromEndpointChain}
}

func (r *ruleRenderer) HostDispatchChains(map[proto.HostEndpointID]*proto.HostEndpoint) []*Chain {
	panic("Not implemented")
	return nil
}

func (r *ruleRenderer) HostEndpointToIptablesChains(epID *proto.HostEndpointID, endpoint *proto.HostEndpoint) []*Chain {
	panic("Not implemented")

	// TODO(smc) Failsafe chains

	return nil
}

func WorkloadEndpointChainName(prefix string, endpoint *proto.WorkloadEndpoint) string {
	return hashutils.GetLengthLimitedID(
		prefix,
		endpoint.Name,
		MaxChainNameLength,
	)
}
