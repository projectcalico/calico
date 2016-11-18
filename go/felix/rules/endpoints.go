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
	"fmt"
	"github.com/projectcalico/felix/go/felix/hashutils"
	"github.com/projectcalico/felix/go/felix/iptables"
	"github.com/projectcalico/felix/go/felix/proto"
)

func (r *ruleRenderer) WorkloadDispatchChains(endpoints map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint) []*iptables.Chain {
	toEndpointRules := make([]iptables.Rule, 0, len(endpoints)+1)
	fromEndpointRules := make([]iptables.Rule, 0, len(endpoints)+1)
	for _, endpoint := range endpoints {
		fromEndpointRules = append(fromEndpointRules, iptables.Rule{
			MatchCriteria: fmt.Sprintf("--in-interface %s", endpoint.Name),
			Action: iptables.GotoAction{
				Target: WorkloadEndpointChainName(WorkloadFromEndpointPfx, endpoint),
			},
		})
		toEndpointRules = append(toEndpointRules, iptables.Rule{
			MatchCriteria: fmt.Sprintf("--out-interface %s", endpoint.Name),
			Action: iptables.GotoAction{
				Target: WorkloadEndpointChainName(WorkloadToEndpointPfx, endpoint),
			},
		})
	}

	toEndpointRules = append(fromEndpointRules, iptables.Rule{
		Action: iptables.DropAction{},
	})
	fromEndpointRules = append(fromEndpointRules, iptables.Rule{
		Action: iptables.DropAction{},
	})

	toEndpointDispatchChain := iptables.Chain{
		Name:  DispatchToWorkloadEndpoint,
		Rules: toEndpointRules,
	}
	fromEndpointDispatchChain := iptables.Chain{
		Name:  DispatchFromWorkloadEndpoint,
		Rules: fromEndpointRules,
	}

	return []*iptables.Chain{&toEndpointDispatchChain, &fromEndpointDispatchChain}
}

func (r *ruleRenderer) WorkloadEndpointToIptablesChains(epID *proto.WorkloadEndpointID, endpoint *proto.WorkloadEndpoint) []*iptables.Chain {
	toEndpointChain := iptables.Chain{
		Name: WorkloadEndpointChainName(WorkloadToEndpointPfx, endpoint),
		// TODO(smc) Fill in rules.
	}
	fromEndpointChain := iptables.Chain{
		Name: WorkloadEndpointChainName(WorkloadFromEndpointPfx, endpoint),
		// TODO(smc) Fill in rules.
	}
	return []*iptables.Chain{&toEndpointChain, &fromEndpointChain}
}

func (r *ruleRenderer) HostDispatchChains(map[proto.HostEndpointID]*proto.HostEndpoint) []*iptables.Chain {
	panic("Not implemented")
	return nil
}

func (r *ruleRenderer) HostEndpointToIptablesChains(epID *proto.HostEndpointID, endpoint *proto.HostEndpoint) []*iptables.Chain {
	panic("Not implemented")
	return nil
}

func WorkloadEndpointChainName(prefix string, endpoint *proto.WorkloadEndpoint) string {
	return hashutils.GetLengthLimitedID(
		prefix,
		endpoint.Name,
		iptables.MaxChainNameLength,
	)
}
