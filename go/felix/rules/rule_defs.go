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
	"github.com/projectcalico/felix/go/felix/iptables"
	"github.com/projectcalico/felix/go/felix/proto"
)

const (
	ChainNamePrefix = "cali"

	PolicyInboundPfx  = ChainNamePrefix + "pi-"
	PolicyOutboundPfx = ChainNamePrefix + "po-"

	DispatchToWorkloadEndpoint   = ChainNamePrefix + "-to-wl-endpoint"
	DispatchFromWorkloadEndpoint = ChainNamePrefix + "-from-wl-endpoint"

	WorkloadToEndpointPfx   = ChainNamePrefix + "tw-"
	WorkloadFromEndpointPfx = ChainNamePrefix + "fw-"

	HostToEndpointPfx   = ChainNamePrefix + "th-"
	HostFromEndpointPfx = ChainNamePrefix + "fh-"

	RuleHashPrefix = "cali:"
)

var (
	AllHistoricChainNamePrefixes = []string{"felix-", "FLX", "cali"}
)

type RuleRenderer interface {
	StaticFilterTableChains() []*iptables.Chain

	WorkloadDispatchChains(map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint) []*iptables.Chain
	WorkloadEndpointToIptablesChains(epID *proto.WorkloadEndpointID, endpoint *proto.WorkloadEndpoint) []*iptables.Chain

	HostDispatchChains(map[proto.HostEndpointID]*proto.HostEndpoint) []*iptables.Chain
	HostEndpointToIptablesChains(epID *proto.HostEndpointID, endpoint *proto.HostEndpoint) []*iptables.Chain

	PolicyToIptablesChains(policyID *proto.PolicyID, policy *proto.Policy) []*iptables.Chain
}

type ruleRenderer struct {
}

func NewRenderer() RuleRenderer {
	return &ruleRenderer{}
}
