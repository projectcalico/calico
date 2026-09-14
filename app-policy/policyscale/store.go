// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package policyscale

import (
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

// NewStore returns a fresh policy store holding the fixture's policies and the IP sets that are
// not marked missing. Policies are shared between stores built from the same fixture; sets are
// built per store, so a test may mutate them.
func (fx *Fixture) NewStore() *policystore.PolicyStore {
	store := policystore.NewPolicyStore()
	fx.LoadStore(store)
	return store
}

// LoadStore adds the fixture's policies and IP sets to an existing store, for callers that own
// the store's lifecycle (a policystore.PolicyStoreManager, say).
func (fx *Fixture) LoadStore(store *policystore.PolicyStore) {
	for _, id := range fx.setOrder {
		s := fx.sets[id]
		if s.missing {
			continue
		}
		set := policystore.NewIPSet(proto.IPSetUpdate_NET)
		for _, m := range s.members {
			set.AddString(m)
		}
		store.IPSetByID[id] = set
	}
	for _, t := range fx.tiers {
		for _, policies := range t.policies {
			for _, p := range policies {
				store.PolicyByID[types.ProtoToPolicyID(p.id)] = p.policy
			}
		}
	}
}

// Updates returns the fixture as the dataplane messages Felix would send to load it into a store
// through PolicyStore.ProcessUpdate: IP sets first, then policies, as Felix orders them. The
// endpoint is not included; callers add it under the ID of their choice.
func (fx *Fixture) Updates() []*proto.ToDataplane {
	var updates []*proto.ToDataplane
	for _, id := range fx.setOrder {
		s := fx.sets[id]
		if s.missing {
			continue
		}
		updates = append(updates, &proto.ToDataplane{Payload: &proto.ToDataplane_IpsetUpdate{
			IpsetUpdate: &proto.IPSetUpdate{Id: id, Type: proto.IPSetUpdate_NET, Members: s.members},
		}})
	}
	for _, t := range fx.tiers {
		for _, policies := range t.policies {
			for _, p := range policies {
				updates = append(updates, &proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyUpdate{
					ActivePolicyUpdate: &proto.ActivePolicyUpdate{Id: p.id, Policy: p.policy},
				}})
			}
		}
	}
	return updates
}

// Endpoint returns a workload endpoint to which every policy of the fixture applies, with one
// TierInfo per tier carrying the ingress and egress policy lists. Each call returns a new
// endpoint, so a test may prepend a policy without disturbing other users of the fixture.
func (fx *Fixture) Endpoint() *proto.WorkloadEndpoint {
	ep := &proto.WorkloadEndpoint{State: "active", Name: "policyscale0"}
	for _, t := range fx.tiers {
		ti := &proto.TierInfo{Name: t.name, DefaultAction: t.defaultAction}
		for _, p := range t.policies[Ingress] {
			ti.IngressPolicies = append(ti.IngressPolicies, p.id)
		}
		for _, p := range t.policies[Egress] {
			ti.EgressPolicies = append(ti.EgressPolicies, p.id)
		}
		ep.Tiers = append(ep.Tiers, ti)
	}
	return ep
}
