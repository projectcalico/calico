// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package checker

import (
	"testing"

	authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

func TestALPCheckProviderName(t *testing.T) {
	RegisterTestingT(t)
	p := NewALPCheckProvider()
	Expect(p.Name()).To(Equal("alp"))
}

func TestALPCheckProviderEnabledForRequest(t *testing.T) {
	RegisterTestingT(t)
	p := NewALPCheckProvider()

	store := policystore.NewPolicyStore()
	req := &authz.CheckRequest{}

	// No endpoint set → disabled.
	Expect(p.EnabledForRequest(store, req)).To(BeFalse())

	// Endpoint set → enabled.
	store.Endpoint = &proto.WorkloadEndpoint{}
	Expect(p.EnabledForRequest(store, req)).To(BeTrue())
}

func TestALPCheckProviderCheckAllow(t *testing.T) {
	RegisterTestingT(t)
	p := NewALPCheckProvider()

	store := policystore.NewPolicyStore()
	store.Endpoint = &proto.WorkloadEndpoint{
		ProfileIds: []string{"default"},
	}
	store.ProfileByID[types.ProfileID{Name: "default"}] = &proto.Profile{
		InboundRules: []*proto.Rule{{Action: "Allow"}},
	}

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/steve",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/sammy",
		},
	}}

	resp, err := p.Check(store, req)
	Expect(err).ToNot(HaveOccurred())
	Expect(resp.GetStatus().GetCode()).To(Equal(OK))
}

func TestALPCheckProviderCheckDeny(t *testing.T) {
	RegisterTestingT(t)
	p := NewALPCheckProvider()

	store := policystore.NewPolicyStore()
	store.Endpoint = &proto.WorkloadEndpoint{
		ProfileIds: []string{"default"},
	}
	store.ProfileByID[types.ProfileID{Name: "default"}] = &proto.Profile{
		InboundRules: []*proto.Rule{{Action: "Deny"}},
	}

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/steve",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/sammy",
		},
	}}

	resp, err := p.Check(store, req)
	Expect(err).ToNot(HaveOccurred())
	Expect(resp.GetStatus().GetCode()).To(Equal(PERMISSION_DENIED))
}
