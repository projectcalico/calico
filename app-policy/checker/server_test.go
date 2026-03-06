// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

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

func TestCheckNoStore(t *testing.T) {
	RegisterTestingT(t)
	ctx := t.Context()

	stores := policystore.NewPolicyStoreManager()
	uut := NewServer(ctx, stores,
		WithRegisteredCheckProvider(NewALPCheckProvider()),
	)

	req := &authz.CheckRequest{}
	resp, err := uut.Check(ctx, req)
	Expect(err).To(BeNil())
	// Endpoint is nil so the ALP provider is not enabled; response stays at initial INTERNAL.
	Expect(resp.GetStatus().GetCode()).To(Equal(INTERNAL))
}

func TestCheckStore(t *testing.T) {
	RegisterTestingT(t)
	ctx := t.Context()

	stores := policystore.NewPolicyStoreManager()
	uut := NewServer(ctx, stores,
		WithRegisteredCheckProvider(NewALPCheckProvider()),
	)

	// Mark in-sync so writes go to the active store, then populate it.
	stores.OnInSync()
	stores.DoWithLock(func(s *policystore.PolicyStore) {
		s.Endpoint = &proto.WorkloadEndpoint{
			ProfileIds: []string{"default"},
		}
		s.ProfileByID[types.ProfileID{Name: "default"}] = &proto.Profile{
			InboundRules: []*proto.Rule{{Action: "Allow"}},
		}
	})

	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/steve",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/sammy",
		},
	}}

	resp, err := uut.Check(ctx, req)
	Expect(err).ToNot(HaveOccurred())
	Expect(resp.GetStatus().GetCode()).To(Equal(OK))
}
