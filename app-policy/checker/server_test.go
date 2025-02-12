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
	"context"
	"testing"

	authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	. "github.com/onsi/gomega"
	"google.golang.org/genproto/googleapis/rpc/status"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

func TestCheckNoStore(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stores := policystore.NewPolicyStoreManager()
	uut := NewServer(ctx, stores)

	req := &authz.CheckRequest{}
	resp, err := uut.Check(ctx, req)
	Expect(err).To(BeNil())
	// No provider is registerted, as such the status code is UNKNOWN
	Expect(resp.GetStatus().GetCode()).To(Equal(UNKNOWN))
}

func TestCheckStore(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stores := policystore.NewPolicyStoreManager()
	uut := NewServer(ctx, stores)

	store := policystore.NewPolicyStoreManager()
	store.DoWithLock(func(s *policystore.PolicyStore) {
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

	chk := func() *authz.CheckResponse {
		rsp, err := uut.Check(ctx, req)
		Expect(err).ToNot(HaveOccurred())
		return rsp
	}
	// No provider is registerted, as such the status code is UNKNOWN
	Eventually(chk).Should(Equal(&authz.CheckResponse{Status: &status.Status{Code: UNKNOWN}}))
}
