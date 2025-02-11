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

	. "github.com/onsi/gomega"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"google.golang.org/genproto/googleapis/rpc/status"
)

func TestCheckNoStore(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stores := make(chan *policystore.PolicyStore)
	uut := NewServer(ctx, stores)

	req := &authz.CheckRequest{}
	resp, err := uut.Check(ctx, req)
	Expect(err).To(BeNil())
	Expect(resp.GetStatus().GetCode()).To(Equal(UNAVAILABLE))
}

func TestCheckStore(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stores := make(chan *policystore.PolicyStore)
	uut := NewServer(ctx, stores)

	store := policystore.NewPolicyStore()
	store.Write(func(s *policystore.PolicyStore) {
		s.Endpoint = &proto.WorkloadEndpoint{
			ProfileIds: []string{"default"},
		}
		s.ProfileByID[types.ProfileID{Name: "default"}] = &proto.Profile{
			InboundRules: []*proto.Rule{{Action: "Allow"}},
		}
	})
	stores <- store

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
	Eventually(chk).Should(Equal(&authz.CheckResponse{Status: &status.Status{Code: OK}}))
}

func TestCheckStoreNoHTTP(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	psm := policystore.NewPolicyStoreManager()
	uut := NewServer(ctx, psm, WithRegisteredCheckProvider(NewALPCheckProvider("per-pod-policies", true)))

	psm.OnInSync()
	psm.DoWithLock(func(s *policystore.PolicyStore) {
		s.Endpoint = &proto.WorkloadEndpoint{
			ProfileIds: []string{"default"},
		}
		s.ProfileByID[proto.ProfileID{Name: "default"}] = &proto.Profile{
			InboundRules: []*proto.Rule{{Action: "Allow"}},
		}
	})

	// Send in request with no HTTP data. Request should pass, we should have no stats updates for this request.
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
	Eventually(chk).Should(Equal(&authz.CheckResponse{Status: &status.Status{Code: OK}}))
}

func TestCheckStoreHTTPAllowed(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dpStats := statscache.New()
	psm := policystore.NewPolicyStoreManager()
	uut := NewServer(ctx, psm, dpStats, WithRegisteredCheckProvider(NewALPCheckProvider("per-pod-policies", true)))

	psm.OnInSync()
	psm.DoWithLock(func(s *policystore.PolicyStore) {
		s.Endpoint = &proto.WorkloadEndpoint{
			ProfileIds: []string{"default"},
		}
		s.ProfileByID[proto.ProfileID{Name: "default"}] = &proto.Profile{
			InboundRules: []*proto.Rule{{Action: "Allow"}},
		}
	})

	// Send in request with no HTTP data. Request should pass, we should have no stats updates for this request.
	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Address: &core.Address{
				Address: &core.Address_SocketAddress{
					SocketAddress: &core.SocketAddress{
						Address:       "1.2.3.4",
						PortSpecifier: &core.SocketAddress_PortValue{PortValue: 1000},
						Protocol:      core.SocketAddress_TCP,
					},
				},
			},
			Principal: "spiffe://cluster.local/ns/default/sa/steve",
		},
		Destination: &authz.AttributeContext_Peer{
			Address: &core.Address{
				Address: &core.Address_SocketAddress{
					SocketAddress: &core.SocketAddress{
						Address:       "11.22.33.44",
						PortSpecifier: &core.SocketAddress_PortValue{PortValue: 2000},
						Protocol:      core.SocketAddress_TCP,
					},
				},
			},
			Principal: "spiffe://cluster.local/ns/default/sa/sammy",
		},
		Request: &authz.AttributeContext_Request{
			Http: &authz.AttributeContext_HttpRequest{Method: "GET", Path: "/foo"},
		},
	}}

	// Check request is allowed and that we don't get any stats updates (stats are not yet enabled).
	chk := func() *authz.CheckResponse {
		rsp, err := uut.Check(ctx, req)
		Expect(err).ToNot(HaveOccurred())
		return rsp
	}

	Eventually(chk).Should(Equal(&authz.CheckResponse{Status: &status.Status{Code: OK}}))

	// Enable stats, re-run the request and this time check we do get stats updates.
	psm.DoWithLock(func(ps *policystore.PolicyStore) {
		ps.DataplaneStatsEnabledForAllowed = true
	})
	chk = func() *authz.CheckResponse {
		rsp, err := uut.Check(ctx, req)
		Expect(err).ToNot(HaveOccurred())
		return rsp
	}
	Eventually(chk).Should(Equal(&authz.CheckResponse{Status: &status.Status{Code: OK}}))
}

func TestCheckStoreHTTPDenied(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dpStats := statscache.New()
	psm := policystore.NewPolicyStoreManager()
	uut := NewServer(ctx, psm, dpStats, WithRegisteredCheckProvider(NewALPCheckProvider("per-pod-policies", true)))

	psm.OnInSync()
	psm.DoWithLock(func(s *policystore.PolicyStore) {
		s.Endpoint = &proto.WorkloadEndpoint{
			ProfileIds: []string{"default"},
		}
		s.ProfileByID[proto.ProfileID{Name: "default"}] = &proto.Profile{
			InboundRules: []*proto.Rule{{Action: "Deny"}},
		}
	})

	// Send in request with no HTTP data. Request should pass, we should have no stats updates for this request.
	req := &authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Address: &core.Address{
				Address: &core.Address_SocketAddress{
					SocketAddress: &core.SocketAddress{
						Address:       "1.2.3.4",
						PortSpecifier: &core.SocketAddress_PortValue{PortValue: 1000},
						Protocol:      core.SocketAddress_TCP,
					},
				},
			},
			Principal: "spiffe://cluster.local/ns/default/sa/steve",
		},
		Destination: &authz.AttributeContext_Peer{
			Address: &core.Address{
				Address: &core.Address_SocketAddress{
					SocketAddress: &core.SocketAddress{
						Address:       "11.22.33.44",
						PortSpecifier: &core.SocketAddress_PortValue{PortValue: 2000},
						Protocol:      core.SocketAddress_TCP,
					},
				},
			},
			Principal: "spiffe://cluster.local/ns/default/sa/sammy",
		},
		Request: &authz.AttributeContext_Request{
			Http: &authz.AttributeContext_HttpRequest{Method: "GET", Path: "/foo"},
		},
	}}

	// Check request is denied and that we don't get any stats updates (stats are not yet enabled).
	chk := func() *authz.CheckResponse {
		rsp, err := uut.Check(ctx, req)
		Expect(err).ToNot(HaveOccurred())
		return rsp
	}
	Eventually(chk, "2s", "50ms").Should(Equal(&authz.CheckResponse{Status: &status.Status{Code: PERMISSION_DENIED}}))

	// Enable stats, re-run the request and this time check we do get stats updates.
	psm.DoWithLock(func(ps *policystore.PolicyStore) {
		ps.DataplaneStatsEnabledForDenied = true
	})
	chk = func() *authz.CheckResponse {
		rsp, err := uut.Check(ctx, req)
		Expect(err).ToNot(HaveOccurred())
		return rsp
	}
	Eventually(chk).Should(Equal(&authz.CheckResponse{Status: &status.Status{Code: PERMISSION_DENIED}}))
}
