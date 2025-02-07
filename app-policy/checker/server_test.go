// Copyright (c) 2018-2022 Tigera, Inc. All rights reserved.

package checker

// . "github.com/onsi/gomega"

// . "github.com/onsi/gomega"

/*func TestCheckNoStore(t *testing.T) {
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
}*/

/*func TestCheckStoreNoHTTP(t *testing.T) {
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
}*/

/*func TestCheckStoreHTTPAllowed(t *testing.T) {
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
}*/

/*func TestCheckStoreHTTPDenied(t *testing.T) {
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
}*/
