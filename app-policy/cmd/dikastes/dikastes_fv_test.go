// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package main

import (
	"context"
	"net"
	"os"
	"path"
	"sync"
	"testing"

	authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"

	"github.com/projectcalico/calico/app-policy/checker"
	"github.com/projectcalico/calico/app-policy/pkg/dikastes"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/app-policy/syncher"
	"github.com/projectcalico/calico/app-policy/uds"
	"github.com/projectcalico/calico/felix/proto"
)

// TestDikastesCheckAllowProfile verifies the full ext_authz flow: sync server
// pushes an endpoint with an allow-all profile, then an authz Check request
// through the dikastes gRPC server returns OK.
func TestDikastesCheckAllowProfile(t *testing.T) {
	RegisterTestingT(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newDikastesTestEnv(t, ctx)
	defer env.cleanup()

	// Push an endpoint with an allow-all profile.
	env.sendUpdate(&proto.ToDataplane{Payload: &proto.ToDataplane_WorkloadEndpointUpdate{
		WorkloadEndpointUpdate: &proto.WorkloadEndpointUpdate{
			Id: &proto.WorkloadEndpointID{
				OrchestratorId: "k8s",
				WorkloadId:     "default/test-pod",
				EndpointId:     "eth0",
			},
			Endpoint: &proto.WorkloadEndpoint{
				ProfileIds: []string{"kns.default"},
			},
		},
	}})
	env.sendUpdate(&proto.ToDataplane{Payload: &proto.ToDataplane_ActiveProfileUpdate{
		ActiveProfileUpdate: &proto.ActiveProfileUpdate{
			Id: &proto.ProfileID{Name: "kns.default"},
			Profile: &proto.Profile{
				InboundRules: []*proto.Rule{{Action: "Allow"}},
			},
		},
	}})
	env.sendInSync()
	env.waitReady()

	resp := env.check(&authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/client",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/server",
		},
	}})
	Expect(resp.GetStatus().GetCode()).To(Equal(checker.OK))
}

// TestDikastesCheckDenyPolicy verifies that a deny policy correctly results in
// PERMISSION_DENIED through the full ext_authz gRPC flow.
func TestDikastesCheckDenyPolicy(t *testing.T) {
	RegisterTestingT(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newDikastesTestEnv(t, ctx)
	defer env.cleanup()

	env.sendUpdate(&proto.ToDataplane{Payload: &proto.ToDataplane_WorkloadEndpointUpdate{
		WorkloadEndpointUpdate: &proto.WorkloadEndpointUpdate{
			Id: &proto.WorkloadEndpointID{
				OrchestratorId: "k8s",
				WorkloadId:     "default/test-pod",
				EndpointId:     "eth0",
			},
			Endpoint: &proto.WorkloadEndpoint{
				Tiers: []*proto.TierInfo{{
					Name:            "default",
					DefaultAction:   "Deny",
					IngressPolicies: []*proto.PolicyID{{Name: "deny-all"}},
				}},
			},
		},
	}})
	env.sendUpdate(&proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyUpdate{
		ActivePolicyUpdate: &proto.ActivePolicyUpdate{
			Id: &proto.PolicyID{Name: "deny-all"},
			Policy: &proto.Policy{
				Tier:         "default",
				InboundRules: []*proto.Rule{{Action: "Deny"}},
			},
		},
	}})
	env.sendInSync()
	env.waitReady()

	resp := env.check(&authz.CheckRequest{Attributes: &authz.AttributeContext{
		Source: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/client",
		},
		Destination: &authz.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/server",
		},
	}})
	Expect(resp.GetStatus().GetCode()).To(Equal(checker.PERMISSION_DENIED))
}

// TestDikastesCheckHTTPMethodMatch verifies L7 policy matching on HTTP method
// through the full ext_authz gRPC flow.
func TestDikastesCheckHTTPMethodMatch(t *testing.T) {
	RegisterTestingT(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newDikastesTestEnv(t, ctx)
	defer env.cleanup()

	// Policy allows only GET requests.
	env.sendUpdate(&proto.ToDataplane{Payload: &proto.ToDataplane_WorkloadEndpointUpdate{
		WorkloadEndpointUpdate: &proto.WorkloadEndpointUpdate{
			Id: &proto.WorkloadEndpointID{
				OrchestratorId: "k8s",
				WorkloadId:     "default/test-pod",
				EndpointId:     "eth0",
			},
			Endpoint: &proto.WorkloadEndpoint{
				Tiers: []*proto.TierInfo{{
					Name:            "default",
					DefaultAction:   "Deny",
					IngressPolicies: []*proto.PolicyID{{Name: "allow-get"}},
				}},
			},
		},
	}})
	env.sendUpdate(&proto.ToDataplane{Payload: &proto.ToDataplane_ActivePolicyUpdate{
		ActivePolicyUpdate: &proto.ActivePolicyUpdate{
			Id: &proto.PolicyID{Name: "allow-get"},
			Policy: &proto.Policy{
				Tier: "default",
				InboundRules: []*proto.Rule{{
					Action:    "Allow",
					HttpMatch: &proto.HTTPMatch{Methods: []string{"GET"}},
				}},
			},
		},
	}})
	env.sendInSync()
	env.waitReady()

	makeReq := func(method string) *authz.CheckRequest {
		return &authz.CheckRequest{Attributes: &authz.AttributeContext{
			Source: &authz.AttributeContext_Peer{
				Principal: "spiffe://cluster.local/ns/default/sa/client",
			},
			Destination: &authz.AttributeContext_Peer{
				Principal: "spiffe://cluster.local/ns/default/sa/server",
			},
			Request: &authz.AttributeContext_Request{
				Http: &authz.AttributeContext_HttpRequest{Method: method},
			},
		}}
	}

	// GET should be allowed by the policy rule.
	resp := env.check(makeReq("GET"))
	Expect(resp.GetStatus().GetCode()).To(Equal(checker.OK))

	// POST does not match the allow rule → falls through to tier default deny.
	resp = env.check(makeReq("POST"))
	Expect(resp.GetStatus().GetCode()).To(Equal(checker.PERMISSION_DENIED))
}

// dikastesTestEnv encapsulates the full dikastes test stack: a fake Felix sync
// server, the dikastes authz gRPC server with ALPCheckProvider, and an authz
// client — all connected over Unix domain sockets.
type dikastesTestEnv struct {
	t            *testing.T
	syncServer   *testSyncServer
	syncClient   *syncher.SyncClient
	dikastesGRPC *grpc.Server
	authzClient  authz.AuthorizationClient
	authzConn    *grpc.ClientConn
	socketDir    string
	ctx          context.Context
}

func newDikastesTestEnv(t *testing.T, ctx context.Context) *dikastesTestEnv {
	t.Helper()
	RegisterTestingT(t)

	socketDir, err := os.MkdirTemp("/tmp", "dikastes-fv-")
	Expect(err).ToNot(HaveOccurred())

	// Start fake Felix sync server.
	syncSocketPath := path.Join(socketDir, "policysync.sock")
	ss := newTestSyncServer(ctx, syncSocketPath)

	// Create the dikastes authz server using the exported NewCheckServer.
	storeManager := policystore.NewPolicyStoreManager()
	gs := grpc.NewServer()
	dikastes.NewCheckServer(ctx, gs, storeManager)

	dikastesSocketPath := path.Join(socketDir, "dikastes.sock")
	lis, err := net.Listen("unix", dikastesSocketPath)
	Expect(err).ToNot(HaveOccurred())
	go func() { _ = gs.Serve(lis) }()

	// Connect sync client to populate the store.
	sc := syncher.NewClient(syncSocketPath, storeManager, uds.GetDialOptions())
	go sc.Sync(ctx)

	// Connect authz client.
	conn, err := grpc.NewClient(dikastesSocketPath, uds.GetDialOptions()...)
	Expect(err).ToNot(HaveOccurred())

	return &dikastesTestEnv{
		t:            t,
		syncServer:   ss,
		syncClient:   sc,
		dikastesGRPC: gs,
		authzClient:  authz.NewAuthorizationClient(conn),
		authzConn:    conn,
		socketDir:    socketDir,
		ctx:          ctx,
	}
}

func (e *dikastesTestEnv) sendUpdate(update *proto.ToDataplane) {
	e.syncServer.updates <- update
}

func (e *dikastesTestEnv) sendInSync() {
	e.syncServer.updates <- &proto.ToDataplane{
		Payload: &proto.ToDataplane_InSync{InSync: &proto.InSync{}},
	}
}

func (e *dikastesTestEnv) waitReady() {
	Eventually(e.syncClient.Readiness, "5s", "100ms").Should(BeTrue())
}

func (e *dikastesTestEnv) check(req *authz.CheckRequest) *authz.CheckResponse {
	resp, err := e.authzClient.Check(e.ctx, req)
	Expect(err).ToNot(HaveOccurred())
	return resp
}

func (e *dikastesTestEnv) cleanup() {
	_ = e.authzConn.Close()
	e.dikastesGRPC.GracefulStop()
	_ = os.RemoveAll(e.socketDir)
}

// testSyncServer is a minimal fake Felix PolicySync gRPC server that sends
// policy updates over a channel. Adapted from syncher/syncserver_test.go.
type testSyncServer struct {
	proto.UnimplementedPolicySyncServer
	ctx        context.Context
	updates    chan *proto.ToDataplane
	grpcServer *grpc.Server
	listener   net.Listener
	cLock      sync.Mutex
	cancelFns  []func()
}

func newTestSyncServer(ctx context.Context, socketPath string) *testSyncServer {
	ss := &testSyncServer{
		ctx:        ctx,
		updates:    make(chan *proto.ToDataplane),
		grpcServer: grpc.NewServer(),
	}
	proto.RegisterPolicySyncServer(ss.grpcServer, ss)
	lis, err := net.Listen("unix", socketPath)
	Expect(err).ToNot(HaveOccurred())
	ss.listener = lis
	go func() { _ = ss.grpcServer.Serve(lis) }()
	return ss
}

func (s *testSyncServer) Sync(_ *proto.SyncRequest, stream proto.PolicySync_SyncServer) error {
	ctx, cancel := context.WithCancel(s.ctx)
	s.cLock.Lock()
	s.cancelFns = append(s.cancelFns, cancel)
	s.cLock.Unlock()
	for {
		select {
		case <-ctx.Done():
			return nil
		case update := <-s.updates:
			if err := stream.Send(update); err != nil {
				return err
			}
		}
	}
}

func (s *testSyncServer) Report(_ context.Context, _ *proto.DataplaneStats) (*proto.ReportResult, error) {
	return &proto.ReportResult{}, nil
}
