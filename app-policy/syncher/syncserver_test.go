// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package syncher

import (
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"google.golang.org/grpc"

	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/app-policy/uds"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

var _ policystore.PolicyStoreManager = (*mockPolicyStoreManager)(nil)

type mockPolicyStoreManager struct {
	callstack []string
	toActive  bool
	rev       uint

	mu sync.Mutex
}

func (mp *mockPolicyStoreManager) OnReconnecting() {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	mp.callstack = append(mp.callstack, "onreconnecting")
}

func (mp *mockPolicyStoreManager) OnInSync() {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	mp.callstack = append(mp.callstack, "oninsync")
}

func (mp *mockPolicyStoreManager) GetCurrentEndpoints() map[types.WorkloadEndpointID]*proto.WorkloadEndpoint {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	mp.callstack = append(mp.callstack, "getcurrentendpoints")

	return nil
}

func (mp *mockPolicyStoreManager) DoWithReadLock(func(*policystore.PolicyStore)) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	mp.callstack = append(mp.callstack, fmt.Sprint("read", mp.toActive, mp.rev))
}

func (mp *mockPolicyStoreManager) DoWithLock(func(*policystore.PolicyStore)) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	mp.callstack = append(mp.callstack, fmt.Sprint("write", mp.toActive, mp.rev))
}

/*func (mp *mockPolicyStoreManager) runAssertions(cb func([]string)) {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	cb(mp.callstack)
}*/

func newMockPolicyStoreManager() policystore.PolicyStoreManager {
	return &mockPolicyStoreManager{}
}

// TODO (mazdak): fix this
/*func TestSyncRestart(t *testing.T) {
	RegisterTestingT(t)

	server := newTestSyncServer()
	defer server.Shutdown()
	server.Start()

	psm := newMockPolicyStoreManager()
	uut := NewClient(server.GetTarget(), psm, uds.GetDialOptions(), WithSubscriptionType(""))

	cCtx, cCancel := context.WithCancel(context.Background())
	defer cCancel()
	if err := uut.Start(cCtx); err != nil {
		t.Fatal(err)
	}

	if uut.Readiness() {
		t.Error("Expected syncClient not to be ready before receiving inSync")
	}

	server.SendInSync()
	Eventually(uut.Readiness, "2s", "200ms").Should(BeTrue())
	server.Restart()
	Eventually(uut.Readiness, "2s", "200ms").ShouldNot(BeTrue())
	server.SendInSync()
	Eventually(uut.Readiness, "2s", "200ms").Should(BeTrue())

	mp, ok := psm.(*mockPolicyStoreManager)
	if !ok {
		t.Fatal("this test must run with mocked PolicyStoreManager")
	}
	mp.runAssertions(func(callstack []string) {
		assert.ElementsMatch(t, callstack, []string{
			"onreconnecting",
			"oninsync",
			"onreconnecting",
			"oninsync",
		})
	})

	if !uut.Readiness() {
		t.Error("Expected syncClient to be ready after receiving inSync")
	}
}*/

func TestSyncCancelBeforeInSync(t *testing.T) {
	RegisterTestingT(t)

	server := newTestSyncServer()
	defer server.Shutdown()
	server.Start()

	psm := newMockPolicyStoreManager()
	uut := NewClient(server.GetTarget(), psm, uds.GetDialOptions(), WithSubscriptionType(""))

	cCtx, cCancel := context.WithCancel(context.Background())
	if err := uut.Start(cCtx); err != nil {
		t.Fatal(err)
	}

	time.Sleep(10 * time.Millisecond)
	cCancel()
	Expect(uut.Readiness()).To(Equal(false))
}

func TestSyncCancelAfterInSync(t *testing.T) {
	RegisterTestingT(t)

	server := newTestSyncServer()
	defer server.Shutdown()
	server.Start()

	psm := newMockPolicyStoreManager()
	uut := NewClient(server.GetTarget(), psm, uds.GetDialOptions(), WithSubscriptionType(""))

	cCtx, cCancel := context.WithCancel(context.Background())
	if err := uut.Start(cCtx); err != nil {
		t.Fatal(err)
	}

	server.SendInSync()
	Eventually(uut.Readiness, "2s", "100ms").Should(BeTrue())

	cCancel()
	Eventually(uut.Readiness, "2s", "100ms").Should(BeFalse())
}

func TestSyncServerCancelBeforeInSync(t *testing.T) {
	RegisterTestingT(t)

	server := newTestSyncServer()
	defer server.Shutdown()
	server.Start()

	psm := newMockPolicyStoreManager()
	uut := NewClient(server.GetTarget(), psm, uds.GetDialOptions(), WithSubscriptionType(""))

	cCtx, cCancel := context.WithCancel(context.Background())
	defer cCancel()

	if err := uut.Start(cCtx); err != nil {
		t.Fatal(err)
	}

	server.Shutdown()
	time.Sleep(10 * time.Millisecond)
	cCancel()
	Eventually(uut.Readiness, "2s", "100ms").Should(BeFalse())
}

type testSyncServer struct {
	cxt              context.Context
	cancel           func()
	updates          chan *proto.ToDataplane
	path             string
	gRPCServer       *grpc.Server
	listener         net.Listener
	cLock            sync.Mutex
	cancelFns        []func()
	dpStats          []*proto.DataplaneStats
	reportSuccessful bool
	proto.UnimplementedPolicySyncServer
}

func newTestSyncServer() *testSyncServer {
	cxt, cancel := context.WithCancel(context.Background())
	socketDir := makeTmpListenerDir()
	socketPath := path.Join(socketDir, ListenerSocket)
	s := &testSyncServer{
		cxt: cxt, cancel: cancel, updates: make(chan *proto.ToDataplane), path: socketPath, gRPCServer: grpc.NewServer(),
		reportSuccessful: true,
	}
	proto.RegisterPolicySyncServer(s.gRPCServer, s)
	return s
}

func (s *testSyncServer) Shutdown() {
	s.cancel()
	s.Stop()
}

func (s *testSyncServer) Start() {
	s.listen()
}

func (s *testSyncServer) Stop() {
	s.cLock.Lock()
	for _, c := range s.cancelFns {
		c()
	}
	s.cancelFns = make([]func(), 0)
	s.cLock.Unlock()

	err := os.Remove(s.path)
	if err != nil && !os.IsNotExist(err) {
		// A test may call Stop/Shutdown multiple times. It shouldn't fail if it does.
		Expect(err).ToNot(HaveOccurred())
	}
}

func (s *testSyncServer) Restart() {
	s.Stop()
	s.Start()
}

func (s *testSyncServer) Sync(_ *proto.SyncRequest, stream proto.PolicySync_SyncServer) error {
	ctx, cancel := context.WithCancel(s.cxt)
	s.cLock.Lock()
	s.cancelFns = append(s.cancelFns, cancel)
	s.cLock.Unlock()
	var update *proto.ToDataplane
	for {
		select {
		case <-ctx.Done():
			return nil
		case update = <-s.updates:
			err := stream.Send(update)
			if err != nil {
				return err
			}
		}
	}
}

func (s *testSyncServer) Report(_ context.Context, d *proto.DataplaneStats) (*proto.ReportResult, error) {
	s.cLock.Lock()
	defer s.cLock.Unlock()

	if !s.reportSuccessful {
		// Mimicking unsuccessful report, don't store the stats - exit returning unsuccessful.
		return &proto.ReportResult{
			Successful: false,
		}, nil
	}
	// Store the stats and return succes.
	s.dpStats = append(s.dpStats, d)
	return &proto.ReportResult{
		Successful: true,
	}, nil
}

func (s *testSyncServer) SendInSync() {
	s.updates <- &proto.ToDataplane{Payload: &proto.ToDataplane_InSync{InSync: &proto.InSync{}}}
}

func (s *testSyncServer) GetTarget() string {
	return s.path
}

func (s *testSyncServer) GetDataplaneStats() []*proto.DataplaneStats {
	s.cLock.Lock()
	defer s.cLock.Unlock()
	stats := make([]*proto.DataplaneStats, len(s.dpStats))
	copy(stats, s.dpStats)
	return stats
}

func (s *testSyncServer) SetReportSuccessful(ret bool) {
	s.cLock.Lock()
	defer s.cLock.Unlock()
	s.reportSuccessful = ret
}

func (s *testSyncServer) listen() {
	var err error

	s.listener = openListener(s.path)
	go func() {
		err = s.gRPCServer.Serve(s.listener)
	}()
	Expect(err).ToNot(HaveOccurred())
}

const ListenerSocket = "policysync.sock"

func makeTmpListenerDir() string {
	dirPath, err := os.MkdirTemp("/tmp", "felixut")
	Expect(err).ToNot(HaveOccurred())
	return dirPath
}

func openListener(socketPath string) net.Listener {
	lis, err := net.Listen("unix", socketPath)
	Expect(err).ToNot(HaveOccurred())
	return lis
}
