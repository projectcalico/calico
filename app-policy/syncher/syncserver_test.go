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
)

func TestSyncRestart(t *testing.T) {
	RegisterTestingT(t)

	sCtx, sCancel := context.WithCancel(context.Background())
	defer sCancel()

	server := newTestSyncServer(sCtx)

	storeManager := policystore.NewPolicyStoreManager()
	uut := NewClient(server.GetTarget(), storeManager, uds.GetDialOptions())

	cCtx, cCancel := context.WithCancel(context.Background())
	defer cCancel()
	go uut.Sync(cCtx)

	if uut.Readiness() {
		t.Error("Expected syncClient not to be ready before receiving inSync")
	}

	server.SendInSync()
	Eventually(uut.Readiness, "2s", "200ms").Should(BeTrue())

	server.Restart()
	Eventually(uut.Readiness, "2s", "200ms").ShouldNot(BeTrue())

	server.SendInSync()
	Eventually(uut.Readiness, "2s", "200ms").Should(BeTrue())

	if !uut.Readiness() {
		t.Error("Expected syncClient to be ready after receiving inSync")
	}
}

func TestSyncCancelBeforeInSync(t *testing.T) {
	RegisterTestingT(t)

	sCtx, sCancel := context.WithCancel(context.Background())
	defer sCancel()

	server := newTestSyncServer(sCtx)

	storeManager := policystore.NewPolicyStoreManager()
	uut := NewClient(server.GetTarget(), storeManager, uds.GetDialOptions())

	cCtx, cCancel := context.WithCancel(context.Background())
	syncDone := make(chan struct{})
	go func() {
		uut.Sync(cCtx)
		close(syncDone)
	}()

	time.Sleep(10 * time.Millisecond)
	cCancel()
	Eventually(syncDone).Should(BeClosed())
}

func TestSyncCancelAfterInSync(t *testing.T) {
	RegisterTestingT(t)

	sCtx, sCancel := context.WithCancel(context.Background())
	defer sCancel()

	server := newTestSyncServer(sCtx)

	storeManager := policystore.NewPolicyStoreManager()
	uut := NewClient(server.GetTarget(), storeManager, uds.GetDialOptions())

	cCtx, cCancel := context.WithCancel(context.Background())
	syncDone := make(chan struct{})
	go func() {
		uut.Sync(cCtx)
		close(syncDone)
	}()

	server.SendInSync()
	Eventually(uut.Readiness, "2s", "200ms").Should(BeTrue())
	cCancel()
	Eventually(syncDone).Should(BeClosed())
}

func TestSyncServerCancelBeforeInSync(t *testing.T) {
	RegisterTestingT(t)

	sCtx, sCancel := context.WithCancel(context.Background())

	server := newTestSyncServer(sCtx)

	storeManager := policystore.NewPolicyStoreManager()
	uut := NewClient(server.GetTarget(), storeManager, uds.GetDialOptions())

	cCtx, cCancel := context.WithCancel(context.Background())
	syncDone := make(chan struct{})
	go func() {
		uut.Sync(cCtx)
		close(syncDone)
	}()

	sCancel()
	time.Sleep(10 * time.Millisecond)
	cCancel()
	Eventually(syncDone).Should(BeClosed())
}

type testSyncServer struct {
	proto.UnimplementedPolicySyncServer
	context    context.Context
	updates    chan *proto.ToDataplane
	path       string
	gRPCServer *grpc.Server
	listener   net.Listener
	cLock      sync.Mutex
	cancelFns  []func()
}

func newTestSyncServer(ctx context.Context) *testSyncServer {
	socketDir := makeTmpListenerDir()
	socketPath := path.Join(socketDir, ListenerSocket)
	ss := &testSyncServer{context: ctx, updates: make(chan *proto.ToDataplane), path: socketPath, gRPCServer: grpc.NewServer()}
	proto.RegisterPolicySyncServer(ss.gRPCServer, ss)
	ss.listen()
	return ss
}

func (s *testSyncServer) Sync(_ *proto.SyncRequest, stream proto.PolicySync_SyncServer) error {
	ctx, cancel := context.WithCancel(s.context)
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

func (s *testSyncServer) Report(_ context.Context, _ *proto.DataplaneStats) (*proto.ReportResult, error) {
	panic("not implemented")
}

func (s *testSyncServer) SendInSync() {
	s.updates <- &proto.ToDataplane{Payload: &proto.ToDataplane_InSync{InSync: &proto.InSync{}}}
}

func (s *testSyncServer) Restart() {
	s.cLock.Lock()
	for _, c := range s.cancelFns {
		c()
	}
	s.cancelFns = make([]func(), 0)
	s.cLock.Unlock()

	err := os.Remove(s.path)
	Expect(err).ToNot(HaveOccurred())

	s.listen()
}

func (s *testSyncServer) GetTarget() string {
	return s.path
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
