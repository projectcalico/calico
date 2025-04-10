// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package goldmane

import (
	"net"
	"sync"

	"github.com/projectcalico/calico/goldmane/pkg/server"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

const (
	LocalGoldmaneServer = "/var/log/calico/flowlogs/goldmane.sock"
)

type flowStore struct {
	lock  sync.RWMutex
	flows []*types.Flow
}

func newFlowStore() *flowStore {
	return &flowStore{}
}

func (s *flowStore) Receive(f *types.Flow) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.flows = append(s.flows, f)
}

func (s *flowStore) List() []*types.Flow {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.flows
}

func (s *flowStore) Flush() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.flows = nil
}

func (s *flowStore) ListAndFlush() []*types.Flow {
	s.lock.Lock()
	defer s.lock.Unlock()
	flows := s.flows
	s.flows = nil
	return flows
}

type NodeServer struct {
	store      *flowStore
	grpcServer *grpc.Server
	once       sync.Once
	sockAddr   string
}

func NewNodeServer(addr string) *NodeServer {
	nodeServer := NodeServer{
		sockAddr:   addr,
		grpcServer: grpc.NewServer(),
		store:      newFlowStore(),
	}
	col := server.NewFlowCollector(nodeServer.store)
	col.RegisterWith(nodeServer.grpcServer)
	return &nodeServer
}

func (s *NodeServer) Run() error {
	var err error
	s.once.Do(func() {
		var l net.Listener
		l, err = net.Listen("unix", s.sockAddr)
		if err != nil {
			return
		}
		logrus.Infof("Running goldmane local server at %v", s.sockAddr)
		go func() {
			err = s.grpcServer.Serve(l)
			if err != nil {
				return
			}
		}()
	})
	return nil
}

func (s *NodeServer) Stop() {
	s.grpcServer.Stop()
}

func (s *NodeServer) List() []*types.Flow {
	return s.store.List()
}

func (s *NodeServer) Flush() {
	s.store.Flush()
}

func (s *NodeServer) ListAndFlush() []*types.Flow {
	return s.store.ListAndFlush()
}
