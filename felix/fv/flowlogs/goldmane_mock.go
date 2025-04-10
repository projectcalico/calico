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

package flowlogs

import (
	"fmt"
	"net"
	"sync"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/projectcalico/calico/goldmane/pkg/server"
	"github.com/projectcalico/calico/goldmane/pkg/types"
)

const (
	LocalGoldmaneServer = "unix:///var/log/calico/flowlogs/goldmane.sock"
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

type GoldmaneMock struct {
	store      *flowStore
	grpcServer *grpc.Server
	once       sync.Once
	sockAddr   string
}

func NewGoldmaneMock(addr string) *GoldmaneMock {
	return &GoldmaneMock{
		sockAddr: addr,
	}
}

func (g *GoldmaneMock) Run() {
	g.once.Do(func() {
		g.grpcServer = grpc.NewServer()
		g.store = newFlowStore()
		col := server.NewFlowCollector(g.store)
		col.RegisterWith(g.grpcServer)

		l, err := net.Listen("unix", g.sockAddr)
		if err != nil {
			panic(fmt.Sprintf("failed to start goldmane listener at %v - err: %v", g.sockAddr, err))
		}
		logrus.Infof("Running goldmane mock server at %v", g.sockAddr)
		go func() {
			err := g.grpcServer.Serve(l)
			if err != nil {
				panic(fmt.Sprintf("failed to start goldmane mock server - err: %v", err))
			}
		}()
	})
}

func (g *GoldmaneMock) Stop() {
	g.grpcServer.GracefulStop()
}

func (g *GoldmaneMock) List() []*types.Flow {
	return g.store.List()
}

func (g *GoldmaneMock) Flush() {
	g.store.Flush()
}
