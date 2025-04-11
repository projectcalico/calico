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
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/projectcalico/calico/goldmane/pkg/server"
	"github.com/projectcalico/calico/goldmane/pkg/types"
)

const (
	NodeSocketDir  = "/var/log/calico/flowlogs"
	NodeSocketName = "goldmane.sock"
)

var (
	NodeSocketPath    = path.Join(NodeSocketDir, NodeSocketName)
	NodeSocketAddress = fmt.Sprintf("unix://%v", NodeSocketPath)
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
	s.lock.RLock()
	defer s.lock.RUnlock()
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

	// In Calico node, the address of unix socket is always /var/log/calico/flowlogs/goldmane.sock.
	// However, NodeServer is also used by Felix FVs, where the code is executed outside of Calico Node. In this case,
	// unix socket is created in host filesystem, and instead mounted at the mentioned path in Felix containers.
	dir string
}

func NewNodeServer(dir string) *NodeServer {
	nodeServer := NodeServer{
		dir:        dir,
		grpcServer: grpc.NewServer(),
		store:      newFlowStore(),
	}
	col := server.NewFlowCollector(nodeServer.store)
	col.RegisterWith(nodeServer.grpcServer)
	return &nodeServer
}

func (s *NodeServer) Run() error {
	var err error
	err = ensureNodeSocketDirExists(s.dir)
	if err != nil {
		logrus.WithError(err).Error("Failed to create goldmane node socket")
		return err
	}

	s.once.Do(func() {
		var l net.Listener
		sockAddr := s.Address()
		l, err = net.Listen("unix", sockAddr)
		if err != nil {
			return
		}
		logrus.WithField("address", sockAddr).Info("Running goldmane node server")
		go func() {
			err = s.grpcServer.Serve(l)
			if err != nil {
				return
			}
		}()
	})
	return nil
}

func (s *NodeServer) Watch(ctx context.Context, num int, processFlow func(*types.Flow)) {
	infinitLoop := num < 0
	var count int
	logrus.Debug("Starting to watch goldmane node socket")
	for {
		if ctx.Err() != nil ||
			(!infinitLoop && count >= num) {
			logrus.Debug("Stopped watching goldmane node socket")
			return
		}

		flows := s.ListAndFlush()
		for _, f := range flows {
			processFlow(f)
		}
		count = count + len(flows)
		time.Sleep(time.Second)
	}
}

func (s *NodeServer) Stop() {
	cleanupNodeSocket(s.Address())
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

func (s *NodeServer) Address() string {
	return path.Join(s.dir, NodeSocketName)
}

func ensureNodeSocketDirExists(dir string) error {
	logrus.Debug("Checking if goldmane node socket exists.")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		logrus.WithField("directory", dir).Debug("Goldmane node socket directory does not exist")
		err := os.MkdirAll(dir, 0o600)
		if err != nil {
			logrus.WithError(err).WithField("directory", dir).Error("Failed to create node socket directory")
			return err
		}
		logrus.WithField("directory", dir).Debug("Created goldmane node socket directory")
	}
	return nil
}

func cleanupNodeSocket(addr string) {
	nodeSocketExists := func(addr string) bool {
		_, err := os.Stat(addr)
		// In case of any error, return false
		return err == nil
	}

	if nodeSocketExists(addr) {
		err := os.Remove(addr)
		if err != nil {
			logrus.WithError(err).WithField("address", addr).Errorf("Failed to remove goldmane node socket")
		}
	}
}
