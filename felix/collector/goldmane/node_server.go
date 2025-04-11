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
	NodeSocketAddress = "unix:///var/log/calico/flowlogs/goldmane.sock"
	NodeSocketPath    = "/var/log/calico/flowlogs"
	NodeSocketName    = "goldmane.sock"
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
	sockAddr   string
}

func NewNodeServer(dir string) *NodeServer {
	nodeServer := NodeServer{
		sockAddr:   path.Join(dir, NodeSocketName),
		grpcServer: grpc.NewServer(),
		store:      newFlowStore(),
	}
	col := server.NewFlowCollector(nodeServer.store)
	col.RegisterWith(nodeServer.grpcServer)
	return &nodeServer
}

func (s *NodeServer) Run() error {
	var err error
	err = ensureNodeSocketDirExists(s.sockAddr)
	if err != nil {
		logrus.WithError(err).Error("Failed to create goldmane node socket")
		return err
	}

	s.once.Do(func() {
		var l net.Listener
		l, err = net.Listen("unix", s.sockAddr)
		if err != nil {
			return
		}
		logrus.WithField("address", s.sockAddr).Info("Running goldmane node server")
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
	cleanupNodeSocket(s.sockAddr)
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

func ensureNodeSocketDirExists(addr string) error {
	path := path.Dir(addr)
	logrus.Debug("Checking if goldmane node socket exists.")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		logrus.WithField("path", path).Debug("Goldmane node socket directory does not exist")
		err := os.MkdirAll(path, 0o600)
		if err != nil {
			logrus.WithError(err).WithField("address", addr).Error("Failed to create node socket directory")
			return err
		}
		logrus.WithField("path", path).Debug("Created goldmane node socket directory")
	}
	return nil
}

func cleanupNodeSocket(addr string) {
	if NodeSocketExists() {
		err := os.Remove(addr)
		if err != nil {
			logrus.WithError(err).WithField("address", addr).Errorf("Failed to remove goldmane node socket")
		}
	}
}

func NodeSocketExists() bool {
	_, err := os.Stat(NodeSocketAddress)
	// In case of any error, return false
	return err == nil
}
