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

package local

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
	SocketDir  = "/var/run/calico/flows"
	SocketName = "flows.sock"
)

var (
	SocketPath    = path.Join(SocketDir, SocketName)
	SocketAddress = fmt.Sprintf("unix://%v", SocketPath)
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

func (s *flowStore) list() []*types.Flow {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.flows
}

func (s *flowStore) flush() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.flows = nil
}

func (s *flowStore) listAndFlush() []*types.Flow {
	s.lock.Lock()
	defer s.lock.Unlock()
	flows := s.flows
	s.flows = nil
	return flows
}

type FlowServer struct {
	store      *flowStore
	grpcServer *grpc.Server
	once       sync.Once

	// In Calico node, the address of unix socket is always /var/run/calico/flows/flows.sock.
	// However, FlowServer is also used by Felix FVs, where the code is executed outside of Calico Node.
	// In this case, unix socket is created in host filesystem, and instead mounted at the mentioned path in
	// Felix containers.
	dir string
}

func NewFlowServer(dir string) *FlowServer {
	nodeServer := FlowServer{
		dir:        dir,
		grpcServer: grpc.NewServer(),
		store:      newFlowStore(),
	}
	col := server.NewFlowCollector(nodeServer.store)
	col.RegisterWith(nodeServer.grpcServer)
	return &nodeServer
}

func (s *FlowServer) Run() error {
	var err error
	err = ensureLocalSocketDirExists(s.dir)
	if err != nil {
		logrus.WithError(err).Error("Failed to create local socket")
		return err
	}

	s.once.Do(func() {
		var l net.Listener
		sockAddr := s.Address()
		l, err = net.Listen("unix", sockAddr)
		if err != nil {
			logrus.WithError(err).Error("Failed to listen on local socket")
			return
		}
		logrus.WithField("address", sockAddr).Info("Running local server")
		go func() {
			err = s.grpcServer.Serve(l)
			if err != nil {
				logrus.WithError(err).Error("Failed to start listening on local socket")
				return
			}
		}()
	})
	return err
}

func (s *FlowServer) Watch(
	ctx context.Context,
	num int,
	period time.Duration,
	processFlow func(*types.Flow),
) {
	infiniteLoop := num < 0
	var count int
	logrus.Debug("Starting to watch local socket")
	for {
		if ctx.Err() != nil ||
			(!infiniteLoop && count >= num) {
			logrus.Debug("Stopped watching local socket")
			return
		}

		flows := s.listAndFlush()
		for _, f := range flows {
			processFlow(f)
		}
		count = count + len(flows)
		time.Sleep(period)
	}
}

func (s *FlowServer) Stop() {
	cleanupLocalSocket(s.Address())
	s.grpcServer.Stop()
}

func (s *FlowServer) List() []*types.Flow {
	return s.store.list()
}

func (s *FlowServer) Flush() {
	s.store.flush()
}

func (s *FlowServer) listAndFlush() []*types.Flow {
	return s.store.listAndFlush()
}

func (s *FlowServer) Address() string {
	return path.Join(s.dir, SocketName)
}

func ensureLocalSocketDirExists(dir string) error {
	logrus.Debug("Checking if local socket exists.")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		logrus.WithField("directory", dir).Debug("Local socket directory does not exist")
		err := os.MkdirAll(dir, 0o600)
		if err != nil {
			logrus.WithError(err).WithField("directory", dir).Error("Failed to create local socket directory")
			return err
		}
		logrus.WithField("directory", dir).Debug("Created local socket directory")
	}
	return nil
}

func cleanupLocalSocket(addr string) {
	_, err := os.Stat(addr)
	if err != nil && os.IsNotExist(err) {
		return
	}
	err = os.Remove(addr)
	if err != nil {
		logrus.WithError(err).WithField("address", addr).Errorf("Failed to remove local socket")
	}
}
