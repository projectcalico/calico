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
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/goldmane/pkg/client"
)

const (
	checkNodeSocketTimer = time.Second * 10
)

type NodeSocketReporter struct {
	client       *client.FlowClient
	clientLock   sync.RWMutex
	clientCancel context.CancelFunc
	once         sync.Once
}

func NewNodeSocketReporter() *NodeSocketReporter {
	return &NodeSocketReporter{}
}

func (n *NodeSocketReporter) Start() error {
	var err error
	n.once.Do(func() {
		go n.nodeSocketReporter()
	})
	return err
}

func (n *NodeSocketReporter) nodeSocketReporter() {
	for {
		if _, err := os.Stat(NodeSocketPath); err == nil {
			n.mayStartNodeSocketReporter()
		} else {
			n.mayStopNodeSocketReporter()
		}
		time.Sleep(checkNodeSocketTimer)
	}
}

func (n *NodeSocketReporter) nodeClientIsNil() bool {
	n.clientLock.RLock()
	defer n.clientLock.RUnlock()
	return n.client == nil
}

func (n *NodeSocketReporter) mayStartNodeSocketReporter() {
	// If node socket is already setup, do not try to set it up again.
	if !n.nodeClientIsNil() {
		return
	}

	var err error
	n.clientLock.Lock()
	defer n.clientLock.Unlock()
	n.client, err = client.NewFlowClient(NodeSocketAddress, "", "", "")
	if err != nil {
		logrus.WithError(err).Warn("Failed to create goldmane node socket client")
		return
	}
	logrus.Info("Created node socket client")
	ctx, cancel := context.WithCancel(context.Background())
	n.clientCancel = cancel
	n.client.Connect(ctx)
}

func (n *NodeSocketReporter) mayStopNodeSocketReporter() {
	// If node socket is already closed, do not try to close it again.
	if n.nodeClientIsNil() {
		return
	}

	n.clientLock.Lock()
	defer n.clientLock.Unlock()
	n.clientCancel()
	n.client = nil
	logrus.Info("Destroyed node socket client")
}

func (n *NodeSocketReporter) Report(logSlice any) error {
	switch logs := logSlice.(type) {
	case []*flowlog.FlowLog:
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logrus.WithField("num", len(logs)).Debug("Dispatching flow logs to node socket")
		}
		for _, l := range logs {
			n.clientLock.RLock()
			if n.client != nil {
				n.client.Push(convertFlowlogToGoldmane(l))
			}
			n.clientLock.RUnlock()
		}
	default:
		logrus.Panic("Unexpected kind of log dispatcher")
	}
	return nil
}
