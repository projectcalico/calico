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
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/collector/goldmane"
	"github.com/projectcalico/calico/goldmane/pkg/client"
)

const (
	checkLocalSocketTimer = time.Second * 10
)

type LocalSocketReporter struct {
	client       *client.FlowClient
	clientLock   sync.RWMutex
	clientCancel context.CancelFunc
	once         sync.Once
}

func NewReporter() *LocalSocketReporter {
	return &LocalSocketReporter{}
}

func (l *LocalSocketReporter) Start() error {
	var err error
	l.once.Do(func() {
		go l.run()
	})
	return err
}

func (l *LocalSocketReporter) run() {
	for {
		if _, err := os.Stat(SocketPath); err == nil {
			l.mayStartClient()
		} else {
			l.mayStopClient()
		}
		time.Sleep(checkLocalSocketTimer)
	}
}

func (l *LocalSocketReporter) clientIsNil() bool {
	l.clientLock.RLock()
	defer l.clientLock.RUnlock()
	return l.client == nil
}

func (l *LocalSocketReporter) mayStartClient() {
	// If local socket is already setup, do not try to set it up again.
	if !l.clientIsNil() {
		return
	}

	var err error
	l.clientLock.Lock()
	defer l.clientLock.Unlock()
	l.client, err = client.NewFlowClient(SocketAddress, "", "", "")
	if err != nil {
		logrus.WithError(err).Warn("Failed to create local socket client")
		return
	}
	logrus.Info("Created local socket client")
	ctx, cancel := context.WithCancel(context.Background())
	l.clientCancel = cancel
	l.client.Connect(ctx)
}

func (l *LocalSocketReporter) mayStopClient() {
	// If local socket is already closed, do not try to close it again.
	if l.clientIsNil() {
		return
	}

	l.clientLock.Lock()
	defer l.clientLock.Unlock()
	l.clientCancel()
	l.client = nil
	logrus.Info("Destroyed local socket client")
}

func (n *LocalSocketReporter) Report(logSlice any) error {
	switch logs := logSlice.(type) {
	case []*flowlog.FlowLog:
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logrus.WithField("num", len(logs)).Debug("Dispatching flow logs to local socket")
		}
		for _, l := range logs {
			n.clientLock.RLock()
			if n.client != nil {
				n.client.Push(goldmane.ConvertFlowlogToGoldmane(l))
			}
			n.clientLock.RUnlock()
		}
	default:
		logrus.Panic("Unexpected kind of log dispatcher")
	}
	return nil
}
