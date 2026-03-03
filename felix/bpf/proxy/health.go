// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.
//
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

// This boilerplate code is based on proxiers in k8s.io/kubernetes/pkg/proxy to
// allow reuse of the rest of the proxy package without change

package proxy

import (
	"context"
	"fmt"
	"time"

	logrus "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	k8sp "k8s.io/kubernetes/pkg/proxy"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
)

type Healthcheck interface {
	Health() healthcheck.ProxyHealth
	QueuedUpdate(v1.IPFamily)
	Updated(v1.IPFamily)
}

func NewHealthCheck(k8s kubernetes.Interface, nodeName string, port int,
	minSyncPeriod time.Duration) (Healthcheck, error) {

	nodeMgr := new(k8sp.NodeManager)
	node := &v1.Node{
		Spec: v1.NodeSpec{},
	}

	nodeMgr.OnNodeChange(node)

	healthzAddr := fmt.Sprintf(":%d", port)
	server := healthcheck.NewProxyHealthServer(healthzAddr, minSyncPeriod, nodeMgr)

	// We cannot wait for the healthz server as we cannot stop it.
	go func() {
		logrus.Infof("Starting BPF Proxy Healthz server on %s", healthzAddr)
		for {
			err := server.Run(context.Background()) // context is mosstly ignored inside
			if err != nil {
				logrus.WithError(err).Error("BPF Proxy Healthz server failed, restarting in 1s")
				time.Sleep(time.Second)
			}
		}
	}()

	return server, nil
}

type alwaysHealthy struct{}

func (a *alwaysHealthy) Health() healthcheck.ProxyHealth {
	return healthcheck.ProxyHealth{Healthy: true}
}

func (a *alwaysHealthy) QueuedUpdate(v1.IPFamily) {}
func (a *alwaysHealthy) Updated(v1.IPFamily)      {}
