// Copyright (c) 2017,2020 Tigera, Inc. All rights reserved.
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

package k8s

import (
	log "github.com/sirupsen/logrus"

	"context"
	"time"

	"github.com/projectcalico/calico/typha/pkg/config"
)

type MaxConnsAPI interface {
	SetMaxConns(numConns int)
}

type K8sAPI interface {
	GetNumTyphas(ctx context.Context, namespace, serviceName, portName string) (int, error)
	GetNumNodes() (int, error)
}

func PollK8sForConnectionLimit(
	cxt context.Context,
	configParams *config.Config,
	tickerC <-chan time.Time,
	k8sAPI K8sAPI,
	server MaxConnsAPI,
	numSyncerTypes int,
) {
	logCxt := log.WithField("thread", "k8s-poll")
	logCxt.Info("Kubernetes poll goroutine started.")
	activeTarget := configParams.MaxConnectionsUpperLimit
	for {
		select {
		case <-tickerC:
			// Get the number of Typhas in the service.
			reqCtx, cancel := context.WithTimeout(cxt, 30*time.Second)
			numTyphas, tErr := k8sAPI.GetNumTyphas(reqCtx, configParams.K8sNamespace, configParams.K8sServiceName, configParams.K8sPortName)
			cancel()
			if tErr != nil || numTyphas <= 0 {
				logCxt.WithError(tErr).WithField("numTyphas", numTyphas).Warn(
					"Failed to get number of Typhas")
			}
			// Get the number of nodes as an estimate for the number of Felix connections we should expect.
			numNodes, nErr := k8sAPI.GetNumNodes()
			if nErr != nil || numNodes <= 0 {
				logCxt.WithError(nErr).WithField("numNodes", numNodes).Warn(
					"Failed to get number of nodes")
			}

			target := configParams.MaxConnectionsUpperLimit
			reason := "error"
			if tErr == nil && nErr == nil {
				target, reason = CalculateMaxConnLimit(configParams, numTyphas, numNodes, numSyncerTypes)
			}

			if target != activeTarget {
				logCxt.WithFields(log.Fields{
					"numTyphas":      numTyphas,
					"numNodes":       numNodes,
					"numSyncerTypes": numSyncerTypes,
					"newLimit":       target,
					"reason":         reason,
				}).Info("Calculated new connection limit.")
				server.SetMaxConns(target)
				activeTarget = target
			}
		case <-cxt.Done():
			logCxt.Info("Context finished")
			return
		}
	}
}

func CalculateMaxConnLimit(configParams *config.Config, numTyphas, numNodes, numSyncerTypes int) (target int, reason string) {
	reason = "configured lower limit"
	target = configParams.MaxConnectionsLowerLimit
	if numTyphas <= 1 {
		reason = "lone typha"
		target = configParams.MaxConnectionsUpperLimit
		return
	}
	// We subtract 1 from the number of Typhas when calculating the fraction to allow for one Typha
	// dying during a rolling upgrade, for example.  That does mean our load will be less even but
	// it reduces the number of expensive disconnections.  We add 20% to give some further headroom.
	const headroomPercent = 20
	candidate := numSyncerTypes * (1 + numNodes*(100+headroomPercent)/(numTyphas-1)/100)
	if candidate > target {
		reason = "fraction+20%"
		target = candidate
	}
	if target > configParams.MaxConnectionsUpperLimit {
		reason = "configured upper limit"
		target = configParams.MaxConnectionsUpperLimit
	}
	return
}
