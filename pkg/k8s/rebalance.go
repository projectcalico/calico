// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	log "github.com/Sirupsen/logrus"

	"github.com/projectcalico/typha/pkg/config"
	"github.com/projectcalico/typha/pkg/jitter"
)

type maxConnsAPI interface {
	SetMaxConns(numConns int)
}

func PollK8sForConnectionLimit(configParams *config.Config, server maxConnsAPI) {
	logCxt := log.WithField("thread", "k8s-poll")
	logCxt.Info("Kubernetes poll goroutine started.")
	ticker := jitter.NewTicker(configParams.K8sServicePollIntervalSecs, configParams.K8sServicePollIntervalSecs/10)
	activeTarget := configParams.MaxConnectionsUpperLimit
	for {
		<-ticker.C
		// Get the number of Typhas in the service.
		numTyphas, err := GetNumTyphas(
			configParams.K8sNamespace,
			configParams.K8sServiceName,
			configParams.K8sPortName,
		)
		if err != nil || numTyphas <= 0 {
			logCxt.WithError(err).Warn("Failed to get number of Typhas, removing connection limit")
			server.SetMaxConns(configParams.MaxConnectionsUpperLimit)
			continue
		}
		// Get the number of nodes as an estimate for the number of Felix connections we should expect.
		numNodes, err := GetNumNodes()
		if err != nil || numNodes <= 0 {
			logCxt.WithError(err).Warn("Failed to get number of nodes, removing connection limit")
			server.SetMaxConns(configParams.MaxConnectionsUpperLimit)
			continue
		}

		reason := "configured lower limit"
		target := configParams.MaxConnectionsLowerLimit
		if numTyphas <= 1 {
			reason = "lone typha"
			target = configParams.MaxConnectionsUpperLimit
		} else {
			candidate := 1 + numNodes*120/(numTyphas-1)/100
			if candidate > target {
				reason = "fraction+20%"
				target = candidate
			}
		}
		if target > configParams.MaxConnectionsUpperLimit {
			reason = "configured upper limit"
			target = configParams.MaxConnectionsUpperLimit
		}

		if target != activeTarget {
			logCxt.WithFields(log.Fields{
				"numTyphas": numTyphas,
				"numNodes":  numNodes,
				"newLimit":  target,
				"reason":    reason,
			}).Info("Calculated new connection limit.")
			server.SetMaxConns(target)
			activeTarget = target
		}
	}
}
