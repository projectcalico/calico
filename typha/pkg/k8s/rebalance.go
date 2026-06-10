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
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/typha/pkg/config"
	"github.com/projectcalico/calico/typha/pkg/rolemanager"
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
			// Get the number of nodes.  We expect one syncer connection of each type per node.
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

// TierConnCounts carries the inputs the tier-aware connection-limit math needs:
// how many Typhas sit in each tier and how many nodes (≈ leaf clients) there
// are.  numTier2 excludes the leader and tier-1 Typhas.
type TierConnCounts struct {
	NumNodes  int // total cluster nodes (≈ number of leaf clients × syncer types)
	NumTier1  int // number of tier-1 Typhas (0 in single-tier mode)
	NumTier2  int // number of tier-2 Typhas (leaf-serving)
	NumSyncer int // number of syncer types (each client opens one conn per type)
}

// CalculateMaxConnLimitForTier computes the per-Typha connection-limit for a
// Typha serving in servingTier, given the per-tier population.  It generalises
// CalculateMaxConnLimit to the two-tier topology (WS-E):
//
//   - TierTwo serves leaf clients: expected conns ≈ nodes × syncerTypes ÷ #tier2.
//   - TierOne serves tier-2 Typhas: expected ≈ #tier2 × syncerTypes ÷ #tier1.
//   - TierLeader serves tier-1 Typhas: expected ≈ #tier1 × syncerTypes
//     (the leader is a single instance per syncer fan-out target).
//
// In single-tier mode (NumTier1==0) a TierLeader Typha serves leaf clients
// directly, so it falls back to the original node-based math — preserving WS-C
// behaviour exactly.  The same headroom / lower / upper clamping as
// CalculateMaxConnLimit is applied.
func CalculateMaxConnLimitForTier(
	configParams *config.Config,
	servingTier rolemanager.Role,
	counts TierConnCounts,
) (target int, reason string) {
	// Single-tier mode: there are no tier-1 Typhas, so the leader serves leaf
	// clients exactly as a lone/clustered Typha does today.  Use the original
	// node-based fraction over the tier-2 population (the only serving tier).
	if counts.NumTier1 <= 0 {
		numServing := counts.NumTier2
		if servingTier == rolemanager.Leader {
			// Leader counts itself among the leaf-servers in single-tier mode.
			numServing = counts.NumTier2 + 1
		}
		return CalculateMaxConnLimit(configParams, numServing, counts.NumNodes, counts.NumSyncer)
	}

	// Two-tier mode: pick the expected upstream/client population for this tier.
	var expectedClients, peers int
	switch servingTier {
	case rolemanager.Leader:
		// Leader serves the tier-1 Typhas (one conn per syncer type each).  There
		// is a single leader, so no peer division.
		expectedClients = counts.NumTier1 * counts.NumSyncer
		peers = 1
	case rolemanager.Tier1:
		// Tier-1 collectively serve the tier-2 Typhas.
		expectedClients = counts.NumTier2 * counts.NumSyncer
		peers = counts.NumTier1
	default: // Tier2
		// Tier-2 collectively serve the leaf clients (≈ one per node per syncer).
		expectedClients = counts.NumNodes * counts.NumSyncer
		peers = counts.NumTier2
	}

	return distributeWithHeadroom(configParams, expectedClients, peers)
}

// distributeWithHeadroom divides expectedClients across peers, applying the same
// "minus-one peer for rolling-upgrade slack + 20% headroom" logic as
// CalculateMaxConnLimit, then clamps to the configured lower/upper limits.
func distributeWithHeadroom(configParams *config.Config, expectedClients, peers int) (target int, reason string) {
	reason = "configured lower limit"
	target = configParams.MaxConnectionsLowerLimit
	if peers <= 1 {
		reason = "lone server in tier"
		target = configParams.MaxConnectionsUpperLimit
		return
	}
	const headroomPercent = 20
	// Subtract one peer for rolling-upgrade slack; add 20% headroom.
	candidate := 1 + expectedClients*(100+headroomPercent)/(peers-1)/100
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
