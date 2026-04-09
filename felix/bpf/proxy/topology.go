// Copyright (c) 2017-2023 Tigera, Inc. All rights reserved.
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

package proxy

import (
	"strings"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	k8sp "k8s.io/kubernetes/pkg/proxy"
)

// FilterEpsByTopologyAwareRouting filters a slice of Kubernetes endpoints based on topology-aware routing criteria.
// It returns a subset of endpoints that match the provided node zone if topology-aware routing is enabled,
// along with a boolean indicating whether topology-aware routing was applied.
//
// Topology-aware routing is applied only if the topologyMode is "Auto" (case-insensitive).
// If any endpoint is missing zone hints, or if no endpoints match the node zone, the function falls back
// to returning all endpoints to ensure safe routing behavior.
// See: https://kubernetes.io/docs/concepts/services-networking/topology-aware-routing/
//
// Parameters:
//
//	endpoints    - Slice of k8sp.Endpoint objects to filter.
//	topologyMode - Service annotation value indicating topology-aware routing mode.
//	nodeZone     - The zone label of the current node.
//
// Returns:
//
//	[]k8sp.Endpoint - Endpoints chosen by topology-aware routing, or all endpoints if the logic falls back.
//	bool            - True if topology-aware routing logic was executed for the service, false if it was not enabled.
func FilterEpsByTopologyAwareRouting(endpoints []k8sp.Endpoint, topologyMode, nodeZone string) ([]k8sp.Endpoint, bool) {
	if strings.ToLower(topologyMode) != "auto" {
		log.Debugf(
			"Skipping topology aware endpoint filtering. Feature is enabled only when '%s' is set to 'Auto'; current value: '%s'",
			v1.AnnotationTopologyMode,
			topologyMode,
		)
		return endpoints, false
	}

	eps := make([]k8sp.Endpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		zoneHints := ep.ZoneHints()
		if !ep.IsReady() && !ep.IsTerminating() {
			log.Debugf("Topology Aware Routing: ignoring Endpoint '%s' since its status is not Ready or Terminating\n", ep.IP())
			continue
		}

		if zoneHints.Len() == 0 {
			// One EP does not have a zone hint. We assume that a transition from or to Topology Aware Hints is underway.
			// Filtering endpoints for a Service in this state would be dangerous so we falls back to using all endpoints.
			// Ref: https://kubernetes.io/docs/concepts/services-networking/topology-aware-routing/#safeguards
			log.Debugf("Topology Aware Routing: not applied since Endpoint %s is missing a zone hint", ep.IP())
			return endpoints, true
		}

		if zoneHints.Has(nodeZone) {
			eps = append(eps, ep)
		} else {
			log.Debugf("Topology Aware Routing: ignoring Endpoint '%s' since its zone '%s' does not match Zone Hints: '%v'\n",
				ep.IP(),
				nodeZone,
				zoneHints)
		}
	}

	if len(eps) == 0 {
		// If it's unable to find at least one endpoint with a hint targeting the zone it is running in,
		// it falls back to using endpoints from all zones.
		// Ref: https://kubernetes.io/docs/concepts/services-networking/topology-aware-routing/#safeguards
		log.Debugf("Topology Aware Routing: not applied since no endpoints matched for zone: '%s'\n", nodeZone)
		return endpoints, true
	}

	return eps, true
}

func filterEndpointsByHints(endpoints []k8sp.Endpoint, targetHint string, getHints func(k8sp.Endpoint) sets.Set[string]) []k8sp.Endpoint {
	eps := make([]k8sp.Endpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		epHints := getHints(ep)
		if !ep.IsReady() && !ep.IsTerminating() {
			log.Debugf("Traffic Distribution: ignoring Endpoint '%s' since its status is not Ready or Terminating\n", ep.IP())
			continue
		}

		if epHints.Has(targetHint) {
			eps = append(eps, ep)
		} else {
			log.Debugf("Traffic Distribution: ignoring Endpoint '%s' since target '%s' does not match Hints: '%v'\n",
				ep.IP(),
				targetHint,
				epHints)
		}
	}

	return eps
}

// FilterEpsByTrafficDistribution selects endpoints based on Kubernetes traffic distribution semantics.
// It prioritizes endpoints on the same node as the client, then falls back to endpoints in the same zone,
// and finally to all available endpoints if no node or zone matches are found.
// See: https://kubernetes.io/docs/reference/networking/virtual-ips/#traffic-distribution
//
// Parameters:
//
//	endpoints - List of candidate endpoints.
//	nodeName  - Name of the client node.
//	nodeZone  - Zone of the client node.
//
// Returns:
//
//	A slice of endpoints selected based on the best match with traffic distribution preference.
func FilterEpsByTrafficDistribution(endpoints []k8sp.Endpoint, nodeName, nodeZone string) []k8sp.Endpoint {
	// Try to prioritizes sending traffic to endpoints on the same node as the client.
	eps := filterEndpointsByHints(endpoints, nodeName, func(ep k8sp.Endpoint) sets.Set[string] {
		return ep.NodeHints()
	})
	if len(eps) != 0 {
		log.Debugf("Traffic Distribution applied for node: '%s' \n", nodeName)
		return eps
	}

	// If client's node does not have any available endpoints, then fall back to "same zone" behavior.
	eps = filterEndpointsByHints(endpoints, nodeZone, func(ep k8sp.Endpoint) sets.Set[string] {
		return ep.ZoneHints()
	})
	if len(eps) != 0 {
		log.Debugf("Traffic Distribution applied for zone: '%s' \n", nodeZone)
		return eps
	}

	// Fall back to cluster-wide if there are no same-zone endpoints either.
	log.Debugf("Traffic Distribution: not applied since no endpoints matched for node: '%s' or zone: '%s'\n", nodeName, nodeZone)
	return endpoints
}
