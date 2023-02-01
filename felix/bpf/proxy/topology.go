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
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

func ShouldAppendTopologyAwareEndpoint(nodeZone string, hintsAnnotation string, zoneHints sets.String) bool {

	// In order for an endpoint to be Topology Aware and added to endpoint collection the following must be true
	// Service annotation contains: "service.kubernetes.io/topology-aware-hints: auto"
	// Node label map contains: "topology.kubernetes.io/zone=ZONE"
	// Endpoint slice contains hints forZone=ZONE"

	// If all of the above match then return true such that the endpoint is Topology Aware thus added to the collection;
	// If service is annotated but endpoint slice zone hint is not included in the node label entry then do not append;
	// Otherwise default to appending the endpoint to the collection as before.

	// If hints annotation is not recognized or empty then ignore Topology Aware Hints.
	if hintsAnnotation != "Auto" && hintsAnnotation != "auto" {
		if hintsAnnotation != "" && hintsAnnotation != "Disabled" && hintsAnnotation != "disabled" {
			log.Debugf("Skipping topology aware endpoint filtering since Service has unexpected value '%s' for key '%s'\n", hintsAnnotation, v1.AnnotationTopologyAwareHints)
		}

		return true
	}

	// If node zone is empty then ignore Topology Aware Hints.
	if len(nodeZone) == 0 {
		log.Debugf("Skipping topology aware endpoint filtering since node zone is empty")
		return true
	}

	// If there are no endpoint zone hints then ignore Topology Aware Hints.
	if zoneHints.Len() == 0 {
		log.Debugf("Skipping topology aware endpoint filtering since one or more endpoints is missing a zone hint")
		return true
	}

	// Return whether zone hints contain node label zone.
	return zoneHints.Has(nodeZone)
}
