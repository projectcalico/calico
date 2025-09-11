// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package protoconv

import (
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/epstatusfile"
)

// WorkloadEndpointIDToWorkloadEndpointKey converts the proto representation
// of an endpoint key back to the canonical model structure.
// Returns nil if passed a nilptr.
func WorkloadEndpointIDToWorkloadEndpointKey(id *proto.WorkloadEndpointID, hostname string) *model.WorkloadEndpointKey {
	if id == nil {
		return nil
	}

	key := &model.WorkloadEndpointKey{
		Hostname:       hostname,
		OrchestratorID: id.OrchestratorId,
		WorkloadID:     id.WorkloadId,
		EndpointID:     id.EndpointId,
	}
	logrus.WithField("key", key).Debug("Generating WorkloadEndpointKey from WorkloadEndpointID")
	return key
}

// WorkloadEndpointToEndpointStatus constructs WorkloadEndpointStatus data from a proto WorkloadEndpoint struct.
func WorkloadEndpointToWorkloadEndpointStatus(ep *proto.WorkloadEndpoint) *epstatusfile.WorkloadEndpointStatus {
	if ep == nil {
		return nil
	}

	var peerName string
	if ep.LocalBgpPeer != nil {
		peerName = ep.LocalBgpPeer.BgpPeerName
	}
	epStatus := &epstatusfile.WorkloadEndpointStatus{
		IfaceName: ep.Name,
		Mac:       ep.Mac,
		// Make sure that zero length slice is nilled out so that it compares
		// equal after round-tripping through JSON.
		Ipv4Nets:    normaliseZeroLenSlice(ep.Ipv4Nets),
		Ipv6Nets:    normaliseZeroLenSlice(ep.Ipv6Nets),
		BGPPeerName: peerName,
	}
	return epStatus
}

func normaliseZeroLenSlice[T any](nets []T) []T {
	if len(nets) == 0 {
		return nil
	}
	return nets
}
