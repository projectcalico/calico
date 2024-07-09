// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

package types

import (
	"github.com/projectcalico/calico/felix/proto"
)

type WorkloadEndpointID struct {
	OrchestratorId string
	WorkloadId     string
	EndpointId     string
}

func ProtoToWorkloadEndpointID(w *proto.WorkloadEndpointID) WorkloadEndpointID {
	return WorkloadEndpointID{
		OrchestratorId: w.GetOrchestratorId(),
		WorkloadId:     w.GetWorkloadId(),
		EndpointId:     w.GetEndpointId(),
	}
}

func WorkloadEndpointIDToProto(w WorkloadEndpointID) *proto.WorkloadEndpointID {
	return &proto.WorkloadEndpointID{
		OrchestratorId: w.OrchestratorId,
		WorkloadId:     w.WorkloadId,
		EndpointId:     w.EndpointId,
	}
}
