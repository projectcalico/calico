// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package names

import (
	"fmt"
	"strings"

	"github.com/projectcalico/calico/felix/proto"

	"github.com/sirupsen/logrus"
)

const (
	fieldOrchestratorID = iota
	fieldWorkloadID
	fieldEndpointID
)
const (
	separator = "-"
)

var (
	expectedFields = []int{fieldOrchestratorID, fieldWorkloadID, fieldEndpointID}
)

// WorkloadEndpointIDToStatusFilename accepts a workload endpoint ID
// and converts it to a filename for use in WEP-policy status syncing
// between Felix and the CNI.
func WorkloadEndpointIDToStatusFilename(id *proto.WorkloadEndpointID) string {
	parts := make([]string, len(expectedFields))
	parts[fieldOrchestratorID] = id.OrchestratorId
	parts[fieldWorkloadID] = strings.ReplaceAll(id.WorkloadId, "/", separator)
	parts[fieldEndpointID] = id.EndpointId
	logrus.WithField("parts", parts).Warn("gnerating filename from workload endpoint ID")
	return strings.Join(parts, separator)
}

// StatusFilenameToWorkloadEndpointID accepts the stringed name of
// a policy-status file and (with loss) reverses the conversion
// from WorkloadEndpointID to filename.
func StatusFilenameToWorkloadEndpointID(filename string) (*proto.WorkloadEndpointID, error) {
	parts := strings.Split(filename, separator)
	if len(parts) != len(expectedFields) {
		return nil, fmt.Errorf("Couldn't parse WorkloadEndpointID from string %s", filename)
	}

	return &proto.WorkloadEndpointID{
		OrchestratorId: parts[fieldOrchestratorID],
		WorkloadId:     parts[fieldWorkloadID],
		EndpointId:     parts[fieldEndpointID]}, nil
}

// WorkloadEndpointIdentifiersToStatusFilename generates a string with a known format
func WorkloadEndpointIdentifiersToStatusFilename(id WorkloadEndpointIdentifiers) string {
	parts := make([]string, len(expectedFields))
	parts[fieldOrchestratorID] = id.Orchestrator
	parts[fieldWorkloadID] = id.Workload
	parts[fieldEndpointID] = id.Endpoint

	return strings.Join(parts, separator)
}
