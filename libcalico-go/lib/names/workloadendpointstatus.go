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
	"net/url"
	"strings"

	"github.com/projectcalico/calico/felix/proto"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"

	"github.com/sirupsen/logrus"
)

const (
	fieldOrchestratorID = iota
	fieldWorkloadID     // WorkloadID resolves to namespace/workload-name
	fieldEndpointID
)
const (
	// Field separator is a char reserved by the escaping algorithm used.
	// We know if we see this char unencoded in a filename, that
	// it is a field separator, and not part of a field's value.
	separator = " "
)

var (
	expectedFields = []int{fieldOrchestratorID, fieldWorkloadID, fieldEndpointID}
	escape         = url.PathEscape
	unescape       = url.PathUnescape
)

// WorkloadEndpointKeyToStatusFilename accepts a workload endpoint Key
// and converts it to a filename for use in WEP-policy status syncing
// between Felix and the CNI.
// Returns "" if passed a nilptr.
func WorkloadEndpointKeyToStatusFilename(id *model.WorkloadEndpointKey) string {
	if id == nil {
		return ""
	}
	parts := make([]string, len(expectedFields))
	parts[fieldOrchestratorID] = escape(id.OrchestratorID)
	parts[fieldWorkloadID] = escape(id.WorkloadID)
	parts[fieldEndpointID] = escape(id.EndpointID)

	logrus.WithFields(logrus.Fields{
		"parts": parts,
		"id":    id,
	}).Debug("Generating filename from workload endpoint ID")

	return strings.Join(parts, separator)
}

// WorkloadEndpointIDToWorkloadEndpointKey converts the proto representation
// of an endpoint key back to the canonical model structure.
// Returns nil if passed a nilptr.
func WorkloadEndpointIDToWorkloadEndpointKey(id *proto.WorkloadEndpointID, hostname string) *model.WorkloadEndpointKey {
	if id == nil {
		return nil
	}
	return &model.WorkloadEndpointKey{
		Hostname:       hostname,
		OrchestratorID: id.OrchestratorId,
		WorkloadID:     id.WorkloadId,
		EndpointID:     id.EndpointId,
	}
}

// APIWorkloadEndpointToWorkloadEndpointKey generates a WorkloadEndpointKey from the given WorkloadEndpoint.
// Returns nil if passed endpoint is nil.
func APIWorkloadEndpointToWorkloadEndpointKey(ep *libapi.WorkloadEndpoint) *model.WorkloadEndpointKey {
	if ep == nil {
		return nil
	}

	key := &model.WorkloadEndpointKey{
		Hostname:       ep.Spec.Node,
		OrchestratorID: ep.Spec.Orchestrator,
		WorkloadID:     ep.Namespace + "/" + ep.Spec.Pod,
		EndpointID:     ep.Spec.Endpoint,
	}

	logrus.WithField("key", key).WithField("endpoint", ep).Debug("Generating WorkloadEndpointKey from api WorkloadEndpoint")
	return key
}
