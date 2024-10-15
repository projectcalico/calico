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

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
	v3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
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
func WorkloadEndpointKeyToStatusFilename(key *model.WorkloadEndpointKey) string {
	if key == nil {
		return ""
	}
	parts := make([]string, len(expectedFields))
	parts[fieldOrchestratorID] = escape(key.OrchestratorID)
	parts[fieldWorkloadID] = escape(key.WorkloadID)
	parts[fieldEndpointID] = escape(key.EndpointID)

	logrus.WithFields(logrus.Fields{
		"parts": parts,
	}).Debug("Generating filename from WorkloadEndpointKey")

	return strings.Join(parts, separator)
}

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

// V3WorkloadEndpointToWorkloadEndpointKey generates a WorkloadEndpointKey from the given WorkloadEndpoint.
// Returns nil if passed endpoint is nil.
func V3WorkloadEndpointToWorkloadEndpointKey(ep *v3.WorkloadEndpoint) (*model.WorkloadEndpointKey, error) {
	if ep == nil {
		return nil, nil
	}

	name := ep.GetName()
	if name == "" {
		// The name is normally calculated when we write the object to the
		// datastore but, in case this is a pre-write object (for example
		// in a test), calculate it now.
		ids := IdentifiersForV3WorkloadEndpoint(ep)
		var err error
		name, err = ids.CalculateWorkloadEndpointName(false)
		if err != nil {
			return nil, err
		}
	}
	v3Key := model.ResourceKey{
		Kind:      v3.KindWorkloadEndpoint,
		Name:      name,
		Namespace: ep.GetNamespace(),
	}

	modelKey, err := ConvertWorkloadEndpointV3KeyToV1Key(v3Key)
	if err != nil {
		return nil, err
	}
	return &modelKey, nil
}
