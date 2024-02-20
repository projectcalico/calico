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
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/projectcalico/calico/felix/proto"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"

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

// WorkloadEndpointIDToStatusFilename accepts a workload endpoint ID
// and converts it to a filename for use in WEP-policy status syncing
// between Felix and the CNI.
func WorkloadEndpointIDToStatusFilename(id *proto.WorkloadEndpointID) string {
	parts := make([]string, len(expectedFields))
	parts[fieldOrchestratorID] = escape(id.OrchestratorId)
	parts[fieldWorkloadID] = escape(id.WorkloadId)
	parts[fieldEndpointID] = escape(id.EndpointId)

	logrus.WithFields(logrus.Fields{
		"parts": parts,
		"id":    id,
	}).Debug("Generating filename from workload endpoint ID")

	return strings.Join(parts, separator)
}

// StatusFilenameToWorkloadEndpointID accepts the stringed name of
// a policy-status file and reverses the conversion
// from WorkloadEndpointID to filename.
func StatusFilenameToWorkloadEndpointID(filename string) (*proto.WorkloadEndpointID, error) {
	parts := strings.Split(filename, separator)
	if len(parts) != len(expectedFields) {
		return nil, fmt.Errorf("couldn't parse WorkloadEndpointID from string %s", filename)
	}

	logrus.WithFields(logrus.Fields{
		"filename": filename,
		"parsed":   parts,
	}).Debug("Generating workload endpoint ID from filename")

	parsed := make([]string, len(parts))
	var err error
	for i, p := range parts {
		if p == "" {
			return nil, errors.New("found double-separated, empty field")
		}
		parsed[i], err = unescape(p)
		if err != nil {
			return nil, err
		}
	}

	return &proto.WorkloadEndpointID{
		OrchestratorId: parsed[fieldOrchestratorID],
		WorkloadId:     parsed[fieldWorkloadID],
		EndpointId:     parsed[fieldEndpointID]}, nil
}

// WorkloadEndpointToStatusFilename generates a string to be used as a status-file's name.
// Operation should be reversible, i.e., the stringification shouldn't be lossy.
// Returns "" if passed endpoint is nil.
func WorkloadEndpointToStatusFilename(ep *libapi.WorkloadEndpoint) string {
	if ep == nil {
		return ""
	}

	parts := make([]string, len(expectedFields))
	parts[fieldOrchestratorID] = escape(ep.Spec.Orchestrator)
	parts[fieldWorkloadID] = escape(ep.Namespace + "/" + ep.Spec.Pod)
	parts[fieldEndpointID] = escape(ep.Spec.Endpoint)

	logrus.WithField("parts", parts).WithField("endpoint", ep).Debug("Generating status filename from workload endpoint")
	return strings.Join(parts, separator)
}
