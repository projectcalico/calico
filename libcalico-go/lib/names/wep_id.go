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
	"github.com/projectcalico/calico/felix/proto"
)

// WorkloadEndpointIDToStatusFilename accepts a workload endpoint ID
// and converts it to a filename for use in WEP-policy status syncing
// between Felix and the CNI.
func WorkloadEndpointIDToStatusFilename(id *proto.WorkloadEndpointID) string {
	return id.WorkloadId
}

// StatusFilenameToWorkloadEndpointID accepts the stringed name of
// a policy-status file and (with loss) reverses the conversion
// from WorkloadEndpointID to filename.
func StatusFilenameToWorkloadEndpointID(filename string) *proto.WorkloadEndpointID {
	return &proto.WorkloadEndpointID{
		WorkloadId: filename,
	}
}
