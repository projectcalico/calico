// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.

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

package v1

import (
	"fmt"
	"log"

	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/scope"
)

// ValidateMetadataIDsAssigned is used to validate the Resource Metadata to ensure
// that all necessary fields are present.
// This is split from the validator so it can be used conditionally
// depending on the command.
func ValidateMetadataIDsAssigned(rm unversioned.ResourceMetadata) error {
	switch metadata := rm.(type) {
	case api.BGPPeerMetadata:
		if metadata.PeerIP.IP == nil {
			return errors.ErrorInsufficientIdentifiers{Name: "peerIP"}
		}
		if metadata.Scope == scope.Undefined ||
			(metadata.Scope != scope.Global && metadata.Node == "") {
			return errors.ErrorInsufficientIdentifiers{Name: "node"}
		}
	case api.HostEndpointMetadata:
		if metadata.Node == "" {
			return errors.ErrorInsufficientIdentifiers{Name: "node"}
		}
		if metadata.Name == "" {
			return errors.ErrorInsufficientIdentifiers{Name: "name"}
		}
	case api.IPPoolMetadata:
		if metadata.CIDR.IP == nil {
			return errors.ErrorInsufficientIdentifiers{Name: "cidr"}
		}
	case api.NodeMetadata:
		if metadata.Name == "" {
			return errors.ErrorInsufficientIdentifiers{Name: "name"}
		}
	case api.PolicyMetadata:
		if metadata.Name == "" {
			return errors.ErrorInsufficientIdentifiers{Name: "name"}
		}
	case api.ProfileMetadata:
		if metadata.Name == "" {
			return errors.ErrorInsufficientIdentifiers{Name: "name"}
		}
	case api.WorkloadEndpointMetadata:
		if metadata.Node == "" {
			return errors.ErrorInsufficientIdentifiers{Name: "node"}
		}
		if metadata.Orchestrator == "" {
			return errors.ErrorInsufficientIdentifiers{Name: "orchestrator"}
		}
		if metadata.Workload == "" {
			return errors.ErrorInsufficientIdentifiers{Name: "workload"}
		}
		if metadata.Name == "" {
			return errors.ErrorInsufficientIdentifiers{Name: "name"}
		}
	default:
		log.Fatal(fmt.Errorf("Unexpected resource metadata: %s", metadata))
	}

	return nil
}
