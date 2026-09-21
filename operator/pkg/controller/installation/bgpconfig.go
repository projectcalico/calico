// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package installation

import (
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/controller/managedfields"
)

// declareBGPConfiguration declares the BIRD half of cluster route programming. It moves in
// lockstep with the FelixConfiguration half: whatever Felix is not programming, BIRD has to be.
func (r *ReconcileInstallation) declareBGPConfiguration(install *operatorv1.Installation) managedfields.DeclareFn[*v3.BGPConfiguration] {
	return func(current *v3.BGPConfiguration) (*managedfields.Declaration, error) {
		bgpConfig := &v3.BGPConfiguration{}
		d := &managedfields.Declaration{
			Manager: installationFieldManager,
			Owned:   bgpConfig,
			Policies: map[string]managedfields.ConflictPolicy{
				"spec.programClusterRoutes": managedfields.ConflictOverride,
			},
		}

		// Gated on the field being set, so leaving it unset keeps meaning "whatever Calico
		// defaults to" rather than pinning today's default into the datastore.
		if install.Spec.CalicoNetwork != nil && install.Spec.CalicoNetwork.ClusterRoutingMode != nil {
			mode := *install.Spec.CalicoNetwork.ClusterRoutingMode
			bgpConfig.Spec.ProgramClusterRoutes = ptr.To(birdProgramClusterRoutesValue(mode))
		}
		return d, nil
	}
}
