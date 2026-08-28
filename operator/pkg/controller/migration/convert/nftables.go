// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package convert

import (
	"fmt"
	"strings"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"k8s.io/apimachinery/pkg/types"
)

// handleNftables is a migration handler which ensures nftables configuration is carried forward.
func handleNftables(c *components, install *operatorv1.Installation) error {
	fc := &v3.FelixConfiguration{}
	err := c.client.Get(ctx, types.NamespacedName{Name: "default"}, fc)
	if err != nil {
		return fmt.Errorf("error reading felixconfiguration %w", err)
	}

	envMode, err := c.node.getEnv(ctx, c.client, containerCalicoNode, "FELIX_NFTABLESMODE")
	if err != nil {
		return fmt.Errorf("error reading FELIX_NFTABLESMODE env var %w", err)
	}

	inFelixConfig := fc.Spec.NFTablesMode != nil && *fc.Spec.NFTablesMode == v3.NFTablesModeEnabled
	enabledEnvVar := envMode != nil && strings.ToLower(*envMode) == "enabled"

	// A disabled env var will override any other configuration. It's possible to have a feature enabled in the FelixConfiguration
	// but disabled via the environment variable as an override (although not recommended!)
	disabledEnvVar := envMode != nil && strings.ToLower(*envMode) == "disabled"

	if !disabledEnvVar && (inFelixConfig || enabledEnvVar) {
		if install.Spec.CalicoNetwork == nil {
			install.Spec.CalicoNetwork = &operatorv1.CalicoNetworkSpec{}
		}

		// Make sure dataplane mode isn't already set by another handler.
		// If we hit this, it means that either there was conflicting configuration in the
		// manifest, or that a dataplane combination exists that is not supported by the operator.
		if install.Spec.CalicoNetwork.LinuxDataplane != nil {
			return fmt.Errorf("cannot enable nftables, already set to %s", *install.Spec.CalicoNetwork.LinuxDataplane)
		}

		nft := operatorv1.LinuxDataplaneNftables
		install.Spec.CalicoNetwork.LinuxDataplane = &nft
	}
	return nil
}
