// Copyright (c) 2022-2024 Tigera, Inc. All rights reserved.

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

package convert

import operatorv1 "github.com/tigera/operator/api/v1"

func handleAddonManager(c *components, install *operatorv1.Installation) error {
	if _, ok := c.node.Labels["addonmanager.kubernetes.io/mode"]; ok {
		return ErrIncompatibleCluster{
			component: ComponentCalicoNode,
			err:       "can't modify components managed by addon-manager",
		}
	}

	if c.typha != nil {
		if _, ok := c.typha.Labels["addonmanager.kubernetes.io/mode"]; ok {
			return ErrIncompatibleCluster{
				component: ComponentTypha,
				err:       "can't modify components managed by addon-manager",
			}
		}
	}

	if c.kubeControllers != nil {
		if _, ok := c.kubeControllers.Labels["addonmanager.kubernetes.io/mode"]; ok {
			return ErrIncompatibleCluster{
				component: ComponentKubeControllers,
				err:       "can't modify components managed by addon-manager",
			}
		}
	}

	return nil
}
