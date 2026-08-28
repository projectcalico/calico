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

import (
	"fmt"
	"strconv"

	operatorv1 "github.com/tigera/operator/api/v1"
)

// handleMTU is a migration handler which ensures MTU configuration is carried forward.
func handleMTU(c *components, install *operatorv1.Installation) error {
	var (
		curMTU    *int32
		curMTUSrc string
	)

	for _, src := range []string{"FELIX_IPINIPMTU", "FELIX_VXLANMTU", "FELIX_VXLANMTUV6", "FELIX_WIREGUARDMTU", "FELIX_WIREGUARDMTUV6"} {
		mtu, err := getMTU(c, containerCalicoNode, src)
		if err != nil {
			return ErrIncompatibleCluster{
				err:       fmt.Sprintf("failed to parse mtu from %s: %v", src, err),
				component: ComponentCalicoNode,
				fix:       fmt.Sprintf("adjust %s to a valid integer or unset the env var", src),
			}
		}

		// if this mtu source is not set, ignore
		if mtu == nil {
			continue
		}

		// compare against current mtu.
		if curMTU != nil && *curMTU != *mtu {
			return ErrIncompatibleCluster{
				err:       fmt.Sprintf("mtu %s=%d does not match mtu %s=%d", src, *mtu, curMTUSrc, *curMTU),
				component: ComponentCalicoNode,
				fix:       fmt.Sprintf("adjust %s and %s to match or unset one of them", src, curMTUSrc),
			}
		}

		curMTU, curMTUSrc = mtu, src
	}

	if c.cni.CalicoConfig != nil {
		if c.cni.CalicoConfig.MTU == -1 {
			// if MTU is -1, we assume it was us who replaced it when doing initial CNI
			// config loading. We need to pull it from the correct source
			var src = "CNI_MTU"
			mtu, err := getMTU(c, containerInstallCNI, src)
			if err != nil {
				return ErrIncompatibleCluster{
					err:       fmt.Sprintf("failed to parse mtu from %s: %v", src, err),
					component: ComponentCalicoNode,
					fix:       fmt.Sprintf("adjust %s to a valid integer", src),
				}
			}

			if mtu == nil {
				// if not set, install-cni will use a known default mtu of 1500
				mtu = new(int32)
				*mtu = 1500
			}

			// compare against current mtu.
			if curMTU != nil && *curMTU != *mtu {
				return ErrIncompatibleCluster{
					err:       fmt.Sprintf("mtu %s=%d does not match mtu %s=%d", src, *mtu, curMTUSrc, *curMTU),
					component: ComponentCalicoNode,
					fix:       fmt.Sprintf("adjust %s and %s to match or unset one of them", src, curMTUSrc)}
			}
			curMTU = mtu

		} else {
			// user must have hardcoded their CNI instead of using the cni templating engine.
			// use the hardcoded value.
			mtu := int32(c.cni.CalicoConfig.MTU)
			if curMTU != nil && *curMTU != mtu {
				return ErrIncompatibleCluster{
					err:       fmt.Sprintf("mtu '%d' specified in CNI config does not match mtu %s=%d", mtu, curMTUSrc, *curMTU),
					component: ComponentCalicoNode,
					fix:       fmt.Sprintf("adjust the mtu value set in CNI config to match %s or unset one of them", curMTUSrc),
				}
			}
			curMTU = &mtu
		}
	}

	if curMTU != nil {
		if install.Spec.CalicoNetwork == nil {
			install.Spec.CalicoNetwork = &operatorv1.CalicoNetworkSpec{}
		}
		install.Spec.CalicoNetwork.MTU = curMTU
	}

	return nil
}

// getMTU retrieves an mtu value from an env var on a container.
// if the specified env var does not exist, it will return nil.
// since env vars are strings, this function also parses it into an int32 pointer.
func getMTU(c *components, container, key string) (*int32, error) {
	m, err := c.node.getEnv(ctx, c.client, container, key)
	if err != nil {
		return nil, err
	}

	if m == nil {
		return nil, nil
	}

	i, err := strconv.ParseInt(*m, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("couldn't convert %s to integer: %v", *m, err)
	}
	mtu := int32(i)
	return &mtu, nil
}
