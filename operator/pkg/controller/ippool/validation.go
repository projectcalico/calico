// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

package ippool

import (
	"fmt"
	"net"
	"strings"

	operator "github.com/tigera/operator/api/v1"
)

// ValidatePools validates the IP pools specified in the Installation object.
func ValidatePools(spec *operator.InstallationSpec) error {
	cidrs := map[string]bool{}
	names := map[string]bool{}
	for _, pool := range spec.CalicoNetwork.IPPools {
		_, cidr, err := net.ParseCIDR(pool.CIDR)
		if err != nil {
			return fmt.Errorf("IP pool CIDR (%s) is invalid: %s", pool.CIDR, err)
		}

		// Validate that there is only a single instance of each CIDR and Name.
		if cidrs[pool.CIDR] {
			return fmt.Errorf("IP pool %v is specified more than once", pool.CIDR)
		}
		cidrs[pool.CIDR] = true
		if names[pool.Name] {
			return fmt.Errorf("IP pool %v is specified more than once", pool.Name)
		}
		names[pool.Name] = true

		// Check if pool is for LoadBalancer
		isLoadBalancer := false
		for _, u := range pool.AllowedUses {
			if u == operator.IPPoolAllowedUseLoadBalancer {
				isLoadBalancer = true
			}
		}

		// Check if pool is set as LoadBalancer no other allowed use is specified
		if isLoadBalancer {
			for _, u := range pool.AllowedUses {
				if u != operator.IPPoolAllowedUseLoadBalancer {
					return fmt.Errorf("IP pool %s AllowedUse LoadBalancer cannot be used with Workload/Tunnel", pool.Name)
				}
			}
		}

		// Verify NAT outgoing values.
		switch pool.NATOutgoing {
		case operator.NATOutgoingEnabled:
		case operator.NATOutgoingDisabled:
		default:
			return fmt.Errorf("%s is invalid for natOutgoing, should be one of %s",
				pool.NATOutgoing, strings.Join(operator.NATOutgoingTypesString, ","))
		}

		// Verify the node selector.
		if pool.NodeSelector == "" {
			return fmt.Errorf("IP pool nodeSelector should not be empty")
		}

		if isLoadBalancer && pool.NodeSelector != "all()" {
			return fmt.Errorf("IP pool nodeSelector should be set to all() if allowedUse is LoadBalancer")
		}

		if spec.CNI == nil {
			// We expect this to be defaulted by the core Installation controller prior to the IP pool controller
			// being invoked, but check just in case.
			return fmt.Errorf("no CNI plugin specified in Installation resource")
		}
		if spec.CNI.Type != operator.PluginCalico {
			if pool.NodeSelector != "all()" {
				return fmt.Errorf("IP pool nodeSelector (%s) should be 'all()' when using non-Calico CNI plugin", pool.NodeSelector)
			}
		}

		// Verify the Encapsulation mode is valid.
		switch pool.Encapsulation {
		case operator.EncapsulationIPIP, operator.EncapsulationIPIPCrossSubnet, operator.EncapsulationVXLAN, operator.EncapsulationVXLANCrossSubnet:
			if isLoadBalancer {
				return fmt.Errorf("IP pool encapsulation must be none if allowedUse is LoadBalancer")
			}
		case operator.EncapsulationNone:
		default:
			return fmt.Errorf("%s is invalid for ipPool.encapsulation, should be one of %s",
				pool.Encapsulation, strings.Join(operator.EncapsulationTypesString, ","))
		}

		// Verify per-address-family settings.
		isIPv4 := !strings.Contains(pool.CIDR, ":")
		if isIPv4 {
			// This is an IPv4 pool.
			if pool.BlockSize != nil {
				if *pool.BlockSize > 32 || *pool.BlockSize < 20 {
					return fmt.Errorf("IPv4 pool block size must be greater than 19 and less than or equal to 32")
				}

				// Verify that the CIDR contains the blocksize.
				ones, _ := cidr.Mask.Size()
				if int32(ones) > *pool.BlockSize {
					return fmt.Errorf("IP pool size is too small. It must be equal to or greater than the block size")
				}
			}
		} else {
			// This is an IPv6 pool.
			if pool.BlockSize != nil {
				if *pool.BlockSize > 128 || *pool.BlockSize < 116 {
					return fmt.Errorf("IPv6 pool block size must be greater than 115 and less than or equal to 128")
				}

				// Verify that the CIDR contains the blocksize.
				ones, _ := cidr.Mask.Size()
				if int32(ones) > *pool.BlockSize {
					return fmt.Errorf("IP pool size is too small. It must be equal to or greater than the block size")
				}
			}
		}

		if isLoadBalancer && *pool.DisableBGPExport {
			return fmt.Errorf("IP pool disable bgp export must be false when AllowedUse is LoadBalancer")
		}
	}
	return nil
}
