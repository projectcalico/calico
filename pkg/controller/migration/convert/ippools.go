// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
//
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
	"net"
	"strings"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
)

// handleIPPools sets the install.Spec.CalicoNetwork.IPPools field based on the
// pools in the datastore.
// We read the pools from the datastore and select the appropriate ones.
// See selectInitialPool for details on which pool will be selected.
// Since the operator only supports one v4 and one v6 only one of each will be picked
// if they exist.
func handleIPPools(c *components, install *operatorv1.Installation) error {
	pools := v3.IPPoolList{}
	if err := c.client.List(ctx, &pools); err != nil && !kerrors.IsNotFound(err) {
		return fmt.Errorf("failed to list IPPools %v", err)
	}

	v4pool, err := selectInitialPool(pools.Items, isIpv4)
	if err != nil {
		return err
	}

	v6pool, err := selectInitialPool(pools.Items, isIpv6)
	if err != nil {
		return err
	}

	var operatorV6Pool operatorv1.IPPool

	// Only if there is at least one v4 or v6 pool will we initialize CalicoNetwork
	if v4pool != nil || v6pool != nil {
		if install.Spec.CalicoNetwork == nil {
			install.Spec.CalicoNetwork = &operatorv1.CalicoNetworkSpec{}
		}

		if install.Spec.CalicoNetwork.IPPools == nil {
			install.Spec.CalicoNetwork.IPPools = []operatorv1.IPPool{}
		}

		// Convert any found CRD pools into Operator pools and add them.
		if render.GetIPv4Pool(install.Spec.CalicoNetwork.IPPools) == nil && v4pool != nil {
			pool, err := convertPool(*v4pool)
			if err != nil {
				return ErrIncompatibleCluster{
					err:       fmt.Sprintf("failed to convert IPPool %s, %v", v4pool.Name, err),
					component: ComponentIPPools,
				}
			}
			install.Spec.CalicoNetwork.IPPools = append(install.Spec.CalicoNetwork.IPPools, pool)
		}

		if render.GetIPv6Pool(install.Spec.CalicoNetwork.IPPools) == nil && v6pool != nil {
			operatorV6Pool, err = convertPool(*v6pool)
			if err != nil {
				return ErrIncompatibleCluster{
					err:       fmt.Sprintf("failed to convert IPPool %s, %s ", v6pool.Name, err),
					component: ComponentIPPools,
				}
			}
			install.Spec.CalicoNetwork.IPPools = append(install.Spec.CalicoNetwork.IPPools, operatorV6Pool)
		}
	}

	// If IPAM is calico then check that the assign_ipv* fields match the IPPools that have been detected
	if c.cni.CalicoConfig != nil && c.cni.CalicoConfig.IPAM.Type == "calico-ipam" {
		if c.cni.CalicoConfig.IPAM.AssignIpv4 == nil || strings.ToLower(*c.cni.CalicoConfig.IPAM.AssignIpv4) == "true" {
			if v4pool == nil {
				return ErrIncompatibleCluster{
					err:       "CNI config indicates assign_ipv4=true but there were no valid IPv4 pools found",
					component: ComponentCNIConfig,
					fix:       "create an IPv4 pool or set assign_ipv4=false",
				}
			}
		} else {
			// If assign_ipv4="false" then remove any discovered IPv4 pools.
			// Since we must have an IPv6 pool here, replace the operator
			// pools with the IPv6 pool.
			// This is needed because the operator renders IPAM config
			// based on the presence of initial ippools in the installation CR.
			if v6pool == nil {
				return ErrIncompatibleCluster{
					err:       "CNI config indicates assign_ipv6=true but there were no valid IPv6 pools found",
					component: ComponentCNIConfig,
					fix:       "create an IPv6 pool or set assign_ipv6=false",
				}
			}

			install.Spec.CalicoNetwork.IPPools = []operatorv1.IPPool{operatorV6Pool}
		}
		if c.cni.CalicoConfig.IPAM.AssignIpv6 != nil && strings.ToLower(*c.cni.CalicoConfig.IPAM.AssignIpv6) == "true" {
			if v6pool == nil {
				return ErrIncompatibleCluster{
					err:       "CNI config indicates assign_ipv6=true but there were no valid IPv6 pools found",
					component: ComponentCNIConfig,
					fix:       "create an IPv6 pool or set assign_ipv6=false",
				}
			}
		} else {
			if v6pool != nil {
				return ErrIncompatibleCluster{
					err:       "CNI config indicates assign_ipv6=false but an IPv6 pool was found",
					component: ComponentCNIConfig,
					fix:       "delete the IPv6 pool or set assign_ipv6=true",
				}
			}
		}
	}

	// Ignore the initial pool variables (other than CIDR), we'll pick up everything we need from the datastore
	// V4
	c.node.ignoreEnv("calico-node", "CALICO_IPV4POOL_CIDR")
	c.node.ignoreEnv("calico-node", "CALICO_IPV4POOL_BLOCK_SIZE")
	c.node.ignoreEnv("calico-node", "CALICO_IPV4POOL_IPIP")
	c.node.ignoreEnv("calico-node", "CALICO_IPV4POOL_VXLAN")
	c.node.ignoreEnv("calico-node", "CALICO_IPV4POOL_NAT_OUTGOING")
	c.node.ignoreEnv("calico-node", "CALICO_IPV4POOL_NODE_SELECTOR")
	c.node.ignoreEnv("calico-node", "CALICO_IPV4POOL_DISABLE_BGP_EXPORT")
	// V6
	c.node.ignoreEnv("calico-node", "CALICO_IPV6POOL_CIDR")
	c.node.ignoreEnv("calico-node", "CALICO_IPV6POOL_BLOCK_SIZE")
	c.node.ignoreEnv("calico-node", "CALICO_IPV6POOL_IPIP")
	c.node.ignoreEnv("calico-node", "CALICO_IPV6POOL_VXLAN")
	c.node.ignoreEnv("calico-node", "CALICO_IPV6POOL_NAT_OUTGOING")
	c.node.ignoreEnv("calico-node", "CALICO_IPV6POOL_NODE_SELECTOR")
	c.node.ignoreEnv("calico-node", "CALICO_IPV6POOL_DISABLE_BGP_EXPORT")

	return nil
}

// getIPPools searches through the pools passed in using the matcher function passed in to see if the pool
// should be selected, the first pool that the matcher returns true on is returned.
// If there is an error returned from the matcher then that error is returned.
// If no pool is found and there is no error then nil,nil is returned.
func getIPPool(pools []v3.IPPool, matcher func(v3.IPPool) (bool, error)) (*v3.IPPool, error) {
	for _, pool := range pools {
		if pool.Spec.Disabled {
			continue
		}
		yes, err := matcher(pool)
		if err != nil {
			return nil, err
		}
		if yes {
			return &pool, nil
		}
	}
	return nil, nil
}

// isIPv4 check if the IP is an IPv4 address
func isIpv4(ip net.IP) bool {
	return ip.To4() != nil
}

// isIPv6 checks if the IP is an IPv6 address
func isIpv6(ip net.IP) bool {
	return ip.To4() == nil
}

// selectInitialPool searches through pools for enabled pools, returning the
// first to match one of the following:
//  1. one prefixed with default-ipv and matching the isver IP version
//  2. one matching isver IP version
//
// if none match then nil, nil is returned
// if there is an error parsing the cidr in a pool then that error will be returned
func selectInitialPool(pools []v3.IPPool, isver func(ip net.IP) bool) (*v3.IPPool, error) {
	// Select pools prefixed with 'default-ipv' and isver is true
	pool, err := getIPPool(pools, func(p v3.IPPool) (bool, error) {
		ip, _, err := net.ParseCIDR(p.Spec.CIDR)
		if err != nil {
			return false, fmt.Errorf("failed to parse IPPool %s in datastore: %v", p.Name, err)
		}
		if isver(ip) {
			if strings.HasPrefix(p.Name, "default-ipv") {
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	if pool != nil {
		return pool, nil
	}

	// If we don't have a pool then just grab any that has the right version
	pool, err = getIPPool(pools, func(p v3.IPPool) (bool, error) {
		ip, _, err := net.ParseCIDR(p.Spec.CIDR)
		if err != nil {
			return false, fmt.Errorf("failed to parse IPPool %s in datastore: %v", p.Name, err)
		}
		return isver(ip), nil
	})
	if err != nil {
		return nil, err
	}
	if pool != nil {
		return pool, nil
	}
	return nil, nil
}

// convertPool converts the src (CRD) pool into an Installation/Operator IPPool
func convertPool(src v3.IPPool) (operatorv1.IPPool, error) {
	p := operatorv1.IPPool{CIDR: src.Spec.CIDR}

	ip := src.Spec.IPIPMode
	if ip == "" {
		ip = v3.IPIPModeNever
	}
	vx := src.Spec.VXLANMode
	if vx == "" {
		vx = v3.VXLANModeNever
	}
	switch {
	case ip == v3.IPIPModeNever && vx == v3.VXLANModeNever:
		p.Encapsulation = operatorv1.EncapsulationNone
	case ip == v3.IPIPModeNever && vx == v3.VXLANModeAlways:
		p.Encapsulation = operatorv1.EncapsulationVXLAN
	case ip == v3.IPIPModeNever && vx == v3.VXLANModeCrossSubnet:
		p.Encapsulation = operatorv1.EncapsulationVXLANCrossSubnet
	case vx == v3.VXLANModeNever && ip == v3.IPIPModeAlways:
		p.Encapsulation = operatorv1.EncapsulationIPIP
	case vx == v3.VXLANModeNever && ip == v3.IPIPModeCrossSubnet:
		p.Encapsulation = operatorv1.EncapsulationIPIPCrossSubnet
	default:
		return p, fmt.Errorf("unexpected encapsulation combination for pool %+v", src)
	}

	p.NATOutgoing = operatorv1.NATOutgoingEnabled
	if !src.Spec.NATOutgoing {
		p.NATOutgoing = operatorv1.NATOutgoingDisabled
	}

	if src.Spec.BlockSize != 0 {
		bs := int32(src.Spec.BlockSize)
		p.BlockSize = &bs
	}

	p.NodeSelector = src.Spec.NodeSelector
	p.DisableBGPExport = &src.Spec.DisableBGPExport

	if src.Spec.AssignmentMode != nil {
		switch *src.Spec.AssignmentMode {
		case v3.Automatic:
			p.AssignmentMode = operatorv1.AssignmentModeAutomatic
		case v3.Manual:
			p.AssignmentMode = operatorv1.AssignmentModeManual
		default:
			return p, fmt.Errorf("unexpected assignment mode %s for pool %+v", *src.Spec.AssignmentMode, src)
		}
	}

	return p, nil
}
