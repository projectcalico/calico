// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operator "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
)

var (
	defaultPoolName   = "default-ipv4-ippool"
	defaultV6PoolName = "default-ipv6-ippool"
)

// cidrToName returns a valid Kubernetes resource name given a CIDR. Kubernetes names must be valid DNS
// names. We do the following:
// - Expand the CIDR so that we get consistent results and remove IPv6 shorthand "::".
// - Replace any slashes with dashes.
// - Replace any : with dots.
func cidrToName(cidr string) (string, error) {
	// First, canonicalize the CIDR. e.g., 192.168.0.1/24 -> 192.168.0.0/24.
	_, nw, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}

	// Parse the CIDR and expand it to its full form.
	// e.g., fe80::/64 -> fe80:0000:0000:0000:0000:0000:0000:0000/64
	pre, err := netip.ParsePrefix(nw.String())
	if err != nil {
		return "", err
	}
	name := pre.Addr().StringExpanded()

	// Replace invalid characters.
	// e.g., fe80:0000:0000:0000:0000:0000:0000:0000/64 -> fe80.0000.0000.0000.0000.0000.0000.0000-64
	name = strings.ReplaceAll(name, ":", ".")
	name += fmt.Sprintf("-%d", pre.Bits())

	return name, nil
}

// fillDefaults fills in IP pool defaults on the Installation object. Defaulting of fields other than IP pools occurs
// in pkg/controller/installation/
func fillDefaults(ctx context.Context, client client.Client, spec *operator.InstallationSpec, currentPools *v3.IPPoolList) error {
	if spec.CNI == nil || spec.CNI.IPAM == nil {
		// These fields are needed for IP pool defaulting but defaulted themselves by the core Installation controller, which this controller waits for before
		// running. We should never hit this branch, but handle it just in case.
		return fmt.Errorf("cannot perform IP pool defaulting until CNI configuration is available")
	}

	// Only add default CIDRs if there are no existing pools in the cluster. On a cluster that already has
	// pools, the caller has decided which ones to manage.
	if currentPools == nil || len(currentPools.Items) == 0 {
		if spec.CNI.Type == operator.PluginCalico {
			platformCIDRs, err := platformPodCIDRs(ctx, client, spec)
			if err != nil {
				return err
			}
			if spec.CalicoNetwork == nil {
				spec.CalicoNetwork = &operator.CalicoNetworkSpec{}
			}
			mergePlatformPodCIDRs(spec, platformCIDRs)
		}

		// Only default the IP pools if Calico IPAM is being used, and there are no IP pools specified.
		// Defaulting of the Spec.CNI field occurs in pkg/controller/installation/
		poolsUnspecified := spec.CalicoNetwork == nil || spec.CalicoNetwork.IPPools == nil
		calicoIPAM := spec.CNI != nil && spec.CNI.IPAM != nil && spec.CNI.IPAM.Type == operator.IPAMPluginCalico
		log.V(1).Info("Checking if we should default IP pool configuration", "calicoIPAM", calicoIPAM, "poolsUnspecified", poolsUnspecified)
		if poolsUnspecified && calicoIPAM {
			if spec.CalicoNetwork == nil {
				spec.CalicoNetwork = &operator.CalicoNetworkSpec{}
			}

			switch spec.KubernetesProvider {
			case operator.ProviderEKS:
				// On EKS, default to a CIDR that doesn't overlap with the host range,
				// and also use VXLAN encap by default.
				spec.CalicoNetwork.IPPools = []operator.IPPool{
					{
						Name:          defaultPoolName,
						CIDR:          "172.16.0.0/16",
						Encapsulation: operator.EncapsulationVXLAN,
					},
				}
			default:
				spec.CalicoNetwork.IPPools = []operator.IPPool{
					{
						Name: defaultPoolName,
						CIDR: "192.168.0.0/16",
					},
				}
			}
		}
	}

	// If there are no CalicoNetwork settings, return early. The code after this point
	// assumes that there are CalicoNetwork settings to default.
	if spec.CalicoNetwork == nil {
		return nil
	}

	currentPoolLookup := map[string]string{}
	if currentPools != nil {
		for _, cur := range currentPools.Items {
			currentPoolLookup[utils.NormalizeCIDR(cur.Spec.CIDR)] = cur.Name
		}
	}

	// Default any fields on each IP pool declared in the Installation object.
	for i := 0; i < len(spec.CalicoNetwork.IPPools); i++ {
		pool := &spec.CalicoNetwork.IPPools[i]

		if len(pool.AllowedUses) == 0 {
			pool.AllowedUses = []operator.IPPoolAllowedUse{operator.IPPoolAllowedUseWorkload, operator.IPPoolAllowedUseTunnel}
		}

		// Do per-IP-family defaulting.
		addr, _, err := net.ParseCIDR(pool.CIDR)
		if err == nil && addr.To4() != nil {
			// This is an IPv4 pool.
			if pool.Encapsulation == "" {
				if spec.CNI.Type == operator.PluginCalico {
					pool.Encapsulation = operator.EncapsulationIPIP
				} else {
					pool.Encapsulation = operator.EncapsulationNone
				}
			}
			if pool.NATOutgoing == "" {
				pool.NATOutgoing = operator.NATOutgoingEnabled
			}
			if pool.NodeSelector == "" {
				pool.NodeSelector = operator.NodeSelectorDefault
			}
			if pool.BlockSize == nil {
				pool.BlockSize = ptr.To(int32(26))
			}
		} else if err == nil && addr.To16() != nil {
			// This is an IPv6 pool.
			if pool.Encapsulation == "" {
				pool.Encapsulation = operator.EncapsulationNone
			}
			if pool.NATOutgoing == "" {
				pool.NATOutgoing = operator.NATOutgoingDisabled
			}
			if pool.NodeSelector == "" {
				pool.NodeSelector = operator.NodeSelectorDefault
			}
			if pool.BlockSize == nil {
				pool.BlockSize = ptr.To(int32(122))
			}
		}

		if pool.DisableNewAllocations == nil {
			pool.DisableNewAllocations = ptr.To(false)
		}

		// Default the name if it's not set.
		if pool.Name == "" {
			if name, ok := currentPoolLookup[utils.NormalizeCIDR(pool.CIDR)]; ok {
				// There's an existing IP pool with the same CIDR - use that. This allows us to
				// assume control of IP pools that are already in the cluster.
				pool.Name = name
			} else if len(spec.CalicoNetwork.IPPools) == 1 {
				// First, attempt to use the standard "default-ipvX-ippool" name for the IP pool.
				// This is to ensure backwards compatible name generation as a convenience when creating new clusters.
				if addr.To4() == nil {
					pool.Name = defaultV6PoolName
				} else {
					pool.Name = defaultPoolName
				}
			} else if len(spec.CalicoNetwork.IPPools) == 2 && isDualStack(spec) {
				// Handle dual-stack in the same way.
				if addr.To4() == nil {
					pool.Name = defaultV6PoolName
				} else {
					pool.Name = defaultPoolName
				}
			} else {
				// For any subsequent IP pools, use the CIDR to generate a name programmatically.
				pool.Name, err = cidrToName(pool.CIDR)
				if err != nil {
					return err
				}
			}
		}

		if pool.AssignmentMode == "" {
			pool.AssignmentMode = operator.AssignmentModeAutomatic
		}
	}
	return nil
}

func isDualStack(spec *operator.InstallationSpec) bool {
	hasV4, hasV6 := false, false
	for _, pool := range spec.CalicoNetwork.IPPools {
		addr, _, err := net.ParseCIDR(pool.CIDR)
		if err != nil {
			// No need to return this error because we perform CIDR validation prior to this.
			log.Error(err, "Failed to parse IPPool CIDR")
			continue
		}
		if addr.To4() != nil {
			hasV4 = true
		} else if addr.To16() != nil {
			hasV6 = true
		}
	}
	return hasV4 && hasV6
}

// platformPodCIDRs returns the pod network CIDRs configured in the underlying Kubernetes platform.
// A cluster without a kubeadm config map has none.
func platformPodCIDRs(ctx context.Context, c client.Client, spec *operator.InstallationSpec) ([]string, error) {
	if spec.KubernetesProvider.IsOpenShift() {
		openshiftConfig := &configv1.Network{}
		if err := c.Get(ctx, types.NamespacedName{Name: "cluster"}, openshiftConfig); err != nil {
			return nil, fmt.Errorf("unable to read openshift network configuration: %w", err)
		}
		cidrs := []string{}
		for _, n := range openshiftConfig.Spec.ClusterNetwork {
			cidrs = append(cidrs, n.CIDR)
		}
		return cidrs, nil
	}

	kubeadmConfig := &corev1.ConfigMap{}
	key := types.NamespacedName{Name: kubeadmConfigMap, Namespace: metav1.NamespaceSystem}
	if err := c.Get(ctx, key, kubeadmConfig); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("unable to read kubeadm config map: %w", err)
	}
	cidrs, err := extractKubeadmCIDRs(kubeadmConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to parse kubeadm config map: %w", err)
	}
	return cidrs, nil
}

// mergePlatformPodCIDRs adds an IP pool for each platform CIDR when the Installation leaves its pools unset.
func mergePlatformPodCIDRs(spec *operator.InstallationSpec, platformCIDRs []string) {
	if spec.CalicoNetwork.IPPools != nil {
		return
	}
	v4found := false
	v6found := false
	for _, c := range platformCIDRs {
		log.Info("Adding IP pool for platform CIDR", "cidr", c)
		addr, _, err := net.ParseCIDR(c)
		if err != nil {
			log.Error(err, "Failed to parse platform's pod network CIDR.")
			continue
		}

		// The first CIDR of each family becomes the default pool; the rest are named after their CIDR.
		if addr.To4() == nil {
			name := defaultV6PoolName
			if v6found {
				name = ""
			}
			v6found = true
			spec.CalicoNetwork.IPPools = append(spec.CalicoNetwork.IPPools, operator.IPPool{Name: name, CIDR: c})
		} else {
			name := defaultPoolName
			if v4found {
				name = ""
			}
			v4found = true
			spec.CalicoNetwork.IPPools = append(spec.CalicoNetwork.IPPools, operator.IPPool{Name: name, CIDR: c})
		}
	}
}

// poolsOutsidePlatformCIDRs returns the CIDRs of the workload pools that don't fit within any of the platform's
// pod network CIDRs.
func poolsOutsidePlatformCIDRs(pools []operator.IPPool, platformCIDRs []string) []string {
	if len(platformCIDRs) == 0 {
		return nil
	}
	var outside []string
	for _, pool := range pools {
		// Only workload addresses have to be inside the pod network.
		if len(pool.AllowedUses) > 0 && !slices.Contains(pool.AllowedUses, operator.IPPoolAllowedUseWorkload) {
			continue
		}
		if !slices.ContainsFunc(platformCIDRs, func(c string) bool { return cidrWithinCidr(c, pool.CIDR) }) {
			outside = append(outside, pool.CIDR)
		}
	}
	return outside
}

// cidrWithinCidr checks that all IPs in the pool passed in are within the
// passed in CIDR
func cidrWithinCidr(cidr, pool string) bool {
	_, cNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	_, pNet, err := net.ParseCIDR(pool)
	if err != nil {
		return false
	}
	ipMin := pNet.IP
	pOnes, _ := pNet.Mask.Size()
	cOnes, _ := cNet.Mask.Size()

	// If the cidr contains the network (1st) address of the pool and the
	// prefix on the pool is larger than or equal to the cidr prefix (the pool size is
	// smaller than the cidr) then the pool network is within the cidr network.
	if cNet.Contains(ipMin) && pOnes >= cOnes {
		return true
	}
	return false
}
