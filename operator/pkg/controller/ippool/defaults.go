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
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/utils"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

	// Only add default CIDRs if there are no existing pools in the cluster. If there are existing pools in the cluster,
	// then we assume that the user has configured them correctly out-of-band and we should not install any others.
	if currentPools == nil || len(currentPools.Items) == 0 {
		if spec.KubernetesProvider.IsOpenShift() {
			// If configured to run in openshift, then also fetch the openshift configuration API.
			log.V(1).Info("Fetching OpenShift network configuration")
			openshiftConfig := &configv1.Network{}
			openshiftNetworkConfig := "cluster"
			if err := client.Get(ctx, types.NamespacedName{Name: openshiftNetworkConfig}, openshiftConfig); err != nil {
				return fmt.Errorf("unable to read openshift network configuration: %s", err.Error())
			}

			// Merge in OpenShift configuration.
			if err := updateInstallationForOpenshiftNetwork(spec, openshiftConfig); err != nil {
				return fmt.Errorf("could not resolve CalicoNetwork IPPool and OpenShift network: %s", err.Error())
			}
		} else {
			// Check if we're running on kubeadm by getting the config map.
			log.V(1).Info("Fetching kubeadm config map")
			kubeadmConfig := &corev1.ConfigMap{}
			key := types.NamespacedName{Name: kubeadmConfigMap, Namespace: metav1.NamespaceSystem}
			if err := client.Get(ctx, key, kubeadmConfig); err == nil {
				// We found the configmap - merge in kubeadm configuration.
				if err := updateInstallationForKubeadm(spec, kubeadmConfig); err != nil {
					return fmt.Errorf("could not resolve CalicoNetwork IPPool and kubeadm configuration: %s", err.Error())
				}
			} else if !apierrors.IsNotFound(err) {
				return fmt.Errorf("unable to read kubeadm config map: %s", err.Error())
			}
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
	} else if spec.CalicoNetwork == nil || spec.CalicoNetwork.IPPools == nil {
		// There are existing IP pools in the cluster, and the installation hasn't specified any. This means IP pools are
		// being managed out-of-band of the operator API. So, default the installation field to an empty list,
		// which means "Don't install any IP pools".
		if spec.CalicoNetwork == nil {
			spec.CalicoNetwork = &operator.CalicoNetworkSpec{}
		}
		spec.CalicoNetwork.IPPools = []operator.IPPool{}
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

func updateInstallationForOpenshiftNetwork(spec *operator.InstallationSpec, o *configv1.Network) error {
	// If CNI plugin is specified and not Calico then skip any CalicoNetwork initialization
	if spec.CNI != nil && spec.CNI.Type != operator.PluginCalico {
		return nil
	}
	if spec.CalicoNetwork == nil {
		spec.CalicoNetwork = &operator.CalicoNetworkSpec{}
	}

	platformCIDRs := []string{}
	for _, c := range o.Spec.ClusterNetwork {
		platformCIDRs = append(platformCIDRs, c.CIDR)
	}
	return mergePlatformPodCIDRs(spec, platformCIDRs)
}

func updateInstallationForKubeadm(spec *operator.InstallationSpec, c *corev1.ConfigMap) error {
	// If CNI plugin is specified and not Calico then skip any CalicoNetwork initialization
	if spec.CNI != nil && spec.CNI.Type != operator.PluginCalico {
		return nil
	}
	if spec.CalicoNetwork == nil {
		spec.CalicoNetwork = &operator.CalicoNetworkSpec{}
	}

	platformCIDRs, err := extractKubeadmCIDRs(c)
	if err != nil {
		return err
	}
	return mergePlatformPodCIDRs(spec, platformCIDRs)
}

func mergePlatformPodCIDRs(spec *operator.InstallationSpec, platformCIDRs []string) error {
	// If IPPools is nil, add IPPool with CIDRs detected from platform configuration.
	if spec.CalicoNetwork.IPPools == nil {
		if len(platformCIDRs) == 0 {
			// If the platform has no CIDRs defined as well, then return and let the
			// normal defaulting happen.
			return nil
		}
		v4found := false
		v6found := false

		// For each platform CIDR, add it as an IP pool.
		for _, c := range platformCIDRs {
			log.Info("Adding IP pool for platform CIDR", "cidr", c)
			addr, _, err := net.ParseCIDR(c)
			if err != nil {
				log.Error(err, "Failed to parse platform's pod network CIDR.")
				continue
			}

			if addr.To4() == nil {
				// Treat the first IPv6 CIDR as the default. Subsequent CIDRs will be named based on their CIDR.
				name := defaultV6PoolName
				if v6found {
					name = ""
				}
				v6found = true
				spec.CalicoNetwork.IPPools = append(spec.CalicoNetwork.IPPools, operator.IPPool{Name: name, CIDR: c})
			} else {
				// Treat the first IPv4 CIDR as the default. Subsequent CIDRs will be named based on their CIDR.
				name := defaultPoolName
				if v4found {
					name = ""
				}
				v4found = true
				spec.CalicoNetwork.IPPools = append(spec.CalicoNetwork.IPPools, operator.IPPool{Name: name, CIDR: c})
			}
		}
	} else if len(spec.CalicoNetwork.IPPools) == 0 {
		// Empty IPPools list so nothing to do.
		return nil
	} else {
		// Pools are configured on the Installation. Make sure they are compatible with
		// the configuration set in the underlying Kubernetes platform.
		for _, pool := range spec.CalicoNetwork.IPPools {
			within := false
			for _, c := range platformCIDRs {
				within = within || cidrWithinCidr(c, pool.CIDR)
			}
			if !within {
				return fmt.Errorf("IPPool %v is not within the platform's configured pod network CIDR(s) %v", pool.CIDR, platformCIDRs)
			}
		}
	}
	return nil
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
