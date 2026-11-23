// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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

package utils

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// PodNetwork is what the cluster's IP pools say about pod traffic: the IP
// families pods get, and the tunnel device each family's traffic uses.
type PodNetwork struct {
	Families     []IPFamily
	EncapDevices map[IPFamily]string
}

// ReadPodNetwork reads the IP pools once, so every answer comes from the same
// pools: disabled, tunnel-only and manual-assignment pools count for neither.
// Families come from the pools rather than node addresses because an IPv4-only
// Calico cluster can run on dual-stack hosts, whose nodes report an IPv6
// InternalIP Calico never uses.
func ReadPodNetwork(cli ctrlclient.Client) (PodNetwork, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pools := &v3.IPPoolList{}
	if err := cli.List(ctx, pools); err != nil {
		return PodNetwork{}, fmt.Errorf("listing IPPools: %w", err)
	}
	// With no pools at all, another CNI's IPAM (e.g. Azure or VPC CNI) hands out
	// pod addresses, so the pods themselves are the only record of the families.
	if len(pools.Items) == 0 {
		pods := &corev1.PodList{}
		if err := cli.List(ctx, pods); err != nil {
			return PodNetwork{}, fmt.Errorf("no IPPools found; listing pods to find pod IP families: %w", err)
		}
		families, err := podFamilies(pods.Items)
		if err != nil {
			return PodNetwork{}, err
		}
		return PodNetwork{Families: families, EncapDevices: map[IPFamily]string{}}, nil
	}
	families, err := poolFamilies(pools.Items)
	if err != nil {
		return PodNetwork{}, err
	}
	return PodNetwork{Families: families, EncapDevices: encapDevices(pools.Items)}, nil
}

func poolFamilies(pools []v3.IPPool) ([]IPFamily, error) {
	have := map[IPFamily]bool{}
	var skipped []string
	for _, p := range pools {
		if reason := poolSkipReason(p); reason != "" {
			skipped = append(skipped, fmt.Sprintf("%s (%s)", p.Name, reason))
			continue
		}
		ip, _, err := net.ParseCIDR(p.Spec.CIDR)
		if err != nil {
			return nil, fmt.Errorf("IPPool %s has unparseable CIDR %q: %w", p.Name, p.Spec.CIDR, err)
		}
		if ip.To4() != nil {
			have[IPv4] = true
		} else {
			have[IPv6] = true
		}
	}
	var families []IPFamily
	for _, f := range allIPFamilies {
		if have[f] {
			families = append(families, f)
		}
	}
	if len(families) == 0 {
		if len(skipped) == 0 {
			return nil, fmt.Errorf("no IPPools found")
		}
		return nil, fmt.Errorf("no IPPool assigns pod addresses automatically: %s", strings.Join(skipped, ", "))
	}
	return families, nil
}

// podFamilies skips host-networked pods, whose addresses are the node's and say
// nothing about what the pod network hands out.
func podFamilies(pods []corev1.Pod) ([]IPFamily, error) {
	have := map[IPFamily]bool{}
	for _, p := range pods {
		if p.Spec.HostNetwork || p.Status.Phase != corev1.PodRunning {
			continue
		}
		for _, ip := range p.Status.PodIPs {
			if fam, ok := FamilyOf(ip.IP); ok {
				have[fam] = true
			}
		}
	}
	var families []IPFamily
	for _, f := range allIPFamilies {
		if have[f] {
			families = append(families, f)
		}
	}
	if len(families) == 0 {
		return nil, fmt.Errorf("no IPPools found, and no running pod-network pod has an IP to read the pod IP families from")
	}
	return families, nil
}

// poolSkipReason is "" for a pool that automatically gives pods addresses; the
// others don't decide which families a pod can have.
func poolSkipReason(p v3.IPPool) string {
	if p.Spec.Disabled {
		return "disabled"
	}
	if len(p.Spec.AllowedUses) > 0 && !slices.Contains(p.Spec.AllowedUses, v3.IPPoolAllowedUseWorkload) {
		return fmt.Sprintf("allowedUses %v", p.Spec.AllowedUses)
	}
	if p.Spec.AssignmentMode != nil && *p.Spec.AssignmentMode != v3.Automatic {
		return fmt.Sprintf("assignmentMode %s", *p.Spec.AssignmentMode)
	}
	return ""
}

// encapDevices keeps the first device it finds per family when pools mix IPIP
// and VXLAN. Callers have already had poolFamilies reject unparseable CIDRs.
func encapDevices(pools []v3.IPPool) map[IPFamily]string {
	devices := map[IPFamily]string{}
	for _, p := range pools {
		if poolSkipReason(p) != "" {
			continue
		}
		ip, _, err := net.ParseCIDR(p.Spec.CIDR)
		if err != nil {
			continue
		}
		fam, _ := FamilyOf(ip.String())
		if dev := encapDevice(p.Spec, fam); dev != "" && devices[fam] == "" {
			devices[fam] = dev
		}
	}
	return devices
}

func encapDevice(spec v3.IPPoolSpec, fam IPFamily) string {
	switch {
	case fam == IPv4 && (spec.IPIPMode == v3.IPIPModeAlways || spec.IPIPMode == v3.IPIPModeCrossSubnet):
		return "tunl0"
	case spec.VXLANMode == v3.VXLANModeAlways || spec.VXLANMode == v3.VXLANModeCrossSubnet:
		if fam == IPv6 {
			return "vxlan-v6.calico"
		}
		return "vxlan.calico"
	}
	return ""
}
