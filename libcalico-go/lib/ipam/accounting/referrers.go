// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package accounting

import (
	"fmt"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// Referrer kinds the builders below use. They match the names calicoctl ipam check reports.
const (
	ReferrerNode     = "Node"
	ReferrerWorkload = "Workload"
	ReferrerService  = "Service"

	ReferrerVirtualMachine = "VirtualMachine"
)

// NodeAddressRefs is a reference for each tunnel address the node's spec names.
func NodeAddressRefs(node *internalapi.Node) ([]AddressRef, error) {
	addrs := []string{node.Spec.IPv4VXLANTunnelAddr, node.Spec.IPv6VXLANTunnelAddr}
	if node.Spec.BGP != nil {
		addrs = append(addrs, node.Spec.BGP.IPv4IPIPTunnelAddr)
	}
	if node.Spec.Wireguard != nil {
		addrs = append(addrs, node.Spec.Wireguard.InterfaceIPv4Address, node.Spec.Wireguard.InterfaceIPv6Address)
	}
	return refsFor(addrs, v3.IPPoolAllowedUseTunnel, Referrer{Kind: ReferrerNode, Name: node.Name})
}

// WorkloadEndpointAddressRefs is a reference for each address the endpoint holds.
func WorkloadEndpointAddressRefs(wep *internalapi.WorkloadEndpoint) ([]AddressRef, error) {
	referrer := Referrer{Kind: ReferrerWorkload, Namespace: wep.Namespace, Name: wep.Name}
	return refsFor(wep.Spec.IPNetworks, v3.IPPoolAllowedUseWorkload, referrer)
}

// ServiceAddressRefs is a reference for each LoadBalancer ingress IP in the service's status. Whether Calico manages the
// service's addresses is the caller's decision.
func ServiceAddressRefs(svc *corev1.Service) ([]AddressRef, error) {
	var addrs []string
	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		addrs = append(addrs, ingress.IP)
	}
	referrer := Referrer{Kind: ReferrerService, Namespace: svc.Namespace, Name: svc.Name}
	return refsFor(addrs, v3.IPPoolAllowedUseLoadBalancer, referrer)
}

// refsFor references each address or CIDR in addrs, skipping empty ones.
func refsFor(addrs []string, kind v3.IPPoolAllowedUse, referrer Referrer) ([]AddressRef, error) {
	var out []AddressRef
	for _, addr := range addrs {
		if addr == "" {
			continue
		}
		ip, _, err := cnet.ParseCIDROrIP(addr)
		if err != nil {
			return nil, fmt.Errorf("%s has an unparseable address %q: %w", referrer, addr, err)
		}
		out = append(out, AddressRef{IP: ip.IP, Kind: kind, Referrer: referrer})
	}
	return out, nil
}
