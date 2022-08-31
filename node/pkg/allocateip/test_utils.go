// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.
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

package allocateip

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

// makeNode creates an api.Node with some BGPSpec info populated.
func makeNode(ipv4 string, ipv6 string) *libapi.Node {
	ip4, ip4net, _ := net.ParseCIDR(ipv4)
	ip4net.IP = ip4.IP

	ip6Addr := ""
	if ipv6 != "" {
		ip6, ip6net, _ := net.ParseCIDR(ipv6)
		// Guard against nil here in case we pass in an empty string for IPv6.
		if ip6 != nil {
			ip6net.IP = ip6.IP
		}
		ip6Addr = ip6net.String()
	}

	n := &libapi.Node{
		Spec: libapi.NodeSpec{
			BGP: &libapi.NodeBGPSpec{
				IPv4Address: ip4net.String(),
				IPv6Address: ip6Addr,
			},
			Wireguard: &libapi.NodeWireguardSpec{},
		},
	}
	return n
}

func makeIPPool(name string, cidr string, blockSize int, ipipMode api.IPIPMode, vxlanMode api.VXLANMode) *api.IPPool {
	return &api.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: api.IPPoolSpec{
			CIDR:        cidr,
			BlockSize:   blockSize,
			NATOutgoing: true,
			IPIPMode:    ipipMode,
			VXLANMode:   vxlanMode,
		},
	}
}
