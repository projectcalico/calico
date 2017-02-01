// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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
package testutils

import (
	gonet "net"

	"github.com/projectcalico/libcalico-go/lib/net"
)

// MustParseNetwork parses the string into a net.IPNet.  The IP address in the
// IPNet is masked.
func MustParseNetwork(c string) net.IPNet {
	_, cidr, err := gonet.ParseCIDR(c)
	if err != nil {
		panic(err)
	}
	return net.IPNet{*cidr}
}

// MustParseCIDR parses the string into a net.IPNet.  The IP address in the
// IPNet is not masked.
func MustParseCIDR(c string) net.IPNet {
	ip, cidr, err := gonet.ParseCIDR(c)
	if err != nil {
		panic(err)
	}
	n := net.IPNet{}
	n.IP = ip
	n.Mask = cidr.Mask
	return n
}

func MustParseIP(i string) net.IP {
	var ip net.IP
	err := ip.UnmarshalText([]byte(i))
	if err != nil {
		panic(err)
	}
	return ip
}
