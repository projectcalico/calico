// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

package calc_test

import (
	net2 "net"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/net"
)

func mustParseMac(m string) *net.MAC {
	hwAddr, err := net2.ParseMAC(m)
	if err != nil {
		log.Panicf("Failed to parse MAC: %v; %v", m, err)
	}
	return &net.MAC{hwAddr}
}

func mustParseNet(n string) net.IPNet {
	_, cidr, err := net.ParseCIDR(n)
	if err != nil {
		log.Panicf("Failed to parse CIDR %v; %v", n, err)
	}
	return *cidr
}

func mustParseIP(s string) net.IP {
	ip := net2.ParseIP(s)
	return net.IP{ip}
}
