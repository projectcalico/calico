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

// Package routeproto classifies the netlink protocol that owns a kernel route
// in terms of which Calico component programmed it. It is the Calico-specific
// counterpart to the generic iputils package: iputils parses `ip -j route show`
// into the protocol string as iproute2 reports it, and routeproto.Parse turns
// that string into a typed owner (Felix, BIRD, ...).
package routeproto

import (
	"fmt"
	"strconv"
)

// Proto identifies the netlink protocol that owns a kernel route. The numeric
// values match the kernel's RTPROT_* constants. Felix-programmed routes carry
// protocol 80 (felix/dataplane/linux/dataplanedefs.DefaultRouteProto);
// BIRD-programmed routes carry protocol 12 (RTPROT_BIRD).
type Proto int

const (
	Unknown Proto = -1
	BIRD    Proto = 12
	Felix   Proto = 80
)

func (p Proto) String() string {
	switch p {
	case BIRD:
		return "bird"
	case Felix:
		return "felix"
	case Unknown:
		return "unknown"
	}
	return fmt.Sprintf("proto-%d", int(p))
}

// Parse maps the protocol string from `ip -j route show` to a Proto. Protocol
// is a string in iproute2's JSON output regardless of whether the kernel proto
// has a name in /etc/iproute2/rt_protos: named protos appear as e.g. "bird";
// unnamed appear as the decimal value (e.g. "80").
func Parse(s string) Proto {
	switch s {
	case "":
		return Unknown
	case "bird":
		return BIRD
	}
	if n, err := strconv.Atoi(s); err == nil {
		return Proto(n)
	}
	return Unknown
}
