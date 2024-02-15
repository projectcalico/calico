// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package routetable

import (
	"strings"

	"github.com/vishvananda/netlink"
)

// MainTableOwnershipPolicy is the OwnershipPolicy for the main routing table.
// It needs to discriminate between our routes and routes from other
// applications.  It does that based on various heuristics that try to
// capture Felix's current and historic behaviour.  It would have been a
// lot cleaner if we'd picked a "protocol" value for all our routes on day one
// and stuck to it!
type MainTableOwnershipPolicy struct {
	WorkloadInterfacePrefixes     []string
	RemoveNonCalicoWorkloadRoutes bool

	// CalicoSpecialInterfaces is a list of interfaces that Calico uses for
	// tunnels and special purposes.
	CalicoSpecialInterfaces []string

	// AllRouteProtocols is a list of protocols that Calico uses,
	// but may be used by other software too.
	AllRouteProtocols []netlink.RouteProtocol

	// ExclusiveRouteProtocols is a list of protocols that should only be
	// used by Calico.
	ExclusiveRouteProtocols []netlink.RouteProtocol
}

func (d *MainTableOwnershipPolicy) IfaceShouldHaveARPEntries(ifaceName string) bool {
	return d.isWorkloadInterface(ifaceName)
}

func (d *MainTableOwnershipPolicy) IfaceShouldHaveGracePeriod(ifaceName string) bool {
	return d.isWorkloadInterface(ifaceName)
}

func (d *MainTableOwnershipPolicy) isWorkloadInterface(ifaceName string) bool {
	for _, prefix := range d.WorkloadInterfacePrefixes {
		if strings.HasPrefix(ifaceName, prefix) {
			return true
		}
	}
	return false
}

func (d *MainTableOwnershipPolicy) IfaceIsOurs(_ string) bool {
	// In the main routing table, we need to keep track of all interfaces
	// so that we can handle cases such as "same-subnet" VXLAN routes moving
	// between interfaces when the parent device changes.
	return true
}

func (d *MainTableOwnershipPolicy) RouteIsOurs(ifaceName string, route *netlink.Route) bool {
	// Check for routes that have a unique protocol that only Calico should
	// be using.  We can safely assume that these belong to us.
	//
	// This covers:
	// - VXLAN "same-subnet" routes via the host's main NIC.
	// - Special no-interface routes such as blackhole/prohibit.
	for _, protocol := range d.ExclusiveRouteProtocols {
		if route.Protocol == protocol {
			return true
		}
	}

	// "No-interface" special routes can only be ours if they have one
	// of our exclusive proto values, so, if we got no hit above, we
	// can assume it's not ours.
	if ifaceName == InterfaceNone {
		return false
	}

	if d.isWorkloadInterface(ifaceName) {
		if d.RemoveNonCalicoWorkloadRoutes {
			// We're configured to assume that any route to one of our
			// interfaces is ours, no need to check the protocol.
			return true
		}
		// Otherwise, we need to check the route's protocol.  We use the
		// more permissive protocol value here because we already know that
		// this is one of our interfaces so the route is very likely to be
		// ours.
		for _, protocol := range d.AllRouteProtocols {
			if route.Protocol == protocol {
				return true
			}
		}
		// Calico interface but not our route.
		return false
	}

	// Check if this route goes to one of our tunnel/special purpose
	// interfaces.  These are always ours.
	for _, iface := range d.CalicoSpecialInterfaces {
		if ifaceName == iface {
			return true
		}
	}

	return false
}
