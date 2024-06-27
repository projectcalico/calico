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

package intdataplane

import (
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/routetable"
)

// mainRoutingTableOwnershipPolicy calculates the ownership policy for the
// main routing table, given Felix's configuration.
func mainRoutingTableOwnershipPolicy(config Config, ipVersion int) *routetable.MainTableOwnershipPolicy {
	var allRouteProtos []netlink.RouteProtocol
	var exclusiveRouteProtos []netlink.RouteProtocol
	if config.DeviceRouteProtocol == unix.RTPROT_BOOT {
		// RTPROTO_BOOT ended up being our default a long time ago, but it was
		// a bad choice.  Originally, it didn't matter because we didn't use
		// the protocol to distinguish our routes (we used the interface name
		// instead).  However, when we added VXLAN, we needed to add blackhole
		// and same-subnet routes, which don't relate to a Calico-owned
		// interface.  To avoid churning routes, we ended up using a new proto
		// value just for the routes we needed to distinguish.
		//
		// So, if we see RTPROTO_BOOT on a route, it's ours if it's also
		// associated with one of our interfaces.  But, if we see a route with
		// defaultVXLANProto, we know it's ours.
		allRouteProtos = []netlink.RouteProtocol{unix.RTPROT_BOOT, defaultVXLANProto}
		exclusiveRouteProtos = []netlink.RouteProtocol{defaultVXLANProto}
	} else {
		// If DeviceRouteProtocol is not RTPROTO_BOOT, then we use that value
		// for all our routes and we don't need to worry about RTPROTO_BOOT.
		allRouteProtos = []netlink.RouteProtocol{config.DeviceRouteProtocol}
		exclusiveRouteProtos = []netlink.RouteProtocol{config.DeviceRouteProtocol}
	}
	var vxlanDevice string
	if ipVersion == 4 {
		vxlanDevice = VXLANIfaceNameV4
	} else {
		vxlanDevice = VXLANIfaceNameV6
	}
	ownershipPolicy := &routetable.MainTableOwnershipPolicy{
		WorkloadInterfacePrefixes:     config.RulesConfig.WorkloadIfacePrefixes,
		RemoveNonCalicoWorkloadRoutes: config.RemoveExternalRoutes,
		CalicoSpecialInterfaces: []string{
			// Always including VXLAN device, even if not enabled.  That means
			// we'll clean up the routes if VXLAN is disabled.
			vxlanDevice,
			bpfInDev,
			// Not including routetable.InterfaceNone because MainTableOwnershipPolicy
			// automatically handles it.
			// Not including tunl0, it is managed by BIRD.
			// Not including Wireguard, it has its own routing table.
		},
		AllRouteProtocols:       allRouteProtos,
		ExclusiveRouteProtocols: exclusiveRouteProtos,
	}
	return ownershipPolicy
}
