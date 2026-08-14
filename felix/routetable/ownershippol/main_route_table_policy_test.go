// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package ownershippol

import (
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
)

func TestRouteIsOurs_BIRDRoutesOnBGPPeerIfaces(t *testing.T) {
	const (
		wlIface    = "cali12345"
		nonWlIface = "eth0"
	)
	exclusiveProto := netlink.RouteProtocol(80) // dataplanedefs.DefaultRouteProto

	peerTrue := func(string) bool { return true }
	peerFalse := func(string) bool { return false }

	tests := []struct {
		name                string
		removeExternal      bool
		ifaceName           string
		protocol            netlink.RouteProtocol
		peerCallback        func(string) bool
		expectedRouteIsOurs bool
	}{
		{
			name:                "workload iface, RTPROT_BIRD, peer=true, removeExternal=true => not ours",
			removeExternal:      true,
			ifaceName:           wlIface,
			protocol:            unix.RTPROT_BIRD,
			peerCallback:        peerTrue,
			expectedRouteIsOurs: false,
		},
		{
			name:                "workload iface, RTPROT_BIRD, peer=false, removeExternal=true => ours",
			removeExternal:      true,
			ifaceName:           wlIface,
			protocol:            unix.RTPROT_BIRD,
			peerCallback:        peerFalse,
			expectedRouteIsOurs: true,
		},
		{
			name:                "workload iface, non-BIRD proto, peer=true, removeExternal=true => ours",
			removeExternal:      true,
			ifaceName:           wlIface,
			protocol:            unix.RTPROT_BOOT,
			peerCallback:        peerTrue,
			expectedRouteIsOurs: true,
		},
		{
			name:                "workload iface, RTPROT_BIRD, nil callback, removeExternal=true => ours",
			removeExternal:      true,
			ifaceName:           wlIface,
			protocol:            unix.RTPROT_BIRD,
			peerCallback:        nil,
			expectedRouteIsOurs: true,
		},
		{
			name:                "non-workload iface, RTPROT_BIRD => not ours",
			removeExternal:      true,
			ifaceName:           nonWlIface,
			protocol:            unix.RTPROT_BIRD,
			peerCallback:        peerTrue,
			expectedRouteIsOurs: false,
		},
		{
			name:                "removeExternal=false, workload iface, RTPROT_BIRD => not ours (proto mismatch)",
			removeExternal:      false,
			ifaceName:           wlIface,
			protocol:            unix.RTPROT_BIRD,
			peerCallback:        peerTrue,
			expectedRouteIsOurs: false,
		},
		{
			name:                "exclusive proto route on workload iface => ours",
			removeExternal:      true,
			ifaceName:           wlIface,
			protocol:            exclusiveProto,
			peerCallback:        peerTrue,
			expectedRouteIsOurs: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pol := &MainTableOwnershipPolicy{
				WorkloadInterfacePrefixes:     []string{"cali"},
				RemoveNonCalicoWorkloadRoutes: tt.removeExternal,
				CalicoSpecialInterfaces:       []string{"vxlan.calico"},
				AllRouteProtocols:             []netlink.RouteProtocol{unix.RTPROT_BOOT, exclusiveProto},
				ExclusiveRouteProtocols:       []netlink.RouteProtocol{exclusiveProto},
				IsWorkloadBGPPeerIface:        tt.peerCallback,
			}

			route := &netlink.Route{Protocol: tt.protocol}
			got := pol.RouteIsOurs(tt.ifaceName, route)
			if got != tt.expectedRouteIsOurs {
				t.Errorf("RouteIsOurs(%q, proto=%d) = %v, want %v",
					tt.ifaceName, tt.protocol, got, tt.expectedRouteIsOurs)
			}
		})
	}
}

// TestRouteIsOurs_BIRDRoutesOnIPIPDevice covers OwnBIRDIPIPRoutes: when Felix programs the IPIP
// cluster routes, BIRD's routes via the IPIP device come inside Felix's ownership boundary, so that
// the ones BIRD left behind on exit (its kernel protocol runs with `persist`) are reconciled away.
// Only BIRD's protocol is claimed, and only on the IPIP device.
func TestRouteIsOurs_BIRDRoutesOnIPIPDevice(t *testing.T) {
	exclusiveProto := netlink.RouteProtocol(80) // dataplanedefs.DefaultRouteProto

	tests := []struct {
		name                string
		ownBIRDIPIPRoutes   bool
		ifaceName           string
		protocol            netlink.RouteProtocol
		expectedRouteIsOurs bool
	}{
		{
			name:                "IPIP device, RTPROT_BIRD, Felix owns IPIP routes => ours",
			ownBIRDIPIPRoutes:   true,
			ifaceName:           dataplanedefs.IPIPIfaceName,
			protocol:            unix.RTPROT_BIRD,
			expectedRouteIsOurs: true,
		},
		{
			name:                "IPIP device, RTPROT_BIRD, BIRD owns IPIP routes => not ours",
			ownBIRDIPIPRoutes:   false,
			ifaceName:           dataplanedefs.IPIPIfaceName,
			protocol:            unix.RTPROT_BIRD,
			expectedRouteIsOurs: false,
		},
		{
			// Felix's own routes are claimed by the exclusive protocol check, whether or not
			// it is the configured owner, so they do not depend on this flag.
			name:                "IPIP device, exclusive proto, BIRD owns IPIP routes => ours",
			ownBIRDIPIPRoutes:   false,
			ifaceName:           dataplanedefs.IPIPIfaceName,
			protocol:            exclusiveProto,
			expectedRouteIsOurs: true,
		},
		{
			// A third party's routes through the device are left alone, even though Felix owns
			// the device itself.
			name:                "IPIP device, unrelated proto, Felix owns IPIP routes => not ours",
			ownBIRDIPIPRoutes:   true,
			ifaceName:           dataplanedefs.IPIPIfaceName,
			protocol:            unix.RTPROT_STATIC,
			expectedRouteIsOurs: false,
		},
		{
			name:                "non-IPIP device, RTPROT_BIRD, Felix owns IPIP routes => not ours",
			ownBIRDIPIPRoutes:   true,
			ifaceName:           "eth0",
			protocol:            unix.RTPROT_BIRD,
			expectedRouteIsOurs: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pol := &MainTableOwnershipPolicy{
				WorkloadInterfacePrefixes: []string{"cali"},
				CalicoSpecialInterfaces:   []string{"vxlan.calico"},
				AllRouteProtocols:         []netlink.RouteProtocol{unix.RTPROT_BOOT, exclusiveProto},
				ExclusiveRouteProtocols:   []netlink.RouteProtocol{exclusiveProto},
				OwnBIRDIPIPRoutes:         tt.ownBIRDIPIPRoutes,
			}

			route := &netlink.Route{Protocol: tt.protocol}
			got := pol.RouteIsOurs(tt.ifaceName, route)
			if got != tt.expectedRouteIsOurs {
				t.Errorf("RouteIsOurs(%q, proto=%d) = %v, want %v",
					tt.ifaceName, tt.protocol, got, tt.expectedRouteIsOurs)
			}
		})
	}
}
