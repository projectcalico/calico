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
