// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
)

func isType(msg *proto.RouteUpdate, t proto.RouteType) bool {
	return msg.Types&t == t
}

func calculateRouteProtocol(dpConfig Config) netlink.RouteProtocol {
	// For same-subnet and blackhole routes, we need a unique protocol
	// to attach to the routes.  If the global DeviceRouteProtocol is set to
	// a usable value, use that; otherwise, pick a safer default.  (For back
	// compatibility, our DeviceRouteProtocol defaults to RTPROT_BOOT, which
	// can also be used by other processes.)
	//
	// Routes to the VXLAN tunnel device itself are identified by their target
	// interface.  We don't need to worry about their protocol.
	routeProtocol := dataplanedefs.DefaultRouteProto
	if dpConfig.DeviceRouteProtocol != syscall.RTPROT_BOOT {
		routeProtocol = dpConfig.DeviceRouteProtocol
	}
	return routeProtocol
}

func routeIsLocalBlock(msg *proto.RouteUpdate, poolType proto.IPPoolType) bool {
	// RouteType_LOCAL_WORKLOAD means "local IPAM block _or_ /32 of workload" in IPv4.
	// It means "local IPAM block _or_ /128 of workload" in IPv6.
	if !isType(msg, proto.RouteType_LOCAL_WORKLOAD) {
		return false
	}
	// Only care about a specific ippool
	if msg.IpPoolType != poolType {
		return false
	}
	// Ignore routes that we know are from local workload endpoints.
	if msg.LocalWorkload {
		return false
	}

	// Check the valid suffix depending on IP version.
	cidr, err := ip.CIDRFromString(msg.Dst)
	if err != nil {
		logrus.WithError(err).WithField("msg", msg).Warning("Unable to parse destination into a CIDR. Treating block as external.")
	}
	// Ignore exact routes, i.e. /32 (ipv4) or /128 (ipv6) routes in any case for two reasons:
	// * If we have a /32 or /128 block then our blackhole route would stop the CNI plugin from
	// programming its /32 or /128 for a newly added workload.
	// * If this isn't a /32 or /128 block then it must be a borrowed /32 or /128 from another
	// block. In that case, we know we're racing with CNI, adding a new workload.
	// We've received the borrowed IP but not the workload endpoint yet.
	exactRoute := "/32"
	if cidr.Version() == 6 {
		exactRoute = "/128"
	}
	return !strings.HasSuffix(msg.Dst, exactRoute)
}

func blackholeRoutes(localIPAMBlocks map[string]*proto.RouteUpdate, proto netlink.RouteProtocol) []routetable.Target {
	var rtt []routetable.Target
	for dst := range localIPAMBlocks {
		cidr, err := ip.CIDRFromString(dst)
		if err != nil {
			logrus.WithError(err).Warning(
				"Error processing IPAM block CIDR: ", dst,
			)
			continue
		}
		rtt = append(rtt, routetable.Target{
			Type:     routetable.TargetTypeBlackhole,
			CIDR:     cidr,
			Protocol: proto,
		})
	}
	return rtt
}

func noEncapRoute(
	ifaceName string,
	cidr ip.CIDR,
	r *proto.RouteUpdate,
	proto netlink.RouteProtocol,
) *routetable.Target {
	if ifaceName == "" {
		return nil
	}
	if !r.GetSameSubnet() {
		return nil
	}
	if r.DstNodeIp == "" {
		return nil
	}
	noEncapRoute := routetable.Target{
		Type:     routetable.TargetTypeNoEncap,
		CIDR:     cidr,
		GW:       ip.FromString(r.DstNodeIp),
		Protocol: proto,
	}
	return &noEncapRoute
}
