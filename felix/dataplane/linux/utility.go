// Copyright (c) 2023 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
)

// added so that we can shim netlink for tests
type netlinkHandle interface {
	LinkByName(name string) (netlink.Link, error)
	LinkSetMTU(link netlink.Link, mtu int) error
	LinkSetUp(link netlink.Link) error
	AddrList(link netlink.Link, family int) ([]netlink.Addr, error)
	AddrAdd(link netlink.Link, addr *netlink.Addr) error
	AddrDel(link netlink.Link, addr *netlink.Addr) error
	LinkList() ([]netlink.Link, error)
	LinkAdd(netlink.Link) error
	LinkDel(netlink.Link) error
}

func routeIsLocalBlock(msg *proto.RouteUpdate, routeProto proto.IPPoolType) bool {
	// RouteType_LOCAL_WORKLOAD means "local IPAM block _or_ /32 of workload" in IPv4.
	// It means "local IPAM block _or_ /128 of workload" in IPv6.
	if msg.Type != proto.RouteType_LOCAL_WORKLOAD {
		return false
	}
	// Only care about a specific ippool
	if msg.IpPoolType != routeProto {
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

func blackholeRoutes(localIPAMBlocks map[string]*proto.RouteUpdate) []routetable.Target {
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
			Type: routetable.TargetTypeBlackhole,
			CIDR: cidr,
		})
	}
	logrus.Debug("calculated blackholes ", rtt)
	return rtt
}
