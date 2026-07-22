// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.
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

package dataplanedefs

import "github.com/vishvananda/netlink"

const (
	IPIPIfaceName    = "tunl0"
	VXLANIfaceNameV4 = "vxlan.calico"
	VXLANIfaceNameV6 = "vxlan-v6.calico"

	DefaultRouteProto netlink.RouteProtocol = 80

	BPFInDev  = "bpfin.cali"
	BPFOutDev = "bpfout.cali"

	// FlowtableName is the name of the nftables flowtable used for offloading established
	// flows. The rule renderer references it via "flow offload @<name>" and the nftables
	// table programs the flowtable object under the same name; the two must stay in lockstep.
	FlowtableName = "calico"
)
