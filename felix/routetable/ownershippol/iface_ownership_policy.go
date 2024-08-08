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

package ownershippol

import (
	"github.com/vishvananda/netlink"
)

type ExclusiveOwnershipPolicy struct {
	InterfaceNames []string
}

func (d *ExclusiveOwnershipPolicy) IfaceShouldHaveARPEntries(ifaceName string) bool {
	// Returning true so that we defer to the RouteTable's main ARP
	// configuration.
	return true
}
func (d *ExclusiveOwnershipPolicy) IfaceShouldHaveGracePeriod(ifaceName string) bool {
	// Returning true so that we defer to the RouteTable's main grace period
	// configuration.
	return true
}

func (d *ExclusiveOwnershipPolicy) IfaceIsOurs(ifaceName string) bool {
	if d.InterfaceNames == nil {
		return true
	}
	for _, iface := range d.InterfaceNames {
		if iface == ifaceName {
			return true
		}
	}
	return false
}

func (d *ExclusiveOwnershipPolicy) RouteIsOurs(ifaceName string, route *netlink.Route) bool {
	return true
}
