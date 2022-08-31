// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

package routetable

import (
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
)

// RouteTableSyncer is the interface used to manage data-sync of route table managers. This includes notification of
// interface state changes, hooks to queue a full resync and apply routing updates.
type RouteTableSyncer interface {
	OnIfaceStateChanged(string, ifacemonitor.State)
	QueueResync()
	Apply() error
}

// RouteTable is the interface provided by the standard routetable module used to program the RIB.
type RouteTableInterface interface {
	RouteTableSyncer
	SetRoutes(ifaceName string, targets []Target)
	SetL2Routes(ifaceName string, targets []L2Target)
	RouteRemove(ifaceName string, cidr ip.CIDR)
	RouteUpdate(ifaceName string, target Target)
}
