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

// SyncerInterface is the interface used to manage data-sync of route table managers. This includes notification of
// interface state changes, hooks to queue a full resync and apply routing updates.
type SyncerInterface interface {
	OnIfaceStateChanged(name string, ifIndex int, state ifacemonitor.State)
	QueueResync()
	Apply() error
}

// Interface is the interface provided by the standard routetable module used to program the RIB.
type Interface interface {
	SyncerInterface
	SetRoutes(routeClass RouteClass, ifaceName string, targets []Target)
	RouteRemove(routeClass RouteClass, ifaceName string, cidr ip.CIDR)
	RouteUpdate(routeClass RouteClass, ifaceName string, target Target)
	Index() int
	QueueResyncIface(ifaceName string)
	ReadRoutesFromKernel(ifaceName string) ([]Target, error)
}

// ClassView wraps a RouteTable with a simplified API that removes the need to
// pass the RouteClass to each method.
type ClassView struct {
	class      RouteClass
	routeTable Interface
}

func NewClassView(class RouteClass, routeTable Interface) *ClassView {
	return &ClassView{
		class:      class,
		routeTable: routeTable,
	}
}

func (cv *ClassView) OnIfaceStateChanged(name string, ifIndex int, state ifacemonitor.State) {
	cv.routeTable.OnIfaceStateChanged(name, ifIndex, state)
}

func (cv *ClassView) QueueResync() {
	cv.routeTable.QueueResync()
}

func (cv *ClassView) Apply() error {
	return cv.routeTable.Apply()
}

func (cv *ClassView) SetRoutes(ifaceName string, targets []Target) {
	cv.routeTable.SetRoutes(cv.class, ifaceName, targets)
}

func (cv *ClassView) RouteRemove(ifaceName string, cidr ip.CIDR) {
	cv.routeTable.RouteRemove(cv.class, ifaceName, cidr)
}

func (cv *ClassView) RouteUpdate(ifaceName string, target Target) {
	cv.routeTable.RouteUpdate(cv.class, ifaceName, target)
}

func (cv *ClassView) Index() int {
	return cv.routeTable.Index()
}

func (cv *ClassView) QueueResyncIface(ifaceName string) {
	cv.routeTable.QueueResyncIface(ifaceName)
}

func (cv *ClassView) ReadRoutesFromKernel(ifaceName string) ([]Target, error) {
	return cv.routeTable.ReadRoutesFromKernel(ifaceName)
}

var _ SyncerInterface = (*ClassView)(nil)
