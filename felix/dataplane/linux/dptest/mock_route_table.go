// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package dptest

import (
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/routetable"
)

type MockRouteTable struct {
	CurrentRoutes map[string][]routetable.Target

	// currentRoutesByClass indexes the same routes the way the real RouteTable
	// does, on (route class, interface name).  Managers that share a route table
	// _and_ an interface - such as the blackhole routes that all hang off
	// InterfaceNone - are only distinguishable by their class.  Lazily created,
	// so that the plain currentRoutes-only struct literals still work.
	currentRoutesByClass map[routetable.RouteClass]map[string][]routetable.Target
}

func NewMockRouteTable() *MockRouteTable {
	return &MockRouteTable{CurrentRoutes: map[string][]routetable.Target{}}
}

func (t *MockRouteTable) SetRoutes(routeClass routetable.RouteClass, ifaceName string, targets []routetable.Target) {
	log.WithFields(log.Fields{
		"routeClass": routeClass,
		"ifaceName":  ifaceName,
		"targets":    targets,
	}).Debug("SetRoutes")
	t.CurrentRoutes[ifaceName] = targets

	if t.currentRoutesByClass == nil {
		t.currentRoutesByClass = map[routetable.RouteClass]map[string][]routetable.Target{}
	}
	if t.currentRoutesByClass[routeClass] == nil {
		t.currentRoutesByClass[routeClass] = map[string][]routetable.Target{}
	}
	t.currentRoutesByClass[routeClass][ifaceName] = targets
}

// CIDRsForClass returns the CIDRs of the routes that the given class currently
// has programmed on the given interface.
func (t *MockRouteTable) CIDRsForClass(routeClass routetable.RouteClass, ifaceName string) []string {
	var cidrs []string
	for _, target := range t.currentRoutesByClass[routeClass][ifaceName] {
		cidrs = append(cidrs, target.CIDR.String())
	}
	return cidrs
}

func (t *MockRouteTable) RouteRemove(routeClass routetable.RouteClass, ifaceName string, routeKey routetable.RouteKey) {
}

func (t *MockRouteTable) RouteUpdate(routeClass routetable.RouteClass, ifaceName string, target routetable.Target) {
}

func (t *MockRouteTable) OnIfaceStateChanged(string, int, ifacemonitor.State) {}
func (t *MockRouteTable) QueueResync()                                        {}
func (t *MockRouteTable) QueueResyncIface(ifaceName string)                   {}

func (t *MockRouteTable) Index() int {
	return 0
}

func (t *MockRouteTable) ReadRoutesFromKernel(ifaceName string) ([]routetable.Target, error) {
	// TODO implement me
	panic("implement me")
}

func (t *MockRouteTable) Apply() error {
	return nil
}

func (t *MockRouteTable) CheckRoutes(ifaceName string, expected []routetable.Target) {
	gomega.Expect(t.CurrentRoutes[ifaceName]).To(gomega.ConsistOf(expected), "Expect route to exist. Current routes = %v", t.CurrentRoutes)
}
