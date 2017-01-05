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

package routetable_test

import (
	. "github.com/projectcalico/felix/go/felix/routetable"

	"errors"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
)

var (
	notImplemented = errors.New("Not implemented")
)

var _ = Describe("RouteTable", func() {
	var dataplane *mockDataplane
	var rt *RouteTable
	BeforeEach(func() {
		dataplane = &mockDataplane{}
		rt = NewWithShims([]string{"cali"}, 4, dataplane)
	})

	It("should be constructable", func() {
		Expect(rt).ToNot(BeNil())
	})
})

type mockDataplane struct {
}

func (r mockDataplane) LinkList() ([]netlink.Link, error) {
	return nil, notImplemented
}

func (r mockDataplane) LinkByName(name string) (netlink.Link, error) {
	return nil, notImplemented
}

func (r mockDataplane) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	return nil, notImplemented
}

func (r mockDataplane) RouteAdd(route *netlink.Route) error {
	return notImplemented
}

func (r mockDataplane) RouteDel(route *netlink.Route) error {
	return notImplemented
}
