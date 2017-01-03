// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package ifacemonitor_test

import (
	"fmt"
	"time"

	"github.com/projectcalico/felix/go/felix/ifacemonitor"
	"github.com/projectcalico/felix/go/felix/set"
	"github.com/vishvananda/netlink"

	. "github.com/onsi/ginkgo"
	//. "github.com/onsi/gomega"
)

type netlinkTest struct {
	linkUpdates chan netlink.LinkUpdate
	addrUpdates chan netlink.AddrUpdate
}

func (nl *netlinkTest) Subscribe(
	linkUpdates chan netlink.LinkUpdate,
	addrUpdates chan netlink.AddrUpdate,
) error {
	nl.linkUpdates = linkUpdates
	nl.addrUpdates = addrUpdates
	return nil
}

func (nl *netlinkTest) LinkList() ([]netlink.Link, error) {
	return []netlink.Link{}, nil
}

func (nl *netlinkTest) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	return []netlink.Addr{}, nil
}

func linkStateCallback(ifaceName string, ifaceState ifacemonitor.State) {
	fmt.Println("addrStateCallback: ifaceName", ifaceName)
	fmt.Println("addrStateCallback: ifaceState", ifaceState)
}

func addrStateCallback(ifaceName string, addrs set.Set) {
	fmt.Println("addrStateCallback: ifaceName", ifaceName)
	fmt.Println("addrStateCallback: addrs", addrs)
}

var _ = Describe("ifacemonitor", func() {
	It("New", func() {
		nl := &netlinkTest{}
		im := ifacemonitor.New(nl)
		im.Callback = linkStateCallback
		im.AddrCallback = addrStateCallback
		go im.MonitorInterfaces()
		time.Sleep(1 * time.Second)
	})
})
