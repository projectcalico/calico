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

package intdataplane

import (
	"github.com/vishvananda/netlink"
	"os/exec"
)

// ipipDataplane is a shim interface for mocking netlink and os/exec in the IPIP manager.
type ipipDataplane interface {
	LinkByName(name string) (netlink.Link, error)
	LinkSetMTU(link netlink.Link, mtu int) error
	LinkSetUp(link netlink.Link) error
	AddrList(link netlink.Link, family int) ([]netlink.Addr, error)
	AddrAdd(link netlink.Link, addr *netlink.Addr) error
	AddrDel(link netlink.Link, addr *netlink.Addr) error
	RunCmd(name string, args ...string) error
}

type realIPIPNetlink struct{}

func (r realIPIPNetlink) LinkByName(name string) (netlink.Link, error) {
	return netlink.LinkByName(name)
}
func (r realIPIPNetlink) LinkSetMTU(link netlink.Link, mtu int) error {
	return netlink.LinkSetMTU(link, mtu)
}

func (r realIPIPNetlink) LinkSetUp(link netlink.Link) error {
	return netlink.LinkSetUp(link)
}

func (r realIPIPNetlink) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	return netlink.AddrList(link, family)
}

func (r realIPIPNetlink) AddrAdd(link netlink.Link, addr *netlink.Addr) error {
	return netlink.AddrAdd(link, addr)
}

func (r realIPIPNetlink) AddrDel(link netlink.Link, addr *netlink.Addr) error {
	return netlink.AddrDel(link, addr)
}

func (r realIPIPNetlink) RunCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}
