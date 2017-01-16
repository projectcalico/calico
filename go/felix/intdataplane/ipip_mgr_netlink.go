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
	. "github.com/vishvananda/netlink"
	"os/exec"
)

// ipipDataplane is a shim interface for mocking netlink and os/exec in the IPIP manager.
type ipipDataplane interface {
	LinkByName(name string) (Link, error)
	LinkSetMTU(link Link, mtu int) error
	LinkSetUp(link Link) error
	AddrList(link Link, family int) ([]Addr, error)
	AddrAdd(link Link, addr *Addr) error
	AddrDel(link Link, addr *Addr) error
	RunCmd(name string, args ...string) error
}

type realIPIPNetlink struct{}

func (r realIPIPNetlink) LinkByName(name string) (Link, error) {
	return LinkByName(name)
}
func (r realIPIPNetlink) LinkSetMTU(link Link, mtu int) error {
	return LinkSetMTU(link, mtu)
}

func (r realIPIPNetlink) LinkSetUp(link Link) error {
	return LinkSetUp(link)
}

func (r realIPIPNetlink) AddrList(link Link, family int) ([]Addr, error) {
	return AddrList(link, family)
}

func (r realIPIPNetlink) AddrAdd(link Link, addr *Addr) error {
	return AddrAdd(link, addr)
}

func (r realIPIPNetlink) AddrDel(link Link, addr *Addr) error {
	return AddrDel(link, addr)
}

func (r realIPIPNetlink) RunCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}
