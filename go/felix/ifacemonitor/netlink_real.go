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

package ifacemonitor

import (
	log "github.com/Sirupsen/logrus"
	"github.com/vishvananda/netlink"
	//"syscall"
)

type netlinkReal struct {
}

func (nl *netlinkReal) Subscribe(
	linkUpdates chan netlink.LinkUpdate,
	addrUpdates chan netlink.AddrUpdate,
) error {
	cancel := make(chan struct{})

	if err := netlink.LinkSubscribe(linkUpdates, cancel); err != nil {
		log.WithError(err).Fatal("Failed to subscribe to link updates")
		return err
	}
	if err := netlink.AddrSubscribe(addrUpdates, cancel); err != nil {
		log.WithError(err).Fatal("Failed to subscribe to addr updates")
		return err
	}

	return nil
}

func (nl *netlinkReal) LinkList() ([]netlink.Link, error) {
	return netlink.LinkList()
}

func (nl *netlinkReal) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	return netlink.AddrList(link, family)
}
