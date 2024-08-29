// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

// Dummy version of the HCN API for compilation on Linux.
package netlinkutils

import (
	"errors"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func AddrListRetryEINTR(link netlink.Link, family int) ([]netlink.Addr, error) {
	retries := 3
	for {
		links, err := netlink.AddrList(link, family)
		if err != nil {
			if errors.Is(err, unix.EINTR) && retries > 0 {
				retries--
				continue
			}
		}
		return links, err
	}
}

func RouteListRetryEINTR(link netlink.Link, family int) ([]netlink.Route, error) {
	retries := 3
	for {
		routes, err := netlink.RouteList(link, family)
		if err != nil {
			if errors.Is(err, unix.EINTR) && retries > 0 {
				retries--
				continue
			}
		}
		return routes, err
	}
}

func LinkListRetryEINTR() ([]netlink.Link, error) {
	retries := 3
	for {
		links, err := netlink.LinkList()
		if err != nil {
			if errors.Is(err, unix.EINTR) && retries > 0 {
				retries--
				continue
			}
		}
		return links, err
	}
}
