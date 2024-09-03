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

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// AddrListRetryEINTR calls netlink's AddrList API and retries for 3 times if the API call
// is interrupted(EINTR returned). This is not an error and the call must be retried.
// AddrListRetryEINTR must be used for listing addresses of an interface in place of netlink's AddrList API.
func AddrListRetryEINTR(nlHandle *netlink.Handle, link netlink.Link, family int) ([]netlink.Addr, error) {
	retries := 3
	for {
		links, err := nlHandle.AddrList(link, family)
		if err != nil {
			if errors.Is(err, unix.EINTR) && retries > 0 {
				log.Debugf("listing address for interface %s hit EINTR. Retrying", link.Attrs().Name)
				retries--
				continue
			}
		}
		return links, err
	}
}

// RouteListRetryEINTR calls netlink's RouteList API and retries for 3 times if the API call
// is interrupted(EINTR returned). This is not an error and the call must be retried.
// RouteListRetryEINTR must be used for listing routes of an interface in place of netlink's RouteList API.
func RouteListRetryEINTR(nlHandle *netlink.Handle, link netlink.Link, family int) ([]netlink.Route, error) {
	retries := 3
	for {
		routes, err := nlHandle.RouteList(link, family)
		if err != nil {
			if errors.Is(err, unix.EINTR) && retries > 0 {
				log.Debugf("listing routes for interface %s, family %d hit EINTR. Retrying", link.Attrs().Name, family)
				retries--
				continue
			}
		}
		return routes, err
	}
}

// LinkListRetryEINTR calls netlink's LinkList API and retries for 3 times if the API call
// is interrupted(EINTR returned). This is not an error and the call must be retried.
// LinkListRetryEINTR must be used for listing interfaces in place of netlink's LinkList API.
func LinkListRetryEINTR(nlHandle *netlink.Handle) ([]netlink.Link, error) {
	retries := 3
	for {
		links, err := nlHandle.LinkList()
		if err != nil {
			if errors.Is(err, unix.EINTR) && retries > 0 {
				log.Debug("listing links hit EINTR. Retrying")
				retries--
				continue
			}
		}
		return links, err
	}
}
