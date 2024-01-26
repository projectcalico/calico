// Copyright (c) 2017,2020-2021 Tigera, Inc. All rights reserved.
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
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/netlinkshim/handlemgr"
)

type netlinkReal struct {
	handleMgr *handlemgr.HandleManager
}

func newRealNetlink(featureDetector environment.FeatureDetectorIface, timeout time.Duration) *netlinkReal {
	return &netlinkReal{
		handleMgr: handlemgr.NewHandleManager(featureDetector, handlemgr.WithSocketTimeout(timeout)),
	}
}

func (nl *netlinkReal) Subscribe(
	linkUpdates chan netlink.LinkUpdate,
	routeUpdates chan netlink.RouteUpdate,
) (chan struct{}, error) {
	// Note: this method doesn't use the HandleManager because each subscription gets its own
	// socket under the covers.
	cancel := make(chan struct{})

	if err := netlink.LinkSubscribeWithOptions(linkUpdates, cancel, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			// Not necessarily fatal (can be an unexpected message, which the library will drop).
			log.WithError(err).Warn("Netlink reported an error.")
		},
	}); err != nil {
		log.WithError(err).Error("Failed to subscribe to link updates")
		close(cancel)
		return nil, err
	}
	if err := netlink.RouteSubscribeWithOptions(routeUpdates, cancel, netlink.RouteSubscribeOptions{
		ErrorCallback: func(err error) {
			// Not necessarily fatal (can be an unexpected message, which the library will drop).
			log.WithError(err).Warn("Netlink reported an error.")
		},
	}); err != nil {
		log.WithError(err).Error("Failed to subscribe to route updates")
		close(cancel)
		return nil, err
	}

	return cancel, nil
}

func (nl *netlinkReal) LinkList() ([]netlink.Link, error) {
	h, err := nl.handleMgr.Handle()
	if err != nil {
		return nil, fmt.Errorf("failed to get netlink handle: %w", err)
	}
	return h.LinkList()
}

func (nl *netlinkReal) ListLocalRoutes(link netlink.Link, family int) ([]netlink.Route, error) {
	h, err := nl.handleMgr.Handle()
	if err != nil {
		return nil, fmt.Errorf("failed to get netlink handle: %w", err)
	}
	routeFilter := &netlink.Route{}
	filterFlags := netlink.RT_FILTER_TABLE | netlink.RT_FILTER_TYPE
	routeFilter.Table = unix.RT_TABLE_LOCAL
	routeFilter.Type = unix.RTN_LOCAL
	if link != nil {
		filterFlags |= netlink.RT_FILTER_OIF
		routeFilter.LinkIndex = link.Attrs().Index
	}
	return h.RouteListFiltered(family, routeFilter, filterFlags)
}
