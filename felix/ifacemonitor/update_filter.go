// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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
	"context"
	"net"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/timeshim"
)

const FlapDampingDelay = 100 * time.Millisecond

type updateFilter struct {
	Time timeshim.Interface
}

type UpdateFilterOp func(filter *updateFilter)

func WithTimeShim(t timeshim.Interface) UpdateFilterOp {
	return func(filter *updateFilter) {
		filter.Time = t
	}
}

// FilterUpdates filters out updates that occur when IPs are quickly removed and re-added.
// Some DHCP clients flap the IP during an IP renewal, for example.
//
// Algorithm:
// * Maintain a queue of link and address updates per interface.
// * When we see a potential flap (i.e. an IP deletion), defer processing the queue for a while.
// * If the flap resolves itself (i.e. the IP is added back), suppress the IP deletion.
func FilterUpdates(ctx context.Context,
	routeOutC chan<- netlink.RouteUpdate, routeInC <-chan netlink.RouteUpdate,
	linkOutC chan<- netlink.LinkUpdate, linkInC <-chan netlink.LinkUpdate,
	options ...UpdateFilterOp,
) {
	// Propagate failures to the downstream channels.
	defer close(routeOutC)
	defer close(linkOutC)

	u := &updateFilter{
		Time: timeshim.RealTime(),
	}
	for _, op := range options {
		op(u)
	}

	logrus.Debug("FilterUpdates: starting")
	var timerC <-chan time.Time

	type timestampedUpd struct {
		ReadyAt time.Time
		Update  interface{} // RouteUpdate or LinkUpdate
	}

	updatesByIfaceIdx := map[int][]timestampedUpd{}

mainLoop:
	for {
		select {
		case <-ctx.Done():
			logrus.Info("FilterUpdates: Context expired, stopping")
			return
		case linkUpd, ok := <-linkInC:
			if !ok {
				logrus.Error("FilterUpdates: link input channel closed.")
				return
			}
			idx := int(linkUpd.Index)
			linkIsUp := linkUpd.Header.Type == syscall.RTM_NEWLINK && linkIsOperUp(linkUpd.Link)
			var delay time.Duration
			if linkIsUp {
				if len(updatesByIfaceIdx[idx]) == 0 {
					// Empty queue (so no flap in progress) and the link is up, no need to delay the message.
					linkOutC <- linkUpd
					continue mainLoop
				}
				// Link is up but potential flap in progress, queue the update behind the other messages.
				delay = 0
			} else {
				// We delay link down updates because a flap can involve both a link down and an IP removal.
				// Since we receive those two messages over separate channels, the two messages can race.
				delay = FlapDampingDelay
			}

			updatesByIfaceIdx[idx] = append(updatesByIfaceIdx[idx],
				timestampedUpd{
					ReadyAt: u.Time.Now().Add(delay),
					Update:  linkUpd,
				})
		case routeUpd, ok := <-routeInC:
			if !ok {
				logrus.Error("FilterUpdates: route input channel closed.")
				return
			}
			logrus.WithField("route", routeUpd).Debug("Route update")
			if !routeIsLocalUnicast(routeUpd.Route) {
				logrus.WithField("route", routeUpd).Debug("Ignoring non-local route.")
				continue
			}
			if routeUpd.LinkIndex == 0 {
				logrus.WithField("route", routeUpd).Debug("Ignoring route with no link index.")
				continue
			}

			idx := routeUpd.LinkIndex
			oldUpds := updatesByIfaceIdx[idx]

			var readyToSendTime time.Time
			if routeUpd.Type == unix.RTM_NEWROUTE {
				logrus.WithField("addr", routeUpd.Dst).Debug("FilterUpdates: got address ADD")
				if len(oldUpds) == 0 {
					// This is an add for a new IP and there's nothing else in the queue for this interface.
					// Short circuit.  We care about flaps where IPs are temporarily removed so no need to
					// delay an add.
					logrus.Debug("FilterUpdates: add with empty queue, short circuit.")
					routeOutC <- routeUpd
					continue
				}

				// Else, there's something else in the queue, need to process the queue...
				logrus.Debug("FilterUpdates: add with non-empty queue.")
				// We don't actually need to delay the add itself so we don't set any delay here.  It will
				// still be queued up behind other updates.
				readyToSendTime = u.Time.Now()
			} else {
				// Got a delete, it might be a flap so queue the update.
				logrus.WithField("addr", routeUpd.Dst).Debug("FilterUpdates: got address DEL")
				readyToSendTime = u.Time.Now().Add(FlapDampingDelay)
			}

			// Coalesce updates for the same IP by squashing any previous updates for the same CIDR before
			// we append this update to the queue.  We need to scan the whole queue because there may be
			// updates for different IPs in flight.
			upds := oldUpds[:0]
			for _, upd := range oldUpds {
				logrus.WithField("previous", upd).Debug("FilterUpdates: examining previous update.")
				if oldAddrUpd, ok := upd.Update.(netlink.RouteUpdate); ok {
					if ipNetsEqual(oldAddrUpd.Dst, routeUpd.Dst) {
						// New update for the same IP, suppress the old update
						logrus.WithField("address", oldAddrUpd.Dst.String()).Debug(
							"Received update for same IP within a short time, squashed the old update.")
						continue
					}
				}
				upds = append(upds, upd)
			}
			upds = append(upds, timestampedUpd{ReadyAt: readyToSendTime, Update: routeUpd})
			updatesByIfaceIdx[idx] = upds
		case <-timerC:
			logrus.Debug("FilterUpdates: timer popped.")
			timerC = nil
		}

		if timerC != nil {
			// Optimisation: we much have just queued an update but there's already a timer set and we know
			// that timer must pop before the one for the new update.  Skip recalculating the timer.
			logrus.Debug("FilterUpdates: timer already set.")
			continue mainLoop
		}

		var nextUpdTime time.Time
		for idx, upds := range updatesByIfaceIdx {
			logrus.WithField("ifaceIdx", idx).Debug("FilterUpdates: examining updates for interface.")
			for len(upds) > 0 {
				firstUpd := upds[0]
				if u.Time.Since(firstUpd.ReadyAt) >= 0 {
					// Either update is old enough to prevent flapping or it's an address being added.
					// Ready to send...
					logrus.WithField("update", firstUpd).Debug("FilterUpdates: update ready to send.")
					switch u := firstUpd.Update.(type) {
					case netlink.RouteUpdate:
						routeOutC <- u
					case netlink.LinkUpdate:
						linkOutC <- u
					}
					upds = upds[1:]
				} else {
					// Update is too new, figure out when it'll be safe to send it.
					logrus.WithField("update", firstUpd).Debug("FilterUpdates: update not ready.")
					if nextUpdTime.IsZero() || firstUpd.ReadyAt.Before(nextUpdTime) {
						nextUpdTime = firstUpd.ReadyAt
					}
					break
				}
			}
			if len(upds) == 0 {
				logrus.WithField("ifaceIdx", idx).Debug("FilterUpdates: no more updates for interface.")
				delete(updatesByIfaceIdx, idx)
			} else {
				logrus.WithField("ifaceIdx", idx).WithField("num", len(upds)).Debug(
					"FilterUpdates: still updates for interface.")
				updatesByIfaceIdx[idx] = upds
			}
		}

		if nextUpdTime.IsZero() {
			// Queue is empty so no need to schedule a timer.
			continue mainLoop
		}

		// Schedule timer to process the rest of the queue.
		delay := u.Time.Until(nextUpdTime)
		if delay <= 0 {
			delay = 1
		}
		logrus.WithField("delay", delay).Debug("FilterUpdates: calculated delay.")
		timerC = u.Time.After(delay)
	}
}

func ipNetsEqual(a *net.IPNet, b *net.IPNet) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	aSize, aBits := a.Mask.Size()
	bSize, bBits := b.Mask.Size()
	return a.IP.Equal(b.IP) && aSize == bSize && aBits == bBits
}

func routeIsLocalUnicast(route netlink.Route) bool {
	return route.Type == unix.RTN_LOCAL
}
