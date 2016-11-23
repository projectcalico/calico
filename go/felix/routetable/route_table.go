// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

package routing

import (
	"github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/go/felix/multidict"
	"github.com/projectcalico/felix/go/felix/set"
	"github.com/vishvananda/netlink"
	"regexp"
	"strings"
	"time"
)

type RouteTable struct {
	ipVersion         int
	ifacePrefixes     set.Set
	ifacePrefixRegexp *regexp.Regexp

	ifaceNameToIPs multidict.StringToIface
}

func New(interfacePrefixes []string, ipVersion uint8) *RouteTable {
	prefixSet := set.New()
	regexpParts := []string{}
	for _, prefix := range interfacePrefixes {
		prefixSet.Add(prefix)
		regexpParts = append(regexpParts, "^"+prefix+".*")
	}

	return &RouteTable{
		ifacePrefixes:     prefixSet,
		ifacePrefixRegexp: regexp.MustCompile(strings.Join(regexpParts, "|")),
		ifaceNameToIPs:    multidict.NewStringToIface(),
	}
}

func (r *RouteTable) Start() {
	go r.loopKeepingRoutesInSync()
}

func (r *RouteTable) loopKeepingRoutesInSync() {
	for {
		links, err := netlink.LinkList()
		if err != nil {
			logrus.WithError(err).Error("Failed to list interfaces, retrying...")
			time.Sleep(100 * time.Millisecond)
			continue
		}

		for _, link := range links {
			attrs := link.Attrs()
			name := attrs.Name
			if r.ifacePrefixRegexp.MatchString(attrs.Name) {
				// One of our interfaces.
				routes, err := netlink.RouteList(link, r.ipVersion)
				if err != nil {
					logrus.WithError(err).WithField("link", name).Error(
						"Failed to list routes, retrying...")
					time.Sleep(100 * time.Millisecond)
					continue
				}

				for _, route := range routes {
					print("Iface", name, "Route", route)
				}
			}
		}
		break
	}
}
