// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/libcalico-go/lib/set"
)

// hostIPManager monitors updates from ifacemonitor for host ip update events. It then flushes host ips into an ipset.
type hostIPManager struct {
	nonHostIfacesRegexp *regexp.Regexp
	// hostIfaceToAddrs maps host interface name to the set of IPs on that interface (reported from the dataplane).
	hostIfaceToAddrs map[string]set.Set

	hostIPSetID     string
	ipsetsDataplane ipsetsDataplane
	maxSize         int
}

func newHostIPManager(wlIfacesPrefixes []string,
	ipSetID string,
	ipsets ipsetsDataplane,
	maxIPSetSize int) *hostIPManager {

	return newHostIPManagerWithShims(
		wlIfacesPrefixes,
		ipSetID,
		ipsets,
		maxIPSetSize,
	)
}

func newHostIPManagerWithShims(wlIfacesPrefixes []string,
	ipSetID string,
	ipsets ipsetsDataplane,
	maxIPSetSize int) *hostIPManager {

	wlIfacesPattern := "^(" + strings.Join(wlIfacesPrefixes, "|") + ").*"
	wlIfacesRegexp := regexp.MustCompile(wlIfacesPattern)

	return &hostIPManager{
		nonHostIfacesRegexp: wlIfacesRegexp,
		hostIfaceToAddrs:    map[string]set.Set{},
		hostIPSetID:         ipSetID,
		ipsetsDataplane:     ipsets,
		maxSize:             maxIPSetSize,
	}
}

func (m *hostIPManager) getCurrentMembers() []string {
	members := []string{}
	for _, addrs := range m.hostIfaceToAddrs {
		addrs.Iter(func(item interface{}) error {
			ip := item.(string)
			members = append(members, ip)
			return nil
		})
	}

	return members
}

func (m *hostIPManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *ifaceAddrsUpdate:
		log.WithField("update", msg).Info("Interface addrs changed.")
		if m.nonHostIfacesRegexp.MatchString(msg.Name) {
			log.WithField("update", msg).Debug("Not a real host interface, ignoring.")
			return
		}
		if msg.Addrs != nil {
			m.hostIfaceToAddrs[msg.Name] = msg.Addrs
		} else {
			delete(m.hostIfaceToAddrs, msg.Name)
		}

		// Host ip update is a relative rare event. Flush entire ipsets to make it simple.
		metadata := ipsets.IPSetMetadata{
			Type:    ipsets.IPSetTypeHashIP,
			SetID:   m.hostIPSetID,
			MaxSize: m.maxSize,
		}
		m.ipsetsDataplane.AddOrReplaceIPSet(metadata, m.getCurrentMembers())
	}
}

func (m *hostIPManager) CompleteDeferredWork() error {
	// Nothing to do, we don't defer any work.
	return nil
}
