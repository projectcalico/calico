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

package intdataplane

import (
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/go/felix/ipsets"
	"github.com/projectcalico/felix/go/felix/proto"
	"github.com/projectcalico/felix/go/felix/rules"
	"github.com/vishvananda/netlink"
	"net"
	"os/exec"
	"reflect"
)

func configureIPIPDevice(mtu int, address net.IP) error {
	log.WithFields(log.Fields{
		"mtu":        mtu,
		"tunnelAddr": address,
	}).Info("Configuring IPIP")
	link, err := netlink.LinkByName("tunl0")
	if err != nil {
		// TODO(smc) WIBNI we could use netlink here too?
		log.WithError(err).Info("Fialed to get IPIP tunnel device, assuming it isn't present")
		cmd := exec.Command("ip", "tunnel", "add", "tunl0", "mode", "ipip")
		err := cmd.Run()
		if err != nil {
			log.WithError(err).Warning("Failed to add IPIP tunnel device")
			return err
		}
		link, err = netlink.LinkByName("tunl0")
		if err != nil {
			log.WithError(err).Warning("Failed to get tunnel device")
			return err
		}
	}
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		log.WithError(err).Warn("Failed to set tunnel device MTU")
		return err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		log.WithError(err).Warn("Failed to set tunnel device up")
		return err
	}

	return setLinkAddressV4(
		"tunl0",
		address,
	)
}

func setLinkAddressV4(linkName string, address net.IP) error {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		log.WithError(err).WithField("name", linkName).Warning("Failed to get device")
		return err
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		log.WithError(err).Warn("Failed to list interface addresses")
		return err
	}

	found := false
	for _, addr := range addrs {
		if reflect.DeepEqual(addr.IP, address) {
			found = true
			continue
		}
		if err := netlink.AddrDel(link, &addr); err != nil {
			log.WithError(err).Warn("Failed to delete address")
			return err
		}
	}

	if !found && address != nil {
		ipNet := net.IPNet{
			IP:   address,
			Mask: net.CIDRMask(32, 32),
		}
		addr := &netlink.Addr{
			IPNet: &ipNet,
			Label: "cali",
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			log.WithError(err).WithField("addr", address).Warn("Failed to add address")
			return err
		}
	}

	return nil
}

// ipipManager manages the all-hosts IP set, which is used by some rules in our static chains
// when IPIP is enabled.
type ipipManager struct {
	ipsets             *ipsets.IPSets
	activeHostnameToIP map[string]string
}

func newIPIPManager(
	ipsetsMgr *ipsets.IPSets,
	maxIPSetSize int,
) *ipipManager {
	// Make sure our IP set exists.  We set the contents to empty here
	// but the IPSets object will defer writing the IP sets until we're
	// in sync, by which point we'll have added all our CIDRs into the sets.
	ipsetsMgr.AddOrReplaceIPSet(ipsets.IPSetMetadata{
		MaxSize: maxIPSetSize,
		SetID:   rules.AllHostIPsSetID,
		Type:    ipsets.IPSetTypeHashIP,
	}, []string{})

	return &ipipManager{
		ipsets:             ipsetsMgr,
		activeHostnameToIP: map[string]string{},
	}
}

func (d *ipipManager) OnUpdate(msg interface{}) {
	var hostname string
	var newIP string

	switch msg := msg.(type) {
	case *proto.HostMetadataUpdate:
		log.WithField("hostanme", msg.Hostname).Debug("Host update/create")
		hostname = msg.Hostname
		newIP = msg.Ipv4Addr
	case *proto.HostMetadataRemove:
		log.WithField("hostname", msg.Hostname).Debug("Host removed")
		hostname = msg.Hostname
	default:
		return
	}

	logCxt := log.WithField("hostname", hostname)
	if oldIP := d.activeHostnameToIP[hostname]; oldIP != "" {
		// For simplicity always remove the old value from the IP set.  The IPSets object
		// defers and coalesces the update so removing then adding the same IP is a no-op
		// anyway.
		logCxt.WithField("oldIP", oldIP).Debug("Removing old IP.")
		d.ipsets.RemoveMembers(rules.AllHostIPsSetID, []string{oldIP})
		delete(d.activeHostnameToIP, hostname)
	}
	if newIP != "" {
		// Update the IP sets.
		logCxt.Debug("Adding host to IP set.")
		d.ipsets.AddMembers(rules.AllHostIPsSetID, []string{newIP})
		d.activeHostnameToIP[hostname] = newIP
	}
}

func (m *ipipManager) CompleteDeferredWork() error {
	// Nothing to do, we don't defer any work.
	return nil
}
