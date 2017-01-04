// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

// configureIPIPDevice ensures the IPIP tunneld evice is up and configures correctly.
func configureIPIPDevice(mtu int, address net.IP) error {
	log.WithFields(log.Fields{
		"mtu":        mtu,
		"tunnelAddr": address,
	}).Debug("Configuring IPIP tunnel")
	link, err := netlink.LinkByName("tunl0")
	if err != nil {
		log.WithError(err).Info("Failed to get IPIP tunnel device, assuming it isn't present")
		// We call out to "ip tunnel", which takes care of loading the kernel module if
		// needed.  The tunl0 device is actually created automatically by the kernel
		// module.
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

	if err := setLinkAddressV4("tunl0", address); err != nil {
		log.WithError(err).Warn("Failed to set tunnel device IP")
		return err
	}
	return nil
}

// setLinkAddressV4 updates the given link to set its local IP address.  It removes any other
// addresses.
func setLinkAddressV4(linkName string, address net.IP) error {
	logCxt := log.WithFields(log.Fields{
		"link": linkName,
		"addr": address,
	})
	logCxt.Info("Setting local IPv4 address on link.")
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
			logCxt.Info("Address already present.")
			found = true
			continue
		}
		logCxt.WithField("oldAddr", addr).Info("Removing old address")
		if err := netlink.AddrDel(link, &addr); err != nil {
			log.WithError(err).Warn("Failed to delete address")
			return err
		}
	}

	if !found && address != nil {
		logCxt.Info("Address wasn't present, adding it.")
		ipNet := net.IPNet{
			IP:   address,
			Mask: net.CIDRMask(32, 32),
		}
		addr := &netlink.Addr{
			IPNet: &ipNet,
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			log.WithError(err).WithField("addr", address).Warn("Failed to add address")
			return err
		}
	}
	logCxt.Info("Address set.")

	return nil
}

// ipipManager manages the all-hosts IP set, which is used by some rules in our static chains
// when IPIP is enabled.  It doesn't actually program the rules, because they are part of the
// top-level static chains.
type ipipManager struct {
	ipsetReg *ipsets.Registry
	// activeHostnameToIP maps hostname to string IP address.  We don't bother to parse into
	// net.IPs because we're going to pass them directly to the IPSet API.
	activeHostnameToIP map[string]string
}

func newIPIPManager(
	ipSetReg *ipsets.Registry,
	maxIPSetSize int,
) *ipipManager {
	// Make sure our IP set exists.  We set the contents to empty here
	// but the IPSets object will defer writing the IP sets until we're
	// in sync, by which point we'll have added all our CIDRs into the sets.
	ipSetReg.AddOrReplaceIPSet(ipsets.IPSetMetadata{
		MaxSize: maxIPSetSize,
		SetID:   rules.IPSetIDAllHostIPs,
		Type:    ipsets.IPSetTypeHashIP,
	}, []string{})

	return &ipipManager{
		ipsetReg:           ipSetReg,
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
		d.ipsetReg.RemoveMembers(rules.IPSetIDAllHostIPs, []string{oldIP})
		delete(d.activeHostnameToIP, hostname)
	}
	if newIP != "" {
		// Update the IP sets.
		logCxt.Debug("Adding host to IP set.")
		d.ipsetReg.AddMembers(rules.IPSetIDAllHostIPs, []string{newIP})
		d.activeHostnameToIP[hostname] = newIP
	}
}

func (m *ipipManager) CompleteDeferredWork() error {
	// Nothing to do, we don't defer any work.
	return nil
}
