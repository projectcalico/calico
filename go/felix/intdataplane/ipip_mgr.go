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
	"time"
)

// ipipManager manages the all-hosts IP set, which is used by some rules in our static chains
// when IPIP is enabled.  It doesn't actually program the rules, because they are part of the
// top-level static chains.
//
// ipipManager also takes care of the configuration of the IPIP tunnel device.
type ipipManager struct {
	ipsetReg *ipsets.Registry
	// activeHostnameToIP maps hostname to string IP address.  We don't bother to parse into
	// net.IPs because we're going to pass them directly to the IPSet API.
	activeHostnameToIP map[string]string

	dataplane ipipDataplane
}

func newIPIPManager(
	ipSetReg *ipsets.Registry,
	maxIPSetSize int,
) *ipipManager {
	return newIPIPManagerWithShim(ipSetReg, maxIPSetSize, realIPIPNetlink{})
}

func newIPIPManagerWithShim(
	ipSetReg *ipsets.Registry,
	maxIPSetSize int,
	dataplane ipipDataplane,
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
		dataplane:          dataplane,
	}
}

// KeepIPIPDeviceInSync is a goroutine that configures the IPIP tunnel device, then periodically
// checks that it is still correctly configured.
func (d *ipipManager) KeepIPIPDeviceInSync(mtu int, address net.IP) {
	log.Info("IPIP thread started.")
	for {
		err := d.configureIPIPDevice(mtu, address)
		if err != nil {
			log.WithError(err).Warn("Failed configure IPIP tunnel device, retrying...")
			time.Sleep(1 * time.Second)
			continue
		}
		time.Sleep(10 * time.Second)
	}
}

// configureIPIPDevice ensures the IPIP tunnel device is up and configures correctly.
func (d *ipipManager) configureIPIPDevice(mtu int, address net.IP) error {
	logCxt := log.WithFields(log.Fields{
		"mtu":        mtu,
		"tunnelAddr": address,
	})
	logCxt.Debug("Configuring IPIP tunnel")
	link, err := d.dataplane.LinkByName("tunl0")
	if err != nil {
		log.WithError(err).Info("Failed to get IPIP tunnel device, assuming it isn't present")
		// We call out to "ip tunnel", which takes care of loading the kernel module if
		// needed.  The tunl0 device is actually created automatically by the kernel
		// module.
		err := d.dataplane.RunCmd("ip", "tunnel", "add", "tunl0", "mode", "ipip")
		if err != nil {
			log.WithError(err).Warning("Failed to add IPIP tunnel device")
			return err
		}
		link, err = d.dataplane.LinkByName("tunl0")
		if err != nil {
			log.WithError(err).Warning("Failed to get tunnel device")
			return err
		}
	}

	attrs := link.Attrs()
	oldMTU := attrs.MTU
	if oldMTU != mtu {
		logCxt.WithField("oldMTU", oldMTU).Info("Tunnel device MTU needs to be updated")
		if err := d.dataplane.LinkSetMTU(link, mtu); err != nil {
			log.WithError(err).Warn("Failed to set tunnel device MTU")
			return err
		}
		logCxt.Info("Updated tunnel MTU")
	}
	if attrs.Flags&net.FlagUp == 0 {
		logCxt.WithField("flags", attrs.Flags).Info("Tunnel wasn't admin up, enabling it")
		if err := d.dataplane.LinkSetUp(link); err != nil {
			log.WithError(err).Warn("Failed to set tunnel device up")
			return err
		}
		logCxt.Info("Set tunnel admin up")
	}

	if err := d.setLinkAddressV4("tunl0", address); err != nil {
		log.WithError(err).Warn("Failed to set tunnel device IP")
		return err
	}
	return nil
}

// setLinkAddressV4 updates the given link to set its local IP address.  It removes any other
// addresses.
func (d *ipipManager) setLinkAddressV4(linkName string, address net.IP) error {
	logCxt := log.WithFields(log.Fields{
		"link": linkName,
		"addr": address,
	})
	logCxt.Debug("Setting local IPv4 address on link.")
	link, err := d.dataplane.LinkByName(linkName)
	if err != nil {
		log.WithError(err).WithField("name", linkName).Warning("Failed to get device")
		return err
	}

	addrs, err := d.dataplane.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		log.WithError(err).Warn("Failed to list interface addresses")
		return err
	}

	found := false
	for _, oldAddr := range addrs {
		if address != nil && oldAddr.IP.Equal(address) {
			logCxt.Debug("Address already present.")
			found = true
			continue
		}
		logCxt.WithField("oldAddr", oldAddr).Info("Removing old address")
		if err := d.dataplane.AddrDel(link, &oldAddr); err != nil {
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
		if err := d.dataplane.AddrAdd(link, addr); err != nil {
			log.WithError(err).WithField("addr", address).Warn("Failed to add address")
			return err
		}
	}
	logCxt.Debug("Address set.")

	return nil
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
