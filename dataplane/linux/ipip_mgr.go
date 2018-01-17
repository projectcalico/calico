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
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/rules"
)

// ipipManager manages the all-hosts IP set, which is used by some rules in our static chains
// when IPIP is enabled.  It doesn't actually program the rules, because they are part of the
// top-level static chains.
//
// ipipManager also takes care of the configuration of the IPIP tunnel device.
type ipipManager struct {
	ipsetsDataplane ipsetsDataplane

	// activeHostnameToIP maps hostname to string IP address.  We don't bother to parse into
	// net.IPs because we're going to pass them directly to the IPSet API.
	activeHostnameToIP map[string]string
	ipSetInSync        bool

	// Config for creating/refreshing the IP set.
	ipSetMetadata ipsets.IPSetMetadata

	// Dataplane shim.
	dataplane ipipDataplane
}

func newIPIPManager(
	ipsetsDataplane ipsetsDataplane,
	maxIPSetSize int,
) *ipipManager {
	return newIPIPManagerWithShim(ipsetsDataplane, maxIPSetSize, realIPIPNetlink{})
}

func newIPIPManagerWithShim(
	ipsetsDataplane ipsetsDataplane,
	maxIPSetSize int,
	dataplane ipipDataplane,
) *ipipManager {
	ipipMgr := &ipipManager{
		ipsetsDataplane:    ipsetsDataplane,
		activeHostnameToIP: map[string]string{},
		dataplane:          dataplane,
		ipSetMetadata: ipsets.IPSetMetadata{
			MaxSize: maxIPSetSize,
			SetID:   rules.IPSetIDAllHostIPs,
			Type:    ipsets.IPSetTypeHashIP,
		},
	}
	return ipipMgr
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
		mask := net.CIDRMask(32, 32)
		ipNet := net.IPNet{
			IP:   address.Mask(mask), // Mask the IP to match ParseCIDR()'s behaviour.
			Mask: mask,
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
	switch msg := msg.(type) {
	case *proto.HostMetadataUpdate:
		log.WithField("hostanme", msg.Hostname).Debug("Host update/create")
		d.activeHostnameToIP[msg.Hostname] = msg.Ipv4Addr
		d.ipSetInSync = false
	case *proto.HostMetadataRemove:
		log.WithField("hostname", msg.Hostname).Debug("Host removed")
		delete(d.activeHostnameToIP, msg.Hostname)
		d.ipSetInSync = false
	}
}

func (m *ipipManager) CompleteDeferredWork() error {
	if !m.ipSetInSync {
		// For simplicity (and on the assumption that host add/removes are rare) rewrite
		// the whole IP set whenever we get a change.  To replace this with delta handling
		// would require reference counting the IPs because it's possible for two hosts
		// to (at least transiently) share an IP.  That would add occupancy and make the
		// code more complex.
		log.Info("All-hosts IP set out-of sync, refreshing it.")
		members := make([]string, 0, len(m.activeHostnameToIP))
		for _, ip := range m.activeHostnameToIP {
			members = append(members, ip)
		}
		m.ipsetsDataplane.AddOrReplaceIPSet(m.ipSetMetadata, members)
		m.ipSetInSync = true
	}
	return nil
}

// ipsetsDataplane is a shim interface for mocking the IPSets object.
type ipsetsDataplane interface {
	AddOrReplaceIPSet(setMetadata ipsets.IPSetMetadata, members []string)
	AddMembers(setID string, newMembers []string)
	RemoveMembers(setID string, removedMembers []string)
	RemoveIPSet(setID string)
}
