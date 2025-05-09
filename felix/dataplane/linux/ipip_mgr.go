// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.
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
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/ethtool"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
)

// ipipManager manages the all-hosts IP set, which is used by some rules in our static chains
// when IPIP is enabled.  It doesn't actually program the rules, because they are part of the
// top-level static chains.
//
// ipipManager also takes care of the configuration of the IPIP tunnel device.
type ipipManager struct {
	ipsetsDataplane dpsets.IPSetsDataplane

	// activeHostnameToIP maps hostname to string IP address.  We don't bother to parse into
	// net.IPs because we're going to pass them directly to the IPSet API.
	activeHostnameToIP map[string]string
	ipSetInSync        bool

	// Config for creating/refreshing the IP set.
	ipSetMetadata ipsets.IPSetMetadata

	// Configured list of external node ip cidr's to be added to the ipset.
	externalNodeCIDRs []string
	nlHandle          netlinkHandle
}

func newIPIPManager(
	ipsetsDataplane dpsets.IPSetsDataplane,
	maxIPSetSize int,
	externalNodeCidrs []string,
) *ipipManager {
	nlHandle, _ := netlinkshim.NewRealNetlink()
	return newIPIPManagerWithShim(ipsetsDataplane, maxIPSetSize, nlHandle, externalNodeCidrs)
}

func newIPIPManagerWithShim(
	ipsetsDataplane dpsets.IPSetsDataplane,
	maxIPSetSize int,
	nlHandle netlinkHandle,
	externalNodeCIDRs []string,
) *ipipManager {
	ipipMgr := &ipipManager{
		ipsetsDataplane:    ipsetsDataplane,
		activeHostnameToIP: map[string]string{},
		ipSetMetadata: ipsets.IPSetMetadata{
			MaxSize: maxIPSetSize,
			SetID:   rules.IPSetIDAllHostNets,
			Type:    ipsets.IPSetTypeHashNet,
		},
		externalNodeCIDRs: externalNodeCIDRs,
		nlHandle:          nlHandle,
	}
	return ipipMgr
}

// KeepIPIPDeviceInSync is a goroutine that configures the IPIP tunnel device, then periodically
// checks that it is still correctly configured.
func (d *ipipManager) KeepIPIPDeviceInSync(mtu int, address net.IP, xsumBroken bool) {
	logrus.Info("IPIP thread started.")
	for {
		err := d.configureIPIPDevice(mtu, address, xsumBroken)
		if err != nil {
			logrus.WithError(err).Warn("Failed configure IPIP tunnel device, retrying...")
			time.Sleep(1 * time.Second)
			continue
		}
		time.Sleep(10 * time.Second)
	}
}

// configureIPIPDevice ensures the IPIP tunnel device is up and configures correctly.
func (d *ipipManager) configureIPIPDevice(mtu int, address net.IP, xsumBroken bool) error {
	logCtx := logrus.WithFields(logrus.Fields{
		"mtu":        mtu,
		"tunnelAddr": address,
	})
	logCtx.Debug("Configuring IPIP tunnel")
	link, err := d.nlHandle.LinkByName(dataplanedefs.IPIPIfaceName)
	if err != nil {
		logrus.WithError(err).Info("Failed to get IPIP tunnel device, assuming it isn't present")
		// We call out to "ip tunnel", which takes care of loading the kernel module if
		// needed.  The tunl0 device is actually created automatically by the kernel
		// module.

		la := netlink.NewLinkAttrs()
		la.Name = dataplanedefs.IPIPIfaceName
		ipip := &netlink.Iptun{
			LinkAttrs: la,
		}
		if err := d.nlHandle.LinkAdd(ipip); err == syscall.EEXIST {
			// Device already exists - likely a race.
			logCtx.Debug("IPIP device already exists, likely created by someone else.")
		} else if err != nil {
			// Error other than "device exists" - return it.
			return err
		}

		link, err = d.nlHandle.LinkByName(dataplanedefs.IPIPIfaceName)
		if err != nil {
			logrus.WithError(err).Warning("Failed to get tunnel device")
			return err
		}
	}

	attrs := link.Attrs()
	oldMTU := attrs.MTU
	if oldMTU != mtu {
		logCtx.WithField("oldMTU", oldMTU).Info("Tunnel device MTU needs to be updated")
		if err := d.nlHandle.LinkSetMTU(link, mtu); err != nil {
			logrus.WithError(err).Warn("Failed to set tunnel device MTU")
			return err
		}
		logCtx.Info("Updated tunnel MTU")
	}

	// If required, disable checksum offload.
	if xsumBroken {
		if err := ethtool.EthtoolTXOff(dataplanedefs.IPIPIfaceName); err != nil {
			return fmt.Errorf("failed to disable checksum offload: %s", err)
		}
	}

	if attrs.Flags&net.FlagUp == 0 {
		logCtx.WithField("flags", attrs.Flags).Info("Tunnel wasn't admin up, enabling it")
		if err := d.nlHandle.LinkSetUp(link); err != nil {
			logrus.WithError(err).Warn("Failed to set tunnel device up")
			return err
		}
		logCtx.Info("Set tunnel admin up")
	}

	if err := d.setLinkAddressV4(dataplanedefs.IPIPIfaceName, address); err != nil {
		logrus.WithError(err).Warn("Failed to set tunnel device IP")
		return err
	}
	return nil
}

// setLinkAddressV4 updates the given link to set its local IP address.  It removes any other
// addresses.
func (d *ipipManager) setLinkAddressV4(linkName string, address net.IP) error {
	logCtx := logrus.WithFields(logrus.Fields{
		"link": linkName,
		"addr": address,
	})
	logCtx.Debug("Setting local IPv4 address on link.")
	link, err := d.nlHandle.LinkByName(linkName)
	if err != nil {
		logrus.WithError(err).WithField("name", linkName).Warning("Failed to get device")
		return err
	}

	addrs, err := d.nlHandle.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		logrus.WithError(err).Warn("Failed to list interface addresses")
		return err
	}

	found := false
	for _, oldAddr := range addrs {
		if address != nil && oldAddr.IP.Equal(address) {
			logCtx.Debug("Address already present.")
			found = true
			continue
		}
		logCtx.WithField("oldAddr", oldAddr).Info("Removing old address")
		if err := d.nlHandle.AddrDel(link, &oldAddr); err != nil {
			logrus.WithError(err).Warn("Failed to delete address")
			return err
		}
	}

	if !found && address != nil {
		logCtx.Info("Address wasn't present, adding it.")
		mask := net.CIDRMask(32, 32)
		ipNet := net.IPNet{
			IP:   address.Mask(mask), // Mask the IP to match ParseCIDR()'s behaviour.
			Mask: mask,
		}
		addr := &netlink.Addr{
			IPNet: &ipNet,
		}
		if err := d.nlHandle.AddrAdd(link, addr); err != nil {
			logrus.WithError(err).WithField("addr", address).Warn("Failed to add address")
			return err
		}
	}
	logCtx.Debug("Address set.")

	return nil
}

func (d *ipipManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *proto.HostMetadataUpdate:
		logrus.WithField("hostname", msg.Hostname).Debug("Host update/create")
		d.activeHostnameToIP[msg.Hostname] = msg.Ipv4Addr
		d.ipSetInSync = false
	case *proto.HostMetadataRemove:
		logrus.WithField("hostname", msg.Hostname).Debug("Host removed")
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
		logrus.Info("All-hosts IP set out-of sync, refreshing it.")
		members := make([]string, 0, len(m.activeHostnameToIP)+len(m.externalNodeCIDRs))
		for _, ip := range m.activeHostnameToIP {
			members = append(members, ip)
		}
		members = append(members, m.externalNodeCIDRs...)
		m.ipsetsDataplane.AddOrReplaceIPSet(m.ipSetMetadata, members)
		m.ipSetInSync = true
	}
	return nil
}
