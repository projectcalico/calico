// Copyright (c) 2016-2019 Tigera, Inc. All rights reserved.
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
	"reflect"
	"sync"
	"syscall"
	"time"

	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/rules"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/routetable"
)

type vxlanManager struct {
	sync.Mutex

	// Our dependencies.
	hostname   string
	routeTable routeTable

	// Hold pending updates.
	routesByDest map[string]*proto.RouteUpdate
	vtepsByNode  map[string]*proto.VXLANTunnelEndpointUpdate

	// Holds this node's VTEP information.
	myVTEP *proto.VXLANTunnelEndpointUpdate

	// VXLAN configuration.
	vxlanDevice string
	vxlanID     int
	vxlanPort   int

	// Indicates if configuration has changed since the last apply.
	routesDirty       bool
	ipsetsDataplane   ipsetsDataplane
	ipSetMetadata     ipsets.IPSetMetadata
	externalNodeCIDRs []string
	vtepsDirty        bool
}

func newVXLANManager(
	ipsetsDataplane ipsetsDataplane,
	maxIPSetSize int,
	hostname string,
	routeTable routeTable,
	deviceName string,
	vxlanID, port int,
	externalNodeCIDRs []string,
) *vxlanManager {
	return &vxlanManager{
		ipsetsDataplane: ipsetsDataplane,
		ipSetMetadata: ipsets.IPSetMetadata{
			MaxSize: maxIPSetSize,
			SetID:   rules.IPSetIDAllVXLANSourceNets,
			Type:    ipsets.IPSetTypeHashNet,
		},
		hostname:          hostname,
		routeTable:        routeTable,
		routesByDest:      map[string]*proto.RouteUpdate{},
		vtepsByNode:       map[string]*proto.VXLANTunnelEndpointUpdate{},
		vxlanDevice:       deviceName,
		vxlanID:           vxlanID,
		vxlanPort:         port,
		externalNodeCIDRs: externalNodeCIDRs,
		routesDirty:       true,
		vtepsDirty:        true,
	}
}

func (m *vxlanManager) OnUpdate(protoBufMsg interface{}) {
	switch msg := protoBufMsg.(type) {
	case *proto.RouteUpdate:
		if msg.Type == proto.RouteType_VXLAN {
			logrus.WithField("msg", msg).Debug("VXLAN data plane received route update")
			m.routesByDest[msg.Dst] = msg
			m.routesDirty = true
		}
	case *proto.RouteRemove:
		if msg.Type == proto.RouteType_VXLAN {
			logrus.WithField("msg", msg).Debug("VXLAN data plane received route remove")
			delete(m.routesByDest, msg.Dst)
			m.routesDirty = true
		}
	case *proto.VXLANTunnelEndpointUpdate:
		logrus.WithField("msg", msg).Debug("VXLAN data plane received VTEP update")
		if msg.Node == m.hostname {
			m.setLocalVTEP(msg)
		} else {
			m.vtepsByNode[msg.Node] = msg
		}
		m.routesDirty = true
		m.vtepsDirty = true
	case *proto.VXLANTunnelEndpointRemove:
		logrus.WithField("msg", msg).Debug("VXLAN data plane received VTEP remove")
		if msg.Node == m.hostname {
			m.setLocalVTEP(nil)
		} else {
			delete(m.vtepsByNode, msg.Node)
		}
		m.routesDirty = true
		m.vtepsDirty = true
	}
}

func (m *vxlanManager) setLocalVTEP(vtep *proto.VXLANTunnelEndpointUpdate) {
	m.Lock()
	defer m.Unlock()
	m.myVTEP = vtep
}

func (m *vxlanManager) getLocalVTEP() *proto.VXLANTunnelEndpointUpdate {
	m.Lock()
	defer m.Unlock()
	return m.myVTEP
}

func (m *vxlanManager) CompleteDeferredWork() error {
	if !m.routesDirty {
		logrus.Debug("No change since last application, nothing to do")
		return nil
	}

	if m.vtepsDirty {
		var allowedVXLANSources []string
		if m.vtepsDirty {
			logrus.Debug("VTEPs are dirty, collecting the allowed VXLAN source set")
			allowedVXLANSources = append(allowedVXLANSources, m.externalNodeCIDRs...)
		}

		// The route table accepts the desired state. Start by setting the desired L2 "routes" by iterating
		// known VTEPs.
		var l2routes []routetable.L2Target
		for _, u := range m.vtepsByNode {
			mac, err := net.ParseMAC(u.Mac)
			if err != nil {
				// Don't block programming of other VTEPs if somehow we receive one with a bad mac.
				logrus.WithError(err).Warn("Failed to parse VTEP mac address")
				continue
			}
			l2routes = append(l2routes, routetable.L2Target{
				VTEPMAC: mac,
				GW:      ip.FromString(u.Ipv4Addr),
				IP:      ip.FromString(u.ParentDeviceIp),
			})
			allowedVXLANSources = append(allowedVXLANSources, u.ParentDeviceIp)
		}
		logrus.WithField("l2routes", l2routes).Debug("VXLAN manager sending L2 updates")
		m.routeTable.SetL2Routes(m.vxlanDevice, l2routes)
		m.ipsetsDataplane.AddOrReplaceIPSet(m.ipSetMetadata, allowedVXLANSources)
		m.vtepsDirty = false
	}

	if m.routesDirty {
		// Iterate through all of our L3 routes and send them through to the route table.
		var routes []routetable.Target
		for _, r := range m.routesByDest {
			logCtx := logrus.WithField("route", r)
			cidr, err := ip.CIDRFromString(r.Dst)
			if err != nil {
				// Don't block programming of other routes if somehow we receive one with a bad dst.
				logCtx.WithError(err).Warn("Failed to parse VXLAN route destination")
				continue
			}

			// Extract the gateway addr for this route based on its remote VTEP.
			vtep, ok := m.vtepsByNode[r.Node]
			if !ok {
				// The calculation graph should by design ensure that we never have a route with no
				// corresponding VTEP. This branch means there is likely a calc graph bug.
				logCtx.Warnf("Dataplane has route with no corresponding VTEP")
				continue
			}

			routes = append(routes, routetable.Target{
				Type: routetable.TargetTypeVXLAN,
				CIDR: cidr,
				GW:   ip.FromString(vtep.Ipv4Addr),
			})
		}

		logrus.WithField("routes", routes).Debug("VXLAN manager sending L3 updates")
		logrus.Info("VXLAN Manager completed deferred work")
		m.routeTable.SetRoutes(m.vxlanDevice, routes)
		m.routesDirty = false
	}

	return nil
}

// KeepVXLANDeviceInSync is a goroutine that configures the VXLAN tunnel device, then periodically
// checks that it is still correctly configured.
func (m *vxlanManager) KeepVXLANDeviceInSync(mtu int) {
	logrus.Info("VXLAN tunnel device thread started.")
	for {
		localVTEP := m.getLocalVTEP()
		if localVTEP == nil {
			logrus.Debug("Missing local VTEP information, retrying...")
			time.Sleep(1 * time.Second)
			continue
		}
		err := m.configureVXLANDevice(mtu, localVTEP)
		if err != nil {
			logrus.WithError(err).Warn("Failed configure VXLAN tunnel device, retrying...")
			time.Sleep(1 * time.Second)
			continue
		}
		logrus.Info("VXLAN tunnel device configured")
		time.Sleep(10 * time.Second)
	}
}

// getParentInterface returns the parent interface for the given local VTEP based on IP address.
func (m *vxlanManager) getParentInterface(localVTEP *proto.VXLANTunnelEndpointUpdate) (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if addr.IPNet.IP.String() == localVTEP.ParentDeviceIp {
				logrus.Debugf("Found parent interface: %s", link)
				return link, nil
			}
		}
	}
	return nil, fmt.Errorf("Unable to find parent interface with address %s", localVTEP.ParentDeviceIp)
}

// configureVXLANDevice ensures the VXLAN tunnel device is up and configured correctly.
func (m *vxlanManager) configureVXLANDevice(mtu int, localVTEP *proto.VXLANTunnelEndpointUpdate) error {
	logCxt := logrus.WithFields(logrus.Fields{"device": m.vxlanDevice})
	logCxt.Debug("Configuring VXLAN tunnel device")
	parent, err := m.getParentInterface(localVTEP)
	if err != nil {
		return err
	}
	mac, err := net.ParseMAC(localVTEP.Mac)
	if err != nil {
		return err
	}
	vxlan := &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:         m.vxlanDevice,
			HardwareAddr: mac,
		},
		VxlanId:      m.vxlanID,
		Port:         m.vxlanPort,
		VtepDevIndex: parent.Attrs().Index,
		SrcAddr:      ip.FromString(localVTEP.ParentDeviceIp).AsNetIP(),
	}

	// Try to get the device.
	link, err := netlink.LinkByName(m.vxlanDevice)
	if err != nil {
		logrus.WithError(err).Info("Failed to get VXLAN tunnel device, assuming it isn't present")
		if err := netlink.LinkAdd(vxlan); err == syscall.EEXIST {
			// Device already exists - likely a race.
			logrus.Debug("VXLAN device already exists, likely created by someone else.")
		} else if err != nil {
			// Error other than "device exists" - return it.
			return err
		}

		// The device now exists - requery it to check that the link exists and is a vxlan device.
		link, err = netlink.LinkByName(m.vxlanDevice)
		if err != nil {
			return fmt.Errorf("can't locate created vxlan device %v", m.vxlanDevice)
		}
	}

	// At this point, we have successfully queried the existing device, or made sure it exists if it didn't
	// already. Check for mismatched configuration. If they don't match, recreate the device.
	if incompat := vxlanLinksIncompat(vxlan, link); incompat != "" {
		// Existing device doesn't match desired configuration - delete it and recreate.
		logrus.Warningf("%q exists with incompatable configuration: %v; recreating device", vxlan.Name, incompat)
		if err = netlink.LinkDel(link); err != nil {
			return fmt.Errorf("failed to delete interface: %v", err)
		}
		if err = netlink.LinkAdd(vxlan); err != nil {
			return fmt.Errorf("failed to create vxlan interface: %v", err)
		}
		link, err = netlink.LinkByName(vxlan.Name)
		if err != nil {
			return err
		}
	}

	// Make sure the MTU is set correctly.
	attrs := link.Attrs()
	oldMTU := attrs.MTU
	if oldMTU != mtu {
		logCxt.WithFields(logrus.Fields{"old": oldMTU, "new": mtu}).Info("VXLAN device MTU needs to be updated")
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			log.WithError(err).Warn("Failed to set vxlan tunnel device MTU")
		} else {
			logCxt.Info("Updated vxlan tunnel MTU")
		}
	}

	// Make sure the IP address is configured.
	if err := ensureV4AddressOnLink(localVTEP.Ipv4Addr, link); err != nil {
		return fmt.Errorf("failed to ensure address of interface: %s", err)
	}

	// And the device is up.
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set interface up: %s", err)
	}

	return nil
}

// ensureV4AddressOnLink ensures that the provided IPv4 address is configured on the provided Link. If there are other addresses,
// this function will remove them, ensuring that the desired IPv4 address is the _only_ address on the Link.
func ensureV4AddressOnLink(ipStr string, link netlink.Link) error {
	_, net, err := net.ParseCIDR(ipStr + "/32")
	if err != nil {
		return err
	}
	addr := netlink.Addr{IPNet: net}
	existingAddrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}

	// Remove any addresses which we don't want.
	addrPresent := false
	for _, existing := range existingAddrs {
		if reflect.DeepEqual(existing.IPNet, addr.IPNet) {
			addrPresent = true
			continue
		}
		logrus.WithFields(logrus.Fields{"address": existing, "link": link.Attrs().Name}).Warn("Removing unwanted IP from VXLAN device")
		if err := netlink.AddrDel(link, &existing); err != nil {
			return fmt.Errorf("failed to remove IP address %s", existing)
		}
	}

	// Actually add the desired address to the interface if needed.
	if !addrPresent {
		logrus.WithFields(logrus.Fields{"address": addr}).Info("Assigning address to VXLAN device")
		if err := netlink.AddrAdd(link, &addr); err != nil {
			return fmt.Errorf("failed to add IP address")
		}
	}
	return nil
}

// vlanLinksIncompat takes two vxlan devices and compares them to make sure they match. If they do not match,
// this function will return a mesasge indicating which configuration is mismatched.
func vxlanLinksIncompat(l1, l2 netlink.Link) string {
	if l1.Type() != l2.Type() {
		return fmt.Sprintf("link type: %v vs %v", l1.Type(), l2.Type())
	}

	v1 := l1.(*netlink.Vxlan)
	v2 := l2.(*netlink.Vxlan)

	if v1.VxlanId != v2.VxlanId {
		return fmt.Sprintf("vni: %v vs %v", v1.VxlanId, v2.VxlanId)
	}

	if v1.VtepDevIndex > 0 && v2.VtepDevIndex > 0 && v1.VtepDevIndex != v2.VtepDevIndex {
		return fmt.Sprintf("vtep (external) interface: %v vs %v", v1.VtepDevIndex, v2.VtepDevIndex)
	}

	if len(v1.SrcAddr) > 0 && len(v2.SrcAddr) > 0 && !v1.SrcAddr.Equal(v2.SrcAddr) {
		return fmt.Sprintf("vtep (external) IP: %v vs %v", v1.SrcAddr, v2.SrcAddr)
	}

	if len(v1.Group) > 0 && len(v2.Group) > 0 && !v1.Group.Equal(v2.Group) {
		return fmt.Sprintf("group address: %v vs %v", v1.Group, v2.Group)
	}

	if v1.L2miss != v2.L2miss {
		return fmt.Sprintf("l2miss: %v vs %v", v1.L2miss, v2.L2miss)
	}

	if v1.Port > 0 && v2.Port > 0 && v1.Port != v2.Port {
		return fmt.Sprintf("port: %v vs %v", v1.Port, v2.Port)
	}

	if v1.GBP != v2.GBP {
		return fmt.Sprintf("gbp: %v vs %v", v1.GBP, v2.GBP)
	}

	return ""
}
