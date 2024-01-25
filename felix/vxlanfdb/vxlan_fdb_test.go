// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vxlanfdb

import (
	"net"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/netlinkshim/mocknetlink"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

func init() {
	logrus.SetFormatter(&logutils.Formatter{})
	logrus.SetLevel(logrus.DebugLevel)
}

func TestVXLANFDB_Mainline(t *testing.T) {
	RegisterTestingT(t)
	logutils.ConfigureLoggingForTestingT(t)

	dataplane := mocknetlink.New()
	fdb := New(
		unix.AF_INET,
		"vxlan.calico",
		&environment.FakeFeatureDetector{
			Features: environment.Features{
				// FDB should force disable strict mode even though we
				// pretend it's supported.
				KernelSideRouteFiltering: true,
			},
		},
		10*time.Second,
		WithNetlinkHandleShim(dataplane.NewMockNetlink),
	)

	hostIP1 := ip.FromString("192.168.0.1")
	hostIP2 := ip.FromString("192.168.1.1")
	hostIP3 := ip.FromString("192.168.2.1")
	hostIP4 := ip.FromString("192.168.3.1")

	tunnelIP1 := ip.FromString("10.0.0.1")
	tunnelIP2 := ip.FromString("10.0.1.1")
	tunnelIP3 := ip.FromString("10.0.2.1")
	tunnelIP4 := ip.FromString("10.0.3.1")

	mac1 := "01:02:03:04:05:06"
	hwAddr1, err := net.ParseMAC(mac1)
	Expect(err).NotTo(HaveOccurred())
	mac2 := "01:02:03:04:05:07"
	hwAddr2, err := net.ParseMAC(mac2)
	Expect(err).NotTo(HaveOccurred())
	mac3 := "01:02:03:04:05:08"
	hwAddr3, err := net.ParseMAC(mac3)
	Expect(err).NotTo(HaveOccurred())
	mac4 := "01:02:03:04:05:09"
	hwAddr4, err := net.ParseMAC(mac4)
	Expect(err).NotTo(HaveOccurred())
	mac5 := "01:02:03:04:05:10"
	hwAddr5, err := net.ParseMAC(mac5)
	Expect(err).NotTo(HaveOccurred())

	// Set initial state of the ARP table.
	dataplane.AddNeighs(unix.AF_INET,
		netlink.Neigh{
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP2.AsNetIP(),
			HardwareAddr: hwAddr2,
		},
		// This one needs to be changed.
		netlink.Neigh{
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP3.AsNetIP(),
			HardwareAddr: hwAddr4,
		},
		// This one needs to be removed.
		netlink.Neigh{
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP4.AsNetIP(),
			HardwareAddr: hwAddr5,
		},
	)

	// Set initial state of the FDB table.
	dataplane.AddNeighs(unix.AF_BRIDGE,
		// This one is correct already.
		netlink.Neigh{
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			HardwareAddr: hwAddr2,
			IP:           hostIP2.AsNetIP(),
		},
		// This one needs to be changed.
		netlink.Neigh{
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			HardwareAddr: hwAddr4,
			IP:           hostIP3.AsNetIP(),
		},
		// This one needs to be removed.
		netlink.Neigh{
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			HardwareAddr: hwAddr5,
			IP:           hostIP4.AsNetIP(),
		},
	)

	fdb.SetVTEPs([]VTEP{
		// This one should be added.
		{
			HostIP:    hostIP1,
			TunnelIP:  tunnelIP1,
			TunnelMAC: hwAddr1,
		},
		// This one already present, shouldn't get touched.
		{
			HostIP:    hostIP2,
			TunnelIP:  tunnelIP2,
			TunnelMAC: hwAddr2,
		},
		// This one is present but MAC is wrong.
		{
			HostIP:    hostIP3,
			TunnelIP:  tunnelIP3,
			TunnelMAC: hwAddr3,
		},
	})

	// Fist apply, link not there yet.
	Expect(fdb.resyncPending).To(BeTrue())
	err = fdb.Apply()
	Expect(err).To(MatchError(ContainSubstring("not found")))
	Expect(fdb.resyncPending).To(BeFalse(), "Link not found should disable resync until OnIfaceStateChanged called")

	// Link arrives.
	dataplane.AddIface(2, "vxlan.calico", true, true)
	fdb.OnIfaceStateChanged("vxlan.calico", ifacemonitor.StateUp)

	// Second apply, should be good.
	err = fdb.Apply()
	Expect(err).NotTo(HaveOccurred())

	Expect(dataplane.NeighsByFamily[unix.AF_INET]).To(Equal(map[mocknetlink.NeighKey]*netlink.Neigh{
		// Should have been added.
		mocknetlink.NeighKey{
			LinkIndex: 2,
			IP:        tunnelIP1,
			MAC:       mac1,
		}: {
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP1.AsNetIP(),
			HardwareAddr: hwAddr1,
		},
		// This one is correct already.
		mocknetlink.NeighKey{
			LinkIndex: 2,
			IP:        tunnelIP2,
			MAC:       mac2,
		}: {
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP2.AsNetIP(),
			HardwareAddr: hwAddr2,
		},
		// Should have been updated.
		mocknetlink.NeighKey{
			LinkIndex: 2,
			IP:        tunnelIP3,
			MAC:       mac3,
		}: {
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP3.AsNetIP(),
			HardwareAddr: hwAddr3,
		},
	}))

	Expect(dataplane.NeighsByFamily[unix.AF_BRIDGE]).To(Equal(map[mocknetlink.NeighKey]*netlink.Neigh{
		// Should have been added.
		mocknetlink.NeighKey{
			LinkIndex: 2,
			MAC:       mac1,
			IP:        hostIP1,
		}: {
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			HardwareAddr: hwAddr1,
			IP:           hostIP1.AsNetIP(),
		},
		// This one is correct already.
		mocknetlink.NeighKey{
			LinkIndex: 2,
			MAC:       mac2,
			IP:        hostIP2,
		}: {
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			HardwareAddr: hwAddr2,
			IP:           hostIP2.AsNetIP(),
		},
		// Should have been updated.
		mocknetlink.NeighKey{
			LinkIndex: 2,
			MAC:       mac3,
			IP:        hostIP3,
		}: {
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			HardwareAddr: hwAddr3,
			IP:           hostIP3.AsNetIP(),
		},
	}))
	Expect(fdb.resyncPending).To(BeFalse())
}
