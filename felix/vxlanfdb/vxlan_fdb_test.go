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

const (
	ifaceName   = "vxlan.calico"
	ifaceNameV6 = "vxlan-v6.calico"
)

var (
	hostIP1 = ip.FromString("192.168.0.1")
	hostIP2 = ip.FromString("192.168.1.1")
	hostIP3 = ip.FromString("192.168.2.1")
	hostIP4 = ip.FromString("192.168.3.1")

	tunnelIP1 = ip.FromString("10.0.0.1")
	tunnelIP2 = ip.FromString("10.0.1.1")
	tunnelIP3 = ip.FromString("10.0.2.1")
	tunnelIP4 = ip.FromString("10.0.3.1")

	hostIP1V6   = ip.FromString("f00f::1")
	tunnelIP1V6 = ip.FromString("f00f::2")

	mac1 = "01:02:03:04:05:06"
	mac2 = "01:02:03:04:05:07"
	mac3 = "01:02:03:04:05:08"
	mac4 = "01:02:03:04:05:09"
	mac5 = "01:02:03:04:05:10"

	hwAddr1 = mustParseMAC(mac1)
	hwAddr2 = mustParseMAC(mac2)
	hwAddr3 = mustParseMAC(mac3)
	hwAddr4 = mustParseMAC(mac4)
	hwAddr5 = mustParseMAC(mac5)
)

// TestVXLANFDB_LinkCreatedAfterSetup tests the case where the VTEPs are configured first,
// then the interface shows up.
func TestVXLANFDB_LinkCreatedAfterSetup(t *testing.T) {
	dataplane, fdb := setup(t)

	fdb.SetVTEPs([]VTEP{
		{
			HostIP:    hostIP1,
			TunnelIP:  tunnelIP1,
			TunnelMAC: hwAddr1,
		},
		{
			HostIP:    hostIP2,
			TunnelIP:  tunnelIP2,
			TunnelMAC: hwAddr2,
		},
	})

	// Fist apply, link not there yet.
	Expect(fdb.resyncPending).To(BeTrue())
	err := fdb.Apply()
	Expect(err).To(MatchError(ContainSubstring("not found")))
	Expect(fdb.resyncPending).To(BeFalse(), "Link not found should disable resync until OnIfaceStateChanged called")

	// Kick for another interface should be ignored.
	fdb.OnIfaceStateChanged("foo", ifacemonitor.StateUp)
	Expect(fdb.resyncPending).To(BeFalse(), "Shouldn't resync for unknown iface")

	// Link arrives.
	dataplane.AddIface(2, ifaceName, false, false)
	fdb.OnIfaceStateChanged(ifaceName, ifacemonitor.StateDown)

	// Second apply, should return early.
	err = fdb.Apply()
	Expect(err).To(Equal(ErrLinkDown))

	// Set link up...
	dataplane.SetIface(ifaceName, true, true)
	fdb.OnIfaceStateChanged(ifaceName, ifacemonitor.StateUp)

	// Now we're up, should see it resync.
	err = fdb.Apply()
	Expect(err).NotTo(HaveOccurred())

	dataplane.ExpectNeighs(unix.AF_INET,
		// Should have been added.
		netlink.Neigh{
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP1.AsNetIP(),
			HardwareAddr: hwAddr1,
		},
		netlink.Neigh{
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP2.AsNetIP(),
			HardwareAddr: hwAddr2,
		},
	)

	dataplane.ExpectNeighs(unix.AF_BRIDGE,
		// Should have been added.
		netlink.Neigh{
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			HardwareAddr: hwAddr1,
			IP:           hostIP1.AsNetIP(),
		},
		netlink.Neigh{
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			HardwareAddr: hwAddr2,
			IP:           hostIP2.AsNetIP(),
		},
	)
	Expect(fdb.resyncPending).To(BeFalse())

	fdb.QueueResync()
	Expect(fdb.resyncPending).To(BeTrue())
}

// TestVXLANFDB_IPv6 mainline test for IPv6.
func TestVXLANFDB_IPv6(t *testing.T) {
	RegisterTestingT(t)
	logutils.ConfigureLoggingForTestingT(t)

	dataplane := mocknetlink.New()
	fdb := New(
		unix.AF_INET6,
		ifaceNameV6,
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

	fdb.SetVTEPs([]VTEP{
		{
			HostIP:    hostIP1V6,
			TunnelIP:  tunnelIP1V6,
			TunnelMAC: hwAddr1,
		},
	})

	// Link arrives.
	dataplane.AddIface(2, ifaceNameV6, true, true)
	fdb.OnIfaceStateChanged(ifaceNameV6, ifacemonitor.StateUp)

	// Now we're up, should see it resync.
	err := fdb.Apply()
	Expect(err).NotTo(HaveOccurred())

	dataplane.ExpectNeighs(unix.AF_INET6,
		// Should have been added.
		netlink.Neigh{
			Family:       unix.AF_INET6,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP1V6.AsNetIP(),
			HardwareAddr: hwAddr1,
		},
	)

	dataplane.ExpectNeighs(unix.AF_BRIDGE,
		// Should have been added.
		netlink.Neigh{
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			HardwareAddr: hwAddr1,
			IP:           hostIP1V6.AsNetIP(),
		},
	)
	Expect(fdb.resyncPending).To(BeFalse())

	fdb.QueueResync()
	Expect(fdb.resyncPending).To(BeTrue())
}

// TestVXLANFDB_LinkPresentAtStartup tests the case where the link is present
// already with some existing neigh entries.
func TestVXLANFDB_LinkPresentAtStartup(t *testing.T) {
	dataplane, fdb := setup(t)

	// Pre-create the link.  We shouldn't even need to signal it with
	// OnIfaceStateChanged.
	dataplane.AddIface(2, ifaceName, true, true)

	// Set initial state of the ARP table.
	dataplane.AddNeighs(unix.AF_INET,
		// This entry is correct already.
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
		// This one should be removed.
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
		// This one should be removed.
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

	// First apply should go straight through
	err := fdb.Apply()
	Expect(err).NotTo(HaveOccurred())

	dataplane.ExpectNeighs(
		unix.AF_INET,
		// Should have been added.
		netlink.Neigh{
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP1.AsNetIP(),
			HardwareAddr: hwAddr1,
		},
		// This one is correct already.
		netlink.Neigh{
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP2.AsNetIP(),
			HardwareAddr: hwAddr2,
		},
		// Should have been updated.
		netlink.Neigh{
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP3.AsNetIP(),
			HardwareAddr: hwAddr3,
		},
	)

	dataplane.ExpectNeighs(
		unix.AF_BRIDGE,
		// Should have been added.
		netlink.Neigh{
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			HardwareAddr: hwAddr1,
			IP:           hostIP1.AsNetIP(),
		},
		// This one is correct already.
		netlink.Neigh{
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			HardwareAddr: hwAddr2,
			IP:           hostIP2.AsNetIP(),
		},
		// Should have been updated.
		netlink.Neigh{
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			HardwareAddr: hwAddr3,
			IP:           hostIP3.AsNetIP(),
		},
	)
	Expect(fdb.resyncPending).To(BeFalse())
}

// TestVXLANFDB_DifferentIPSameMAC repros a bug where we were getting confused
// by having multiple IPs with the same MAC.
func TestVXLANFDB_DifferentIPSameMAC(t *testing.T) {
	dataplane, fdb := setup(t)

	// Pre-create the link.  We shouldn't even need to signal it with
	// OnIfaceStateChanged.
	dataplane.AddIface(2, ifaceName, true, true)

	// Set initial state of the ARP table.
	dataplane.AddNeighs(unix.AF_INET,
		// Lots of IPs all sharing same MAC.
		netlink.Neigh{
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP2.AsNetIP(),
			HardwareAddr: hwAddr2,
		},
		netlink.Neigh{
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP4.AsNetIP(),
			HardwareAddr: hwAddr2,
		},
		netlink.Neigh{
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP3.AsNetIP(),
			HardwareAddr: hwAddr2,
		},
	)

	// Set initial state of the FDB table.
	dataplane.AddNeighs(unix.AF_BRIDGE,
		// Inverse: several MACs sharing same IP.
		netlink.Neigh{
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			HardwareAddr: hwAddr2,
			IP:           hostIP2.AsNetIP(),
		},
		netlink.Neigh{
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			HardwareAddr: hwAddr4,
			IP:           hostIP2.AsNetIP(),
		},
		netlink.Neigh{
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			HardwareAddr: hwAddr5,
			IP:           hostIP2.AsNetIP(),
		},
	)

	// Re-use that MAC for the VTEP that we create.
	fdb.SetVTEPs([]VTEP{
		{
			HostIP:    hostIP2,
			TunnelIP:  tunnelIP2,
			TunnelMAC: hwAddr2,
		},
	})

	// First apply should go straight through
	err := fdb.Apply()
	Expect(err).NotTo(HaveOccurred())

	// All but correct entry should be cleaned up.
	dataplane.ExpectNeighs(
		unix.AF_INET,
		netlink.Neigh{
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP2.AsNetIP(),
			HardwareAddr: hwAddr2,
		},
	)
	// All but correct entry should be cleaned up.
	dataplane.ExpectNeighs(
		unix.AF_BRIDGE,
		netlink.Neigh{
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			HardwareAddr: hwAddr2,
			IP:           hostIP2.AsNetIP(),
		},
	)
	Expect(fdb.resyncPending).To(BeFalse())

	// Trigger a resync, should be idempotent.
	fdb.QueueResync()
	err = fdb.Apply()
	Expect(err).NotTo(HaveOccurred())
	dataplane.ExpectNeighs(
		unix.AF_INET,
		netlink.Neigh{
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP2.AsNetIP(),
			HardwareAddr: hwAddr2,
		},
	)

	dataplane.ExpectNeighs(
		unix.AF_BRIDGE,
		netlink.Neigh{
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			HardwareAddr: hwAddr2,
			IP:           hostIP2.AsNetIP(),
		},
	)
	Expect(fdb.resyncPending).To(BeFalse())
}

func TestVXLANFDB_IgnoreNonCalicoNeighs(t *testing.T) {
	dataplane, fdb := setup(t)

	// Pre-create the link.  We shouldn't even need to signal it with
	// OnIfaceStateChanged.
	dataplane.AddIface(2, ifaceName, true, true)

	// Set initial state of the ARP table.
	dataplane.AddNeighs(unix.AF_INET,
		// Should be ignored.
		netlink.Neigh{
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PROBE,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP4.AsNetIP(),
			HardwareAddr: hwAddr4,
		},
		netlink.Neigh{
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PROBE,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP3.AsNetIP(),
			HardwareAddr: nil,
		},
	)

	// Set initial state of the FDB table.
	dataplane.AddNeighs(unix.AF_BRIDGE,
		// Should be ignored, wrong flags.
		netlink.Neigh{
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PROBE,
			HardwareAddr: hwAddr2,
			IP:           hostIP2.AsNetIP(),
		},
		// Missing MAC.
		netlink.Neigh{
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			HardwareAddr: nil,
			IP:           hostIP2.AsNetIP(),
		},
	)

	fdb.SetVTEPs([]VTEP{
		// This one should be added.
		{
			HostIP:    hostIP1,
			TunnelIP:  tunnelIP1,
			TunnelMAC: hwAddr1,
		},
	})

	// First apply should go straight through
	err := fdb.Apply()
	Expect(err).NotTo(HaveOccurred())

	dataplane.ExpectNeighs(
		unix.AF_INET,
		// Should have been added.
		netlink.Neigh{
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP1.AsNetIP(),
			HardwareAddr: hwAddr1,
		},

		// No change to these.
		netlink.Neigh{
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PROBE,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP4.AsNetIP(),
			HardwareAddr: hwAddr4,
		},
		netlink.Neigh{
			Family:       unix.AF_INET,
			LinkIndex:    2,
			State:        netlink.NUD_PROBE,
			Type:         unix.RTN_UNICAST,
			IP:           tunnelIP3.AsNetIP(),
			HardwareAddr: nil,
		},
	)

	dataplane.ExpectNeighs(
		unix.AF_BRIDGE,
		// Should have been added.
		netlink.Neigh{
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			HardwareAddr: hwAddr1,
			IP:           hostIP1.AsNetIP(),
		},

		// No cahnge to these.
		netlink.Neigh{
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PROBE,
			HardwareAddr: hwAddr2,
			IP:           hostIP2.AsNetIP(),
		},
		netlink.Neigh{
			Family:       unix.AF_BRIDGE,
			Flags:        netlink.NTF_SELF,
			LinkIndex:    2,
			State:        netlink.NUD_PERMANENT,
			HardwareAddr: nil,
			IP:           hostIP2.AsNetIP(),
		},
	)
	Expect(fdb.resyncPending).To(BeFalse())
}

func TestVXLANFDB_TransientNetlinkErrors(t *testing.T) {
	for _, failFlag := range []mocknetlink.FailFlags{
		mocknetlink.FailNextNeighSet,
		mocknetlink.FailNextNeighDel,
		mocknetlink.FailNextNeighList,
		mocknetlink.FailNextNewNetlink,
	} {
		t.Run(failFlag.String(), func(t *testing.T) {
			dataplane, fdb := setup(t)
			dataplane.FailuresToSimulate = failFlag
			dataplane.PersistFailures = true

			// Pre-create the link.  We shouldn't even need to signal it with
			// OnIfaceStateChanged.
			dataplane.AddIface(2, ifaceName, true, true)

			// Add an unknown entry so that the FDB has something to delete.
			dataplane.AddNeighs(unix.AF_INET,
				// This one should be removed.
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
				// This one should be removed.
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
			})

			// Applies should fail while we have persistent failures.
			err := fdb.Apply()
			Expect(err).To(HaveOccurred())
			Expect(fdb.resyncPending).To(BeTrue())
			Expect(dataplane.NumNewNetlinkCalls).To(Equal(1))
			err = fdb.Apply()
			Expect(err).To(HaveOccurred())
			Expect(fdb.resyncPending).To(BeTrue())
			Expect(dataplane.NumNewNetlinkCalls).To(Equal(2))
			dataplane.FailuresToSimulate = 0

			// Now apply should succeed.
			err = fdb.Apply()
			Expect(err).NotTo(HaveOccurred())
			Expect(fdb.resyncPending).To(BeFalse())

			dataplane.ExpectNeighs(
				unix.AF_INET,
				netlink.Neigh{
					Family:       unix.AF_INET,
					LinkIndex:    2,
					State:        netlink.NUD_PERMANENT,
					Type:         unix.RTN_UNICAST,
					IP:           tunnelIP1.AsNetIP(),
					HardwareAddr: hwAddr1,
				},
			)
			dataplane.ExpectNeighs(
				unix.AF_BRIDGE,
				netlink.Neigh{
					Family:       unix.AF_BRIDGE,
					Flags:        netlink.NTF_SELF,
					LinkIndex:    2,
					State:        netlink.NUD_PERMANENT,
					HardwareAddr: hwAddr1,
					IP:           hostIP1.AsNetIP(),
				},
			)
		})
	}
}

func setup(t *testing.T) (*mocknetlink.MockNetlinkDataplane, *VXLANFDB) {
	RegisterTestingT(t)
	logutils.ConfigureLoggingForTestingT(t)

	dataplane := mocknetlink.New()
	fdb := New(
		unix.AF_INET,
		ifaceName,
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
	return dataplane, fdb
}

func mustParseMAC(s string) net.HardwareAddr {
	hwAddr, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return hwAddr
}
