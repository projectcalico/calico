// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package wireguard_test

import (
	"github.com/projectcalico/calico/felix/logutils"
	. "github.com/projectcalico/calico/felix/wireguard"

	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
	mocknetlink "github.com/projectcalico/calico/felix/netlinkshim/mocknetlink"
	"github.com/projectcalico/calico/felix/timeshim/mocktime"
)

var (
	zeroKey            = wgtypes.Key{}
	ifaceName          = "wireguard-if"
	hostname           = "my-host"
	peer1              = "peer1"
	peer2              = "peer2"
	peer3              = "peer3"
	peer4              = "peer4"
	FelixRouteProtocol = netlink.RouteProtocol(syscall.RTPROT_BOOT)
	tableIndex         = 99
	rulePriority       = 98
	firewallMark       = 10
	listeningPort      = 1000
	mtu                = 2000

	ipv4_int1 = ip.FromString("192.168.0.0")
	ipv4_int2 = ip.FromString("192.168.10.0")

	ipv4_host    = ip.FromString("1.2.3.0")
	ipv4_peer1   = ip.FromString("1.2.3.5")
	ipv4_peer2   = ip.FromString("1.2.3.6")
	ipv4_peer2_2 = ip.FromString("1.2.3.7")
	ipv4_peer3   = ip.FromString("10.10.20.20")
	ipv4_peer4   = ip.FromString("10.10.20.30")

	cidr_local = ip.MustParseCIDROrIP("192.180.0.0/30")
	cidr_1     = ip.MustParseCIDROrIP("192.168.1.0/24")
	cidr_2     = ip.MustParseCIDROrIP("192.168.2.0/24")
	cidr_3     = ip.MustParseCIDROrIP("192.168.3.0/24")
	cidr_4     = ip.MustParseCIDROrIP("192.168.4.0/26")
	cidr_5     = ip.MustParseCIDROrIP("192.168.5.0/26")
	cidr_6     = ip.MustParseCIDROrIP("192.168.6.0/32") // Single IP
	ipnet_1    = cidr_1.ToIPNet()
	ipnet_2    = cidr_2.ToIPNet()
	ipnet_3    = cidr_3.ToIPNet()
	ipnet_4    = cidr_4.ToIPNet()
	//ipnet_6             = cidr_6.ToIPNet()
	routekey_cidr_local = fmt.Sprintf("%d-%s", tableIndex, cidr_local)
	//routekey_1 = fmt.Sprintf("%d-%s", tableIndex, cidr_1)
	//routekey_2 = fmt.Sprintf("%d-%s", tableIndex, cidr_2)
	//routekey_3 = fmt.Sprintf("%d-%s", tableIndex, cidr_3)
	routekey_4 = fmt.Sprintf("%d-%s", tableIndex, cidr_4)
	routekey_6 = fmt.Sprintf("%d-%s", tableIndex, cidr_6)
)

func mustGeneratePrivateKey() wgtypes.Key {
	key, err := wgtypes.GeneratePrivateKey()
	Expect(err).ToNot(HaveOccurred())
	return key
}

type applyWithErrors struct {
	numExpected int
	errors      []error
	wg          *Wireguard
}

func newApplyWithErrors(wg *Wireguard, numExpected int) *applyWithErrors {
	return &applyWithErrors{wg: wg, numExpected: numExpected}
}

func (a *applyWithErrors) Apply() error {
	for {
		err := a.wg.Apply()
		if err == nil {
			log.Debug("Successfully applied")
			return nil
		}
		log.WithError(err).Debug("Failed to apply")
		a.errors = append(a.errors, err)

		a.numExpected--
		if a.numExpected < 0 {
			log.Error("Hit failure limit")
			return err
		}
	}
}

func (a *applyWithErrors) LastError() error {
	if len(a.errors) == 0 {
		return nil
	}
	return a.errors[len(a.errors)-1]
}

type mockCallbacks struct {
	numStatusCallbacks int
	statusErr          error
	statusKey          wgtypes.Key

	numProcSysCallbacks int
	procSysPath         string
	procSysValue        string
	procSysErr          error
}

func (m *mockCallbacks) status(publicKey wgtypes.Key) error {
	log.Debugf("Status update with public key: %s", publicKey)
	m.numStatusCallbacks++
	if m.statusErr != nil {
		return m.statusErr
	}
	m.statusKey = publicKey

	log.Debugf("Num callbacks: %d", m.numStatusCallbacks)
	return nil
}

func (m *mockCallbacks) writeProcSys(path, value string) error {
	m.numProcSysCallbacks++
	if m.procSysErr != nil {
		return m.procSysErr
	}
	m.procSysPath = path
	m.procSysValue = value
	return nil
}

var _ = Describe("Enable wireguard", func() {
	var wgDataplane, rtDataplane, rrDataplane *mocknetlink.MockNetlinkDataplane
	var t *mocktime.MockTime
	var s *mockCallbacks
	var wg *Wireguard
	var rule *netlink.Rule

	BeforeEach(func() {
		wgDataplane = mocknetlink.New()
		rtDataplane = mocknetlink.New()
		rrDataplane = mocknetlink.New()
		t = mocktime.New()
		s = &mockCallbacks{}
		// Setting an auto-increment greater than the route cleanup delay effectively
		// disables the grace period for these tests.
		t.SetAutoIncrement(11 * time.Second)

		wg = NewWithShims(
			hostname,
			&Config{
				Enabled:             true,
				ListeningPort:       listeningPort,
				FirewallMark:        firewallMark,
				RoutingRulePriority: rulePriority,
				RoutingTableIndex:   tableIndex,
				InterfaceName:       ifaceName,
				MTU:                 mtu,
				EncryptHostTraffic:  true,
			},
			rtDataplane.NewMockNetlink,
			rrDataplane.NewMockNetlink,
			wgDataplane.NewMockNetlink,
			wgDataplane.NewMockWireguard,
			10*time.Second,
			t,
			FelixRouteProtocol,
			s.status,
			s.writeProcSys,
			logutils.NewSummarizer("test loop"),
		)

		rule = netlink.NewRule()
		rule.Family = netlink.FAMILY_V4
		rule.Priority = rulePriority
		rule.Table = tableIndex
		rule.Invert = true
		rule.Mark = firewallMark
		rule.Mask = firewallMark
	})

	It("should be constructable", func() {
		Expect(wg).ToNot(BeNil())
	})

	Describe("create the wireguard link", func() {
		BeforeEach(func() {
			err := wg.Apply()
			Expect(err).NotTo(HaveOccurred())
		})

		It("should configure the link but wait for link to be active", func() {
			Expect(wgDataplane.NumLinkAddCalls).To(Equal(1))
			Expect(wgDataplane.AddedLinks).To(HaveKey(ifaceName))
			Expect(wgDataplane.NameToLink[ifaceName].LinkType).To(Equal("wireguard"))
			Expect(wgDataplane.NameToLink[ifaceName].LinkAttrs.MTU).To(Equal(2000))
			Expect(wgDataplane.NumLinkAddCalls).To(Equal(1))
			Expect(wgDataplane.WireguardOpen).To(BeFalse())
		})

		It("another apply will no-op until link is active", func() {
			// Apply, but still not iface update
			wgDataplane.ResetDeltas()
			err := wg.Apply()
			Expect(err).NotTo(HaveOccurred())
			Expect(wgDataplane.NumLinkAddCalls).To(Equal(0))
			Expect(wgDataplane.WireguardOpen).To(BeFalse())
		})

		It("no op after a link down callback", func() {
			// Iface update indicating down.
			wgDataplane.ResetDeltas()
			wg.OnIfaceStateChanged(ifaceName, ifacemonitor.StateDown)
			err := wg.Apply()
			Expect(err).NotTo(HaveOccurred())
			Expect(wgDataplane.NumLinkAddCalls).To(Equal(0))
			Expect(wgDataplane.WireguardOpen).To(BeFalse())
		})

		It("no op for an interface callback for non-wg interface (same prefix)", func() {
			// Iface update indicating up.
			wgDataplane.ResetDeltas()
			wgDataplane.AddIface(1919, ifaceName+".foobar", true, true)
			wg.OnIfaceStateChanged(ifaceName+".foobar", ifacemonitor.StateUp)
			err := wg.Apply()
			Expect(err).NotTo(HaveOccurred())
			Expect(wgDataplane.NumLinkAddCalls).To(Equal(0))
			Expect(wgDataplane.WireguardOpen).To(BeFalse())
		})

		It("should handle status update raising an error", func() {
			wgDataplane.SetIface(ifaceName, true, true)
			wg.OnIfaceStateChanged(ifaceName, ifacemonitor.StateUp)
			s.statusErr = errors.New("foobarbaz")
			err := wg.Apply()
			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(s.statusErr))
		})

		Describe("set the link up", func() {
			BeforeEach(func() {
				wgDataplane.SetIface(ifaceName, true, true)
				wg.OnIfaceStateChanged(ifaceName, ifacemonitor.StateUp)
				err := wg.Apply()
				Expect(err).NotTo(HaveOccurred())
			})

			It("should create wireguard client and create private key", func() {
				Expect(wgDataplane.NumLinkAddCalls).To(Equal(1))
				Expect(wgDataplane.WireguardOpen).To(BeTrue())
				link := wgDataplane.NameToLink[ifaceName]
				Expect(link.WireguardFirewallMark).To(Equal(10))
				Expect(link.WireguardListenPort).To(Equal(listeningPort))
				Expect(link.WireguardPrivateKey).NotTo(Equal(zeroKey))
				Expect(link.WireguardPrivateKey.PublicKey()).To(Equal(link.WireguardPublicKey))
				Expect(s.numStatusCallbacks).To(Equal(1))
				Expect(s.statusKey).To(Equal(link.WireguardPublicKey))
			})

			It("should add the routing rule when wireguard device is configured", func() {
				wgDataplane.ResetDeltas()
				err := wg.Apply()
				Expect(err).ToNot(HaveOccurred())

				Expect(rrDataplane.AddedRules).To(HaveLen(1))
				Expect(rrDataplane.DeletedRules).To(HaveLen(0))
				Expect(rrDataplane.AddedRules).To(ConsistOf(*rule))
			})

			It("should delete invalid rules jumping to the wireguard table", func() {
				incorrectRule := netlink.NewRule()
				incorrectRule.Family = 2
				incorrectRule.Priority = rulePriority + 10
				incorrectRule.Table = tableIndex
				incorrectRule.Mark = firewallMark + 10
				incorrectRule.Invert = false
				err := rrDataplane.RuleAdd(incorrectRule)
				Expect(err).ToNot(HaveOccurred())
				rrDataplane.ResetDeltas()

				wg.QueueResync()
				err = wg.Apply()
				Expect(err).ToNot(HaveOccurred())

				Expect(rrDataplane.AddedRules).To(HaveLen(0))
				Expect(rrDataplane.DeletedRules).To(ConsistOf(*incorrectRule))
			})

			It("after endpoint update with incorrect key should program the interface address and resend same key as status", func() {
				link := wgDataplane.NameToLink[ifaceName]
				Expect(link.WireguardPrivateKey).NotTo(Equal(zeroKey))
				Expect(s.numStatusCallbacks).To(Equal(1))
				key := link.WireguardPrivateKey
				Expect(s.statusKey).To(Equal(key.PublicKey()))

				ipv4 := ip.FromString("1.2.3.4")
				wg.EndpointWireguardUpdate(hostname, zeroKey, ipv4)
				err := wg.Apply()
				Expect(err).NotTo(HaveOccurred())
				link = wgDataplane.NameToLink[ifaceName]
				Expect(link.Addrs).To(HaveLen(1))
				Expect(link.Addrs[0].IP).To(Equal(ipv4.AsNetIP()))
				Expect(wgDataplane.WireguardOpen).To(BeTrue())
				Expect(link.WireguardFirewallMark).To(Equal(10))
				Expect(link.WireguardListenPort).To(Equal(listeningPort))
				Expect(link.WireguardPrivateKey).To(Equal(key))
				Expect(link.WireguardPrivateKey.PublicKey()).To(Equal(link.WireguardPublicKey))
				Expect(s.numStatusCallbacks).To(Equal(2))
				Expect(s.statusKey).To(Equal(key.PublicKey()))
			})

			It("after endpoint update with correct key should program the interface address and not send another status update", func() {
				link := wgDataplane.NameToLink[ifaceName]
				Expect(link.WireguardPrivateKey).NotTo(Equal(zeroKey))
				Expect(s.numStatusCallbacks).To(Equal(1))
				key := link.WireguardPrivateKey

				ipv4 := ip.FromString("1.2.3.4")
				wg.EndpointWireguardUpdate(hostname, key.PublicKey(), ipv4)
				err := wg.Apply()
				Expect(err).NotTo(HaveOccurred())
				link = wgDataplane.NameToLink[ifaceName]
				Expect(link.Addrs).To(HaveLen(1))
				Expect(link.Addrs[0].IP).To(Equal(ipv4.AsNetIP()))
				Expect(wgDataplane.WireguardOpen).To(BeTrue())
				Expect(link.WireguardFirewallMark).To(Equal(10))
				Expect(link.WireguardListenPort).To(Equal(listeningPort))
				Expect(link.WireguardPrivateKey).To(Equal(key))
				Expect(link.WireguardPrivateKey.PublicKey()).To(Equal(link.WireguardPublicKey))
				Expect(s.numStatusCallbacks).To(Equal(1))
			})

			It("will use node IP on EndpointUpdate when interface is not specified on previous EndpointWireguardUpdate", func() {
				link := wgDataplane.NameToLink[ifaceName]
				Expect(link.WireguardPrivateKey).NotTo(Equal(zeroKey))
				Expect(s.numStatusCallbacks).To(Equal(1))
				key := link.WireguardPrivateKey

				ipv4 := ip.FromString("1.2.3.4")
				wg.EndpointWireguardUpdate(hostname, key.PublicKey(), nil)
				wg.EndpointUpdate(hostname, ipv4)
				err := wg.Apply()

				Expect(err).NotTo(HaveOccurred())
				link = wgDataplane.NameToLink[ifaceName]
				Expect(link.Addrs).To(HaveLen(1))
				Expect(link.Addrs[0].IP).To(Equal(ipv4.AsNetIP()))
				Expect(wgDataplane.WireguardOpen).To(BeTrue())
				Expect(link.WireguardFirewallMark).To(Equal(10))
				Expect(link.WireguardListenPort).To(Equal(listeningPort))
				Expect(link.WireguardPrivateKey).To(Equal(key))
				Expect(link.WireguardPrivateKey.PublicKey()).To(Equal(link.WireguardPublicKey))
				Expect(s.numStatusCallbacks).To(Equal(1))
			})

			It("will use node IP from previous EndpointUpdate when interface is not specified on EndpointWireguardUpdate", func() {
				link := wgDataplane.NameToLink[ifaceName]
				Expect(link.WireguardPrivateKey).NotTo(Equal(zeroKey))
				Expect(s.numStatusCallbacks).To(Equal(1))
				key := link.WireguardPrivateKey

				// Basically the same test as before but calls are reveresed.
				ipv4 := ip.FromString("1.2.3.4")
				wg.EndpointUpdate(hostname, ipv4)
				wg.EndpointWireguardUpdate(hostname, key.PublicKey(), nil)
				err := wg.Apply()

				Expect(err).NotTo(HaveOccurred())
				link = wgDataplane.NameToLink[ifaceName]
				Expect(link.Addrs).To(HaveLen(1))
				Expect(link.Addrs[0].IP).To(Equal(ipv4.AsNetIP()))
				Expect(wgDataplane.WireguardOpen).To(BeTrue())
				Expect(link.WireguardFirewallMark).To(Equal(10))
				Expect(link.WireguardListenPort).To(Equal(listeningPort))
				Expect(link.WireguardPrivateKey).To(Equal(key))
				Expect(link.WireguardPrivateKey.PublicKey()).To(Equal(link.WireguardPublicKey))
				Expect(s.numStatusCallbacks).To(Equal(1))
			})

			Describe("add local routes with overlap", func() {
				var lc1, lc2, lc3 ip.CIDR

				BeforeEach(func() {
					lc1 = ip.MustParseCIDROrIP("12.12.10.10/32")
					lc2 = ip.MustParseCIDROrIP("12.12.10.0/24")
					lc3 = ip.MustParseCIDROrIP("12.12.11.0/32")

					wg.RouteUpdate(hostname, lc1)
					wg.RouteUpdate(hostname, lc2)
					wg.RouteUpdate(hostname, lc3)

					err := wg.Apply()
					Expect(err).ToNot(HaveOccurred())
				})

				It("should create the rule when routing config is updated", func() {
					Expect(rrDataplane.DeletedRules).To(HaveLen(0))
					Expect(rrDataplane.AddedRules).To(ConsistOf(*rule))
				})

				It("should not re-add a deleted rule until resync", func() {
					err := rrDataplane.RuleDel(rule)
					Expect(err).ToNot(HaveOccurred())
					rrDataplane.ResetDeltas()
					err = wg.Apply()
					Expect(err).ToNot(HaveOccurred())
					Expect(rrDataplane.AddedRules).To(HaveLen(0))
					Expect(rrDataplane.DeletedRules).To(HaveLen(0))

					wg.QueueResync()
					err = wg.Apply()
					Expect(err).ToNot(HaveOccurred())
					Expect(rrDataplane.DeletedRules).To(HaveLen(0))
					Expect(rrDataplane.AddedRules).To(ConsistOf(*rule))
				})

				It("should not fix a modified rule until resync", func() {
					badrule := netlink.NewRule()
					badrule.Family = netlink.FAMILY_V4
					badrule.Priority = rulePriority + 1
					badrule.Table = tableIndex
					badrule.Mark = 0
					badrule.Mask = firewallMark

					err := rrDataplane.RuleDel(rule)
					Expect(err).ToNot(HaveOccurred())
					err = rrDataplane.RuleAdd(badrule)
					Expect(err).ToNot(HaveOccurred())

					rrDataplane.ResetDeltas()
					err = wg.Apply()
					Expect(err).ToNot(HaveOccurred())
					Expect(rrDataplane.AddedRules).To(HaveLen(0))
					Expect(rrDataplane.DeletedRules).To(HaveLen(0))

					wg.QueueResync()
					err = wg.Apply()
					Expect(err).ToNot(HaveOccurred())
					Expect(rrDataplane.DeletedRules).To(ConsistOf(*badrule))
					Expect(rrDataplane.AddedRules).To(ConsistOf(*rule))
				})
			})

			Describe("create two wireguard nodes with different public keys", func() {
				var key_peer1, key_peer2 wgtypes.Key
				var link *mocknetlink.MockLink
				BeforeEach(func() {
					Expect(s.numStatusCallbacks).To(Equal(1))
					wg.EndpointWireguardUpdate(hostname, s.statusKey, nil)
					key_peer1 = mustGeneratePrivateKey().PublicKey()
					wg.EndpointWireguardUpdate(peer1, key_peer1, nil)
					wg.EndpointUpdate(peer1, ipv4_peer1)
					key_peer2 = mustGeneratePrivateKey().PublicKey()
					wg.EndpointWireguardUpdate(peer2, key_peer2, nil)
					wg.EndpointUpdate(peer2, ipv4_peer2)
					wg.RouteUpdate(hostname, cidr_local)
					err := wg.Apply()
					Expect(err).NotTo(HaveOccurred())
					link = wgDataplane.NameToLink[ifaceName]
					Expect(link).ToNot(BeNil())
					Expect(wgDataplane.WireguardOpen).To(BeTrue())
					Expect(rrDataplane.NetlinkOpen).To(BeTrue())
					Expect(rrDataplane.NumRuleDelCalls).To(Equal(0))
					Expect(rrDataplane.NumRuleAddCalls).To(Equal(1))
				})

				It("should have both nodes configured", func() {
					Expect(link.WireguardPeers).To(HaveLen(2))
					Expect(link.WireguardPeers).To(HaveKey(key_peer1))
					Expect(link.WireguardPeers).To(HaveKey(key_peer2))
					Expect(link.WireguardPeers[key_peer1]).To(Equal(wgtypes.Peer{
						PublicKey: key_peer1,
						Endpoint: &net.UDPAddr{
							IP:   ipv4_peer1.AsNetIP(),
							Port: 1000,
						},
					}))
					Expect(link.WireguardPeers[key_peer2]).To(Equal(wgtypes.Peer{
						PublicKey: key_peer2,
						Endpoint: &net.UDPAddr{
							IP:   ipv4_peer2.AsNetIP(),
							Port: 1000,
						},
					}))
				})

				It("should have no updates for local EndpointUpdate and EndpointRemove msgs", func() {
					wgDataplane.ResetDeltas()
					rtDataplane.ResetDeltas()
					wg.EndpointUpdate(hostname, nil)
					err := wg.Apply()
					Expect(err).NotTo(HaveOccurred())
					wg.EndpointRemove(hostname)
					err = wg.Apply()
					Expect(err).NotTo(HaveOccurred())
					Expect(rtDataplane.AddedRouteKeys).To(HaveLen(0))
					Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(0))
					Expect(wgDataplane.WireguardConfigUpdated).To(BeFalse())
				})

				It("should have no updates for backing out an endpoint update", func() {
					wgDataplane.ResetDeltas()
					rtDataplane.ResetDeltas()
					wg.EndpointUpdate(peer1, ipv4_peer2)
					wg.EndpointUpdate(peer1, ipv4_peer1)
					err := wg.Apply()
					Expect(err).NotTo(HaveOccurred())
					Expect(wgDataplane.WireguardConfigUpdated).To(BeFalse())
				})

				It("should have no updates for backing out a peer key update", func() {
					wgDataplane.ResetDeltas()
					rtDataplane.ResetDeltas()
					wg.EndpointWireguardUpdate(peer1, key_peer2, nil)
					wg.EndpointWireguardUpdate(peer1, key_peer1, nil)
					err := wg.Apply()
					Expect(err).NotTo(HaveOccurred())
					Expect(wgDataplane.WireguardConfigUpdated).To(BeFalse())
				})

				It("should have no updates if adding and deleting peer config before applying", func() {
					wgDataplane.ResetDeltas()
					rtDataplane.ResetDeltas()
					wg.EndpointUpdate(peer3, ipv4_peer3)
					wg.EndpointWireguardUpdate(peer3, key_peer1, nil)
					wg.EndpointRemove(peer3)
					wg.EndpointWireguardRemove(peer3)
					err := wg.Apply()
					Expect(err).NotTo(HaveOccurred())
					Expect(rtDataplane.AddedRouteKeys).To(HaveLen(0))
					Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(0))
					Expect(wgDataplane.WireguardConfigUpdated).To(BeFalse())
				})

				It("should trigger another status message if deleting the local Wireguard config", func() {
					wgDataplane.ResetDeltas()
					rtDataplane.ResetDeltas()
					Expect(s.numStatusCallbacks).To(Equal(1))
					wg.EndpointWireguardRemove(hostname)
					err := wg.Apply()
					Expect(err).NotTo(HaveOccurred())
					Expect(s.numStatusCallbacks).To(Equal(2))
				})

				It("should contain a throw route for the local CIDR", func() {
					Expect(rtDataplane.AddedRouteKeys).To(HaveLen(1))
					Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_cidr_local))
					Expect(rtDataplane.AddedRouteKeys).To(HaveLen(1))
					Expect(rtDataplane.DeletedRouteKeys).To(BeEmpty())
				})

				Describe("add local workload as a single IP", func() {
					BeforeEach(func() {
						// Update the routetable dataplane so it knows about the interface.
						rtDataplane.NameToLink[ifaceName] = link

						wgDataplane.ResetDeltas()
						rtDataplane.ResetDeltas()
						wg.RouteUpdate(hostname, cidr_6)
						err := wg.Apply()
						Expect(err).NotTo(HaveOccurred())
					})

					It("should have a throw route to the local IP", func() {
						Expect(rtDataplane.AddedRouteKeys).To(HaveLen(1))
						Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(0))
						Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_6))
					})

					It("should handle the IP being deleted and then moved to another node", func() {
						wgDataplane.ResetDeltas()
						rtDataplane.ResetDeltas()

						wg.RouteRemove(cidr_6)
						wg.RouteUpdate(peer1, cidr_6)
						err := wg.Apply()
						Expect(err).NotTo(HaveOccurred())

						Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(1))
						Expect(rtDataplane.DeletedRouteKeys).To(HaveKey(routekey_6))
						Expect(rtDataplane.AddedRouteKeys).To(HaveLen(1))
						Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_6))
					})

					It("should handle the IP being moved to another node without first deleting", func() {
						wgDataplane.ResetDeltas()
						rtDataplane.ResetDeltas()

						wg.RouteUpdate(peer1, cidr_6)
						err := wg.Apply()
						Expect(err).NotTo(HaveOccurred())

						Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(1))
						Expect(rtDataplane.DeletedRouteKeys).To(HaveKey(routekey_6))
						Expect(rtDataplane.AddedRouteKeys).To(HaveLen(1))
						Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_6))
					})

					It("should handle the IP being moved to another node with a deletion in between", func() {
						wgDataplane.ResetDeltas()
						rtDataplane.ResetDeltas()

						wg.RouteUpdate(peer1, cidr_6)
						wg.RouteRemove(cidr_6)
						wg.RouteUpdate(peer1, cidr_6)
						err := wg.Apply()
						Expect(err).NotTo(HaveOccurred())

						Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(1))
						Expect(rtDataplane.DeletedRouteKeys).To(HaveKey(routekey_6))
						Expect(rtDataplane.AddedRouteKeys).To(HaveLen(1))
						Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_6))
					})
				})

				Describe("public key updated to conflict on two nodes", func() {
					var wgPeers map[wgtypes.Key]wgtypes.Peer

					BeforeEach(func() {
						link = wgDataplane.NameToLink[ifaceName]

						// Take a copy of the current peer configuration for one of the tests.
						wgPeers = make(map[wgtypes.Key]wgtypes.Peer)
						for k, p := range link.WireguardPeers {
							wgPeers[k] = p
						}

						wg.EndpointWireguardUpdate(peer2, key_peer1, nil)
						rtDataplane.ResetDeltas()
						err := wg.Apply()
						Expect(err).NotTo(HaveOccurred())
					})

					It("should remove both nodes", func() {
						Expect(link.WireguardPeers).To(HaveLen(0))
					})

					It("should handle a resync if the peer is added back in out-of-band", func() {
						link.WireguardPeers = wgPeers
						link.WireguardListenPort = listeningPort + 1
						link.WireguardFirewallMark = firewallMark + 1
						link.LinkAttrs.MTU = mtu + 1
						wg.QueueResync()
						err := wg.Apply()
						Expect(err).NotTo(HaveOccurred())

						Expect(link.WireguardListenPort).To(Equal(listeningPort))
						Expect(link.WireguardFirewallMark).To(Equal(firewallMark))
						Expect(link.WireguardPeers).To(HaveLen(0))
					})

					It("should add both nodes when conflicting public keys updated to no longer conflict", func() {
						wg.EndpointWireguardUpdate(peer2, key_peer2, nil)
						err := wg.Apply()
						Expect(err).NotTo(HaveOccurred())
						Expect(link.WireguardPeers).To(HaveKey(key_peer1))
						Expect(link.WireguardPeers).To(HaveKey(key_peer2))
						Expect(link.WireguardPeers[key_peer1]).To(Equal(wgtypes.Peer{
							PublicKey: key_peer1,
							Endpoint: &net.UDPAddr{
								IP:   ipv4_peer1.AsNetIP(),
								Port: 1000,
							},
						}))
						Expect(link.WireguardPeers[key_peer2]).To(Equal(wgtypes.Peer{
							PublicKey: key_peer2,
							Endpoint: &net.UDPAddr{
								IP:   ipv4_peer2.AsNetIP(),
								Port: 1000,
							},
						}))
					})

					It("should contain no more route updates", func() {
						Expect(rtDataplane.AddedRouteKeys).To(BeEmpty())
						Expect(rtDataplane.DeletedRouteKeys).To(BeEmpty())
					})
				})

				Describe("create a non-wireguard peer", func() {
					BeforeEach(func() {
						wg.EndpointUpdate(peer3, ipv4_peer3)
						rtDataplane.ResetDeltas()
						err := wg.Apply()
						Expect(err).NotTo(HaveOccurred())
					})

					It("should not create wireguard configuration for the peer", func() {
						Expect(link.WireguardPeers).To(HaveLen(2))
						Expect(link.WireguardPeers).To(HaveKey(key_peer1))
						Expect(link.WireguardPeers).To(HaveKey(key_peer2))
					})

					It("should contain no more route updates", func() {
						Expect(rtDataplane.AddedRouteKeys).To(BeEmpty())
						Expect(rtDataplane.DeletedRouteKeys).To(BeEmpty())
					})

					Describe("create destinations on each peer", func() {
						var routekey_1, routekey_2, routekey_3 string
						BeforeEach(func() {
							// Update the mock routing table dataplane so that it knows about the wireguard interface.
							rtDataplane.NameToLink[ifaceName] = link
							routekey_1 = fmt.Sprintf("%d-%s", tableIndex, cidr_1)
							routekey_2 = fmt.Sprintf("%d-%s", tableIndex, cidr_2)
							routekey_3 = fmt.Sprintf("%d-%s", tableIndex, cidr_3)

							wg.RouteUpdate(hostname, cidr_local)
							wg.RouteUpdate(peer1, cidr_1)
							wg.RouteUpdate(peer1, cidr_2)
							wg.RouteUpdate(peer2, cidr_3)
							wg.RouteUpdate(peer3, cidr_4)
							err := wg.Apply()
							Expect(err).NotTo(HaveOccurred())
						})

						It("should have wireguard routes for peer1 and peer2", func() {
							Expect(link.WireguardPeers).To(HaveKey(key_peer1))
							Expect(link.WireguardPeers).To(HaveKey(key_peer2))
							Expect(link.WireguardPeers[key_peer1]).To(Equal(wgtypes.Peer{
								PublicKey: key_peer1,
								Endpoint: &net.UDPAddr{
									IP:   ipv4_peer1.AsNetIP(),
									Port: 1000,
								},
								AllowedIPs: []net.IPNet{ipnet_1, ipnet_2},
							}))
							Expect(link.WireguardPeers[key_peer2]).To(Equal(wgtypes.Peer{
								PublicKey: key_peer2,
								Endpoint: &net.UDPAddr{
									IP:   ipv4_peer2.AsNetIP(),
									Port: 1000,
								},
								AllowedIPs: []net.IPNet{ipnet_3},
							}))
						})

						It("should route to wireguard for peer1 and peer2 routes, but not peer3 routes", func() {
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(4))
							Expect(rtDataplane.DeletedRouteKeys).To(BeEmpty())
							Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_1))
							Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_2))
							Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_3))
							Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_4))
							Expect(rtDataplane.RouteKeyToRoute[routekey_1]).To(Equal(netlink.Route{
								LinkIndex: link.LinkAttrs.Index,
								Dst:       &ipnet_1,
								Type:      syscall.RTN_UNICAST,
								Protocol:  FelixRouteProtocol,
								Scope:     netlink.SCOPE_LINK,
								Table:     tableIndex,
							}))
							Expect(rtDataplane.RouteKeyToRoute[routekey_2]).To(Equal(netlink.Route{
								LinkIndex: link.LinkAttrs.Index,
								Dst:       &ipnet_2,
								Type:      syscall.RTN_UNICAST,
								Protocol:  FelixRouteProtocol,
								Scope:     netlink.SCOPE_LINK,
								Table:     tableIndex,
							}))
							Expect(rtDataplane.RouteKeyToRoute[routekey_3]).To(Equal(netlink.Route{
								LinkIndex: link.LinkAttrs.Index,
								Dst:       &ipnet_3,
								Type:      syscall.RTN_UNICAST,
								Protocol:  FelixRouteProtocol,
								Scope:     netlink.SCOPE_LINK,
								Table:     tableIndex,
							}))
							Expect(rtDataplane.RouteKeyToRoute[routekey_4]).To(Equal(netlink.Route{
								Dst:      &ipnet_4,
								Type:     syscall.RTN_THROW,
								Protocol: FelixRouteProtocol,
								Scope:    netlink.SCOPE_UNIVERSE,
								Table:    tableIndex,
							}))
						})

						It("should remove a route from the peer", func() {
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()
							wg.RouteRemove(cidr_1)
							err := wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(0))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(1))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveKey(routekey_1))
							Expect(wgDataplane.WireguardConfigUpdated).To(BeTrue())
							Expect(link.WireguardPeers).To(HaveKey(key_peer1))
							Expect(link.WireguardPeers[key_peer1]).To(Equal(wgtypes.Peer{
								PublicKey: key_peer1,
								Endpoint: &net.UDPAddr{
									IP:   ipv4_peer1.AsNetIP(),
									Port: 1000,
								},
								AllowedIPs: []net.IPNet{ipnet_2},
							}))
						})

						It("should have no updates if swapping routes and swapping back before an apply", func() {
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()
							wg.RouteUpdate(peer1, cidr_3)
							wg.RouteUpdate(peer2, cidr_1)
							wg.RouteUpdate(peer1, cidr_1)
							wg.RouteUpdate(peer2, cidr_3)
							err := wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(0))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(0))
							Expect(wgDataplane.WireguardConfigUpdated).To(BeFalse())
						})

						It("should have no updates if adding and deleting a CIDR to a peer", func() {
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()
							wg.RouteUpdate(peer1, cidr_5)
							wg.RouteRemove(cidr_5)
							err := wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(0))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(0))
							Expect(wgDataplane.WireguardConfigUpdated).To(BeFalse())
						})

						It("should have no updates if deleting an unknown CIDR", func() {
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()
							wg.RouteRemove(cidr_5)
							err := wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(0))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(0))
							Expect(wgDataplane.WireguardConfigUpdated).To(BeFalse())
						})

						It("should handle deletion of nodes 2 and 3", func() {
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()
							wg.EndpointRemove(peer3)
							wg.EndpointWireguardRemove(peer3)
							wg.RouteRemove(cidr_4)
							wg.RouteRemove(cidr_3)
							wg.EndpointWireguardRemove(peer2)
							wg.EndpointRemove(peer2)
							err := wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(0))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(2))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveKey(routekey_4))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveKey(routekey_3))
							Expect(wgDataplane.WireguardConfigUpdated).To(BeTrue())
							Expect(link.WireguardPeers).To(HaveLen(1))
							Expect(link.WireguardPeers).To(HaveKey(key_peer1))
						})

						It("should handle deletion of a wireguard peer over multiple applies: endpoint, wireguard, route", func() {
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()

							// Remove the endpoint. Wireguard config should be removed at this point. The route should
							// be converted to a throw route.
							By("Removing the node")
							wg.EndpointRemove(peer2)
							err := wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(wg.DebugNodes()).To(HaveLen(4))
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(1))
							Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_3))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(1))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveKey(routekey_3))
							Expect(wgDataplane.WireguardConfigUpdated).To(BeTrue())
							Expect(link.WireguardPeers).To(HaveLen(1))
							Expect(link.WireguardPeers).To(HaveKey(key_peer1))
							Expect(rtDataplane.RouteKeyToRoute[routekey_3]).To(Equal(netlink.Route{
								Dst:      &ipnet_3,
								Type:     syscall.RTN_THROW,
								Protocol: FelixRouteProtocol,
								Scope:    netlink.SCOPE_UNIVERSE,
								Table:    tableIndex,
							}))

							// Remove the wireguard config for this peer. Should have no further impact.
							By("Removing the wireguard configuration")
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()
							wg.EndpointWireguardRemove(peer2)
							err = wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(wg.DebugNodes()).To(HaveLen(4))
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(0))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(0))
							Expect(wgDataplane.WireguardConfigUpdated).To(BeFalse())
							Expect(link.WireguardPeers).To(HaveLen(1))

							// Remove the route.
							// This is the last bit of configuration for the peer and so the node should be removed
							// from the cache.
							By("Removing the route")
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()
							wg.RouteRemove(cidr_3)
							err = wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(wg.DebugNodes()).To(HaveLen(3))
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(0))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(1))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveKey(routekey_3))
							Expect(link.WireguardPeers).To(HaveLen(1))
						})

						It("should handle deletion of a wireguard peer over multiple applies: route, endpoint, wireguard", func() {
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()

							// Remove the route.
							By("Removing the route")
							wg.RouteRemove(cidr_3)
							err := wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(wg.DebugNodes()).To(HaveLen(4))
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(0))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(1))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveKey(routekey_3))
							Expect(rtDataplane.RouteKeyToRoute).ToNot(HaveKey(routekey_3))
							Expect(wgDataplane.WireguardConfigUpdated).To(BeTrue())
							Expect(link.WireguardPeers).To(HaveLen(2))

							// Remove the endpoint. Wireguard config should be removed at this point. The route should
							// be converted to a throw route.
							By("Removing the node")
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()
							wg.EndpointRemove(peer2)
							err = wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(wg.DebugNodes()).To(HaveLen(4))
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(0))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(0))
							Expect(wgDataplane.WireguardConfigUpdated).To(BeTrue())
							Expect(link.WireguardPeers).To(HaveLen(1))
							Expect(link.WireguardPeers).To(HaveKey(key_peer1))

							// Remove the wireguard config for this peer.
							// This is the last bit of configuration for the peer and so the node should be removed
							// from the cache.
							By("Removing the wireguard configuration")
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()
							wg.EndpointWireguardRemove(peer2)
							err = wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(wg.DebugNodes()).To(HaveLen(3))
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(0))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(0))
							Expect(wgDataplane.WireguardConfigUpdated).To(BeFalse())
							Expect(link.WireguardPeers).To(HaveLen(1))
						})

						It("should handle deletion of a wireguard peer over multiple applies: route, endpoint, wireguard", func() {
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()

							// Remove the wireguard config for this peer. Wireguard config should be removed at this
							// point. The route should be converted to a throw route.
							By("Removing the wireguard configuration")
							wg.EndpointWireguardRemove(peer2)
							err := wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(wg.DebugNodes()).To(HaveLen(4))
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(1))
							Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_3))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(1))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveKey(routekey_3))
							Expect(wgDataplane.WireguardConfigUpdated).To(BeTrue())
							Expect(rtDataplane.RouteKeyToRoute[routekey_3]).To(Equal(netlink.Route{
								Dst:      &ipnet_3,
								Type:     syscall.RTN_THROW,
								Protocol: FelixRouteProtocol,
								Scope:    netlink.SCOPE_UNIVERSE,
								Table:    tableIndex,
							}))
							Expect(link.WireguardPeers).To(HaveLen(1))
							Expect(link.WireguardPeers).To(HaveKey(key_peer1))

							// Remove the route.
							By("Removing the route")
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()
							wg.RouteRemove(cidr_3)
							err = wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(wg.DebugNodes()).To(HaveLen(4))
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(0))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(1))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveKey(routekey_3))
							Expect(rtDataplane.RouteKeyToRoute).ToNot(HaveKey(routekey_3))
							Expect(wgDataplane.WireguardConfigUpdated).To(BeFalse())
							Expect(link.WireguardPeers).To(HaveLen(1))

							// Remove the endpoint.
							// This is the last bit of configuration for the peer and so the node should be removed
							// from the cache.
							By("Removing the node")
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()
							wg.EndpointRemove(peer2)
							err = wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(wg.DebugNodes()).To(HaveLen(3))
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(0))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(0))
							Expect(wgDataplane.WireguardConfigUpdated).To(BeFalse())
							Expect(link.WireguardPeers).To(HaveLen(1))
						})

						It("should handle deletion and re-adding an endpoint over multiple applies", func() {
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()

							// Remove the endpoint. Wireguard config should be removed at this point. The route should
							// be converted to a throw route.
							By("Removing the node")
							wg.EndpointRemove(peer2)
							err := wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(wg.DebugNodes()).To(HaveLen(4))
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(1))
							Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_3))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(1))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveKey(routekey_3))
							Expect(wgDataplane.WireguardConfigUpdated).To(BeTrue())
							Expect(link.WireguardPeers).To(HaveLen(1))
							Expect(link.WireguardPeers).To(HaveKey(key_peer1))
							Expect(rtDataplane.RouteKeyToRoute[routekey_3]).To(Equal(netlink.Route{
								Dst:      &ipnet_3,
								Type:     syscall.RTN_THROW,
								Protocol: FelixRouteProtocol,
								Scope:    netlink.SCOPE_UNIVERSE,
								Table:    tableIndex,
							}))

							// Re-add the endpoint. Wireguard config will be added back in.
							By("Re-adding the node")
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()
							wg.EndpointUpdate(peer2, ipv4_peer2)
							err = wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(wg.DebugNodes()).To(HaveLen(4))
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(1))
							Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_3))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(1))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveKey(routekey_3))
							Expect(wgDataplane.WireguardConfigUpdated).To(BeTrue())
							Expect(link.WireguardPeers).To(HaveLen(2))
							Expect(link.WireguardPeers).To(HaveKey(key_peer1))
							Expect(link.WireguardPeers).To(HaveKey(key_peer2))
							Expect(rtDataplane.RouteKeyToRoute[routekey_3]).To(Equal(netlink.Route{
								LinkIndex: link.LinkAttrs.Index,
								Dst:       &ipnet_3,
								Type:      syscall.RTN_UNICAST,
								Protocol:  FelixRouteProtocol,
								Scope:     netlink.SCOPE_LINK,
								Table:     tableIndex,
							}))
						})

						It("should handle deletion and re-adding an endpoint in a single apply", func() {
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()

							// Remove the endpoint. Wireguard config should be removed at this point. The route should
							// be converted to a throw route.
							By("Removing the node")
							wg.EndpointRemove(peer2)
							wg.EndpointUpdate(peer2, ipv4_peer2)
							err := wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(wg.DebugNodes()).To(HaveLen(4))
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(0))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(0))
							Expect(wgDataplane.WireguardConfigUpdated).To(BeFalse())
							Expect(link.WireguardPeers).To(HaveLen(2))
							Expect(link.WireguardPeers).To(HaveKey(key_peer1))
							Expect(link.WireguardPeers).To(HaveKey(key_peer2))
						})

						It("should handle deletion and re-adding an endpoint with a different IP in a single apply", func() {
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()

							// Remove the endpoint. Wireguard config should be removed at this point. The route should
							// be converted to a throw route.
							By("Removing the node")
							wg.EndpointRemove(peer2)
							wg.EndpointUpdate(peer2, ipv4_peer2_2)
							err := wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(wg.DebugNodes()).To(HaveLen(4))
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(0))
							Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(0))
							Expect(wgDataplane.WireguardConfigUpdated).To(BeTrue())
							Expect(link.WireguardPeers).To(HaveLen(2))
							Expect(link.WireguardPeers).To(HaveKey(key_peer1))
							Expect(link.WireguardPeers).To(HaveKey(key_peer2))
							Expect(link.WireguardPeers[key_peer2].Endpoint.IP).To(Equal(ipv4_peer2_2.AsNetIP()))
						})

						It("should handle immediate and subsequent reuse after a node deletion", func() {
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()
							wg.EndpointRemove(peer2)
							wg.EndpointWireguardRemove(peer2)
							wg.RouteRemove(cidr_3)
							wg.RouteUpdate(hostname, cidr_3)
							By("Applying deletion and IP moving to local host")
							err := wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(rtDataplane.DeletedRouteKeys).To(HaveKey(routekey_3))
							Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_3))
							Expect(rtDataplane.RouteKeyToRoute[routekey_3]).To(Equal(netlink.Route{
								Dst:      &ipnet_3,
								Type:     syscall.RTN_THROW,
								Protocol: FelixRouteProtocol,
								Scope:    netlink.SCOPE_UNIVERSE,
								Table:    tableIndex,
							}))

							By("Deleting local route")
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()
							wg.RouteRemove(cidr_3)
							err = wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(1))
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(0))
							Expect(rtDataplane.RouteKeyToRoute).NotTo(HaveKey(routekey_3))

							By("Applying the same route to be remote")
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()
							wg.RouteUpdate(peer1, cidr_3)
							err = wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(0))
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(1))
							Expect(rtDataplane.RouteKeyToRoute[routekey_3]).To(Equal(netlink.Route{
								LinkIndex: link.LinkAttrs.Index,
								Dst:       &ipnet_3,
								Type:      syscall.RTN_UNICAST,
								Protocol:  FelixRouteProtocol,
								Scope:     netlink.SCOPE_LINK,
								Table:     tableIndex,
							}))
						})

						Describe("move a route from peer1 to peer2 and a route from peer2 to peer3", func() {
							BeforeEach(func() {
								wg.RouteRemove(cidr_2)
								wg.RouteUpdate(peer2, cidr_2)
								wg.RouteUpdate(peer3, cidr_3)
								rtDataplane.ResetDeltas()
								err := wg.Apply()
								Expect(err).NotTo(HaveOccurred())
							})

							It("should have wireguard routes for peer1 and peer2", func() {
								Expect(link.WireguardPeers).To(HaveKey(key_peer1))
								Expect(link.WireguardPeers).To(HaveKey(key_peer2))
								Expect(link.WireguardPeers[key_peer1]).To(Equal(wgtypes.Peer{
									PublicKey: key_peer1,
									Endpoint: &net.UDPAddr{
										IP:   ipv4_peer1.AsNetIP(),
										Port: 1000,
									},
									AllowedIPs: []net.IPNet{ipnet_1},
								}))
								Expect(link.WireguardPeers[key_peer2]).To(Equal(wgtypes.Peer{
									PublicKey: key_peer2,
									Endpoint: &net.UDPAddr{
										IP:   ipv4_peer2.AsNetIP(),
										Port: 1000,
									},
									AllowedIPs: []net.IPNet{ipnet_2},
								}))
							})

							It("should reprogram the route to the non-wireguard peer only", func() {
								Expect(rtDataplane.AddedRouteKeys).To(HaveLen(1))
								Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(1))
								Expect(rtDataplane.DeletedRouteKeys).To(HaveKey(routekey_3))
								Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_3))
								Expect(rtDataplane.RouteKeyToRoute[routekey_3]).To(Equal(netlink.Route{
									Dst:      &ipnet_3,
									Type:     syscall.RTN_THROW,
									Protocol: FelixRouteProtocol,
									Scope:    netlink.SCOPE_UNIVERSE,
									Table:    tableIndex,
								}))
							})
						})

						Describe("enable wireguard on peer 3", func() {
							var key_peer3 wgtypes.Key
							BeforeEach(func() {
								key_peer3 = mustGeneratePrivateKey()
								wg.EndpointWireguardUpdate(peer3, key_peer3, nil)
								rtDataplane.ResetDeltas()
								err := wg.Apply()
								Expect(err).NotTo(HaveOccurred())
							})

							It("should have wireguard routes for all nodes", func() {
								Expect(link.WireguardPeers).To(HaveKey(key_peer1))
								Expect(link.WireguardPeers).To(HaveKey(key_peer2))
								Expect(link.WireguardPeers).To(HaveKey(key_peer3))
								Expect(link.WireguardPeers[key_peer1]).To(Equal(wgtypes.Peer{
									PublicKey: key_peer1,
									Endpoint: &net.UDPAddr{
										IP:   ipv4_peer1.AsNetIP(),
										Port: 1000,
									},
									AllowedIPs: []net.IPNet{ipnet_1, ipnet_2},
								}))
								Expect(link.WireguardPeers[key_peer2]).To(Equal(wgtypes.Peer{
									PublicKey: key_peer2,
									Endpoint: &net.UDPAddr{
										IP:   ipv4_peer2.AsNetIP(),
										Port: 1000,
									},
									AllowedIPs: []net.IPNet{ipnet_3},
								}))
								Expect(link.WireguardPeers[key_peer3]).To(Equal(wgtypes.Peer{
									PublicKey: key_peer3,
									Endpoint: &net.UDPAddr{
										IP:   ipv4_peer3.AsNetIP(),
										Port: 1000,
									},
									AllowedIPs: []net.IPNet{ipnet_4},
								}))
							})

							It("should reprogram the route to peer3 only", func() {
								routekey_4 := fmt.Sprintf("%d-%s", tableIndex, cidr_4)
								Expect(rtDataplane.AddedRouteKeys).To(HaveLen(1))
								Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(1))
								Expect(rtDataplane.DeletedRouteKeys).To(HaveKey(routekey_4))
								Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_4))
								Expect(rtDataplane.RouteKeyToRoute[routekey_4]).To(Equal(netlink.Route{
									LinkIndex: link.LinkAttrs.Index,
									Dst:       &ipnet_4,
									Type:      syscall.RTN_UNICAST,
									Protocol:  FelixRouteProtocol,
									Scope:     netlink.SCOPE_LINK,
									Table:     tableIndex,
								}))
							})
						})
					})
				})
			})
		})
	})

	It("should create wireguard client if link activates immediately", func() {
		wgDataplane.ImmediateLinkUp = true
		err := wg.Apply()
		Expect(err).NotTo(HaveOccurred())
		Expect(wgDataplane.NumLinkAddCalls).To(Equal(1))
		Expect(wgDataplane.WireguardOpen).To(BeTrue())
	})

	It("should create wireguard client and not attempt to create the link if link is already up", func() {
		wgDataplane.AddIface(10, ifaceName, true, true)
		err := wg.Apply()
		Expect(err).NotTo(HaveOccurred())
		Expect(wgDataplane.NumLinkAddCalls).To(Equal(0))
		Expect(wgDataplane.WireguardOpen).To(BeTrue())
	})

	It("should update listen port and firewall mark but maintain correct key", func() {
		key, err := wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		wgDataplane.AddIface(10, ifaceName, true, true)
		link := wgDataplane.NameToLink[ifaceName]
		Expect(link).ToNot(BeNil())
		link.WireguardPrivateKey = key
		link.WireguardPublicKey = key.PublicKey()
		link.WireguardListenPort = 1010
		link.WireguardFirewallMark = 11

		ipv4 := ip.FromString("1.2.3.4")
		wg.EndpointWireguardUpdate(hostname, key, ipv4)

		err = wg.Apply()
		Expect(err).NotTo(HaveOccurred())
		Expect(wgDataplane.NumLinkAddCalls).To(Equal(0))
		Expect(wgDataplane.WireguardOpen).To(BeTrue())

		link = wgDataplane.NameToLink[ifaceName]
		Expect(link).ToNot(BeNil())
		Expect(link.Addrs).To(HaveLen(1))
		Expect(link.Addrs[0].IP).To(Equal(ipv4.AsNetIP()))
		Expect(wgDataplane.WireguardOpen).To(BeTrue())
		Expect(link.WireguardFirewallMark).To(Equal(10))
		Expect(link.WireguardListenPort).To(Equal(1000))
		Expect(link.WireguardPrivateKey).To(Equal(key))
		Expect(link.WireguardPrivateKey.PublicKey()).To(Equal(link.WireguardPublicKey))
		Expect(s.numStatusCallbacks).To(Equal(1))
	})

	Describe("wireguard initially not supported", func() {
		BeforeEach(func() {
			// Set the fail flags.
			wgDataplane.FailuresToSimulate = mocknetlink.FailNextLinkAddNotSupported

			// Set the wireguard interface ip address
			wg.EndpointWireguardUpdate(hostname, zeroKey, ipv4_peer1)

			// No error should occur
			err := wg.Apply()
			Expect(err).NotTo(HaveOccurred())
		})

		It("should not create the wireguard interface", func() {
			link := wgDataplane.NameToLink[ifaceName]
			Expect(link).To(BeNil())
		})

		It("should not create the wireguard interface after another apply", func() {
			err := wg.Apply()
			Expect(err).NotTo(HaveOccurred())
			link := wgDataplane.NameToLink[ifaceName]
			Expect(link).To(BeNil())
		})

		It("should create the wireguard interface after a resync", func() {
			wg.QueueResync()
			err := wg.Apply()
			Expect(err).NotTo(HaveOccurred())
			link := wgDataplane.NameToLink[ifaceName]
			Expect(link).ToNot(BeNil())
		})
	})

	for _, testFailFlags := range []mocknetlink.FailFlags{
		mocknetlink.FailNextNewNetlink, mocknetlink.FailNextLinkAdd, mocknetlink.FailNextLinkByName,
		mocknetlink.FailNextAddrList, mocknetlink.FailNextAddrAdd, mocknetlink.FailNextAddrDel,
		mocknetlink.FailNextLinkSetUp, mocknetlink.FailNextLinkSetMTU, mocknetlink.FailNextRuleList,
		mocknetlink.FailNextRuleAdd, mocknetlink.FailNextNewWireguard, mocknetlink.FailNextWireguardConfigureDevice,
		mocknetlink.FailNextWireguardDeviceByName,
	} {
		failFlags := testFailFlags
		desc := fmt.Sprintf("multiple nodes with routes and failed link management (%v)", failFlags)

		Describe(desc, func() {
			var key_peer1, key_peer2 wgtypes.Key
			var routekey_1, routekey_2, routekey_3 string
			var link *mocknetlink.MockLink

			BeforeEach(func() {
				// Set the fail flags and reset errors.|
				Expect(wgDataplane.FailuresToSimulate).To(Equal(mocknetlink.FailNone))
				Expect(rrDataplane.FailuresToSimulate).To(Equal(mocknetlink.FailNone))
				Expect(rtDataplane.FailuresToSimulate).To(Equal(mocknetlink.FailNone))
				if failFlags&(mocknetlink.FailNextRuleList|mocknetlink.FailNextRuleAdd) != 0 {
					rrDataplane.FailuresToSimulate = failFlags
				} else {
					wgDataplane.FailuresToSimulate = failFlags
				}
				wgDataplane.ResetDeltas()
				rtDataplane.ResetDeltas()
				rrDataplane.ResetDeltas()

				// Expect exactly one error from the series of applies.
				apply := newApplyWithErrors(wg, 1)

				// Set the wireguard interface ip address
				wg.EndpointWireguardUpdate(hostname, zeroKey, ipv4_int1)
				err := apply.Apply()
				Expect(err).NotTo(HaveOccurred())

				// We expect the link to exist.
				link = wgDataplane.NameToLink[ifaceName]
				Expect(link).ToNot(BeNil())
				routekey_1 = fmt.Sprintf("%d-%s", tableIndex, cidr_1)
				routekey_2 = fmt.Sprintf("%d-%s", tableIndex, cidr_2)
				routekey_3 = fmt.Sprintf("%d-%s", tableIndex, cidr_3)

				// Set the interface to be up
				wgDataplane.SetIface(ifaceName, true, true)
				rtDataplane.AddIface(link.LinkAttrs.Index, ifaceName, true, true)
				wg.OnIfaceStateChanged(ifaceName, ifacemonitor.StateUp)
				err = apply.Apply()
				Expect(err).NotTo(HaveOccurred())

				// Change the wireguard interface ip address
				wg.EndpointWireguardUpdate(hostname, zeroKey, ipv4_int2)

				// Add a single wireguard peer with a single route
				key_peer1 = mustGeneratePrivateKey()
				wg.EndpointWireguardUpdate(peer1, key_peer1, nil)
				wg.EndpointUpdate(peer1, ipv4_peer1)
				wg.RouteUpdate(peer1, cidr_1)
				wg.RouteUpdate(peer1, cidr_2)

				// Add a single local workload CIDR to ensure we add a route rule.
				wg.RouteUpdate(hostname, cidr_local)

				// Apply - a single error should have been observed across all of the Applies.
				err = apply.Apply()
				Expect(wgDataplane.FailuresToSimulate).To(Equal(mocknetlink.FailNone))
				Expect(rtDataplane.FailuresToSimulate).To(Equal(mocknetlink.FailNone))
				Expect(err).NotTo(HaveOccurred())
				Expect(apply.LastError()).To(HaveOccurred())
			})

			It("should correctly program the dataplane after a single failure", func() {
				Expect(link.LinkType).To(Equal("wireguard"))
				Expect(link.LinkAttrs.MTU).To(Equal(2000))
				Expect(link.Addrs).To(HaveLen(1))
				Expect(link.Addrs[0].IP).To(Equal(ipv4_int2.AsNetIP()))

				Expect(link.WireguardPeers).To(HaveLen(1))
				Expect(link.WireguardPeers).To(HaveKey(key_peer1))
				Expect(link.WireguardPeers[key_peer1].AllowedIPs).To(ConsistOf(cidr_1.ToIPNet(), cidr_2.ToIPNet()))

				Expect(rtDataplane.AddedRouteKeys).To(HaveLen(3))
				Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(0))
				Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_1))
				Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_2))
				Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_cidr_local))

				// All of these failures will trigger an attempt to get a either a new netlink or wireguard client.
				if failFlags&(mocknetlink.FailNextNewWireguard|mocknetlink.FailNextWireguardConfigureDevice|mocknetlink.FailNextWireguardDeviceByName) != 0 {
					Expect(wgDataplane.NumNewWireguardCalls).To(Equal(2))
				} else if failFlags&(mocknetlink.FailNextRuleList|mocknetlink.FailNextRuleAdd) != 0 {
					Expect(rrDataplane.NumNewNetlinkCalls).To(Equal(2))
				} else {
					Expect(wgDataplane.NumNewNetlinkCalls).To(Equal(2))
				}
			})

			for _, nextTestFailFlags := range []mocknetlink.FailFlags{
				mocknetlink.FailNextWireguardConfigureDevice, mocknetlink.FailNextRouteAdd, mocknetlink.FailNextRouteDel,
			} {
				failFlags := nextTestFailFlags
				desc := fmt.Sprintf("additional adds/deletes with another failure (%v)", failFlags)

				Describe(desc, func() {
					BeforeEach(func() {
						// Set the fail flags and reset errors.
						if failFlags&mocknetlink.FailNextWireguardConfigureDevice != 0 {
							wgDataplane.FailuresToSimulate = failFlags
						} else {
							rtDataplane.FailuresToSimulate = failFlags
							rtDataplane.PersistFailures = true
						}
						wgDataplane.ResetDeltas()
						rtDataplane.ResetDeltas()

						// Delete peer1
						wg.EndpointWireguardRemove(peer1)
						wg.EndpointRemove(peer1)
						wg.RouteRemove(cidr_1)
						wg.RouteRemove(cidr_2)

						// Add peer2 with one of the same CIDRs as the previous peer1, and one different CIDR
						key_peer2 = mustGeneratePrivateKey()
						wg.EndpointWireguardUpdate(peer2, key_peer2, nil)
						wg.EndpointUpdate(peer2, ipv4_peer2)
						wg.RouteUpdate(peer2, cidr_1)
						wg.RouteUpdate(peer2, cidr_3)

						// Apply.
						err := wg.Apply()
						Expect(err).To(HaveOccurred())
						rtDataplane.PersistFailures = false

						err = wg.Apply()
						Expect(err).ToNot(HaveOccurred())
					})

					It("should correctly program the dataplane after a second failure", func() {
						Expect(link.WireguardPeers).To(HaveLen(1))
						Expect(link.WireguardPeers).To(HaveKey(key_peer2))
						Expect(link.WireguardPeers[key_peer2].AllowedIPs).To(Equal([]net.IPNet{cidr_1.ToIPNet(), cidr_3.ToIPNet()}))

						Expect(rtDataplane.AddedRouteKeys).To(HaveLen(1))
						Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(1))
						Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_3))
						Expect(rtDataplane.DeletedRouteKeys).To(HaveKey(routekey_2))

						if failFlags&mocknetlink.FailNextWireguardConfigureDevice != 0 {
							Expect(wgDataplane.NumNewWireguardCalls).ToNot(Equal(0))
							Expect(rtDataplane.NumNewNetlinkCalls).To(Equal(0))
						} else {
							Expect(rtDataplane.NumNewNetlinkCalls).ToNot(Equal(0))
							Expect(wgDataplane.NumNewWireguardCalls).To(Equal(0))
						}
					})
				})
			}
		})
	}

	for _, testFailFlags := range []mocknetlink.FailFlags{
		mocknetlink.FailNextLinkAddNotSupported, mocknetlink.FailNextNewWireguardNotSupported,
	} {
		failFlags := testFailFlags
		desc := fmt.Sprintf("multiple nodes with wireguard not supported (%v)", failFlags)

		Describe(desc, func() {

			It("should update on resync", func() {
				// Set the fail flags and set link to automatically come up.
				wgDataplane.FailuresToSimulate = failFlags
				wgDataplane.ImmediateLinkUp = true

				// Set the wireguard interface ip address. No error should occur because "not supported" is perfectly
				// valid.
				wg.EndpointWireguardUpdate(hostname, zeroKey, ipv4_peer1)
				err := wg.Apply()
				Expect(err).NotTo(HaveOccurred())

				// Expect a zero key status update.
				Expect(s.statusKey).To(Equal(zeroKey))
				Expect(s.numStatusCallbacks).To(Equal(1))

				// Always expect to attempt to create the netlink client
				Expect(wgDataplane.NumNewNetlinkCalls).To(Equal(1))
				if failFlags&mocknetlink.FailNextLinkAddNotSupported == 0 {
					// If we are not emulating netlink link-not-supported failure then we should also attempt to create
					// the wireguard client.
					Expect(wgDataplane.NumNewWireguardCalls).To(Equal(1))
				}

				// Should not attempt any further updates
				wgDataplane.ResetDeltas()
				err = wg.Apply()
				Expect(err).NotTo(HaveOccurred())
				Expect(wgDataplane.NumNewNetlinkCalls).To(Equal(0))
				Expect(wgDataplane.NumNewWireguardCalls).To(Equal(0))

				// Queue a resync and re-apply.
				wg.QueueResync()
				err = wg.Apply()
				Expect(err).NotTo(HaveOccurred())

				// Expect an updated public key and the previously failed client to have been re-requested.
				Expect(s.statusKey).NotTo(Equal(zeroKey))
				Expect(s.numStatusCallbacks).To(Equal(2))
				if failFlags&mocknetlink.FailNextNewWireguardNotSupported != 0 {
					// And if emulating the wireguard failure, we expect a call to that too.
					Expect(wgDataplane.NumNewWireguardCalls).To(Equal(1))
				}

				// The previous netlink client is still ok - just wireguard wasn't supported, we should not attempt to
				// recreate the netlink client.
				Expect(wgDataplane.NumNewNetlinkCalls).To(Equal(0))
			})
		})
	}

	for _, port := range []int{listeningPort, listeningPort + 1} {
		configuredPort := port

		desc := fmt.Sprintf("wireguard dataplane needs updating (port=%d)", configuredPort)

		Describe(desc, func() {

			It("should handle a resync", func() {
				key_peer1 := mustGeneratePrivateKey().PublicKey()
				key_peer2 := mustGeneratePrivateKey().PublicKey()
				key_peer3 := mustGeneratePrivateKey().PublicKey()
				key_peer4 := mustGeneratePrivateKey().PublicKey()

				wg.EndpointUpdate(hostname, ipv4_host)
				wg.EndpointUpdate(peer1, ipv4_peer1)
				wg.EndpointUpdate(peer2, ipv4_peer2)
				wg.EndpointUpdate(peer3, ipv4_peer3)
				wg.EndpointUpdate(peer4, ipv4_peer4)
				wg.EndpointWireguardUpdate(peer1, key_peer1, nil)
				wg.EndpointWireguardUpdate(peer2, key_peer2, nil)
				wg.EndpointWireguardUpdate(peer3, key_peer3, nil)
				wg.EndpointWireguardUpdate(peer4, key_peer3, nil) // Peer 3 and 4 declaring same public key
				wg.RouteUpdate(peer1, cidr_1)
				wg.RouteUpdate(peer2, cidr_2)
				wg.RouteUpdate(peer3, cidr_3)
				wg.RouteUpdate(peer4, cidr_4)

				wgDataplane.AddIface(1, ifaceName, true, true)
				link := wgDataplane.NameToLink[ifaceName]
				Expect(link).NotTo(BeNil())
				link.WireguardPeers = map[wgtypes.Key]wgtypes.Peer{
					key_peer1: {
						PublicKey: key_peer1,
						Endpoint: &net.UDPAddr{
							IP:   ipv4_peer1.AsNetIP(),
							Port: configuredPort,
						},
						AllowedIPs: []net.IPNet{}, // Need to add an entry (no deletes)
					},
					key_peer2: {
						PublicKey: key_peer2,
						Endpoint:  nil,
						AllowedIPs: []net.IPNet{
							cidr_2.ToIPNet(),
							cidr_3.ToIPNet(), // Need to delete an entry.
						},
					},
					key_peer3: {
						PublicKey:  key_peer3,
						Endpoint:   &net.UDPAddr{},
						AllowedIPs: []net.IPNet{},
					},
					key_peer4: {
						PublicKey: key_peer4,
						Endpoint:  &net.UDPAddr{},
						AllowedIPs: []net.IPNet{
							cidr_4.ToIPNet(),
						},
					},
				}

				// Apply the update.
				err := wg.Apply()
				Expect(err).NotTo(HaveOccurred())

				// Expect peer1 and peer2 to be updated and peer3 and peer4 to be deleted.
				link = wgDataplane.NameToLink[ifaceName]
				Expect(link).NotTo(BeNil())
				Expect(link.WireguardPeers).To(HaveLen(2))
				Expect(link.WireguardPeers).To(HaveKey(key_peer1))
				Expect(link.WireguardPeers).To(HaveKey(key_peer2))
				Expect(link.WireguardPeers[key_peer1]).To(Equal(wgtypes.Peer{
					PublicKey: key_peer1,
					Endpoint: &net.UDPAddr{
						IP:   ipv4_peer1.AsNetIP(),
						Port: listeningPort,
					},
					AllowedIPs: []net.IPNet{cidr_1.ToIPNet()},
				}))
				Expect(link.WireguardPeers[key_peer2]).To(Equal(wgtypes.Peer{
					PublicKey: key_peer2,
					Endpoint: &net.UDPAddr{
						IP:   ipv4_peer2.AsNetIP(),
						Port: listeningPort,
					},
					AllowedIPs: []net.IPNet{cidr_2.ToIPNet()},
				}))

				// If the listening port was incorrect then we expect that to be included in the updated,
				// otherwise we do not.
				Expect(wgDataplane.LastWireguardUpdates).To(HaveKey(key_peer1))
				if configuredPort == listeningPort {
					Expect(wgDataplane.LastWireguardUpdates[key_peer1].Endpoint).To(BeNil())
				} else {
					Expect(wgDataplane.LastWireguardUpdates[key_peer1].Endpoint).NotTo(BeNil())
				}

				// Expect peer2 update to include the endpoint addr (since this was missing)
				Expect(wgDataplane.LastWireguardUpdates).To(HaveKey(key_peer2))
				Expect(wgDataplane.LastWireguardUpdates[key_peer2].Endpoint).NotTo(BeNil())

				// Expect peer1 to be an update and peer2 to be a full replace of CIDRs.
				Expect(wgDataplane.LastWireguardUpdates[key_peer1].ReplaceAllowedIPs).To(BeFalse())
				Expect(wgDataplane.LastWireguardUpdates[key_peer2].ReplaceAllowedIPs).To(BeTrue())
			})
		})
	}
})

var _ = Describe("Wireguard (disabled)", func() {
	var wgDataplane, rtDataplane, rrDataplane *mocknetlink.MockNetlinkDataplane
	var t *mocktime.MockTime
	var s mockCallbacks
	var wg *Wireguard

	BeforeEach(func() {
		wgDataplane = mocknetlink.New()
		rtDataplane = mocknetlink.New()
		rrDataplane = mocknetlink.New()
		t = mocktime.New()
		// Setting an auto-increment greater than the route cleanup delay effectively
		// disables the grace period for these tests.
		t.SetAutoIncrement(11 * time.Second)

		wg = NewWithShims(
			hostname,
			&Config{
				Enabled:             false,
				ListeningPort:       1000,
				FirewallMark:        1,
				RoutingRulePriority: rulePriority,
				RoutingTableIndex:   tableIndex,
				InterfaceName:       ifaceName,
				MTU:                 1042,
			},
			rtDataplane.NewMockNetlink,
			rrDataplane.NewMockNetlink,
			wgDataplane.NewMockNetlink,
			wgDataplane.NewMockWireguard,
			10*time.Second,
			t,
			FelixRouteProtocol,
			s.status,
			s.writeProcSys,
			logutils.NewSummarizer("test loop"),
		)
	})

	It("should be constructable", func() {
		Expect(wg).ToNot(BeNil())
	})

	It("should not attempt to create the link", func() {
		err := wg.Apply()
		Expect(err).NotTo(HaveOccurred())
		err = wg.Apply()
		Expect(err).NotTo(HaveOccurred())
		Expect(wgDataplane.NumLinkAddCalls).To(Equal(0))
		Expect(wgDataplane.NumLinkDeleteCalls).To(Equal(0))
	})

	It("should handle deletion of the wireguard link", func() {
		wgDataplane.AddIface(1, ifaceName, true, true)
		err := wg.Apply()
		Expect(err).NotTo(HaveOccurred())
		Expect(wgDataplane.NumLinkAddCalls).To(Equal(0))
		Expect(wgDataplane.NumLinkDeleteCalls).To(Equal(1))
		Expect(wgDataplane.DeletedLinks).To(HaveKey(ifaceName))
	})

	Describe("With some endpoint updates", func() {
		BeforeEach(func() {
			wg.EndpointUpdate(peer1, ipv4_peer1)
			wg.EndpointWireguardUpdate(peer1, mustGeneratePrivateKey().PublicKey(), nil)
			wg.RouteUpdate(peer1, cidr_1)
			err := wg.Apply()
			Expect(err).NotTo(HaveOccurred())
		})

		It("should ignore the updates", func() {
			Expect(wgDataplane.NumLinkAddCalls).To(Equal(0))
			Expect(wgDataplane.NumLinkDeleteCalls).To(Equal(0))
			Expect(wgDataplane.WireguardConfigUpdated).To(BeFalse())
		})

		It("should ignore endpoint deletes", func() {
			wg.RouteRemove(cidr_1)
			wg.EndpointRemove(peer1)
			wg.EndpointWireguardRemove(peer1)
			err := wg.Apply()
			Expect(err).NotTo(HaveOccurred())
			Expect(wgDataplane.NumLinkAddCalls).To(Equal(0))
			Expect(wgDataplane.NumLinkDeleteCalls).To(Equal(0))
			Expect(wgDataplane.WireguardConfigUpdated).To(BeFalse())
		})
	})

	for _, testFailFlags := range []mocknetlink.FailFlags{
		mocknetlink.FailNextNewNetlink, mocknetlink.FailNextLinkDel, mocknetlink.FailNextLinkByName,
		mocknetlink.FailNextRuleList, mocknetlink.FailNextRuleDel, mocknetlink.FailNextRouteList,
	} {
		failFlags := testFailFlags
		desc := fmt.Sprintf("failed netlink management (%v), sync with incorrect rule", failFlags)

		Describe(desc, func() {
			BeforeEach(func() {
				// Create an interface to delete.
				wgDataplane.AddIface(1, ifaceName, true, true)
				rtDataplane.AddIface(1, ifaceName, true, true)

				// Create a rule to route to the wireguard table.
				rrDataplane.Rules = []netlink.Rule{
					{
						Family:   2,
						Priority: 0,
						Table:    255,
					},
					{
						Family: 2,
						Table:  tableIndex,
						Mark:   firewallMark,
						Invert: true,
					},
					{
						Family:   2,
						Priority: 32766,
						Table:    254,
					},
					{
						Family:   2,
						Priority: 32767,
						Table:    253,
					},
				}

				// Set the fail flags and reset errors. Routetable and Routerule modules have retry mechanisms built in
				// so need to persist failures in those cases.
				if failFlags&mocknetlink.FailNextRouteList != 0 {
					rtDataplane.FailuresToSimulate = failFlags
					rtDataplane.PersistFailures = true
				} else if failFlags&(mocknetlink.FailNextRuleList|mocknetlink.FailNextRuleDel) != 0 {
					rrDataplane.FailuresToSimulate = failFlags
				} else {
					wgDataplane.FailuresToSimulate = failFlags
				}

				// Apply the settings - this should remove wireguard config.
				err := wg.Apply()
				Expect(err).To(HaveOccurred())

				// The error should now resolve itself.
				rtDataplane.PersistFailures = false
				err = wg.Apply()
				Expect(err).NotTo(HaveOccurred())
			})

			It("deletes the link", func() {
				link := wgDataplane.NameToLink[ifaceName]
				Expect(link).To(BeNil())

				// These errors will trigger netlink reconnection. The routetable retries multiple times, so just assert
				// there is >0 reconnections.
				if failFlags&mocknetlink.FailNextRouteList != 0 {
					Expect(rtDataplane.NumNewNetlinkCalls).To(BeNumerically(">", 1))
				} else {
					Expect(wgDataplane.NumNewNetlinkCalls).To(BeNumerically(">", 1))
				}
			})

			It("should delete the route rule", func() {
				Expect(rrDataplane.NumRuleDelCalls).ToNot(Equal(0))
				Expect(rrDataplane.NumRuleAddCalls).To(Equal(0))
				Expect(rrDataplane.Rules).To(Equal([]netlink.Rule{
					{
						Family:   2,
						Priority: 0,
						Table:    255,
					},
					{
						Family:   2,
						Priority: 32766,
						Table:    254,
					},
					{
						Family:   2,
						Priority: 32767,
						Table:    253,
					},
				}))
			})
		})
	}
})

var _ = Describe("Wireguard (with no table index)", func() {
	var wgDataplane, rtDataplane, rrDataplane *mocknetlink.MockNetlinkDataplane
	var t *mocktime.MockTime
	var s mockCallbacks
	var wgFn func(bool)

	BeforeEach(func() {
		wgDataplane = mocknetlink.New()
		rtDataplane = mocknetlink.New()
		rrDataplane = mocknetlink.New()
		t = mocktime.New()
		t.SetAutoIncrement(11 * time.Second)

		wgFn = func(enabled bool) {
			NewWithShims(
				hostname,
				&Config{
					Enabled:             enabled,
					ListeningPort:       1000,
					FirewallMark:        1,
					RoutingRulePriority: rulePriority,
					RoutingTableIndex:   0,
					InterfaceName:       ifaceName,
					MTU:                 1042,
				},
				rtDataplane.NewMockNetlink,
				rrDataplane.NewMockNetlink,
				wgDataplane.NewMockNetlink,
				wgDataplane.NewMockWireguard,
				10*time.Second,
				t,
				FelixRouteProtocol,
				s.status,
				s.writeProcSys,
				logutils.NewSummarizer("test loop"),
			)
		}
	})

	It("should panic if wireguard is enabled", func() {
		Expect(func() { wgFn(true) }).To(Panic())
	})

	It("should not panic if wireguard is disabled", func() {
		Expect(func() { wgFn(false) }).NotTo(Panic())
	})
})
