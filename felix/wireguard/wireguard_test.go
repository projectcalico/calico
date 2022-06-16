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
	ifaceNameV6        = "wireguard-if-v6"
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
	//ipnet_5    = cidr_5.ToIPNet()
	//ipnet_6    = cidr_6.ToIPNet()
	routekey_cidr_local = fmt.Sprintf("%d-%s", tableIndex, cidr_local)
	//routekey_1 = fmt.Sprintf("%d-%s", tableIndex, cidr_1)
	//routekey_2 = fmt.Sprintf("%d-%s", tableIndex, cidr_2)
	//routekey_3 = fmt.Sprintf("%d-%s", tableIndex, cidr_3)
	routekey_4 = fmt.Sprintf("%d-%s", tableIndex, cidr_4)
	//routekey_5 = fmt.Sprintf("%d-%s", tableIndex, cidr_5)
	routekey_6 = fmt.Sprintf("%d-%s", tableIndex, cidr_6)

	ipv6_int1 = ip.FromString("2001:db8::192:168:0:0")
	ipv6_int2 = ip.FromString("2001:db8::192:168:10:0")

	ipv6_host    = ip.FromString("2001:db8::1:2:3:0")
	ipv6_peer1   = ip.FromString("2001:db8::1:2:3:5")
	ipv6_peer2   = ip.FromString("2001:db8::1:2:3:6")
	ipv6_peer2_2 = ip.FromString("2001:db8::1:2:3:7")
	ipv6_peer3   = ip.FromString("2001:db8::10:10:20:20")
	ipv6_peer4   = ip.FromString("2001:db8::10:10:20:30")

	cidrV6_local = ip.MustParseCIDROrIP("2001:db8::192:180:0:0/124")
	cidrV6_1     = ip.MustParseCIDROrIP("2001:db8::192:168:1:0/120")
	cidrV6_2     = ip.MustParseCIDROrIP("2001:db8::192:168:2:0/120")
	cidrV6_3     = ip.MustParseCIDROrIP("2001:db8::192:168:3:0/120")
	cidrV6_4     = ip.MustParseCIDROrIP("2001:db8::192:168:4:0/124")
	cidrV6_5     = ip.MustParseCIDROrIP("2001:db8::192:168:5:0/124")
	cidrV6_6     = ip.MustParseCIDROrIP("2001:db8::192:168:6:0/128") // Single IP
	ipnetV6_1    = cidrV6_1.ToIPNet()
	ipnetV6_2    = cidrV6_2.ToIPNet()
	ipnetV6_3    = cidrV6_3.ToIPNet()
	ipnetV6_4    = cidrV6_4.ToIPNet()
	//ipnetV6_5    = cidrV6_5.ToIPNet()
	//ipnetV6_6    = cidrV6_6.ToIPNet()
	routekey_cidrV6_local = fmt.Sprintf("%d-%s", tableIndex, cidrV6_local)
	//routekeyV6_1 = fmt.Sprintf("%d-%s", tableIndex, cidrV6_1)
	//routekeyV6_2 = fmt.Sprintf("%d-%s", tableIndex, cidrV6_2)
	//routekeyV6_3 = fmt.Sprintf("%d-%s", tableIndex, cidrV6_3)
	routekeyV6_4 = fmt.Sprintf("%d-%s", tableIndex, cidrV6_4)
	//routekeyV6_5 = fmt.Sprintf("%d-%s", tableIndex, cidr_5)
	routekeyV6_6 = fmt.Sprintf("%d-%s", tableIndex, cidrV6_6)
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
	type testConf struct {
		EnableV4 bool
		EnableV6 bool
	}
	for _, testConfig := range []testConf{
		{true, false},
		{true, true},
		{false, true},
	} {
		enableV4 := testConfig.EnableV4
		enableV6 := testConfig.EnableV6
		var wgDataplane, rtDataplane, rrDataplane *mocknetlink.MockNetlinkDataplane
		var wgDataplaneV6, rtDataplaneV6, rrDataplaneV6 *mocknetlink.MockNetlinkDataplane
		var t *mocktime.MockTime
		var s, sV6 *mockCallbacks
		var wg, wgV6 *Wireguard
		var rule, ruleV6 *netlink.Rule

		BeforeEach(func() {
			if enableV4 {
				wgDataplane = mocknetlink.New()
				rtDataplane = mocknetlink.New()
				rrDataplane = mocknetlink.New()
				s = &mockCallbacks{}
			}
			if enableV6 {
				wgDataplaneV6 = mocknetlink.New()
				rtDataplaneV6 = mocknetlink.New()
				rrDataplaneV6 = mocknetlink.New()
				sV6 = &mockCallbacks{}
			}
			t = mocktime.New()
			// Setting an auto-increment greater than the route cleanup delay effectively
			// disables the grace period for these tests.
			t.SetAutoIncrement(11 * time.Second)

			config := &Config{
				Enabled:             enableV4,
				EnabledV6:           enableV6,
				ListeningPort:       listeningPort,
				FirewallMark:        firewallMark,
				RoutingRulePriority: rulePriority,
				RoutingTableIndex:   tableIndex,
				InterfaceName:       ifaceName,
				InterfaceNameV6:     ifaceNameV6,
				MTU:                 mtu,
				MTUV6:               mtu,
				EncryptHostTraffic:  true,
			}

			if enableV4 {
				wg = NewWithShims(
					hostname,
					config,
					4,
					rtDataplane.NewMockNetlink,
					rrDataplane.NewMockNetlink,
					wgDataplane.NewMockNetlink,
					wgDataplane.NewMockWireguard,
					10*time.Second,
					t,
					FelixRouteProtocol,
					s.status,
					s.writeProcSys,
					logutils.NewSummarizer("test loop v4"),
				)

				rule = netlink.NewRule()
				rule.Family = netlink.FAMILY_V4
				rule.Priority = rulePriority
				rule.Table = tableIndex
				rule.Invert = true
				rule.Mark = firewallMark
				rule.Mask = firewallMark
			}

			if enableV6 {
				wgV6 = NewWithShims(
					hostname,
					config,
					6,
					rtDataplaneV6.NewMockNetlink,
					rrDataplaneV6.NewMockNetlink,
					wgDataplaneV6.NewMockNetlink,
					wgDataplaneV6.NewMockWireguard,
					10*time.Second,
					t,
					FelixRouteProtocol,
					sV6.status,
					sV6.writeProcSys,
					logutils.NewSummarizer("test loop v6"),
				)

				ruleV6 = netlink.NewRule()
				ruleV6.Family = netlink.FAMILY_V6
				ruleV6.Priority = rulePriority
				ruleV6.Table = tableIndex
				ruleV6.Invert = true
				ruleV6.Mark = firewallMark
				ruleV6.Mask = firewallMark
			}
		})

		It("should be constructable", func() {
			if enableV4 {
				Expect(wg).ToNot(BeNil())
			}
			if enableV6 {
				Expect(wgV6).ToNot(BeNil())
			}
		})

		Describe("create the wireguard link", func() {
			BeforeEach(func() {
				if enableV4 {
					err := wg.Apply()
					Expect(err).NotTo(HaveOccurred())
				}
				if enableV6 {
					err := wgV6.Apply()
					Expect(err).NotTo(HaveOccurred())
				}
			})

			It("should configure the link but wait for link to be active", func() {
				if enableV4 {
					Expect(wgDataplane.NumLinkAddCalls).To(Equal(1))
					Expect(wgDataplane.AddedLinks).To(HaveKey(ifaceName))
					Expect(wgDataplane.NameToLink[ifaceName].LinkType).To(Equal("wireguard"))
					Expect(wgDataplane.NameToLink[ifaceName].LinkAttrs.MTU).To(Equal(2000))
					Expect(wgDataplane.NumLinkAddCalls).To(Equal(1))
					Expect(wgDataplane.WireguardOpen).To(BeFalse())
				}
				if enableV6 {
					Expect(wgDataplaneV6.NumLinkAddCalls).To(Equal(1))
					Expect(wgDataplaneV6.AddedLinks).To(HaveKey(ifaceNameV6))
					Expect(wgDataplaneV6.NameToLink[ifaceNameV6].LinkType).To(Equal("wireguard"))
					Expect(wgDataplaneV6.NameToLink[ifaceNameV6].LinkAttrs.MTU).To(Equal(2000))
					Expect(wgDataplaneV6.NumLinkAddCalls).To(Equal(1))
					Expect(wgDataplaneV6.WireguardOpen).To(BeFalse())
				}
			})

			It("another apply will no-op until link is active", func() {
				// Apply, but still not iface update
				if enableV4 {
					wgDataplane.ResetDeltas()
					err := wg.Apply()
					Expect(err).NotTo(HaveOccurred())
					Expect(wgDataplane.NumLinkAddCalls).To(Equal(0))
					Expect(wgDataplane.WireguardOpen).To(BeFalse())
				}
				if enableV6 {
					wgDataplaneV6.ResetDeltas()
					err := wgV6.Apply()
					Expect(err).NotTo(HaveOccurred())
					Expect(wgDataplaneV6.NumLinkAddCalls).To(Equal(0))
					Expect(wgDataplaneV6.WireguardOpen).To(BeFalse())
				}
			})

			It("no op after a link down callback", func() {
				// Iface update indicating down.
				if enableV4 {
					wgDataplane.ResetDeltas()
					wg.OnIfaceStateChanged(ifaceName, ifacemonitor.StateDown)
					err := wg.Apply()
					Expect(err).NotTo(HaveOccurred())
					Expect(wgDataplane.NumLinkAddCalls).To(Equal(0))
					Expect(wgDataplane.WireguardOpen).To(BeFalse())
				}
				if enableV6 {
					wgDataplaneV6.ResetDeltas()
					wgV6.OnIfaceStateChanged(ifaceNameV6, ifacemonitor.StateDown)
					err := wgV6.Apply()
					Expect(err).NotTo(HaveOccurred())
					Expect(wgDataplaneV6.NumLinkAddCalls).To(Equal(0))
					Expect(wgDataplaneV6.WireguardOpen).To(BeFalse())
				}
			})

			It("no op for an interface callback for non-wg interface (same prefix)", func() {
				// Iface update indicating up.
				if enableV4 {
					wgDataplane.ResetDeltas()
					wgDataplane.AddIface(1919, ifaceName+".foobar", true, true)
					wg.OnIfaceStateChanged(ifaceName+".foobar", ifacemonitor.StateUp)
					err := wg.Apply()
					Expect(err).NotTo(HaveOccurred())
					Expect(wgDataplane.NumLinkAddCalls).To(Equal(0))
					Expect(wgDataplane.WireguardOpen).To(BeFalse())
				}
				if enableV6 {
					wgDataplaneV6.ResetDeltas()
					wgDataplaneV6.AddIface(1919, ifaceNameV6+".foobar", true, true)
					wgV6.OnIfaceStateChanged(ifaceNameV6+".foobar", ifacemonitor.StateUp)
					err := wgV6.Apply()
					Expect(err).NotTo(HaveOccurred())
					Expect(wgDataplaneV6.NumLinkAddCalls).To(Equal(0))
					Expect(wgDataplaneV6.WireguardOpen).To(BeFalse())
				}
			})

			It("should handle status update raising an error", func() {
				if enableV4 {
					wgDataplane.SetIface(ifaceName, true, true)
					wg.OnIfaceStateChanged(ifaceName, ifacemonitor.StateUp)
					s.statusErr = errors.New("foobarbaz")
					err := wg.Apply()
					Expect(err).To(HaveOccurred())
					Expect(err).To(Equal(s.statusErr))
				}
				if enableV6 {
					wgDataplaneV6.SetIface(ifaceNameV6, true, true)
					wgV6.OnIfaceStateChanged(ifaceNameV6, ifacemonitor.StateUp)
					sV6.statusErr = errors.New("foobarbaz")
					err := wgV6.Apply()
					Expect(err).To(HaveOccurred())
					Expect(err).To(Equal(sV6.statusErr))
				}
			})

			Describe("set the link up", func() {
				BeforeEach(func() {
					if enableV4 {
						wgDataplane.SetIface(ifaceName, true, true)
						wg.OnIfaceStateChanged(ifaceName, ifacemonitor.StateUp)
						err := wg.Apply()
						Expect(err).NotTo(HaveOccurred())
					}
					if enableV6 {
						wgDataplaneV6.SetIface(ifaceNameV6, true, true)
						wgV6.OnIfaceStateChanged(ifaceNameV6, ifacemonitor.StateUp)
						err := wgV6.Apply()
						Expect(err).NotTo(HaveOccurred())
					}
				})

				It("should create wireguard client and create private key", func() {
					if enableV4 {
						Expect(wgDataplane.NumLinkAddCalls).To(Equal(1))
						Expect(wgDataplane.WireguardOpen).To(BeTrue())
						link := wgDataplane.NameToLink[ifaceName]
						Expect(link.WireguardFirewallMark).To(Equal(10))
						Expect(link.WireguardListenPort).To(Equal(listeningPort))
						Expect(link.WireguardPrivateKey).NotTo(Equal(zeroKey))
						Expect(link.WireguardPrivateKey.PublicKey()).To(Equal(link.WireguardPublicKey))
						Expect(s.numStatusCallbacks).To(Equal(1))
						Expect(s.statusKey).To(Equal(link.WireguardPublicKey))
					}
					if enableV6 {
						Expect(wgDataplaneV6.NumLinkAddCalls).To(Equal(1))
						Expect(wgDataplaneV6.WireguardOpen).To(BeTrue())
						linkV6 := wgDataplaneV6.NameToLink[ifaceNameV6]
						Expect(linkV6.WireguardFirewallMark).To(Equal(10))
						Expect(linkV6.WireguardListenPort).To(Equal(listeningPort))
						Expect(linkV6.WireguardPrivateKey).NotTo(Equal(zeroKey))
						Expect(linkV6.WireguardPrivateKey.PublicKey()).To(Equal(linkV6.WireguardPublicKey))
						Expect(sV6.numStatusCallbacks).To(Equal(1))
						Expect(sV6.statusKey).To(Equal(linkV6.WireguardPublicKey))
					}
				})

				It("should add the routing rule when wireguard device is configured", func() {
					if enableV4 {
						wgDataplane.ResetDeltas()
						err := wg.Apply()
						Expect(err).ToNot(HaveOccurred())

						Expect(rrDataplane.AddedRules).To(HaveLen(1))
						Expect(rrDataplane.DeletedRules).To(HaveLen(0))
						Expect(rrDataplane.AddedRules).To(ConsistOf(*rule))
					}
					if enableV6 {
						wgDataplaneV6.ResetDeltas()
						err := wgV6.Apply()
						Expect(err).ToNot(HaveOccurred())

						Expect(rrDataplaneV6.AddedRules).To(HaveLen(1))
						Expect(rrDataplaneV6.DeletedRules).To(HaveLen(0))
						Expect(rrDataplaneV6.AddedRules).To(ConsistOf(*ruleV6))
					}
				})

				It("should delete invalid rules jumping to the wireguard table", func() {
					if enableV4 {
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
					}
					if enableV6 {
						incorrectRuleV6 := netlink.NewRule()
						incorrectRuleV6.Family = 10
						incorrectRuleV6.Priority = rulePriority + 10
						incorrectRuleV6.Table = tableIndex
						incorrectRuleV6.Mark = firewallMark + 10
						incorrectRuleV6.Invert = false
						err := rrDataplaneV6.RuleAdd(incorrectRuleV6)
						Expect(err).ToNot(HaveOccurred())
						rrDataplaneV6.ResetDeltas()

						wgV6.QueueResync()
						err = wgV6.Apply()
						Expect(err).ToNot(HaveOccurred())

						Expect(rrDataplaneV6.AddedRules).To(HaveLen(0))
						Expect(rrDataplaneV6.DeletedRules).To(ConsistOf(*incorrectRuleV6))
					}
				})

				It("after endpoint update with incorrect key should program the interface address and resend same key as status", func() {
					if enableV4 {
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
					}
					if enableV6 {
						link := wgDataplaneV6.NameToLink[ifaceNameV6]
						Expect(link.WireguardPrivateKey).NotTo(Equal(zeroKey))
						Expect(sV6.numStatusCallbacks).To(Equal(1))
						key := link.WireguardPrivateKey
						Expect(sV6.statusKey).To(Equal(key.PublicKey()))

						ipv6 := ip.FromString("2001:db8::1:2:3")
						wgV6.EndpointWireguardUpdate(hostname, zeroKey, ipv6)
						err := wgV6.Apply()
						Expect(err).NotTo(HaveOccurred())
						link = wgDataplaneV6.NameToLink[ifaceNameV6]
						Expect(link.Addrs).To(HaveLen(1))
						Expect(link.Addrs[0].IP).To(Equal(ipv6.AsNetIP()))
						Expect(wgDataplaneV6.WireguardOpen).To(BeTrue())
						Expect(link.WireguardFirewallMark).To(Equal(10))
						Expect(link.WireguardListenPort).To(Equal(listeningPort))
						Expect(link.WireguardPrivateKey).To(Equal(key))
						Expect(link.WireguardPrivateKey.PublicKey()).To(Equal(link.WireguardPublicKey))
						Expect(sV6.numStatusCallbacks).To(Equal(2))
						Expect(sV6.statusKey).To(Equal(key.PublicKey()))
					}
				})

				It("after endpoint update with correct key should program the interface address and not send another status update", func() {
					if enableV4 {
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
					}
					if enableV6 {
						link := wgDataplaneV6.NameToLink[ifaceNameV6]
						Expect(link.WireguardPrivateKey).NotTo(Equal(zeroKey))
						Expect(sV6.numStatusCallbacks).To(Equal(1))
						key := link.WireguardPrivateKey

						ipv6 := ip.FromString("2001:db8::1:2:3")
						wgV6.EndpointWireguardUpdate(hostname, key.PublicKey(), ipv6)
						err := wgV6.Apply()
						Expect(err).NotTo(HaveOccurred())
						link = wgDataplaneV6.NameToLink[ifaceNameV6]
						Expect(link.Addrs).To(HaveLen(1))
						Expect(link.Addrs[0].IP).To(Equal(ipv6.AsNetIP()))
						Expect(wgDataplaneV6.WireguardOpen).To(BeTrue())
						Expect(link.WireguardFirewallMark).To(Equal(10))
						Expect(link.WireguardListenPort).To(Equal(listeningPort))
						Expect(link.WireguardPrivateKey).To(Equal(key))
						Expect(link.WireguardPrivateKey.PublicKey()).To(Equal(link.WireguardPublicKey))
						Expect(sV6.numStatusCallbacks).To(Equal(1))
					}
				})

				It("will use node IP on EndpointUpdate when interface is not specified on previous EndpointWireguardUpdate", func() {
					if enableV4 {
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
					}
					if enableV6 {
						linkV6 := wgDataplaneV6.NameToLink[ifaceNameV6]
						Expect(linkV6.WireguardPrivateKey).NotTo(Equal(zeroKey))
						Expect(sV6.numStatusCallbacks).To(Equal(1))
						key := linkV6.WireguardPrivateKey

						ipv6 := ip.FromString("2001:db8::1:2:3:4")
						wgV6.EndpointWireguardUpdate(hostname, key.PublicKey(), nil)
						wgV6.EndpointUpdate(hostname, ipv6)
						err := wgV6.Apply()

						Expect(err).NotTo(HaveOccurred())
						linkV6 = wgDataplaneV6.NameToLink[ifaceNameV6]
						Expect(linkV6.Addrs).To(HaveLen(1))
						Expect(linkV6.Addrs[0].IP).To(Equal(ipv6.AsNetIP()))
						Expect(wgDataplaneV6.WireguardOpen).To(BeTrue())
						Expect(linkV6.WireguardFirewallMark).To(Equal(10))
						Expect(linkV6.WireguardListenPort).To(Equal(listeningPort))
						Expect(linkV6.WireguardPrivateKey).To(Equal(key))
						Expect(linkV6.WireguardPrivateKey.PublicKey()).To(Equal(linkV6.WireguardPublicKey))
						Expect(sV6.numStatusCallbacks).To(Equal(1))
					}
				})

				It("will use node IP from previous EndpointUpdate when interface is not specified on EndpointWireguardUpdate", func() {
					if enableV4 {
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
					}
					if enableV6 {
						linkV6 := wgDataplaneV6.NameToLink[ifaceNameV6]
						Expect(linkV6.WireguardPrivateKey).NotTo(Equal(zeroKey))
						Expect(sV6.numStatusCallbacks).To(Equal(1))
						key := linkV6.WireguardPrivateKey

						// Basically the same test as before but calls are reveresed.
						ipv6 := ip.FromString("2001:db8::1:2:3:4")
						wgV6.EndpointUpdate(hostname, ipv6)
						wgV6.EndpointWireguardUpdate(hostname, key.PublicKey(), nil)
						err := wgV6.Apply()

						Expect(err).NotTo(HaveOccurred())
						linkV6 = wgDataplaneV6.NameToLink[ifaceNameV6]
						Expect(linkV6.Addrs).To(HaveLen(1))
						Expect(linkV6.Addrs[0].IP).To(Equal(ipv6.AsNetIP()))
						Expect(wgDataplaneV6.WireguardOpen).To(BeTrue())
						Expect(linkV6.WireguardFirewallMark).To(Equal(10))
						Expect(linkV6.WireguardListenPort).To(Equal(listeningPort))
						Expect(linkV6.WireguardPrivateKey).To(Equal(key))
						Expect(linkV6.WireguardPrivateKey.PublicKey()).To(Equal(linkV6.WireguardPublicKey))
						Expect(sV6.numStatusCallbacks).To(Equal(1))
					}
				})

				Describe("add local routes with overlap", func() {
					var lc1, lc2, lc3 ip.CIDR
					var lc1V6, lc2V6, lc3V6 ip.CIDR

					BeforeEach(func() {
						if enableV4 {
							lc1 = ip.MustParseCIDROrIP("12.12.10.10/32")
							lc2 = ip.MustParseCIDROrIP("12.12.10.0/24")
							lc3 = ip.MustParseCIDROrIP("12.12.11.0/32")

							wg.RouteUpdate(hostname, lc1)
							wg.RouteUpdate(hostname, lc2)
							wg.RouteUpdate(hostname, lc3)

							err := wg.Apply()
							Expect(err).ToNot(HaveOccurred())
						}
						if enableV6 {
							lc1V6 = ip.MustParseCIDROrIP("2001:db8::10:10/128")
							lc2V6 = ip.MustParseCIDROrIP("2001:db8::10:0/120")
							lc3V6 = ip.MustParseCIDROrIP("2001:db8::11:0/128")

							wgV6.RouteUpdate(hostname, lc1V6)
							wgV6.RouteUpdate(hostname, lc2V6)
							wgV6.RouteUpdate(hostname, lc3V6)

							err := wgV6.Apply()
							Expect(err).ToNot(HaveOccurred())
						}
					})

					It("should create the rule when routing config is updated", func() {
						if enableV4 {
							Expect(rrDataplane.DeletedRules).To(HaveLen(0))
							Expect(rrDataplane.AddedRules).To(ConsistOf(*rule))
						}
						if enableV6 {
							Expect(rrDataplaneV6.DeletedRules).To(HaveLen(0))
							Expect(rrDataplaneV6.AddedRules).To(ConsistOf(*ruleV6))
						}
					})

					It("should not re-add a deleted rule until resync", func() {
						if enableV4 {
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
						}
						if enableV6 {
							err := rrDataplaneV6.RuleDel(ruleV6)
							Expect(err).ToNot(HaveOccurred())
							rrDataplaneV6.ResetDeltas()
							err = wgV6.Apply()
							Expect(err).ToNot(HaveOccurred())
							Expect(rrDataplaneV6.AddedRules).To(HaveLen(0))
							Expect(rrDataplaneV6.DeletedRules).To(HaveLen(0))

							wgV6.QueueResync()
							err = wgV6.Apply()
							Expect(err).ToNot(HaveOccurred())
							Expect(rrDataplaneV6.DeletedRules).To(HaveLen(0))
							Expect(rrDataplaneV6.AddedRules).To(ConsistOf(*ruleV6))
						}
					})

					It("should not fix a modified rule until resync", func() {
						if enableV4 {
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
						}
						if enableV6 {
							badruleV6 := netlink.NewRule()
							badruleV6.Family = netlink.FAMILY_V6
							badruleV6.Priority = rulePriority + 1
							badruleV6.Table = tableIndex
							badruleV6.Mark = 0
							badruleV6.Mask = firewallMark

							err := rrDataplaneV6.RuleDel(ruleV6)
							Expect(err).ToNot(HaveOccurred())
							err = rrDataplaneV6.RuleAdd(badruleV6)
							Expect(err).ToNot(HaveOccurred())

							rrDataplaneV6.ResetDeltas()
							err = wgV6.Apply()
							Expect(err).ToNot(HaveOccurred())
							Expect(rrDataplaneV6.AddedRules).To(HaveLen(0))
							Expect(rrDataplaneV6.DeletedRules).To(HaveLen(0))

							wgV6.QueueResync()
							err = wgV6.Apply()
							Expect(err).ToNot(HaveOccurred())
							Expect(rrDataplaneV6.DeletedRules).To(ConsistOf(*badruleV6))
							Expect(rrDataplaneV6.AddedRules).To(ConsistOf(*ruleV6))
						}
					})
				})

				Describe("create two wireguard nodes with different public keys", func() {
					var key_peer1, key_peer2 wgtypes.Key
					var keyV6_peer1, keyV6_peer2 wgtypes.Key
					var link, linkV6 *mocknetlink.MockLink
					BeforeEach(func() {
						if enableV4 {
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
						}
						if enableV6 {
							Expect(sV6.numStatusCallbacks).To(Equal(1))
							wgV6.EndpointWireguardUpdate(hostname, sV6.statusKey, nil)
							keyV6_peer1 = mustGeneratePrivateKey().PublicKey()
							wgV6.EndpointWireguardUpdate(peer1, keyV6_peer1, nil)
							wgV6.EndpointUpdate(peer1, ipv6_peer1)
							keyV6_peer2 = mustGeneratePrivateKey().PublicKey()
							wgV6.EndpointWireguardUpdate(peer2, keyV6_peer2, nil)
							wgV6.EndpointUpdate(peer2, ipv6_peer2)
							wgV6.RouteUpdate(hostname, cidrV6_local)
							err := wgV6.Apply()
							Expect(err).NotTo(HaveOccurred())
							linkV6 = wgDataplaneV6.NameToLink[ifaceNameV6]
							Expect(linkV6).ToNot(BeNil())
							Expect(wgDataplaneV6.WireguardOpen).To(BeTrue())
							Expect(rrDataplaneV6.NetlinkOpen).To(BeTrue())
							Expect(rrDataplaneV6.NumRuleDelCalls).To(Equal(0))
							Expect(rrDataplaneV6.NumRuleAddCalls).To(Equal(1))
						}
					})

					It("should have both nodes configured", func() {
						if enableV4 {
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
						}
						if enableV6 {
							Expect(linkV6.WireguardPeers).To(HaveLen(2))
							Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer1))
							Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer2))
							Expect(linkV6.WireguardPeers[keyV6_peer1]).To(Equal(wgtypes.Peer{
								PublicKey: keyV6_peer1,
								Endpoint: &net.UDPAddr{
									IP:   ipv6_peer1.AsNetIP(),
									Port: 1000,
								},
							}))
							Expect(linkV6.WireguardPeers[keyV6_peer2]).To(Equal(wgtypes.Peer{
								PublicKey: keyV6_peer2,
								Endpoint: &net.UDPAddr{
									IP:   ipv6_peer2.AsNetIP(),
									Port: 1000,
								},
							}))
						}
					})

					It("should have no updates for local EndpointUpdate and EndpointRemove msgs", func() {
						if enableV4 {
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
						}
						if enableV6 {
							wgDataplaneV6.ResetDeltas()
							rtDataplaneV6.ResetDeltas()
							wgV6.EndpointUpdate(hostname, nil)
							err := wgV6.Apply()
							Expect(err).NotTo(HaveOccurred())
							wgV6.EndpointRemove(hostname)
							err = wgV6.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(0))
							Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(0))
							Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeFalse())
						}
					})

					It("should have no updates for backing out an endpoint update", func() {
						if enableV4 {
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()
							wg.EndpointUpdate(peer1, ipv4_peer2)
							wg.EndpointUpdate(peer1, ipv4_peer1)
							err := wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(wgDataplane.WireguardConfigUpdated).To(BeFalse())
						}
						if enableV6 {
							wgDataplaneV6.ResetDeltas()
							rtDataplaneV6.ResetDeltas()
							wgV6.EndpointUpdate(peer1, ipv6_peer2)
							wgV6.EndpointUpdate(peer1, ipv6_peer1)
							err := wgV6.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeFalse())
						}
					})

					It("should have no updates for backing out a peer key update", func() {
						if enableV4 {
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()
							wg.EndpointWireguardUpdate(peer1, key_peer2, nil)
							wg.EndpointWireguardUpdate(peer1, key_peer1, nil)
							err := wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(wgDataplane.WireguardConfigUpdated).To(BeFalse())
						}
						if enableV6 {
							wgDataplaneV6.ResetDeltas()
							rtDataplaneV6.ResetDeltas()
							wgV6.EndpointWireguardUpdate(peer1, keyV6_peer2, nil)
							wgV6.EndpointWireguardUpdate(peer1, keyV6_peer1, nil)
							err := wgV6.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeFalse())
						}
					})

					It("should have no updates if adding and deleting peer config before applying", func() {
						if enableV4 {
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
						}
						if enableV6 {
							wgDataplaneV6.ResetDeltas()
							rtDataplaneV6.ResetDeltas()
							wgV6.EndpointUpdate(peer3, ipv6_peer3)
							wgV6.EndpointWireguardUpdate(peer3, keyV6_peer1, nil)
							wgV6.EndpointRemove(peer3)
							wgV6.EndpointWireguardRemove(peer3)
							err := wgV6.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(0))
							Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(0))
							Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeFalse())
						}
					})

					It("should trigger another status message if deleting the local Wireguard config", func() {
						if enableV4 {
							wgDataplane.ResetDeltas()
							rtDataplane.ResetDeltas()
							Expect(s.numStatusCallbacks).To(Equal(1))
							wg.EndpointWireguardRemove(hostname)
							err := wg.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(s.numStatusCallbacks).To(Equal(2))
						}
						if enableV6 {
							wgDataplaneV6.ResetDeltas()
							rtDataplaneV6.ResetDeltas()
							Expect(sV6.numStatusCallbacks).To(Equal(1))
							wgV6.EndpointWireguardRemove(hostname)
							err := wgV6.Apply()
							Expect(err).NotTo(HaveOccurred())
							Expect(sV6.numStatusCallbacks).To(Equal(2))
						}
					})

					It("should contain a throw route for the local CIDR", func() {
						if enableV4 {
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(1))
							Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_cidr_local))
							Expect(rtDataplane.AddedRouteKeys).To(HaveLen(1))
							Expect(rtDataplane.DeletedRouteKeys).To(BeEmpty())
						}
						if enableV6 {
							Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(1))
							Expect(rtDataplaneV6.AddedRouteKeys).To(HaveKey(routekey_cidrV6_local))
							Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(1))
							Expect(rtDataplaneV6.DeletedRouteKeys).To(BeEmpty())
						}
					})
					Describe("add local workload as a single IP", func() {
						BeforeEach(func() {
							if enableV4 {
								// Update the routetable dataplane so it knows about the interface.
								rtDataplane.NameToLink[ifaceName] = link

								wgDataplane.ResetDeltas()
								rtDataplane.ResetDeltas()
								wg.RouteUpdate(hostname, cidr_6)
								err := wg.Apply()
								Expect(err).NotTo(HaveOccurred())
							}
							if enableV6 {
								// Update the routetable dataplane so it knows about the interface.
								rtDataplaneV6.NameToLink[ifaceNameV6] = linkV6

								wgDataplaneV6.ResetDeltas()
								rtDataplaneV6.ResetDeltas()
								wgV6.RouteUpdate(hostname, cidrV6_6)
								err := wgV6.Apply()
								Expect(err).NotTo(HaveOccurred())
							}
						})

						It("should have a throw route to the local IP", func() {
							if enableV4 {
								Expect(rtDataplane.AddedRouteKeys).To(HaveLen(1))
								Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(0))
								Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_6))
							}
							if enableV6 {
								Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(1))
								Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(0))
								Expect(rtDataplaneV6.AddedRouteKeys).To(HaveKey(routekeyV6_6))
							}
						})

						It("should handle the IP being deleted and then moved to another node", func() {
							if enableV4 {
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
							}
							if enableV6 {
								wgDataplaneV6.ResetDeltas()
								rtDataplaneV6.ResetDeltas()

								wgV6.RouteRemove(cidrV6_6)
								wgV6.RouteUpdate(peer1, cidrV6_6)
								err := wgV6.Apply()
								Expect(err).NotTo(HaveOccurred())

								Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(1))
								Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveKey(routekeyV6_6))
								Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(1))
								Expect(rtDataplaneV6.AddedRouteKeys).To(HaveKey(routekeyV6_6))
							}
						})

						It("should handle the IP being moved to another node without first deleting", func() {
							if enableV4 {
								wgDataplane.ResetDeltas()
								rtDataplane.ResetDeltas()

								wg.RouteUpdate(peer1, cidr_6)
								err := wg.Apply()
								Expect(err).NotTo(HaveOccurred())

								Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(1))
								Expect(rtDataplane.DeletedRouteKeys).To(HaveKey(routekey_6))
								Expect(rtDataplane.AddedRouteKeys).To(HaveLen(1))
								Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_6))
							}
							if enableV6 {
								wgDataplaneV6.ResetDeltas()
								rtDataplaneV6.ResetDeltas()

								wgV6.RouteUpdate(peer1, cidrV6_6)
								err := wgV6.Apply()
								Expect(err).NotTo(HaveOccurred())

								Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(1))
								Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveKey(routekeyV6_6))
								Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(1))
								Expect(rtDataplaneV6.AddedRouteKeys).To(HaveKey(routekeyV6_6))
							}
						})

						It("should handle the IP being moved to another node with a deletion in between", func() {
							if enableV4 {
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
							}
							if enableV6 {
								wgDataplaneV6.ResetDeltas()
								rtDataplaneV6.ResetDeltas()

								wgV6.RouteUpdate(peer1, cidrV6_6)
								wgV6.RouteRemove(cidrV6_6)
								wgV6.RouteUpdate(peer1, cidrV6_6)
								err := wgV6.Apply()
								Expect(err).NotTo(HaveOccurred())

								Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(1))
								Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveKey(routekeyV6_6))
								Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(1))
								Expect(rtDataplaneV6.AddedRouteKeys).To(HaveKey(routekeyV6_6))
							}
						})
					})

					Describe("public key updated to conflict on two nodes", func() {
						var wgPeers map[wgtypes.Key]wgtypes.Peer
						var wgPeersV6 map[wgtypes.Key]wgtypes.Peer

						BeforeEach(func() {
							if enableV4 {
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
							}
							if enableV6 {
								linkV6 = wgDataplaneV6.NameToLink[ifaceNameV6]

								// Take a copy of the current peer configuration for one of the tests.
								wgPeersV6 = make(map[wgtypes.Key]wgtypes.Peer)
								for k, p := range linkV6.WireguardPeers {
									wgPeersV6[k] = p
								}

								wgV6.EndpointWireguardUpdate(peer2, keyV6_peer1, nil)
								rtDataplaneV6.ResetDeltas()
								err := wgV6.Apply()
								Expect(err).NotTo(HaveOccurred())
							}
						})

						It("should remove both nodes", func() {
							if enableV4 {
								Expect(link.WireguardPeers).To(HaveLen(0))
							}
							if enableV6 {
								Expect(linkV6.WireguardPeers).To(HaveLen(0))
							}
						})

						It("should handle a resync if the peer is added back in out-of-band", func() {
							if enableV4 {
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
							}
							if enableV6 {
								linkV6.WireguardPeers = wgPeers
								linkV6.WireguardListenPort = listeningPort + 1
								linkV6.WireguardFirewallMark = firewallMark + 1
								linkV6.LinkAttrs.MTU = mtu + 1
								wgV6.QueueResync()
								err := wgV6.Apply()
								Expect(err).NotTo(HaveOccurred())

								Expect(linkV6.WireguardListenPort).To(Equal(listeningPort))
								Expect(linkV6.WireguardFirewallMark).To(Equal(firewallMark))
								Expect(linkV6.WireguardPeers).To(HaveLen(0))
							}
						})

						It("should add both nodes when conflicting public keys updated to no longer conflict", func() {
							if enableV4 {
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
							}
							if enableV6 {
								wgV6.EndpointWireguardUpdate(peer2, keyV6_peer2, nil)
								err := wgV6.Apply()
								Expect(err).NotTo(HaveOccurred())
								Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer1))
								Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer2))
								Expect(linkV6.WireguardPeers[keyV6_peer1]).To(Equal(wgtypes.Peer{
									PublicKey: keyV6_peer1,
									Endpoint: &net.UDPAddr{
										IP:   ipv6_peer1.AsNetIP(),
										Port: 1000,
									},
								}))
								Expect(linkV6.WireguardPeers[keyV6_peer2]).To(Equal(wgtypes.Peer{
									PublicKey: keyV6_peer2,
									Endpoint: &net.UDPAddr{
										IP:   ipv6_peer2.AsNetIP(),
										Port: 1000,
									},
								}))
							}
						})

						It("should contain no more route updates", func() {
							if enableV4 {
								Expect(rtDataplane.AddedRouteKeys).To(BeEmpty())
								Expect(rtDataplane.DeletedRouteKeys).To(BeEmpty())
							}
							if enableV6 {
								Expect(rtDataplaneV6.AddedRouteKeys).To(BeEmpty())
								Expect(rtDataplaneV6.DeletedRouteKeys).To(BeEmpty())
							}
						})
					})

					Describe("create a non-wireguard peer", func() {
						BeforeEach(func() {
							if enableV4 {
								wg.EndpointUpdate(peer3, ipv4_peer3)
								rtDataplane.ResetDeltas()
								err := wg.Apply()
								Expect(err).NotTo(HaveOccurred())
							}
							if enableV6 {
								wgV6.EndpointUpdate(peer3, ipv6_peer3)
								rtDataplaneV6.ResetDeltas()
								err := wgV6.Apply()
								Expect(err).NotTo(HaveOccurred())
							}
						})

						It("should not create wireguard configuration for the peer", func() {
							if enableV4 {
								Expect(link.WireguardPeers).To(HaveLen(2))
								Expect(link.WireguardPeers).To(HaveKey(key_peer1))
								Expect(link.WireguardPeers).To(HaveKey(key_peer2))
							}
							if enableV6 {
								Expect(linkV6.WireguardPeers).To(HaveLen(2))
								Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer1))
								Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer2))
							}
						})

						It("should contain no more route updates", func() {
							if enableV4 {
								Expect(rtDataplane.AddedRouteKeys).To(BeEmpty())
								Expect(rtDataplane.DeletedRouteKeys).To(BeEmpty())
							}
							if enableV6 {
								Expect(rtDataplaneV6.AddedRouteKeys).To(BeEmpty())
								Expect(rtDataplaneV6.DeletedRouteKeys).To(BeEmpty())
							}
						})

						Describe("create destinations on each peer", func() {
							var routekey_1, routekey_2, routekey_3 string
							var routekeyV6_1, routekeyV6_2, routekeyV6_3 string
							BeforeEach(func() {
								if enableV4 {
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
								}
								if enableV6 {
									// Update the mock routing table dataplane so that it knows about the wireguard interface.
									rtDataplaneV6.NameToLink[ifaceNameV6] = linkV6
									routekeyV6_1 = fmt.Sprintf("%d-%s", tableIndex, cidrV6_1)
									routekeyV6_2 = fmt.Sprintf("%d-%s", tableIndex, cidrV6_2)
									routekeyV6_3 = fmt.Sprintf("%d-%s", tableIndex, cidrV6_3)

									wgV6.RouteUpdate(hostname, cidrV6_local)
									wgV6.RouteUpdate(peer1, cidrV6_1)
									wgV6.RouteUpdate(peer1, cidrV6_2)
									wgV6.RouteUpdate(peer2, cidrV6_3)
									wgV6.RouteUpdate(peer3, cidrV6_4)
									err := wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
								}
							})

							It("should have wireguard routes for peer1 and peer2", func() {
								if enableV4 {
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
								}
								if enableV6 {
									Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer1))
									Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer2))
									Expect(linkV6.WireguardPeers[keyV6_peer1]).To(Equal(wgtypes.Peer{
										PublicKey: keyV6_peer1,
										Endpoint: &net.UDPAddr{
											IP:   ipv6_peer1.AsNetIP(),
											Port: 1000,
										},
										AllowedIPs: []net.IPNet{ipnetV6_1, ipnetV6_2},
									}))
									Expect(linkV6.WireguardPeers[keyV6_peer2]).To(Equal(wgtypes.Peer{
										PublicKey: keyV6_peer2,
										Endpoint: &net.UDPAddr{
											IP:   ipv6_peer2.AsNetIP(),
											Port: 1000,
										},
										AllowedIPs: []net.IPNet{ipnetV6_3},
									}))
								}
							})

							It("should route to wireguard for peer1 and peer2 routes, but not peer3 routes", func() {
								if enableV4 {
									Expect(rtDataplane.AddedRouteKeys).To(HaveLen(4))
									Expect(rtDataplane.DeletedRouteKeys).To(BeEmpty())
									Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_1))
									Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_2))
									Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_3))
									Expect(rtDataplane.AddedRouteKeys).To(HaveKey(routekey_4))
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
								}
								if enableV6 {
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(4))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(BeEmpty())
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveKey(routekeyV6_1))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveKey(routekeyV6_2))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveKey(routekeyV6_3))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveKey(routekeyV6_4))
									Expect(rtDataplaneV6.RouteKeyToRoute[routekeyV6_1]).To(Equal(netlink.Route{
										LinkIndex: linkV6.LinkAttrs.Index,
										Dst:       &ipnetV6_1,
										Type:      syscall.RTN_UNICAST,
										Protocol:  FelixRouteProtocol,
										Scope:     netlink.SCOPE_LINK,
										Table:     tableIndex,
									}))
									Expect(rtDataplaneV6.RouteKeyToRoute[routekeyV6_2]).To(Equal(netlink.Route{
										LinkIndex: linkV6.LinkAttrs.Index,
										Dst:       &ipnetV6_2,
										Type:      syscall.RTN_UNICAST,
										Protocol:  FelixRouteProtocol,
										Scope:     netlink.SCOPE_LINK,
										Table:     tableIndex,
									}))
									Expect(rtDataplaneV6.RouteKeyToRoute[routekeyV6_3]).To(Equal(netlink.Route{
										LinkIndex: linkV6.LinkAttrs.Index,
										Dst:       &ipnetV6_3,
										Type:      syscall.RTN_UNICAST,
										Protocol:  FelixRouteProtocol,
										Scope:     netlink.SCOPE_LINK,
										Table:     tableIndex,
									}))
									Expect(rtDataplaneV6.RouteKeyToRoute[routekeyV6_4]).To(Equal(netlink.Route{
										LinkIndex: 1,
										Dst:       &ipnetV6_4,
										Type:      syscall.RTN_THROW,
										Protocol:  FelixRouteProtocol,
										Scope:     netlink.SCOPE_UNIVERSE,
										Table:     tableIndex,
									}))
								}
							})

							It("should remove a route from the peer", func() {
								if enableV4 {
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
								}
								if enableV6 {
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()
									wgV6.RouteRemove(cidrV6_1)
									err := wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(0))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(1))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveKey(routekeyV6_1))
									Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeTrue())
									Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer1))
									Expect(linkV6.WireguardPeers[keyV6_peer1]).To(Equal(wgtypes.Peer{
										PublicKey: keyV6_peer1,
										Endpoint: &net.UDPAddr{
											IP:   ipv6_peer1.AsNetIP(),
											Port: 1000,
										},
										AllowedIPs: []net.IPNet{ipnetV6_2},
									}))
								}
							})

							It("should have no updates if swapping routes and swapping back before an apply", func() {
								if enableV4 {
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
								}
								if enableV6 {
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()
									wgV6.RouteUpdate(peer1, cidrV6_3)
									wgV6.RouteUpdate(peer2, cidrV6_1)
									wgV6.RouteUpdate(peer1, cidrV6_1)
									wgV6.RouteUpdate(peer2, cidrV6_3)
									err := wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(0))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(0))
									Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeFalse())
								}
							})

							It("should have no updates if adding and deleting a CIDR to a peer", func() {
								if enableV4 {
									wgDataplane.ResetDeltas()
									rtDataplane.ResetDeltas()
									wg.RouteUpdate(peer1, cidr_5)
									wg.RouteRemove(cidr_5)
									err := wg.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(rtDataplane.AddedRouteKeys).To(HaveLen(0))
									Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(0))
									Expect(wgDataplane.WireguardConfigUpdated).To(BeFalse())
								}
								if enableV6 {
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()
									wgV6.RouteUpdate(peer1, cidr_5)
									wgV6.RouteRemove(cidr_5)
									err := wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(0))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(0))
									Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeFalse())
								}
							})

							It("should have no updates if deleting an unknown CIDR", func() {
								if enableV4 {
									wgDataplane.ResetDeltas()
									rtDataplane.ResetDeltas()
									wg.RouteRemove(cidr_5)
									err := wg.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(rtDataplane.AddedRouteKeys).To(HaveLen(0))
									Expect(rtDataplane.DeletedRouteKeys).To(HaveLen(0))
									Expect(wgDataplane.WireguardConfigUpdated).To(BeFalse())
								}
								if enableV6 {
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()
									wgV6.RouteRemove(cidrV6_5)
									err := wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(0))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(0))
									Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeFalse())
								}
							})

							It("should handle deletion of nodes 2 and 3", func() {
								if enableV4 {
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
									Expect(rtDataplane.AddedRouteKeys).NotTo(HaveKey(routekey_3))
									Expect(rtDataplane.AddedRouteKeys).NotTo(HaveKey(routekey_4))
									Expect(wgDataplane.WireguardConfigUpdated).To(BeTrue())
									Expect(link.WireguardPeers).To(HaveKey(key_peer1))
									Expect(link.WireguardPeers).To(HaveLen(1))
								}
								if enableV6 {
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()
									wgV6.EndpointRemove(peer3)
									wgV6.EndpointWireguardRemove(peer3)
									wgV6.RouteRemove(cidrV6_4)
									wgV6.RouteRemove(cidrV6_3)
									wgV6.EndpointWireguardRemove(peer2)
									wgV6.EndpointRemove(peer2)
									err := wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(0))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(2))
									Expect(rtDataplaneV6.AddedRouteKeys).NotTo(HaveKey(routekeyV6_3))
									Expect(rtDataplaneV6.AddedRouteKeys).NotTo(HaveKey(routekeyV6_4))
									Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeTrue())
									Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer1))
									Expect(linkV6.WireguardPeers).To(HaveLen(1))
								}
							})
							It("should handle deletion of a wireguard peer over multiple applies: endpoint, wireguard, route", func() {
								if enableV4 {
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
								}
								if enableV6 {
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()

									// Remove the endpoint. Wireguard config should be removed at this point. The route should
									// be converted to a throw route.
									By("Removing the node")
									wgV6.EndpointRemove(peer2)
									err := wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(wgV6.DebugNodes()).To(HaveLen(4))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(1))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveKey(routekeyV6_3))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(1))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveKey(routekeyV6_3))
									Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeTrue())
									Expect(linkV6.WireguardPeers).To(HaveLen(1))
									Expect(linkV6.WireguardPeers).To(HaveLen(1))
									Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer1))
									Expect(rtDataplaneV6.RouteKeyToRoute[routekeyV6_3]).To(Equal(netlink.Route{
										LinkIndex: 1,
										Dst:       &ipnetV6_3,
										Type:      syscall.RTN_THROW,
										Protocol:  FelixRouteProtocol,
										Scope:     netlink.SCOPE_UNIVERSE,
										Table:     tableIndex,
									}))

									// Remove the wireguard config for this peer. Should have no further impact.
									By("Removing the wireguard configuration")
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()
									wgV6.EndpointWireguardRemove(peer2)
									err = wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(wgV6.DebugNodes()).To(HaveLen(4))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(0))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(0))
									Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeFalse())
									Expect(linkV6.WireguardPeers).To(HaveLen(1))

									// Remove the route.
									// This is the last bit of configuration for the peer and so the node should be removed
									// from the cache.
									By("Removing the route")
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()
									wgV6.RouteRemove(cidrV6_3)
									err = wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(wgV6.DebugNodes()).To(HaveLen(3))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(0))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(1))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveKey(routekeyV6_3))
									Expect(linkV6.WireguardPeers).To(HaveLen(1))
								}
							})

							It("should handle deletion of a wireguard peer over multiple applies: route, endpoint, wireguard", func() {
								if enableV4 {
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
								}
								if enableV6 {
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()

									// Remove the route.
									By("Removing the route")
									wgV6.RouteRemove(cidrV6_3)
									err := wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(wgV6.DebugNodes()).To(HaveLen(4))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(0))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(1))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveKey(routekeyV6_3))
									Expect(rtDataplaneV6.RouteKeyToRoute).ToNot(HaveKey(routekeyV6_3))
									Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeTrue())
									Expect(linkV6.WireguardPeers).To(HaveLen(2))

									// Remove the endpoint. Wireguard config should be removed at this point. The route should
									// be converted to a throw route.
									By("Removing the node")
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()
									wgV6.EndpointRemove(peer2)
									err = wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(wgV6.DebugNodes()).To(HaveLen(4))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(0))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(0))
									Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeTrue())
									Expect(linkV6.WireguardPeers).To(HaveLen(1))
									Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer1))

									// Remove the wireguard config for this peer.
									// This is the last bit of configuration for the peer and so the node should be removed
									// from the cache.
									By("Removing the wireguard configuration")
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()
									wgV6.EndpointWireguardRemove(peer2)
									err = wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(wgV6.DebugNodes()).To(HaveLen(3))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(0))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(0))
									Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeFalse())
									Expect(linkV6.WireguardPeers).To(HaveLen(1))
								}
							})

							It("should handle deletion of a wireguard peer over multiple applies: route, endpoint, wireguard", func() {
								if enableV4 {
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
								}
								if enableV6 {
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()

									// Remove the wireguard config for this peer. Wireguard config should be removed at this
									// point. The route should be converted to a throw route.
									By("Removing the wireguard configuration")
									wgV6.EndpointWireguardRemove(peer2)
									err := wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(wgV6.DebugNodes()).To(HaveLen(4))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(1))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveKey(routekeyV6_3))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(1))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveKey(routekeyV6_3))
									Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeTrue())
									Expect(rtDataplaneV6.RouteKeyToRoute[routekeyV6_3]).To(Equal(netlink.Route{
										LinkIndex: 1,
										Dst:       &ipnetV6_3,
										Type:      syscall.RTN_THROW,
										Protocol:  FelixRouteProtocol,
										Scope:     netlink.SCOPE_UNIVERSE,
										Table:     tableIndex,
									}))
									Expect(linkV6.WireguardPeers).To(HaveLen(1))
									Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer1))

									// Remove the route.
									By("Removing the route")
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()
									wgV6.RouteRemove(cidrV6_3)
									err = wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(wgV6.DebugNodes()).To(HaveLen(4))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(0))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(1))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveKey(routekeyV6_3))
									Expect(rtDataplaneV6.RouteKeyToRoute).ToNot(HaveKey(routekeyV6_3))
									Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeFalse())
									Expect(linkV6.WireguardPeers).To(HaveLen(1))

									// Remove the endpoint.
									// This is the last bit of configuration for the peer and so the node should be removed
									// from the cache.
									By("Removing the node")
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()
									wgV6.EndpointRemove(peer2)
									err = wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(wgV6.DebugNodes()).To(HaveLen(3))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(0))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(0))
									Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeFalse())
									Expect(linkV6.WireguardPeers).To(HaveLen(1))
								}
							})

							It("should handle deletion and re-adding an endpoint over multiple applies", func() {
								if enableV4 {
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
								}
								if enableV6 {
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()

									// Remove the endpoint. Wireguard config should be removed at this point. The route should
									// be converted to a throw route.
									By("Removing the node")
									wgV6.EndpointRemove(peer2)
									err := wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(wgV6.DebugNodes()).To(HaveLen(4))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(1))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveKey(routekeyV6_3))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(1))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveKey(routekeyV6_3))
									Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeTrue())
									Expect(linkV6.WireguardPeers).To(HaveLen(1))
									Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer1))
									Expect(rtDataplaneV6.RouteKeyToRoute[routekeyV6_3]).To(Equal(netlink.Route{
										LinkIndex: 1,
										Dst:       &ipnetV6_3,
										Type:      syscall.RTN_THROW,
										Protocol:  FelixRouteProtocol,
										Scope:     netlink.SCOPE_UNIVERSE,
										Table:     tableIndex,
									}))

									// Re-add the endpoint. Wireguard config will be added back in.
									By("Re-adding the node")
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()
									wgV6.EndpointUpdate(peer2, ipv6_peer2)
									err = wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(wgV6.DebugNodes()).To(HaveLen(4))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(1))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveKey(routekeyV6_3))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(1))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveKey(routekeyV6_3))
									Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeTrue())
									Expect(linkV6.WireguardPeers).To(HaveLen(2))
									Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer1))
									Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer2))
									Expect(rtDataplaneV6.RouteKeyToRoute[routekeyV6_3]).To(Equal(netlink.Route{
										LinkIndex: linkV6.LinkAttrs.Index,
										Dst:       &ipnetV6_3,
										Type:      syscall.RTN_UNICAST,
										Protocol:  FelixRouteProtocol,
										Scope:     netlink.SCOPE_LINK,
										Table:     tableIndex,
									}))
								}
							})

							It("should handle deletion and re-adding an endpoint in a single apply", func() {
								if enableV4 {
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
								}
								if enableV6 {
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()

									// Remove the endpoint. Wireguard config should be removed at this point. The route should
									// be converted to a throw route.
									By("Removing the node")
									wgV6.EndpointRemove(peer2)
									wgV6.EndpointUpdate(peer2, ipv6_peer2)
									err := wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(wgV6.DebugNodes()).To(HaveLen(4))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(0))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(0))
									Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeFalse())
									Expect(linkV6.WireguardPeers).To(HaveLen(2))
									Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer1))
									Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer2))
								}
							})

							It("should handle deletion and re-adding an endpoint with a different IP in a single apply", func() {
								if enableV4 {
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
								}
								if enableV6 {
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()

									// Remove the endpoint. Wireguard config should be removed at this point. The route should
									// be converted to a throw route.
									By("Removing the node")
									wgV6.EndpointRemove(peer2)
									wgV6.EndpointUpdate(peer2, ipv6_peer2_2)
									err := wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(wgV6.DebugNodes()).To(HaveLen(4))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(0))
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(0))
									Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeTrue())
									Expect(linkV6.WireguardPeers).To(HaveLen(2))
									Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer1))
									Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer2))
									Expect(linkV6.WireguardPeers[keyV6_peer2].Endpoint.IP).To(Equal(ipv6_peer2_2.AsNetIP()))
								}
							})

							It("should handle immediate and subsequent reuse after a node deletion", func() {
								if enableV4 {
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
								}
								if enableV6 {
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()
									wgV6.EndpointRemove(peer2)
									wgV6.EndpointWireguardRemove(peer2)
									wgV6.RouteRemove(cidrV6_3)
									wgV6.RouteUpdate(hostname, cidrV6_3)
									By("Applying deletion and IP moving to local host")
									err := wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveKey(routekeyV6_3))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveKey(routekeyV6_3))
									Expect(rtDataplaneV6.RouteKeyToRoute[routekeyV6_3]).To(Equal(netlink.Route{
										LinkIndex: 1,
										Dst:       &ipnetV6_3,
										Type:      syscall.RTN_THROW,
										Protocol:  FelixRouteProtocol,
										Scope:     netlink.SCOPE_UNIVERSE,
										Table:     tableIndex,
									}))

									By("Deleting local route")
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()
									wgV6.RouteRemove(cidrV6_3)
									err = wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(1))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(0))
									Expect(rtDataplaneV6.RouteKeyToRoute).NotTo(HaveKey(routekeyV6_3))

									By("Applying the same route to be remote")
									wgDataplaneV6.ResetDeltas()
									rtDataplaneV6.ResetDeltas()
									wgV6.RouteUpdate(peer1, cidrV6_3)
									err = wgV6.Apply()
									Expect(err).NotTo(HaveOccurred())
									Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(0))
									Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(1))
									Expect(rtDataplaneV6.RouteKeyToRoute[routekeyV6_3]).To(Equal(netlink.Route{
										LinkIndex: linkV6.LinkAttrs.Index,
										Dst:       &ipnetV6_3,
										Type:      syscall.RTN_UNICAST,
										Protocol:  FelixRouteProtocol,
										Scope:     netlink.SCOPE_LINK,
										Table:     tableIndex,
									}))
								}
							})
							Describe("move a route from peer1 to peer2 and a route from peer2 to peer3", func() {
								BeforeEach(func() {
									if enableV4 {
										wg.RouteRemove(cidr_2)
										wg.RouteUpdate(peer2, cidr_2)
										wg.RouteUpdate(peer3, cidr_3)
										rtDataplane.ResetDeltas()
										err := wg.Apply()
										Expect(err).NotTo(HaveOccurred())
									}
									if enableV6 {
										wgV6.RouteRemove(cidrV6_2)
										wgV6.RouteUpdate(peer2, cidrV6_2)
										wgV6.RouteUpdate(peer3, cidrV6_3)
										rtDataplaneV6.ResetDeltas()
										err := wgV6.Apply()
										Expect(err).NotTo(HaveOccurred())
									}
								})

								It("should have wireguard routes for peer1 and peer2", func() {
									if enableV4 {
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
									}
									if enableV6 {
										Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer1))
										Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer2))
										Expect(linkV6.WireguardPeers[keyV6_peer1]).To(Equal(wgtypes.Peer{
											PublicKey: keyV6_peer1,
											Endpoint: &net.UDPAddr{
												IP:   ipv6_peer1.AsNetIP(),
												Port: 1000,
											},
											AllowedIPs: []net.IPNet{ipnetV6_1},
										}))
										Expect(linkV6.WireguardPeers[keyV6_peer2]).To(Equal(wgtypes.Peer{
											PublicKey: keyV6_peer2,
											Endpoint: &net.UDPAddr{
												IP:   ipv6_peer2.AsNetIP(),
												Port: 1000,
											},
											AllowedIPs: []net.IPNet{ipnetV6_2},
										}))
									}
								})

								It("should reprogram the route to the non-wireguard peer only", func() {
									if enableV4 {
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
									}
									if enableV6 {
										Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(1))
										Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(1))
										Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveKey(routekeyV6_3))
										Expect(rtDataplaneV6.AddedRouteKeys).To(HaveKey(routekeyV6_3))
										Expect(rtDataplaneV6.RouteKeyToRoute[routekeyV6_3]).To(Equal(netlink.Route{
											LinkIndex: 1,
											Dst:       &ipnetV6_3,
											Type:      syscall.RTN_THROW,
											Protocol:  FelixRouteProtocol,
											Scope:     netlink.SCOPE_UNIVERSE,
											Table:     tableIndex,
										}))
									}
								})
							})

							Describe("enable wireguard on peer 3", func() {
								var key_peer3, keyV6_peer3 wgtypes.Key
								BeforeEach(func() {
									if enableV4 {
										key_peer3 = mustGeneratePrivateKey()
										wg.EndpointWireguardUpdate(peer3, key_peer3, nil)
										rtDataplane.ResetDeltas()
										err := wg.Apply()
										Expect(err).NotTo(HaveOccurred())
									}
									if enableV6 {
										keyV6_peer3 = mustGeneratePrivateKey()
										wgV6.EndpointWireguardUpdate(peer3, keyV6_peer3, nil)
										rtDataplaneV6.ResetDeltas()
										err := wgV6.Apply()
										Expect(err).NotTo(HaveOccurred())
									}
								})

								It("should have wireguard routes for all nodes", func() {
									if enableV4 {
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
									}
									if enableV6 {
										Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer1))
										Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer2))
										Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer3))
										Expect(linkV6.WireguardPeers[keyV6_peer1]).To(Equal(wgtypes.Peer{
											PublicKey: keyV6_peer1,
											Endpoint: &net.UDPAddr{
												IP:   ipv6_peer1.AsNetIP(),
												Port: 1000,
											},
											AllowedIPs: []net.IPNet{ipnetV6_1, ipnetV6_2},
										}))
										Expect(linkV6.WireguardPeers[keyV6_peer2]).To(Equal(wgtypes.Peer{
											PublicKey: keyV6_peer2,
											Endpoint: &net.UDPAddr{
												IP:   ipv6_peer2.AsNetIP(),
												Port: 1000,
											},
											AllowedIPs: []net.IPNet{ipnetV6_3},
										}))
										Expect(linkV6.WireguardPeers[keyV6_peer3]).To(Equal(wgtypes.Peer{
											PublicKey: keyV6_peer3,
											Endpoint: &net.UDPAddr{
												IP:   ipv6_peer3.AsNetIP(),
												Port: 1000,
											},
											AllowedIPs: []net.IPNet{ipnetV6_4},
										}))
									}
								})

								It("should reprogram the route to peer3 only", func() {
									if enableV4 {
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
									}
									if enableV6 {
										routekeyV6_4 := fmt.Sprintf("%d-%s", tableIndex, cidrV6_4)
										Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(1))
										Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(1))
										Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveKey(routekeyV6_4))
										Expect(rtDataplaneV6.AddedRouteKeys).To(HaveKey(routekeyV6_4))
										Expect(rtDataplaneV6.RouteKeyToRoute[routekeyV6_4]).To(Equal(netlink.Route{
											LinkIndex: linkV6.LinkAttrs.Index,
											Dst:       &ipnetV6_4,
											Type:      syscall.RTN_UNICAST,
											Protocol:  FelixRouteProtocol,
											Scope:     netlink.SCOPE_LINK,
											Table:     tableIndex,
										}))
									}
								})
							})
						})
					})
				})
			})
		})

		It("should create wireguard client if link activates immediately", func() {
			if enableV4 {
				wgDataplane.ImmediateLinkUp = true
				err := wg.Apply()
				Expect(err).NotTo(HaveOccurred())
				Expect(wgDataplane.NumLinkAddCalls).To(Equal(1))
				Expect(wgDataplane.WireguardOpen).To(BeTrue())
			}
			if enableV6 {
				wgDataplaneV6.ImmediateLinkUp = true
				err := wgV6.Apply()
				Expect(err).NotTo(HaveOccurred())
				Expect(wgDataplaneV6.NumLinkAddCalls).To(Equal(1))
				Expect(wgDataplaneV6.WireguardOpen).To(BeTrue())
			}
		})

		It("should create wireguard client and not attempt to create the link if link is already up", func() {
			if enableV4 {
				wgDataplane.AddIface(10, ifaceName, true, true)
				err := wg.Apply()
				Expect(err).NotTo(HaveOccurred())
				Expect(wgDataplane.NumLinkAddCalls).To(Equal(0))
				Expect(wgDataplane.WireguardOpen).To(BeTrue())
			}
			if enableV6 {
				wgDataplaneV6.AddIface(10, ifaceNameV6, true, true)
				err := wgV6.Apply()
				Expect(err).NotTo(HaveOccurred())
				Expect(wgDataplaneV6.NumLinkAddCalls).To(Equal(0))
				Expect(wgDataplaneV6.WireguardOpen).To(BeTrue())
			}
		})

		It("should update listen port and firewall mark but maintain correct key", func() {
			if enableV4 {
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
			}
			if enableV6 {
				key, err := wgtypes.GeneratePrivateKey()
				Expect(err).NotTo(HaveOccurred())
				wgDataplaneV6.AddIface(10, ifaceNameV6, true, true)
				linkV6 := wgDataplaneV6.NameToLink[ifaceNameV6]
				Expect(linkV6).ToNot(BeNil())
				linkV6.WireguardPrivateKey = key
				linkV6.WireguardPublicKey = key.PublicKey()
				linkV6.WireguardListenPort = 1010
				linkV6.WireguardFirewallMark = 11

				ipv6 := ip.FromString("2001:db8::1:2:3:4")
				wgV6.EndpointWireguardUpdate(hostname, key, ipv6)

				err = wgV6.Apply()
				Expect(err).NotTo(HaveOccurred())
				Expect(wgDataplaneV6.NumLinkAddCalls).To(Equal(0))
				Expect(wgDataplaneV6.WireguardOpen).To(BeTrue())

				linkV6 = wgDataplaneV6.NameToLink[ifaceNameV6]
				Expect(linkV6).ToNot(BeNil())
				Expect(linkV6.Addrs).To(HaveLen(1))
				Expect(linkV6.Addrs[0].IP).To(Equal(ipv6.AsNetIP()))
				Expect(wgDataplaneV6.WireguardOpen).To(BeTrue())
				Expect(linkV6.WireguardFirewallMark).To(Equal(10))
				Expect(linkV6.WireguardListenPort).To(Equal(1000))
				Expect(linkV6.WireguardPrivateKey).To(Equal(key))
				Expect(linkV6.WireguardPrivateKey.PublicKey()).To(Equal(linkV6.WireguardPublicKey))
				Expect(sV6.numStatusCallbacks).To(Equal(1))
			}
		})

		Describe("wireguard initially not supported", func() {
			BeforeEach(func() {
				if enableV4 {
					// Set the fail flags.
					wgDataplane.FailuresToSimulate = mocknetlink.FailNextLinkAddNotSupported

					// Set the wireguard interface ip address
					wg.EndpointWireguardUpdate(hostname, zeroKey, ipv4_peer1)

					// No error should occur
					err := wg.Apply()
					Expect(err).NotTo(HaveOccurred())
				}
				if enableV6 {
					// Set the fail flags.
					wgDataplaneV6.FailuresToSimulate = mocknetlink.FailNextLinkAddNotSupported

					// Set the wireguard interface ip address
					wgV6.EndpointWireguardUpdate(hostname, zeroKey, ipv6_peer1)

					// No error should occur
					err := wgV6.Apply()
					Expect(err).NotTo(HaveOccurred())
				}
			})

			It("should not create the wireguard interface", func() {
				if enableV4 {
					link := wgDataplane.NameToLink[ifaceName]
					Expect(link).To(BeNil())
				}
				if enableV6 {
					linkV6 := wgDataplaneV6.NameToLink[ifaceNameV6]
					Expect(linkV6).To(BeNil())
				}
			})

			It("should not create the wireguard interface after another apply", func() {
				if enableV4 {
					err := wg.Apply()
					Expect(err).NotTo(HaveOccurred())
					link := wgDataplane.NameToLink[ifaceName]
					Expect(link).To(BeNil())
				}
				if enableV6 {
					err := wgV6.Apply()
					Expect(err).NotTo(HaveOccurred())
					linkV6 := wgDataplaneV6.NameToLink[ifaceNameV6]
					Expect(linkV6).To(BeNil())
				}
			})

			It("should create the wireguard interface after a resync", func() {
				if enableV4 {
					wg.QueueResync()
					err := wg.Apply()
					Expect(err).NotTo(HaveOccurred())
					link := wgDataplane.NameToLink[ifaceName]
					Expect(link).ToNot(BeNil())
				}
				if enableV6 {
					wgV6.QueueResync()
					err := wgV6.Apply()
					Expect(err).NotTo(HaveOccurred())
					linkV6 := wgDataplaneV6.NameToLink[ifaceNameV6]
					Expect(linkV6).ToNot(BeNil())
				}
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
				var keyV6_peer1, keyV6_peer2 wgtypes.Key
				var routekey_1, routekey_2, routekey_3 string
				var routekeyV6_1, routekeyV6_2, routekeyV6_3 string
				var link, linkV6 *mocknetlink.MockLink

				BeforeEach(func() {
					if enableV4 {
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
					}
					if enableV6 {
						// Set the fail flags and reset errors.|
						Expect(wgDataplaneV6.FailuresToSimulate).To(Equal(mocknetlink.FailNone))
						Expect(rrDataplaneV6.FailuresToSimulate).To(Equal(mocknetlink.FailNone))
						Expect(rtDataplaneV6.FailuresToSimulate).To(Equal(mocknetlink.FailNone))
						if failFlags&(mocknetlink.FailNextRuleList|mocknetlink.FailNextRuleAdd) != 0 {
							rrDataplaneV6.FailuresToSimulate = failFlags
						} else {
							wgDataplaneV6.FailuresToSimulate = failFlags
						}
						wgDataplaneV6.ResetDeltas()
						rtDataplaneV6.ResetDeltas()
						rrDataplaneV6.ResetDeltas()

						// Expect exactly one error from the series of applies.
						apply := newApplyWithErrors(wgV6, 1)

						// Set the wireguard interface ip address
						wgV6.EndpointWireguardUpdate(hostname, zeroKey, ipv6_int1)
						err := apply.Apply()
						Expect(err).NotTo(HaveOccurred())

						// We expect the link to exist.
						linkV6 = wgDataplaneV6.NameToLink[ifaceNameV6]
						Expect(linkV6).ToNot(BeNil())
						routekeyV6_1 = fmt.Sprintf("%d-%s", tableIndex, cidrV6_1)
						routekeyV6_2 = fmt.Sprintf("%d-%s", tableIndex, cidrV6_2)
						routekeyV6_3 = fmt.Sprintf("%d-%s", tableIndex, cidrV6_3)

						// Set the interface to be up
						wgDataplaneV6.SetIface(ifaceNameV6, true, true)
						rtDataplaneV6.AddIface(linkV6.LinkAttrs.Index, ifaceNameV6, true, true)
						wgV6.OnIfaceStateChanged(ifaceNameV6, ifacemonitor.StateUp)
						err = apply.Apply()
						Expect(err).NotTo(HaveOccurred())

						// Change the wireguard interface ip address
						wgV6.EndpointWireguardUpdate(hostname, zeroKey, ipv6_int2)

						// Add a single wireguard peer with a single route
						keyV6_peer1 = mustGeneratePrivateKey()
						wgV6.EndpointWireguardUpdate(peer1, keyV6_peer1, nil)
						wgV6.EndpointUpdate(peer1, ipv6_peer1)
						wgV6.RouteUpdate(peer1, cidrV6_1)
						wgV6.RouteUpdate(peer1, cidrV6_2)

						// Add a single local workload CIDR to ensure we add a route rule.
						wgV6.RouteUpdate(hostname, cidrV6_local)

						// Apply - a single error should have been observed across all of the Applies.
						err = apply.Apply()
						Expect(wgDataplaneV6.FailuresToSimulate).To(Equal(mocknetlink.FailNone))
						Expect(rtDataplaneV6.FailuresToSimulate).To(Equal(mocknetlink.FailNone))
						Expect(err).NotTo(HaveOccurred())
						Expect(apply.LastError()).To(HaveOccurred())
					}
				})

				It("should correctly program the dataplane after a single failure", func() {
					if enableV4 {
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
					}
					if enableV6 {
						Expect(linkV6.LinkType).To(Equal("wireguard"))
						Expect(linkV6.LinkAttrs.MTU).To(Equal(2000))
						Expect(linkV6.Addrs).To(HaveLen(1))
						Expect(linkV6.Addrs[0].IP).To(Equal(ipv6_int2.AsNetIP()))

						Expect(linkV6.WireguardPeers).To(HaveLen(1))
						Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer1))
						Expect(linkV6.WireguardPeers[keyV6_peer1].AllowedIPs).To(ConsistOf(cidrV6_1.ToIPNet(), cidrV6_2.ToIPNet()))

						Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(3))
						Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(0))
						Expect(rtDataplaneV6.AddedRouteKeys).To(HaveKey(routekeyV6_1))
						Expect(rtDataplaneV6.AddedRouteKeys).To(HaveKey(routekeyV6_2))
						Expect(rtDataplaneV6.AddedRouteKeys).To(HaveKey(routekey_cidrV6_local))

						// All of these failures will trigger an attempt to get a either a new netlink or wireguard client.
						if failFlags&(mocknetlink.FailNextNewWireguard|mocknetlink.FailNextWireguardConfigureDevice|mocknetlink.FailNextWireguardDeviceByName) != 0 {
							Expect(wgDataplaneV6.NumNewWireguardCalls).To(Equal(2))
						} else if failFlags&(mocknetlink.FailNextRuleList|mocknetlink.FailNextRuleAdd) != 0 {
							Expect(rrDataplaneV6.NumNewNetlinkCalls).To(Equal(2))
						} else {
							Expect(wgDataplaneV6.NumNewNetlinkCalls).To(Equal(2))
						}
					}
				})

				for _, nextTestFailFlags := range []mocknetlink.FailFlags{
					mocknetlink.FailNextWireguardConfigureDevice, mocknetlink.FailNextRouteAdd, mocknetlink.FailNextRouteDel,
				} {
					failFlags := nextTestFailFlags
					desc := fmt.Sprintf("additional adds/deletes with another failure (%v)", failFlags)

					Describe(desc, func() {
						BeforeEach(func() {
							if enableV4 {
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
							}
							if enableV6 {
								// Set the fail flags and reset errors.
								if failFlags&mocknetlink.FailNextWireguardConfigureDevice != 0 {
									wgDataplaneV6.FailuresToSimulate = failFlags
								} else {
									rtDataplaneV6.FailuresToSimulate = failFlags
									rtDataplaneV6.PersistFailures = true
								}
								wgDataplaneV6.ResetDeltas()
								rtDataplaneV6.ResetDeltas()

								// Delete peer1
								wgV6.EndpointWireguardRemove(peer1)
								wgV6.EndpointRemove(peer1)
								wgV6.RouteRemove(cidrV6_1)
								wgV6.RouteRemove(cidrV6_2)

								// Add peer2 with one of the same CIDRs as the previous peer1, and one different CIDR
								keyV6_peer2 = mustGeneratePrivateKey()
								wgV6.EndpointWireguardUpdate(peer2, keyV6_peer2, nil)
								wgV6.EndpointUpdate(peer2, ipv6_peer2)
								wgV6.RouteUpdate(peer2, cidrV6_1)
								wgV6.RouteUpdate(peer2, cidrV6_3)

								// Apply.
								err := wgV6.Apply()
								Expect(err).To(HaveOccurred())
								rtDataplaneV6.PersistFailures = false

								err = wgV6.Apply()
								Expect(err).ToNot(HaveOccurred())
							}
						})

						It("should correctly program the dataplane after a second failure", func() {
							if enableV4 {
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
							}
							if enableV6 {
								Expect(linkV6.WireguardPeers).To(HaveLen(1))
								Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer2))
								Expect(linkV6.WireguardPeers[keyV6_peer2].AllowedIPs).To(Equal([]net.IPNet{cidrV6_1.ToIPNet(), cidrV6_3.ToIPNet()}))

								Expect(rtDataplaneV6.AddedRouteKeys).To(HaveLen(1))
								Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveLen(1))
								Expect(rtDataplaneV6.AddedRouteKeys).To(HaveKey(routekeyV6_3))
								Expect(rtDataplaneV6.DeletedRouteKeys).To(HaveKey(routekeyV6_2))

								if failFlags&mocknetlink.FailNextWireguardConfigureDevice != 0 {
									Expect(wgDataplaneV6.NumNewWireguardCalls).ToNot(Equal(0))
									Expect(rtDataplaneV6.NumNewNetlinkCalls).To(Equal(0))
								} else {
									Expect(rtDataplaneV6.NumNewNetlinkCalls).ToNot(Equal(0))
									Expect(wgDataplaneV6.NumNewWireguardCalls).To(Equal(0))
								}
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
					if enableV4 {
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
					}
					if enableV6 {
						// Set the fail flags and set link to automatically come up.
						wgDataplaneV6.FailuresToSimulate = failFlags
						wgDataplaneV6.ImmediateLinkUp = true

						// Set the wireguard interface ip address. No error should occur because "not supported" is perfectly
						// valid.
						wgV6.EndpointWireguardUpdate(hostname, zeroKey, ipv6_peer1)
						err := wgV6.Apply()
						Expect(err).NotTo(HaveOccurred())

						// Expect a zero key status update.
						Expect(sV6.statusKey).To(Equal(zeroKey))
						Expect(sV6.numStatusCallbacks).To(Equal(1))

						// Always expect to attempt to create the netlink client
						Expect(wgDataplaneV6.NumNewNetlinkCalls).To(Equal(1))
						if failFlags&mocknetlink.FailNextLinkAddNotSupported == 0 {
							// If we are not emulating netlink link-not-supported failure then we should also attempt to create
							// the wireguard client.
							Expect(wgDataplaneV6.NumNewWireguardCalls).To(Equal(1))
						}

						// Should not attempt any further updates
						wgDataplaneV6.ResetDeltas()
						err = wgV6.Apply()
						Expect(err).NotTo(HaveOccurred())
						Expect(wgDataplaneV6.NumNewNetlinkCalls).To(Equal(0))
						Expect(wgDataplaneV6.NumNewWireguardCalls).To(Equal(0))

						// Queue a resync and re-apply.
						wgV6.QueueResync()
						err = wgV6.Apply()
						Expect(err).NotTo(HaveOccurred())

						// Expect an updated public key and the previously failed client to have been re-requested.
						Expect(sV6.statusKey).NotTo(Equal(zeroKey))
						Expect(sV6.numStatusCallbacks).To(Equal(2))
						if failFlags&mocknetlink.FailNextNewWireguardNotSupported != 0 {
							// And if emulating the wireguard failure, we expect a call to that too.
							Expect(wgDataplaneV6.NumNewWireguardCalls).To(Equal(1))
						}

						// The previous netlink client is still ok - just wireguard wasn't supported, we should not attempt to
						// recreate the netlink client.
						Expect(wgDataplaneV6.NumNewNetlinkCalls).To(Equal(0))
					}
				})
			})
		}

		for _, port := range []int{listeningPort, listeningPort + 1} {
			configuredPort := port

			desc := fmt.Sprintf("wireguard dataplane needs updating (port=%d)", configuredPort)

			Describe(desc, func() {

				It("should handle a resync", func() {
					if enableV4 {
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
					}
					if enableV6 {
						keyV6_peer1 := mustGeneratePrivateKey().PublicKey()
						keyV6_peer2 := mustGeneratePrivateKey().PublicKey()
						keyV6_peer3 := mustGeneratePrivateKey().PublicKey()
						keyV6_peer4 := mustGeneratePrivateKey().PublicKey()

						wgV6.EndpointUpdate(hostname, ipv6_host)
						wgV6.EndpointUpdate(peer1, ipv6_peer1)
						wgV6.EndpointUpdate(peer2, ipv6_peer2)
						wgV6.EndpointUpdate(peer3, ipv6_peer3)
						wgV6.EndpointUpdate(peer4, ipv6_peer4)
						wgV6.EndpointWireguardUpdate(peer1, keyV6_peer1, nil)
						wgV6.EndpointWireguardUpdate(peer2, keyV6_peer2, nil)
						wgV6.EndpointWireguardUpdate(peer3, keyV6_peer3, nil)
						wgV6.EndpointWireguardUpdate(peer4, keyV6_peer3, nil) // Peer 3 and 4 declaring same public key
						wgV6.RouteUpdate(peer1, cidrV6_1)
						wgV6.RouteUpdate(peer2, cidrV6_2)
						wgV6.RouteUpdate(peer3, cidrV6_3)
						wgV6.RouteUpdate(peer4, cidrV6_4)

						wgDataplaneV6.AddIface(1, ifaceNameV6, true, true)
						linkV6 := wgDataplaneV6.NameToLink[ifaceNameV6]
						Expect(linkV6).NotTo(BeNil())
						linkV6.WireguardPeers = map[wgtypes.Key]wgtypes.Peer{
							keyV6_peer1: {
								PublicKey: keyV6_peer1,
								Endpoint: &net.UDPAddr{
									IP:   ipv6_peer1.AsNetIP(),
									Port: configuredPort,
								},
								AllowedIPs: []net.IPNet{}, // Need to add an entry (no deletes)
							},
							keyV6_peer2: {
								PublicKey: keyV6_peer2,
								Endpoint:  nil,
								AllowedIPs: []net.IPNet{
									cidrV6_2.ToIPNet(),
									cidrV6_3.ToIPNet(), // Need to delete an entry.
								},
							},
							keyV6_peer3: {
								PublicKey:  keyV6_peer3,
								Endpoint:   &net.UDPAddr{},
								AllowedIPs: []net.IPNet{},
							},
							keyV6_peer4: {
								PublicKey: keyV6_peer4,
								Endpoint:  &net.UDPAddr{},
								AllowedIPs: []net.IPNet{
									cidrV6_4.ToIPNet(),
								},
							},
						}

						// Apply the update.
						err := wgV6.Apply()
						Expect(err).NotTo(HaveOccurred())

						// Expect peer1 and peer2 to be updated and peer3 and peer4 to be deleted.
						linkV6 = wgDataplaneV6.NameToLink[ifaceNameV6]
						Expect(linkV6).NotTo(BeNil())
						Expect(linkV6.WireguardPeers).To(HaveLen(2))
						Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer1))
						Expect(linkV6.WireguardPeers).To(HaveKey(keyV6_peer2))
						Expect(linkV6.WireguardPeers[keyV6_peer1]).To(Equal(wgtypes.Peer{
							PublicKey: keyV6_peer1,
							Endpoint: &net.UDPAddr{
								IP:   ipv6_peer1.AsNetIP(),
								Port: listeningPort,
							},
							AllowedIPs: []net.IPNet{cidrV6_1.ToIPNet()},
						}))
						Expect(linkV6.WireguardPeers[keyV6_peer2]).To(Equal(wgtypes.Peer{
							PublicKey: keyV6_peer2,
							Endpoint: &net.UDPAddr{
								IP:   ipv6_peer2.AsNetIP(),
								Port: listeningPort,
							},
							AllowedIPs: []net.IPNet{cidrV6_2.ToIPNet()},
						}))

						// If the listening port was incorrect then we expect that to be included in the updated,
						// otherwise we do not.
						Expect(wgDataplaneV6.LastWireguardUpdates).To(HaveKey(keyV6_peer1))
						if configuredPort == listeningPort {
							Expect(wgDataplaneV6.LastWireguardUpdates[keyV6_peer1].Endpoint).To(BeNil())
						} else {
							Expect(wgDataplaneV6.LastWireguardUpdates[keyV6_peer1].Endpoint).NotTo(BeNil())
						}

						// Expect peer2 update to include the endpoint addr (since this was missing)
						Expect(wgDataplaneV6.LastWireguardUpdates).To(HaveKey(keyV6_peer2))
						Expect(wgDataplaneV6.LastWireguardUpdates[keyV6_peer2].Endpoint).NotTo(BeNil())

						// Expect peer1 to be an update and peer2 to be a full replace of CIDRs.
						Expect(wgDataplaneV6.LastWireguardUpdates[keyV6_peer1].ReplaceAllowedIPs).To(BeFalse())
						Expect(wgDataplaneV6.LastWireguardUpdates[keyV6_peer2].ReplaceAllowedIPs).To(BeTrue())
					}
				})
			})
		}
	}
})

var _ = Describe("Wireguard (disabled)", func() {
	var wgDataplane, rtDataplane, rrDataplane *mocknetlink.MockNetlinkDataplane
	var wgDataplaneV6, rtDataplaneV6, rrDataplaneV6 *mocknetlink.MockNetlinkDataplane
	var t *mocktime.MockTime
	var s, sV6 mockCallbacks
	var wg, wgV6 *Wireguard

	BeforeEach(func() {
		wgDataplane = mocknetlink.New()
		rtDataplane = mocknetlink.New()
		rrDataplane = mocknetlink.New()

		wgDataplaneV6 = mocknetlink.New()
		rtDataplaneV6 = mocknetlink.New()
		rrDataplaneV6 = mocknetlink.New()

		t = mocktime.New()
		// Setting an auto-increment greater than the route cleanup delay effectively
		// disables the grace period for these tests.
		t.SetAutoIncrement(11 * time.Second)

		config := &Config{
			Enabled:             false,
			EnabledV6:           false,
			ListeningPort:       1000,
			FirewallMark:        1,
			RoutingRulePriority: rulePriority,
			RoutingTableIndex:   tableIndex,
			InterfaceName:       ifaceName,
			InterfaceNameV6:     ifaceNameV6,
			MTU:                 1042,
			MTUV6:               1042,
		}

		wg = NewWithShims(
			hostname,
			config,
			4,
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

		wgV6 = NewWithShims(
			hostname,
			config,
			6,
			rtDataplaneV6.NewMockNetlink,
			rrDataplaneV6.NewMockNetlink,
			wgDataplaneV6.NewMockNetlink,
			wgDataplaneV6.NewMockWireguard,
			10*time.Second,
			t,
			FelixRouteProtocol,
			sV6.status,
			sV6.writeProcSys,
			logutils.NewSummarizer("test loop"),
		)
	})

	It("should be constructable", func() {
		Expect(wg).ToNot(BeNil())
		Expect(wgV6).ToNot(BeNil())
	})

	It("should not attempt to create the link", func() {
		err := wg.Apply()
		Expect(err).NotTo(HaveOccurred())
		err = wg.Apply()
		Expect(err).NotTo(HaveOccurred())
		Expect(wgDataplane.NumLinkAddCalls).To(Equal(0))
		Expect(wgDataplane.NumLinkDeleteCalls).To(Equal(0))

		err = wgV6.Apply()
		Expect(err).NotTo(HaveOccurred())
		err = wgV6.Apply()
		Expect(err).NotTo(HaveOccurred())
		Expect(wgDataplaneV6.NumLinkAddCalls).To(Equal(0))
		Expect(wgDataplaneV6.NumLinkDeleteCalls).To(Equal(0))
	})

	It("should handle deletion of the wireguard link", func() {
		wgDataplane.AddIface(1, ifaceName, true, true)
		err := wg.Apply()
		Expect(err).NotTo(HaveOccurred())
		Expect(wgDataplane.NumLinkAddCalls).To(Equal(0))
		Expect(wgDataplane.NumLinkDeleteCalls).To(Equal(1))
		Expect(wgDataplane.DeletedLinks).To(HaveKey(ifaceName))

		wgDataplaneV6.AddIface(1, ifaceNameV6, true, true)
		err = wgV6.Apply()
		Expect(err).NotTo(HaveOccurred())
		Expect(wgDataplaneV6.NumLinkAddCalls).To(Equal(0))
		Expect(wgDataplaneV6.NumLinkDeleteCalls).To(Equal(1))
		Expect(wgDataplaneV6.DeletedLinks).To(HaveKey(ifaceNameV6))
	})

	Describe("With some endpoint updates", func() {
		BeforeEach(func() {
			wg.EndpointUpdate(peer1, ipv4_peer1)
			wg.EndpointWireguardUpdate(peer1, mustGeneratePrivateKey().PublicKey(), nil)
			wg.RouteUpdate(peer1, cidr_1)
			err := wg.Apply()
			Expect(err).NotTo(HaveOccurred())

			wgV6.EndpointUpdate(peer1, ipv6_peer1)
			wgV6.EndpointWireguardUpdate(peer1, mustGeneratePrivateKey().PublicKey(), nil)
			wgV6.RouteUpdate(peer1, cidrV6_1)
			err = wgV6.Apply()
			Expect(err).NotTo(HaveOccurred())
		})

		It("should ignore the updates", func() {
			Expect(wgDataplane.NumLinkAddCalls).To(Equal(0))
			Expect(wgDataplane.NumLinkDeleteCalls).To(Equal(0))
			Expect(wgDataplane.WireguardConfigUpdated).To(BeFalse())

			Expect(wgDataplaneV6.NumLinkAddCalls).To(Equal(0))
			Expect(wgDataplaneV6.NumLinkDeleteCalls).To(Equal(0))
			Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeFalse())
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

			wgV6.RouteRemove(cidrV6_1)
			wgV6.EndpointRemove(peer1)
			wgV6.EndpointWireguardRemove(peer1)
			err = wgV6.Apply()
			Expect(err).NotTo(HaveOccurred())
			Expect(wgDataplaneV6.NumLinkAddCalls).To(Equal(0))
			Expect(wgDataplaneV6.NumLinkDeleteCalls).To(Equal(0))
			Expect(wgDataplaneV6.WireguardConfigUpdated).To(BeFalse())
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

				// Create an interface to delete.
				wgDataplaneV6.AddIface(1, ifaceNameV6, true, true)
				rtDataplaneV6.AddIface(1, ifaceNameV6, true, true)

				// Create a rule to route to the wireguard table.
				rrDataplaneV6.Rules = []netlink.Rule{
					{
						Family:   10,
						Priority: 0,
						Table:    255,
					},
					{
						Family: 10,
						Table:  tableIndex,
						Mark:   firewallMark,
						Invert: true,
					},
					{
						Family:   10,
						Priority: 32766,
						Table:    254,
					},
					{
						Family:   10,
						Priority: 32767,
						Table:    253,
					},
				}

				// Set the fail flags and reset errors. Routetable and Routerule modules have retry mechanisms built in
				// so need to persist failures in those cases.
				if failFlags&mocknetlink.FailNextRouteList != 0 {
					rtDataplaneV6.FailuresToSimulate = failFlags
					rtDataplaneV6.PersistFailures = true
				} else if failFlags&(mocknetlink.FailNextRuleList|mocknetlink.FailNextRuleDel) != 0 {
					rrDataplaneV6.FailuresToSimulate = failFlags
				} else {
					wgDataplaneV6.FailuresToSimulate = failFlags
				}

				// Apply the settings - this should remove wireguard config.
				err = wgV6.Apply()
				Expect(err).To(HaveOccurred())

				// The error should now resolve itself.
				rtDataplaneV6.PersistFailures = false
				err = wgV6.Apply()
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

				linkV6 := wgDataplaneV6.NameToLink[ifaceNameV6]
				Expect(linkV6).To(BeNil())

				// These errors will trigger netlink reconnection. The routetable retries multiple times, so just assert
				// there is >0 reconnections.
				if failFlags&mocknetlink.FailNextRouteList != 0 {
					Expect(rtDataplaneV6.NumNewNetlinkCalls).To(BeNumerically(">", 1))
				} else {
					Expect(wgDataplaneV6.NumNewNetlinkCalls).To(BeNumerically(">", 1))
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

				Expect(rrDataplaneV6.NumRuleDelCalls).ToNot(Equal(0))
				Expect(rrDataplaneV6.NumRuleAddCalls).To(Equal(0))
				Expect(rrDataplaneV6.Rules).To(Equal([]netlink.Rule{
					{
						Family:   10,
						Priority: 0,
						Table:    255,
					},
					{
						Family:   10,
						Priority: 32766,
						Table:    254,
					},
					{
						Family:   10,
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
	var wgFn func(bool, uint8)

	BeforeEach(func() {
		wgDataplane = mocknetlink.New()
		rtDataplane = mocknetlink.New()
		rrDataplane = mocknetlink.New()
		t = mocktime.New()
		t.SetAutoIncrement(11 * time.Second)

		wgFn = func(enabled bool, ipVersion uint8) {
			NewWithShims(
				hostname,
				&Config{
					Enabled:             enabled,
					EnabledV6:           enabled,
					ListeningPort:       1000,
					FirewallMark:        1,
					RoutingRulePriority: rulePriority,
					RoutingTableIndex:   0,
					InterfaceName:       ifaceName,
					InterfaceNameV6:     ifaceNameV6,
					MTU:                 1042,
					MTUV6:               1042,
				},
				ipVersion,
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
		Expect(func() { wgFn(true, 4) }).To(Panic())
		Expect(func() { wgFn(true, 6) }).To(Panic())
	})

	It("should not panic if wireguard is disabled", func() {
		Expect(func() { wgFn(false, 4) }).NotTo(Panic())
		Expect(func() { wgFn(false, 6) }).NotTo(Panic())
	})
	It("should panic with an invalid IP version", func() {
		Expect(func() { wgFn(false, 7) }).To(Panic())
		Expect(func() { wgFn(true, 7) }).To(Panic())
	})
})
