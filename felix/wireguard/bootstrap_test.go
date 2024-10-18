// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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
	"context"
	"errors"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/config"
	mocknetlink "github.com/projectcalico/calico/felix/netlinkshim/mocknetlink"
	. "github.com/projectcalico/calico/felix/wireguard"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/typha/pkg/discovery"
)

var (
	nodeName1 = "nodeName1"
	nodeName2 = "nodeName2"
	nodeName3 = "nodeName3"
	typha1    = discovery.Typha{
		Addr:     "1.2.3.4:2222",
		IP:       "1.2.3.4",
		NodeName: &nodeName1,
	}
	typha2 = discovery.Typha{
		Addr:     "1.2.5.5:1111",
		IP:       "1.2.3.5",
		NodeName: &nodeName2,
	}
	typha3 = discovery.Typha{
		Addr:     "1.2.6.7:1234",
		IP:       "1.2.6.7",
		NodeName: &nodeName3,
	}
	typha4 = discovery.Typha{
		Addr:     "1.2.6.7:1234",
		IP:       "",
		NodeName: nil,
	}
	typha1V6 = discovery.Typha{
		Addr:     "[2001:db8::1:2:3:4]:2222",
		IP:       "2001:db8::1:2:3:4",
		NodeName: &nodeName1,
	}
	typha2V6 = discovery.Typha{
		Addr:     "[2001:db8::1:2:5:5]:1111",
		IP:       "2001:db8::1:2:3:5",
		NodeName: &nodeName2,
	}
	typha3V6 = discovery.Typha{
		Addr:     "[2001:db8::1:2:6:7]:1234",
		IP:       "2001:db8::1:2:6:7",
		NodeName: &nodeName3,
	}
	typha4V6 = discovery.Typha{
		Addr:     "[2001:db8::1:2:6:7]:1234",
		IP:       "",
		NodeName: nil,
	}
	node1PrivateKey, _   = wgtypes.GeneratePrivateKey()
	node1PrivateKeyV6, _ = wgtypes.GeneratePrivateKey()
	node2PrivateKey, _   = wgtypes.GeneratePrivateKey()
	node2PrivateKeyV6, _ = wgtypes.GeneratePrivateKey()
	node1V4              = &libapiv3.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: nodeName1,
		},
		Status: libapiv3.NodeStatus{
			WireguardPublicKey: node1PrivateKey.PublicKey().String(),
		},
	}
	node1V6 = &libapiv3.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: nodeName1,
		},
		Status: libapiv3.NodeStatus{
			WireguardPublicKeyV6: node1PrivateKeyV6.PublicKey().String(),
		},
	}
	node1V4V6 = &libapiv3.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: nodeName1,
		},
		Status: libapiv3.NodeStatus{
			WireguardPublicKey:   node1PrivateKey.PublicKey().String(),
			WireguardPublicKeyV6: node1PrivateKeyV6.PublicKey().String(),
		},
	}
	node2V4 = &libapiv3.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: nodeName2,
		},
		Status: libapiv3.NodeStatus{
			WireguardPublicKey: node2PrivateKey.PublicKey().String(),
		},
	}
	node2V6 = &libapiv3.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: nodeName2,
		},
		Status: libapiv3.NodeStatus{
			WireguardPublicKeyV6: node2PrivateKeyV6.PublicKey().String(),
		},
	}
	node2V4V6 = &libapiv3.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: nodeName2,
		},
		Status: libapiv3.NodeStatus{
			WireguardPublicKey:   node2PrivateKey.PublicKey().String(),
			WireguardPublicKeyV6: node2PrivateKeyV6.PublicKey().String(),
		},
	}
	// node3 has neither IPv4 nor IPv6 wireguard config
	node3 = &libapiv3.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: nodeName3,
		},
		Status: libapiv3.NodeStatus{
			WireguardPublicKey:   "",
			WireguardPublicKeyV6: "",
		},
	}
)

func newMockClient() *mockClient {
	return &mockClient{
		nodes: make(map[string]*libapiv3.Node),
	}
}

type mockClient struct {
	clientv3.Interface
	clientv3.NodeInterface

	numGets         int
	numUpdates      int
	numGetErrors    int
	numUpdateErrors int
	nodes           map[string]*libapiv3.Node
}

func (c *mockClient) Nodes() clientv3.NodeInterface {
	return c
}

func (c *mockClient) Get(_ context.Context, name string, _ options.GetOptions) (*libapiv3.Node, error) {
	c.numGets++
	if c.numGetErrors > 0 {
		c.numGetErrors--
		return nil, errors.New("Generic error getting node")
	}
	n, ok := c.nodes[name]
	if !ok {
		return nil, errors.New("Generic error getting node")
	}
	return n.DeepCopy(), nil
}

func (c *mockClient) Update(_ context.Context, res *libapiv3.Node, _ options.SetOptions) (*libapiv3.Node, error) {
	c.numUpdates++
	if c.numUpdateErrors > 0 {
		c.numUpdateErrors--
		return nil, errors.New("Generic error updating node")
	}
	n, ok := c.nodes[res.Name]
	if !ok {
		return nil, errors.New("Generic error updating node")
	}
	c.nodes[res.Name] = res
	return n, nil
}

var _ = Describe("Wireguard bootstrapping", func() {
	var nodeClient *mockClient
	var netlinkDataplane *mocknetlink.MockNetlinkDataplane
	var configParams *config.Config

	type testConf struct {
		EnableIPv4 bool
		EnableIPv6 bool
	}
	for _, testConfig := range []testConf{
		{true, false},
		{false, true},
		{true, true},
	} {
		enableIPv4 := testConfig.EnableIPv4
		enableIPv6 := testConfig.EnableIPv6
		Describe(fmt.Sprintf("IPv4 enabled: %v, IPv6 enabled: %v", enableIPv4, enableIPv6), func() {
			BeforeEach(func() {
				nodeClient = newMockClient()
				netlinkDataplane = mocknetlink.New()
			})

			Context("HostEncryption is not enabled but wireguard is", func() {
				BeforeEach(func() {
					configParams = &config.Config{
						WireguardHostEncryptionEnabled: false,
						WireguardEnabled:               enableIPv4,
						WireguardEnabledV6:             enableIPv6,
						WireguardInterfaceName:         "wireguard.cali",
						WireguardInterfaceNameV6:       "wg-v6.cali",
						FelixHostname:                  nodeName1,
					}
				})

				It("no-ops for BootstrapAndFilterTyphaAddresses", func() {
					// We need to add the local node to nodeClient as it may need to be accessed by
					// bootstrapping to remove wireguard
					var numGets, numNewNetlinkCalls int
					if enableIPv4 && enableIPv6 {
						nodeClient.nodes[nodeName1] = node1V4V6.DeepCopy()
						numGets = 0
						numNewNetlinkCalls = 0
					} else if enableIPv4 {
						nodeClient.nodes[nodeName1] = node1V4.DeepCopy()
						numGets = 1
						numNewNetlinkCalls = 1
					} else if enableIPv6 {
						nodeClient.nodes[nodeName1] = node1V6.DeepCopy()
						numGets = 1
						numNewNetlinkCalls = 1
					}

					f, err := BootstrapAndFilterTyphaAddresses(
						configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient, nil,
					)
					Expect(err).ToNot(HaveOccurred())
					Expect(f).To(BeNil())
					Expect(nodeClient.numGets).To(Equal(numGets))
					Expect(nodeClient.numUpdates).To(BeZero())
					Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(numNewNetlinkCalls))
					Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
				})

				It("no-ops for RemoveWireguardForHostEncryptionBootstrapping", func() {
					err := RemoveWireguardConditionallyOnBootstrap(
						configParams,
						netlinkDataplane.NewMockNetlink,
						nodeClient,
					)
					Expect(err).ToNot(HaveOccurred())
					Expect(nodeClient.numGets).To(BeZero())
					Expect(nodeClient.numUpdates).To(BeZero())
					Expect(netlinkDataplane.NumNewNetlinkCalls).To(BeZero())
					Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
				})
			})

			Context("Wireguard is programmed in the kernel for node 2 and not node 3", func() {
				var link, linkV6 *mocknetlink.MockLink
				BeforeEach(func() {
					configParams = &config.Config{
						WireguardHostEncryptionEnabled: true,
						WireguardEnabled:               enableIPv4,
						WireguardEnabledV6:             enableIPv6,
						WireguardInterfaceName:         "wireguard.cali",
						WireguardInterfaceNameV6:       "wg-v6.cali",
						FelixHostname:                  nodeName1,
					}
					if enableIPv4 {
						la := netlink.NewLinkAttrs()
						la.Name = "wireguard.cali"
						la.Index = 10
						link = &mocknetlink.MockLink{
							LinkAttrs:           la,
							LinkType:            "wireguard",
							WireguardPrivateKey: node1PrivateKey,
							WireguardPublicKey:  node1PrivateKey.PublicKey(),
							WireguardPeers: map[wgtypes.Key]wgtypes.Peer{
								node2PrivateKey.PublicKey(): {
									PublicKey: node2PrivateKey.PublicKey(),
								},
							},
						}
						netlinkDataplane.NameToLink["wireguard.cali"] = link
					}
					if enableIPv6 {
						la := netlink.NewLinkAttrs()
						la.Name = "wg-v6.cali"
						la.Index = 10
						linkV6 = &mocknetlink.MockLink{
							LinkAttrs:           la,
							LinkType:            "wireguard",
							WireguardPrivateKey: node1PrivateKeyV6,
							WireguardPublicKey:  node1PrivateKeyV6.PublicKey(),
							WireguardPeers: map[wgtypes.Key]wgtypes.Peer{
								node2PrivateKeyV6.PublicKey(): {
									PublicKey: node2PrivateKeyV6.PublicKey(),
								},
							},
						}
						netlinkDataplane.NameToLink["wg-v6.cali"] = linkV6
					}
					if enableIPv4 && enableIPv6 {
						nodeClient.nodes[nodeName1] = node1V4V6.DeepCopy()
						nodeClient.nodes[nodeName2] = node2V4V6.DeepCopy()
					} else if enableIPv4 {
						nodeClient.nodes[nodeName1] = node1V4.DeepCopy()
						nodeClient.nodes[nodeName2] = node2V4.DeepCopy()
					} else if enableIPv6 {
						nodeClient.nodes[nodeName1] = node1V6.DeepCopy()
						nodeClient.nodes[nodeName2] = node2V6.DeepCopy()
					}
					nodeClient.nodes[nodeName3] = node3.DeepCopy()
				})

				It("returns the correct filtered typhas when calling BootstrapAndFilterTyphaAddresses", func() {
					var numGets, numNewNetlinkCalls, numNewWireguardCalls int
					if enableIPv4 && enableIPv6 {
						numGets = 6
						numNewNetlinkCalls = 0
						numNewWireguardCalls = 2
					} else {
						numGets = 4
						numNewNetlinkCalls = 1
						numNewWireguardCalls = 1
					}
					typhas := []discovery.Typha{}
					if enableIPv4 {
						typhas = append(typhas, typha1, typha2, typha3, typha4)
					}
					if enableIPv6 {
						typhas = append(typhas, typha1V6, typha2V6, typha3V6, typha4V6)
					}

					f, err := BootstrapAndFilterTyphaAddresses(
						configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient, typhas,
					)
					Expect(err).ToNot(HaveOccurred())

					// We expect all typhas:
					// typha1 (local), typha2 (key is in kernel), typha3 (no key and IP not in kernel), typha4 (missing in client)
					Expect(f).To(Equal(typhas))

					// Get for local node and the two remote typhas with node names.
					Expect(nodeClient.numGets).To(Equal(numGets))

					// No updates made.
					Expect(nodeClient.numUpdates).To(Equal(0))
					Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(numNewNetlinkCalls))
					Expect(netlinkDataplane.NumNewWireguardCalls).To(Equal(numNewWireguardCalls))
				})

				It("returns the correct filtered typhas (filters out missing key) when calling BootstrapAndFilterTyphaAddresses", func() {
					var numGets, numNewNetlinkCalls, numNewWireguardCalls int
					if enableIPv4 && enableIPv6 {
						numGets = 6
						numNewNetlinkCalls = 0
						numNewWireguardCalls = 2
					} else {
						numGets = 4
						numNewNetlinkCalls = 1
						numNewWireguardCalls = 1
					}
					typhas := []discovery.Typha{}
					expectedTyphas := []discovery.Typha{}
					if enableIPv4 {
						typhas = append(typhas, typha1, typha2, typha3, typha4)
						expectedTyphas = append(expectedTyphas, typha1, typha3, typha4)

						delete(link.WireguardPeers, node2PrivateKey.PublicKey())
						pvt, _ := wgtypes.GeneratePrivateKey()
						link.WireguardPeers[pvt.PublicKey()] = wgtypes.Peer{
							PublicKey: pvt.PublicKey(),
						}
					}
					if enableIPv6 {
						typhas = append(typhas, typha1V6, typha2V6, typha3V6, typha4V6)
						expectedTyphas = append(expectedTyphas, typha1V6, typha3V6, typha4V6)

						delete(linkV6.WireguardPeers, node2PrivateKeyV6.PublicKey())
						pvt, _ := wgtypes.GeneratePrivateKey()
						linkV6.WireguardPeers[pvt.PublicKey()] = wgtypes.Peer{
							PublicKey: pvt.PublicKey(),
						}
					}

					f, err := BootstrapAndFilterTyphaAddresses(
						configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient, typhas,
					)
					Expect(err).ToNot(HaveOccurred())

					// We expect typhas:
					// typha1 (local), typha3 (no key and IP not in kernel), typha4 (missing in client)
					// Filtered:
					// typha2 (key is not in kernel)
					Expect(f).To(Equal(expectedTyphas))

					// Get for local node and the two remote typhas with node names.
					Expect(nodeClient.numGets).To(Equal(numGets))

					// No updates.
					Expect(nodeClient.numUpdates).To(Equal(0))
					Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(numNewNetlinkCalls))
					Expect(netlinkDataplane.NumNewWireguardCalls).To(Equal(numNewWireguardCalls))
				})

				It("returns all typhas and deletes wireguard if all typhas would be filtered when calling BootstrapAndFilterTyphaAddresses", func() {
					typhas := []discovery.Typha{}
					if enableIPv4 {
						typhas = append(typhas, typha2)

						delete(link.WireguardPeers, node2PrivateKey.PublicKey())
						pvt, _ := wgtypes.GeneratePrivateKey()
						link.WireguardPeers[pvt.PublicKey()] = wgtypes.Peer{
							PublicKey: pvt.PublicKey(),
						}
					}
					if enableIPv6 {
						typhas = append(typhas, typha2V6)

						delete(linkV6.WireguardPeers, node2PrivateKeyV6.PublicKey())
						pvt, _ := wgtypes.GeneratePrivateKey()
						linkV6.WireguardPeers[pvt.PublicKey()] = wgtypes.Peer{
							PublicKey: pvt.PublicKey(),
						}
					}
					var numGets, numUpdates, numNewWireguardCalls int
					if enableIPv4 && enableIPv6 {
						numGets = 6
						numUpdates = 2
						numNewWireguardCalls = 2
					} else {
						numGets = 4
						numUpdates = 1
						numNewWireguardCalls = 1
					}

					f, err := BootstrapAndFilterTyphaAddresses(
						configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient, typhas,
					)
					Expect(err).ToNot(HaveOccurred())

					// All typhas would be filtered out (missing key and IP in kernel). Therefore wireguard will be deleted and
					// no typhas will be filtered out.
					Expect(f).To(Equal(typhas))

					// Get for local node, one remote node for typha, local node for deleting WG.
					Expect(nodeClient.numGets).To(Equal(numGets))
					Expect(nodeClient.numUpdates).To(Equal(numUpdates))

					Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(2))
					Expect(netlinkDataplane.NumNewWireguardCalls).To(Equal(numNewWireguardCalls))

					// Device will be deleted.
					Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wireguard.cali"))
					Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
					Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wg-v6.cali"))
					Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKeyV6).To(Equal(""))
				})

				It("deletes all wireguard from node 1 if public key does not match kernel when calling BootstrapAndFilterTyphaAddresses", func() {
					typhas := []discovery.Typha{}
					if enableIPv4 {
						otherKey, _ := wgtypes.GeneratePrivateKey()
						link.WireguardPrivateKey = otherKey
						link.WireguardPublicKey = otherKey.PublicKey()
						typhas = append(typhas, typha2, typha3)
					}
					if enableIPv6 {
						otherKey, _ := wgtypes.GeneratePrivateKey()
						linkV6.WireguardPrivateKey = otherKey
						linkV6.WireguardPublicKey = otherKey.PublicKey()
						typhas = append(typhas, typha2V6, typha3V6)
					}
					var numGets, numUpdates, numNewWireguardCalls int
					if enableIPv4 && enableIPv6 {
						numGets = 4
						numUpdates = 2
						numNewWireguardCalls = 2
					} else {
						numGets = 3
						numUpdates = 1
						numNewWireguardCalls = 1
					}

					f, err := BootstrapAndFilterTyphaAddresses(
						configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient, typhas,
					)
					Expect(err).ToNot(HaveOccurred())
					Expect(f).To(Equal(typhas)) // Should be unchanged.
					// Two gets - once for the check, once for the update.
					Expect(nodeClient.numGets).To(Equal(numGets))
					Expect(nodeClient.numUpdates).To(Equal(numUpdates))
					Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(2))
					Expect(netlinkDataplane.NumNewWireguardCalls).To(Equal(numNewWireguardCalls))
					Expect(netlinkDataplane.NetlinkOpen).To(BeFalse())
					Expect(netlinkDataplane.WireguardOpen).To(BeFalse())

					if enableIPv4 {
						Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wireguard.cali"))
						Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
					}
					if enableIPv6 {
						Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wg-v6.cali"))
						Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKeyV6).To(Equal(""))
					}
				})

				It("RemoveWireguardForHostEncryptionBootstrapping deletes all wireguard configuration", func() {
					var numGets, numUpdates, numNewNetlinkCalls int
					if enableIPv4 && enableIPv6 {
						numGets = 2
						numUpdates = 2
						numNewNetlinkCalls = 2
					} else {
						numGets = 1
						numUpdates = 1
						numNewNetlinkCalls = 1
					}
					err := RemoveWireguardConditionallyOnBootstrap(
						configParams,
						netlinkDataplane.NewMockNetlink,
						nodeClient,
					)
					Expect(err).ToNot(HaveOccurred())
					Expect(nodeClient.numGets).To(Equal(numGets))
					Expect(nodeClient.numUpdates).To(Equal(numUpdates))
					Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(numNewNetlinkCalls))
					Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
					Expect(netlinkDataplane.NetlinkOpen).To(BeFalse())
					Expect(netlinkDataplane.WireguardOpen).To(BeFalse())
					Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wireguard.cali"))
					Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
					Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wg-v6.cali"))
					Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKeyV6).To(Equal(""))
				})

				It("RemoveWireguardForHostEncryptionBootstrapping deletes key from node even if device is not found", func() {
					var numGets, numUpdates, numNewNetlinkCalls int
					if enableIPv4 && enableIPv6 {
						delete(netlinkDataplane.NameToLink, "wireguard.cali")
						delete(netlinkDataplane.NameToLink, "wg-v6.cali")
						numGets = 2
						numUpdates = 2
						numNewNetlinkCalls = 2
					} else if enableIPv4 {
						delete(netlinkDataplane.NameToLink, "wireguard.cali")
						numGets = 1
						numUpdates = 1
						numNewNetlinkCalls = 1
					} else if enableIPv6 {
						delete(netlinkDataplane.NameToLink, "wg-v6.cali")
						numGets = 1
						numUpdates = 1
						numNewNetlinkCalls = 1
					}
					err := RemoveWireguardConditionallyOnBootstrap(
						configParams,
						netlinkDataplane.NewMockNetlink,
						nodeClient,
					)
					Expect(err).ToNot(HaveOccurred())
					Expect(nodeClient.numGets).To(Equal(numGets))
					Expect(nodeClient.numUpdates).To(Equal(numUpdates))
					Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(numNewNetlinkCalls))
					Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
					Expect(netlinkDataplane.NetlinkOpen).To(BeFalse())
					Expect(netlinkDataplane.WireguardOpen).To(BeFalse())
					Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wireguard.cali"))
					Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wg-v6.cali"))
					Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
					Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKeyV6).To(Equal(""))
				})

				It("RemoveWireguardForHostEncryptionBootstrapping deletes all wireguard config with temporary netlink and client errors", func() {
					var numGets, numUpdates, numNewNetlinkCalls int
					if enableIPv4 && enableIPv6 {
						numGets = 6
						numUpdates = 4
						numNewNetlinkCalls = 2
						nodeClient.numGetErrors = 2
						nodeClient.numUpdateErrors = 2
					} else {
						numGets = 4
						numUpdates = 2
						numNewNetlinkCalls = 1
						nodeClient.numGetErrors = 2
						nodeClient.numUpdateErrors = 1
					}
					netlinkDataplane.FailuresToSimulate = mocknetlink.FailNextLinkByName | mocknetlink.FailNextLinkDel

					err := RemoveWireguardConditionallyOnBootstrap(
						configParams,
						netlinkDataplane.NewMockNetlink,
						nodeClient,
					)
					Expect(err).ToNot(HaveOccurred())
					// 2 failures, 1 get + failed update, 1 get +  successful update.
					Expect(nodeClient.numGets).To(Equal(numGets))
					Expect(nodeClient.numUpdates).To(Equal(numUpdates))
					Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(numNewNetlinkCalls))
					Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
					Expect(netlinkDataplane.NetlinkOpen).To(BeFalse())
					Expect(netlinkDataplane.WireguardOpen).To(BeFalse())
					Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wireguard.cali"))
					Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wg-v6.cali"))
					Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
					Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKeyV6).To(Equal(""))
				})

				It("RemoveWireguardForHostEncryptionBootstrapping deletes public key but leaves link with permanent netlink errors", func() {
					var numGets, numUpdates, numNewNetlinkCalls int
					if enableIPv4 && enableIPv6 {
						numGets = 2
						numUpdates = 2
						numNewNetlinkCalls = 2
					} else {
						numGets = 1
						numUpdates = 1
						numNewNetlinkCalls = 1
					}
					netlinkDataplane.FailuresToSimulate = mocknetlink.FailNextLinkByName | mocknetlink.FailNextLinkDel
					netlinkDataplane.PersistFailures = true
					err := RemoveWireguardConditionallyOnBootstrap(
						configParams,
						netlinkDataplane.NewMockNetlink,
						nodeClient,
					)
					Expect(err).To(HaveOccurred())
					// 2 failures, 1 get + failed update, 1 get +  successful update.
					Expect(nodeClient.numGets).To(Equal(numGets))
					Expect(nodeClient.numUpdates).To(Equal(numUpdates))
					Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(numNewNetlinkCalls))
					Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
					Expect(netlinkDataplane.NetlinkOpen).To(BeFalse())
					Expect(netlinkDataplane.WireguardOpen).To(BeFalse())
					if enableIPv4 {
						Expect(netlinkDataplane.NameToLink).To(HaveKey("wireguard.cali"))
					}
					if enableIPv6 {
						Expect(netlinkDataplane.NameToLink).To(HaveKey("wg-v6.cali"))
					}
					Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
					Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKeyV6).To(Equal(""))
				})

				It("RemoveWireguardForHostEncryptionBootstrapping deletes device but leaves key with too many client errors", func() {
					var numGets, numNewNetlinkCalls int
					if enableIPv4 && enableIPv6 {
						nodeClient.numGetErrors = 10
						numGets = 10
						numNewNetlinkCalls = 2
					} else if enableIPv4 {
						nodeClient.numGetErrors = 5
						numGets = 5
						numNewNetlinkCalls = 1
					} else if enableIPv6 {
						nodeClient.numGetErrors = 5
						numGets = 5
						numNewNetlinkCalls = 1
					}
					err := RemoveWireguardConditionallyOnBootstrap(
						configParams,
						netlinkDataplane.NewMockNetlink,
						nodeClient,
					)
					Expect(err).To(HaveOccurred())
					Expect(nodeClient.numGets).To(Equal(numGets))
					Expect(nodeClient.numUpdates).To(BeZero())
					Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(numNewNetlinkCalls))
					Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
					Expect(netlinkDataplane.NetlinkOpen).To(BeFalse())
					Expect(netlinkDataplane.WireguardOpen).To(BeFalse())
					Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wireguard.cali"))
					Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wg-v6.cali"))
					if enableIPv4 {
						Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).ToNot(Equal(""))
					}
					if enableIPv6 {
						Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKeyV6).ToNot(Equal(""))
					}
				})

				It("deletes all wireguard from node 1 if wireguard is disabled when calling BootstrapAndFilterTyphaAddresses", func() {
					configParams.WireguardHostEncryptionEnabled = false
					configParams.WireguardEnabled = false
					configParams.WireguardEnabledV6 = false

					typhas := []discovery.Typha{}
					var numUpdates int
					if enableIPv4 && enableIPv6 {
						typhas = append(typhas, typha2, typha3, typha2V6, typha3V6)
						numUpdates = 2
					} else if enableIPv4 {
						typhas = append(typhas, typha2, typha3)
						numUpdates = 1
					} else if enableIPv6 {
						typhas = append(typhas, typha2V6, typha3V6)
						numUpdates = 1
					}
					f, err := BootstrapAndFilterTyphaAddresses(
						configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient, typhas,
					)
					Expect(err).ToNot(HaveOccurred())
					Expect(f).To(Equal(typhas))
					Expect(nodeClient.numGets).To(Equal(2))
					Expect(nodeClient.numUpdates).To(Equal(numUpdates))
					Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(2))
					Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
					Expect(netlinkDataplane.NetlinkOpen).To(BeFalse())
					Expect(netlinkDataplane.WireguardOpen).To(BeFalse())
					Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wireguard.cali"))
					Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wg-v6.cali"))
					Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
					Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKeyV6).To(Equal(""))
				})

				It("deletes wireguard key from node 1 if wireguard interface is empty when calling BootstrapAndFilterTyphaAddresses", func() {
					configParams.WireguardInterfaceName = ""
					configParams.WireguardInterfaceNameV6 = ""

					var numUpdates int
					typhas := []discovery.Typha{}
					if enableIPv4 && enableIPv6 {
						numUpdates = 2
						typhas = append(typhas, typha2, typha3, typha2V6, typha3V6)
					} else if enableIPv4 {
						numUpdates = 1
						typhas = append(typhas, typha2, typha3)
					} else if enableIPv6 {
						numUpdates = 1
						typhas = append(typhas, typha2V6, typha3V6)
					}
					f, err := BootstrapAndFilterTyphaAddresses(
						configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient, typhas,
					)
					Expect(err).ToNot(HaveOccurred())
					Expect(f).To(Equal(typhas))
					Expect(nodeClient.numGets).To(Equal(2))
					Expect(nodeClient.numUpdates).To(Equal(numUpdates))
					Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(0))
					Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
					Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
					Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKeyV6).To(Equal(""))
				})

				It("deletes wireguard key from node 1 if wireguard interface is not present when calling BootstrapAndFilterTyphaAddresses", func() {
					delete(netlinkDataplane.NameToLink, "wireguard.cali")
					delete(netlinkDataplane.NameToLink, "wg-v6.cali")

					typhas := []discovery.Typha{}
					var numUpdates, numNewWireguardCalls int
					if enableIPv4 && enableIPv6 {
						typhas = append(typhas, typha2, typha3, typha2V6, typha3V6)
						numUpdates = 2
						numNewWireguardCalls = 2
					} else if enableIPv4 {
						typhas = append(typhas, typha2, typha3)
						numUpdates = 1
						numNewWireguardCalls = 1
					} else if enableIPv6 {
						typhas = append(typhas, typha2V6, typha3V6)
						numUpdates = 1
						numNewWireguardCalls = 1
					}
					f, err := BootstrapAndFilterTyphaAddresses(
						configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient, typhas,
					)
					Expect(err).ToNot(HaveOccurred())
					Expect(f).To(Equal(typhas))
					Expect(nodeClient.numGets).To(Equal(2))
					Expect(nodeClient.numUpdates).To(Equal(numUpdates))
					Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(2))
					Expect(netlinkDataplane.NumNewWireguardCalls).To(Equal(numNewWireguardCalls))
					Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
					Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKeyV6).To(Equal(""))
				})

				It("deletes wireguard key from node 1 if wireguard interface has no peers when calling BootstrapAndFilterTyphaAddresses", func() {
					if enableIPv4 {
						link.WireguardPeers = nil
					}
					if enableIPv6 {
						linkV6.WireguardPeers = nil
					}

					typhas := []discovery.Typha{}
					var numUpdates, numNewWireguardCalls int
					if enableIPv4 && enableIPv6 {
						typhas = append(typhas, typha2, typha3, typha2V6, typha3V6)
						numUpdates = 2
						numNewWireguardCalls = 2
					} else if enableIPv4 {
						typhas = append(typhas, typha2, typha3)
						numUpdates = 1
						numNewWireguardCalls = 1
					} else if enableIPv6 {
						typhas = append(typhas, typha2V6, typha3V6)
						numUpdates = 1
						numNewWireguardCalls = 1
					}
					f, err := BootstrapAndFilterTyphaAddresses(
						configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient, typhas,
					)
					Expect(err).ToNot(HaveOccurred())
					Expect(f).To(Equal(typhas))
					Expect(nodeClient.numGets).To(Equal(2))
					Expect(nodeClient.numUpdates).To(Equal(numUpdates))
					Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(2))
					Expect(netlinkDataplane.NumNewWireguardCalls).To(Equal(numNewWireguardCalls))
					Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wireguard.cali"))
					Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wg-v6.cali"))
					Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
					Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKeyV6).To(Equal(""))
				})
			})
		})
	}
})
