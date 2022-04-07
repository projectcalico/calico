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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
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
	node1PrivateKey, _ = wgtypes.GeneratePrivateKey()
	node2PrivateKey, _ = wgtypes.GeneratePrivateKey()
	node1              = &libapiv3.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: nodeName1,
		},
		Status: libapiv3.NodeStatus{
			WireguardPublicKey: node1PrivateKey.PublicKey().String(),
		},
	}
	node2 = &libapiv3.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: nodeName2,
		},
		Status: libapiv3.NodeStatus{
			WireguardPublicKey: node2PrivateKey.PublicKey().String(),
		},
	}
	node3 = &libapiv3.Node{
		ObjectMeta: v1.ObjectMeta{
			Name: nodeName3,
		},
		Status: libapiv3.NodeStatus{
			WireguardPublicKey: "",
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
		return nil, errors.New("Generic error getting node")
	}
	n, ok := c.nodes[res.Name]
	if !ok {
		return nil, errors.New("Generic error getting node")
	}
	c.nodes[res.Name] = res
	return n, nil
}

var _ = Describe("Wireguard bootstrapping", func() {
	var nodeClient *mockClient
	var netlinkDataplane *mocknetlink.MockNetlinkDataplane
	var configParams *config.Config

	BeforeEach(func() {
		nodeClient = newMockClient()
		netlinkDataplane = mocknetlink.New()
	})

	Context("HostEncryption is not enabled but wireguard is", func() {
		BeforeEach(func() {
			configParams = &config.Config{
				WireguardHostEncryptionEnabled: false,
				WireguardEnabled:               true,
				WireguardInterfaceName:         "wireguard.cali",
				FelixHostname:                  nodeName1,
			}
		})

		It("no-ops for BootstrapHostConnectivityAndFilterTyphaAddresses", func() {
			f, err := BootstrapHostConnectivityAndFilterTyphaAddresses(
				configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient, nil,
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(f).To(BeNil())
			Expect(nodeClient.numGets).To(BeZero())
			Expect(nodeClient.numUpdates).To(BeZero())
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(BeZero())
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
		var link *mocknetlink.MockLink
		BeforeEach(func() {
			configParams = &config.Config{
				WireguardHostEncryptionEnabled: true,
				WireguardEnabled:               true,
				WireguardInterfaceName:         "wireguard.cali",
				FelixHostname:                  nodeName1,
			}
			link = &mocknetlink.MockLink{
				LinkAttrs: netlink.LinkAttrs{
					Name:  "wireguard.cali",
					Index: 10,
				},
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
			nodeClient.nodes[nodeName1] = node1.DeepCopy()
			nodeClient.nodes[nodeName2] = node2.DeepCopy()
			nodeClient.nodes[nodeName3] = node3.DeepCopy()
		})

		It("returns the correct filtered typhas when calling BootstrapHostConnectivity", func() {
			typhas := []discovery.Typha{typha1, typha2, typha3, typha4}
			f, err := BootstrapHostConnectivityAndFilterTyphaAddresses(
				configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient, typhas,
			)
			Expect(err).ToNot(HaveOccurred())

			// We expect all typhas:
			// typha1 (local), typha2 (key is in kernel), typha3 (no key and IP not in kernel), typha4 (missing in client)
			Expect(f).To(Equal(typhas))

			// Get for local node and the two remote typhas with node names.
			Expect(nodeClient.numGets).To(Equal(3))

			// No updates made.
			Expect(nodeClient.numUpdates).To(Equal(0))
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(0))
			Expect(netlinkDataplane.NumNewWireguardCalls).To(Equal(1))
		})

		It("returns the correct filtered typhas (filters out missing key) when calling BootstrapHostConnectivity", func() {
			typhas := []discovery.Typha{typha1, typha2, typha3, typha4}
			delete(link.WireguardPeers, node2PrivateKey.PublicKey())
			pvt, _ := wgtypes.GeneratePrivateKey()
			link.WireguardPeers[pvt.PublicKey()] = wgtypes.Peer{
				PublicKey: pvt.PublicKey(),
			}

			f, err := BootstrapHostConnectivityAndFilterTyphaAddresses(
				configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient, typhas,
			)
			Expect(err).ToNot(HaveOccurred())

			// We expect typhas:
			// typha1 (local), typha3 (no key and IP not in kernel), typha4 (missing in client)
			// Filtered:
			// typha2 (key is not in kernel)
			Expect(f).To(Equal([]discovery.Typha{typha1, typha3, typha4}))

			// Get for local node and the two remote typhas with node names.
			Expect(nodeClient.numGets).To(Equal(3))

			// No updates.
			Expect(nodeClient.numUpdates).To(Equal(0))
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(0))
			Expect(netlinkDataplane.NumNewWireguardCalls).To(Equal(1))
		})

		It("returns all typhas and deletes wireguard if all typhas would be filtered when calling BootstrapHostConnectivity", func() {
			typhas := []discovery.Typha{typha2}
			delete(link.WireguardPeers, node2PrivateKey.PublicKey())
			pvt, _ := wgtypes.GeneratePrivateKey()
			link.WireguardPeers[pvt.PublicKey()] = wgtypes.Peer{
				PublicKey: pvt.PublicKey(),
			}

			f, err := BootstrapHostConnectivityAndFilterTyphaAddresses(
				configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient, typhas,
			)
			Expect(err).ToNot(HaveOccurred())

			// All typhas would be filtered out (missing key and Ip in kernel). Therefore wireguard will be deleted and
			// no typhas will be filtered out.
			Expect(f).To(Equal(typhas))

			// Get for local node, one remote node for typha, local node for deleting WG.
			Expect(nodeClient.numGets).To(Equal(3))
			Expect(nodeClient.numUpdates).To(Equal(1))

			// Device will be deleted.
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(1))
			Expect(netlinkDataplane.NumNewWireguardCalls).To(Equal(1))
			Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wireguard.cali"))
			Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
		})

		It("deletes all wireguard from node 1 if public key does not match kernel when calling BootstrapHostConnectivity", func() {
			otherKey, _ := wgtypes.GeneratePrivateKey()
			link.WireguardPrivateKey = otherKey
			link.WireguardPublicKey = otherKey.PublicKey()
			typhas := []discovery.Typha{typha2, typha3}
			f, err := BootstrapHostConnectivityAndFilterTyphaAddresses(
				configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient, typhas,
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(f).To(Equal(typhas)) // Should be unchanged.
			// Two gets - once for the check, once for the update.
			Expect(nodeClient.numGets).To(Equal(2))
			Expect(nodeClient.numUpdates).To(Equal(1))
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(1))
			Expect(netlinkDataplane.NumNewWireguardCalls).To(Equal(1))
			Expect(netlinkDataplane.NetlinkOpen).To(BeFalse())
			Expect(netlinkDataplane.WireguardOpen).To(BeFalse())
			Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wireguard.cali"))
			Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
		})

		It("RemoveWireguardForHostEncryptionBootstrapping deletes all wireguard configuration", func() {
			err := RemoveWireguardConditionallyOnBootstrap(
				configParams,
				netlinkDataplane.NewMockNetlink,
				nodeClient,
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(nodeClient.numGets).To(Equal(1))
			Expect(nodeClient.numUpdates).To(Equal(1))
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(1))
			Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
			Expect(netlinkDataplane.NetlinkOpen).To(BeFalse())
			Expect(netlinkDataplane.WireguardOpen).To(BeFalse())
			Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wireguard.cali"))
			Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
		})

		It("RemoveWireguardForHostEncryptionBootstrapping deletes key from node even if device is not found", func() {
			delete(netlinkDataplane.NameToLink, "wireguard.cali")
			err := RemoveWireguardConditionallyOnBootstrap(
				configParams,
				netlinkDataplane.NewMockNetlink,
				nodeClient,
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(nodeClient.numGets).To(Equal(1))
			Expect(nodeClient.numUpdates).To(Equal(1))
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(1))
			Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
			Expect(netlinkDataplane.NetlinkOpen).To(BeFalse())
			Expect(netlinkDataplane.WireguardOpen).To(BeFalse())
			Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wireguard.cali"))
			Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
		})

		It("RemoveWireguardForHostEncryptionBootstrapping deletes all wireguard config with temporary netlink and client errors", func() {
			netlinkDataplane.FailuresToSimulate = mocknetlink.FailNextLinkByName | mocknetlink.FailNextLinkDel
			nodeClient.numGetErrors = 2
			nodeClient.numUpdateErrors = 1

			err := RemoveWireguardConditionallyOnBootstrap(
				configParams,
				netlinkDataplane.NewMockNetlink,
				nodeClient,
			)
			Expect(err).ToNot(HaveOccurred())
			// 2 failures, 1 get + failed update, 1 get +  successful update.
			Expect(nodeClient.numGets).To(Equal(4))
			Expect(nodeClient.numUpdates).To(Equal(2))
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(1))
			Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
			Expect(netlinkDataplane.NetlinkOpen).To(BeFalse())
			Expect(netlinkDataplane.WireguardOpen).To(BeFalse())
			Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wireguard.cali"))
			Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
		})

		It("RemoveWireguardForHostEncryptionBootstrapping deletes public key but leaves link with permanent netlink errors", func() {
			netlinkDataplane.FailuresToSimulate = mocknetlink.FailNextLinkByName | mocknetlink.FailNextLinkDel
			netlinkDataplane.PersistFailures = true
			err := RemoveWireguardConditionallyOnBootstrap(
				configParams,
				netlinkDataplane.NewMockNetlink,
				nodeClient,
			)
			Expect(err).To(HaveOccurred())
			// 2 failures, 1 get + failed update, 1 get +  successful update.
			Expect(nodeClient.numGets).To(Equal(1))
			Expect(nodeClient.numUpdates).To(Equal(1))
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(1))
			Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
			Expect(netlinkDataplane.NetlinkOpen).To(BeFalse())
			Expect(netlinkDataplane.WireguardOpen).To(BeFalse())
			Expect(netlinkDataplane.NameToLink).To(HaveKey("wireguard.cali"))
			Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
		})

		It("RemoveWireguardForHostEncryptionBootstrapping deletes device but leaves key with too many client errors", func() {
			nodeClient.numGetErrors = 5
			err := RemoveWireguardConditionallyOnBootstrap(
				configParams,
				netlinkDataplane.NewMockNetlink,
				nodeClient,
			)
			Expect(err).To(HaveOccurred())
			Expect(nodeClient.numGets).To(Equal(5))
			Expect(nodeClient.numUpdates).To(BeZero())
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(1))
			Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
			Expect(netlinkDataplane.NetlinkOpen).To(BeFalse())
			Expect(netlinkDataplane.WireguardOpen).To(BeFalse())
			Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wireguard.cali"))
			Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).ToNot(Equal(""))
		})

		It("deletes all wireguard from node 1 if wireguard is disabled when calling BootstrapHostConnectivityAndFilterTyphaAddresses", func() {
			configParams.WireguardHostEncryptionEnabled = false
			configParams.WireguardEnabled = false
			typhas := []discovery.Typha{typha2, typha3}
			f, err := BootstrapHostConnectivityAndFilterTyphaAddresses(
				configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient, typhas,
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(f).To(Equal(typhas))
			Expect(nodeClient.numGets).To(Equal(1))
			Expect(nodeClient.numUpdates).To(Equal(1))
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(1))
			Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
			Expect(netlinkDataplane.NetlinkOpen).To(BeFalse())
			Expect(netlinkDataplane.WireguardOpen).To(BeFalse())
			Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wireguard.cali"))
			Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
		})

		It("deletes wireguard key from node 1 if wireguard intface is empty when calling BootstrapHostConnectivityAndFilterTyphaAddresses", func() {
			configParams.WireguardInterfaceName = ""
			typhas := []discovery.Typha{typha2, typha3}
			f, err := BootstrapHostConnectivityAndFilterTyphaAddresses(
				configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient, typhas,
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(f).To(Equal(typhas))
			Expect(nodeClient.numGets).To(Equal(1))
			Expect(nodeClient.numUpdates).To(Equal(1))
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(BeZero())
			Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
			Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
		})

		It("deletes wireguard key from node 1 if wireguard interface is not present when calling BootstrapHostConnectivityAndFilterTyphaAddresses", func() {
			delete(netlinkDataplane.NameToLink, "wireguard.cali")
			typhas := []discovery.Typha{typha2, typha3}
			f, err := BootstrapHostConnectivityAndFilterTyphaAddresses(
				configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient, typhas,
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(f).To(Equal(typhas))
			Expect(nodeClient.numGets).To(Equal(1))
			Expect(nodeClient.numUpdates).To(Equal(1))
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(1))
			Expect(netlinkDataplane.NumNewWireguardCalls).To(Equal(1))
			Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
		})

		It("deletes wireguard key from node 1 if wireguard interface has no peers when calling BootstrapHostConnectivityAndFilterTyphaAddresses", func() {
			link.WireguardPeers = nil
			typhas := []discovery.Typha{typha2, typha3}
			f, err := BootstrapHostConnectivityAndFilterTyphaAddresses(
				configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient, typhas,
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(f).To(Equal(typhas))
			Expect(nodeClient.numGets).To(Equal(1))
			Expect(nodeClient.numUpdates).To(Equal(1))
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(1))
			Expect(netlinkDataplane.NumNewWireguardCalls).To(Equal(1))
			Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wireguard.cali"))
			Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
		})
	})
})
