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

	"github.com/projectcalico/calico/libcalico-go/lib/set"

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

		It("no-ops for BootstrapHostConnectivity", func() {
			v, err := BootstrapHostConnectivity(
				configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient,
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(v).To(BeNil())
			Expect(nodeClient.numGets).To(BeZero())
			Expect(nodeClient.numUpdates).To(BeZero())
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(BeZero())
			Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
		})

		It("no-ops for FilterTyphaEndpoints", func() {
			typhas := []discovery.Typha{typha1, typha2, typha3, typha4}
			filtered := FilterTyphaEndpoints(
				configParams, nodeClient, typhas, nil,
			)
			Expect(filtered).To(Equal(typhas))
			Expect(nodeClient.numGets).To(BeZero())
			Expect(nodeClient.numUpdates).To(BeZero())
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(BeZero())
			Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
		})

		It("no-ops for RemoveWireguardForHostEncryptionBootstrapping", func() {
			err := RemoveWireguardForHostEncryptionBootstrapping(
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

		It("returns the set of programmed peers when calling BootstrapHostConnectivity", func() {
			v, err := BootstrapHostConnectivity(
				configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient,
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(v).NotTo(BeNil())
			Expect(v.Len()).To(Equal(1))
			Expect(v.Contains(node2PrivateKey.PublicKey().String())).To(BeTrue())
			Expect(nodeClient.numGets).To(Equal(1))
			Expect(nodeClient.numUpdates).To(Equal(0))
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(0))
			Expect(netlinkDataplane.NumNewWireguardCalls).To(Equal(1))
		})

		It("deletes all wireguard from node 1 if public key does not match kernel when calling BootstrapHostConnectivity", func() {
			otherKey, _ := wgtypes.GeneratePrivateKey()
			link.WireguardPrivateKey = otherKey
			link.WireguardPublicKey = otherKey.PublicKey()
			v, err := BootstrapHostConnectivity(
				configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient,
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(v).To(BeNil())
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
			err := RemoveWireguardForHostEncryptionBootstrapping(
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
			err := RemoveWireguardForHostEncryptionBootstrapping(
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

			err := RemoveWireguardForHostEncryptionBootstrapping(
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
			err := RemoveWireguardForHostEncryptionBootstrapping(
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
			err := RemoveWireguardForHostEncryptionBootstrapping(
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

		It("deletes all wireguard from node 1 if wireguard is disabled when calling BootstrapHostConnectivity", func() {
			configParams.WireguardHostEncryptionEnabled = false
			configParams.WireguardEnabled = false
			v, err := BootstrapHostConnectivity(
				configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient,
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(v).To(BeNil())
			Expect(nodeClient.numGets).To(Equal(1))
			Expect(nodeClient.numUpdates).To(Equal(1))
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(1))
			Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
			Expect(netlinkDataplane.NetlinkOpen).To(BeFalse())
			Expect(netlinkDataplane.WireguardOpen).To(BeFalse())
			Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wireguard.cali"))
			Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
		})

		It("deletes wireguard key from node 1 if wireguard intface is empty when calling BootstrapHostConnectivity", func() {
			configParams.WireguardInterfaceName = ""
			v, err := BootstrapHostConnectivity(
				configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient,
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(v).To(BeNil())
			Expect(nodeClient.numGets).To(Equal(1))
			Expect(nodeClient.numUpdates).To(Equal(1))
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(BeZero())
			Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
			Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
		})

		It("deletes wireguard key from node 1 if wireguard interface is not present when calling BootstrapHostConnectivity", func() {
			delete(netlinkDataplane.NameToLink, "wireguard.cali")
			v, err := BootstrapHostConnectivity(
				configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient,
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(v).To(BeNil())
			Expect(nodeClient.numGets).To(Equal(1))
			Expect(nodeClient.numUpdates).To(Equal(1))
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(1))
			Expect(netlinkDataplane.NumNewWireguardCalls).To(Equal(1))
			Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
		})

		It("deletes wireguard key from node 1 if wireguard interface has no peers when calling BootstrapHostConnectivity", func() {
			link.WireguardPeers = nil
			v, err := BootstrapHostConnectivity(
				configParams, netlinkDataplane.NewMockNetlink, netlinkDataplane.NewMockWireguard, nodeClient,
			)
			Expect(err).ToNot(HaveOccurred())
			Expect(v).To(BeNil())
			Expect(nodeClient.numGets).To(Equal(1))
			Expect(nodeClient.numUpdates).To(Equal(1))
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(Equal(1))
			Expect(netlinkDataplane.NumNewWireguardCalls).To(Equal(1))
			Expect(netlinkDataplane.NameToLink).ToNot(HaveKey("wireguard.cali"))
			Expect(nodeClient.nodes[nodeName1].Status.WireguardPublicKey).To(Equal(""))
		})

		It("includes all typha endpoints when calling FilterTyphaEndpoints if keys are correct, name is not known, or is local", func() {
			// Typha1 is local, Typha2 has public key, Typha3 does not and Typha4 is on an unknown node.
			// Should have 2 queries for nodes 2 and 3.
			peersToValidate := set.From(node2PrivateKey.PublicKey().String())
			typhas := []discovery.Typha{typha1, typha2, typha3, typha4}
			filtered := FilterTyphaEndpoints(
				configParams, nodeClient, typhas, peersToValidate,
			)
			Expect(filtered).To(Equal(typhas))
			Expect(nodeClient.numGets).To(Equal(2))
			Expect(nodeClient.numUpdates).To(BeZero())
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(BeZero())
			Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
		})

		It("omits any typha endpoint with a public key that is not in local wireguard when calling FilterTyphaEndpoints", func() {
			// Typha1 is local, Typha2 has public key, Typha3 does not and Typha4 is on an unknown node.
			// We omit the key for node 2.
			// Should have 2 queries for nodes 2 and 3.
			peersToValidate := set.From(node1PrivateKey.PublicKey())
			typhas := []discovery.Typha{typha1, typha2, typha3, typha4}
			filtered := FilterTyphaEndpoints(
				configParams, nodeClient, typhas, peersToValidate,
			)
			Expect(filtered).To(Equal([]discovery.Typha{typha1, typha3, typha4}))
			Expect(nodeClient.numGets).To(Equal(2))
			Expect(nodeClient.numUpdates).To(BeZero())
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(BeZero())
			Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
		})

		It("includes all endpoints if unable to lookup the key FilterTyphaEndpoints", func() {
			// Typha1 is local, Typha2 has public key, Typha3 does not and Typha4 is on an unknown node.
			// We omit the key for node 2.
			// Should have 2 queries for nodes 2 and 3.
			peersToValidate := set.From(node1PrivateKey.PublicKey())
			typhas := []discovery.Typha{typha1, typha2, typha3, typha4}
			nodeClient.numGetErrors = 10
			filtered := FilterTyphaEndpoints(
				configParams, nodeClient, typhas, peersToValidate,
			)
			Expect(filtered).To(Equal(typhas))
			// Filter queries only retry twice.
			Expect(nodeClient.numGets).To(Equal(4))
			Expect(nodeClient.numUpdates).To(BeZero())
			Expect(netlinkDataplane.NumNewNetlinkCalls).To(BeZero())
			Expect(netlinkDataplane.NumNewWireguardCalls).To(BeZero())
		})
	})
})
