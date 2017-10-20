// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package bgpsyncer_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"context"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/backend"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/syncersv1/bgpsyncer"
	"github.com/projectcalico/libcalico-go/lib/clientv2"
	"github.com/projectcalico/libcalico-go/lib/ipam"
	"github.com/projectcalico/libcalico-go/lib/ipip"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/testutils"
)

// These tests validate that the various resources that the BGP watches are
// handled correctly by the syncer.  We don't validate in detail the behavior of
// each of udpate handlers that are invoked, since these are tested more thoroughly
// elsewhere.
var _ = testutils.E2eDatastoreDescribe("BGP syncer tests", testutils.DatastoreEtcdV3, func(config apiconfig.CalicoAPIConfig) {

	ctx := context.Background()

	Describe("BGP syncer functionality", func() {
		It("should receive the synced after return all current data", func() {
			// Create a v2 client to drive data changes (luckily because this is the _test module,
			// we don't get circular imports.
			c, err := clientv2.New(config)
			Expect(err).NotTo(HaveOccurred())

			// Create the backend client to obtain a syncer interface.
			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			// Create a SyncerTester to receive the BGP syncer callback events and to allow us
			// to assert state.
			syncTester := testutils.NewSyncerTester()
			syncer := bgpsyncer.New(be, syncTester, "mynode", true)
			syncer.Start()

			By("Checking status is updated to sync'd when there is no data")
			syncTester.ExpectStatusUpdate(api.WaitForDatastore)
			syncTester.ExpectCacheSize(0)
			syncTester.ExpectStatusUpdate(api.ResyncInProgress)
			syncTester.ExpectCacheSize(0)
			syncTester.ExpectStatusUpdate(api.InSync)
			syncTester.ExpectCacheSize(0)

			By("Disabling node to node mesh and adding a default ASNumber")
			n2n := false
			asn := numorstring.ASNumber(12345)
			bgpCfg, err := c.BGPConfigurations().Create(
				ctx,
				&apiv2.BGPConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: "default"},
					Spec: apiv2.BGPConfigurationSpec{
						NodeToNodeMeshEnabled: &n2n,
						ASNumber:              &asn,
					},
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			// We should have entries for each config option (i.e. 2)
			syncTester.ExpectCacheSize(2)
			syncTester.ExpectData(model.KVPair{
				Key:      model.GlobalBGPConfigKey{"as_num"},
				Value:    "12345",
				Revision: bgpCfg.ResourceVersion,
			})
			syncTester.ExpectData(model.KVPair{
				Key:      model.GlobalBGPConfigKey{"node_mesh"},
				Value:    "{\"enabled\":false}",
				Revision: bgpCfg.ResourceVersion,
			})

			By("Creating a node with BGP configuration")
			node, err := c.Nodes().Create(
				ctx,
				&apiv2.Node{
					ObjectMeta: metav1.ObjectMeta{Name: "mynode"},
					Spec: apiv2.NodeSpec{
						BGP: &apiv2.NodeBGPSpec{
							IPv4Address: "1.2.3.4/24",
							IPv6Address: "aa:bb::cc/120",
						},
					},
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			// The two IP addresses will also add two networks ( +4 )
			syncTester.ExpectCacheSize(6)
			syncTester.ExpectData(model.KVPair{
				Key:      model.NodeBGPConfigKey{Nodename: "mynode", Name: "ip_addr_v4"},
				Value:    "1.2.3.4",
				Revision: node.ResourceVersion,
			})
			syncTester.ExpectData(model.KVPair{
				Key:      model.NodeBGPConfigKey{Nodename: "mynode", Name: "ip_addr_v6"},
				Value:    "aa:bb::cc",
				Revision: node.ResourceVersion,
			})
			syncTester.ExpectData(model.KVPair{
				Key:      model.NodeBGPConfigKey{Nodename: "mynode", Name: "network_v4"},
				Value:    "1.2.3.0/24",
				Revision: node.ResourceVersion,
			})
			syncTester.ExpectData(model.KVPair{
				Key:      model.NodeBGPConfigKey{Nodename: "mynode", Name: "network_v6"},
				Value:    "aa:bb::/120",
				Revision: node.ResourceVersion,
			})

			By("Updating the BGPConfiguration to remove the default ASNumber")
			bgpCfg.Spec.ASNumber = nil
			_, err = c.BGPConfigurations().Update(ctx, bgpCfg, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			// Removing one config option ( -1 )
			syncTester.ExpectCacheSize(5)
			syncTester.ExpectNoData(model.GlobalBGPConfigKey{"as_num"})

			By("Creating an IPPool")
			poolCIDR := "192.124.0.0/21"
			poolCIDRNet := net.MustParseCIDR(poolCIDR)
			pool, err := c.IPPools().Create(
				ctx,
				&apiv2.IPPool{
					ObjectMeta: metav1.ObjectMeta{Name: "mypool"},
					Spec: apiv2.IPPoolSpec{
						CIDR: poolCIDR,
						IPIPMode: apiv2.IPIPModeCrossSubnet,
						NATOutgoing: true,
					},
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			// The pool will add as single entry ( +1 )
			syncTester.ExpectCacheSize(6)
			syncTester.ExpectData(model.KVPair{
				Key: model.IPPoolKey{CIDR: net.MustParseCIDR("192.124.0.0/21")},
				Value: &model.IPPool{
					CIDR:          poolCIDRNet,
					IPIPInterface: "tunl0",
					IPIPMode:      ipip.CrossSubnet,
					Masquerade:    true,
					IPAM:          true,
					Disabled:      false,
				},
				Revision: pool.ResourceVersion,
			})

			By("Creating a BGPPeer")
			peer1, err := c.BGPPeers().Create(
				ctx,
				&apiv2.BGPPeer{
					ObjectMeta: metav1.ObjectMeta{Name: "peer1"},
					Spec: apiv2.BGPPeerSpec{
						PeerIP:   "192.124.10.20",
						ASNumber: numorstring.ASNumber(75758),
					},
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			peer1kvp := model.KVPair{
				Key: model.GlobalBGPPeerKey{PeerIP: net.MustParseIP("192.124.10.20")},
				Value: &model.BGPPeer{
					PeerIP: net.MustParseIP("192.124.10.20"),
					ASNum:  numorstring.ASNumber(75758),
				},
				Revision: peer1.ResourceVersion,
			}
			// The peer will add as single entry ( +1 )
			syncTester.ExpectCacheSize(7)
			syncTester.ExpectData(peer1kvp)

			By("Adding a new BGPPeer with conflicting peer IP (and lower priority than the first one)")
			peer2, err := c.BGPPeers().Create(
				ctx,
				&apiv2.BGPPeer{
					ObjectMeta: metav1.ObjectMeta{Name: "peer9-lowerpriority"},
					Spec: apiv2.BGPPeerSpec{
						PeerIP:   "192.124.10.20",
						ASNumber: numorstring.ASNumber(99999),
					},
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			peer2kvp := model.KVPair{
				Key: model.GlobalBGPPeerKey{PeerIP: net.MustParseIP("192.124.10.20")},
				Value: &model.BGPPeer{
					PeerIP: net.MustParseIP("192.124.10.20"),
					ASNum:  numorstring.ASNumber(99999),
				},
				Revision: peer2.ResourceVersion,
			}
			// The peer will result in no updates and the entry key off 192.124.10.20
			// will still be the same.
			syncTester.ExpectCacheSize(7)
			syncTester.ExpectData(peer1kvp)

			By("Updating the first peer to be a Node specific peer (get updates for both peers)")
			peer1.Spec.Node = "mynode"
			peer1, err = c.BGPPeers().Update(ctx, peer1, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			peer1kvp = model.KVPair{
				Key: model.NodeBGPPeerKey{Nodename: "mynode", PeerIP: net.MustParseIP("192.124.10.20")},
				Value: &model.BGPPeer{
					PeerIP: net.MustParseIP("192.124.10.20"),
					ASNum:  numorstring.ASNumber(75758),
				},
				Revision: peer1.ResourceVersion,
			}

			// The first peer has moved to be a node-specific peer and no longer clashes with
			// the second.  We should have an extra data store entry, and both peers should be present.
			syncTester.ExpectCacheSize(8)
			syncTester.ExpectData(peer1kvp)
			syncTester.ExpectData(peer2kvp)

			By("Allocating an IP address and checking that we get an allocation block")
			_, _, err = c.IPAM().AutoAssign(ctx, ipam.AutoAssignArgs{
				Num4:     1,
				Hostname: "mynode",
			})
			Expect(err).NotTo(HaveOccurred())

			// Allocating an IP will create an affinity block that we should be notified of.  Not sure
			// what CIDR will be chosen, so search the cached entries.
			syncTester.ExpectCacheSize(9)
			current := syncTester.GetCacheEntries()
			found := false
			for _, kvp := range current {
				if kab, ok := kvp.Key.(model.BlockAffinityKey); ok {
					if kab.Host == "mynode" && poolCIDRNet.Contains(kab.CIDR.IP) {
						found = true
						break
					}
				}
			}
			Expect(found).To(BeTrue(), "Did not find affinity block in sync data")

			By("Starting a new syncer and verifying that all current entries are returned before sync status")
			// We need to create a new syncTester and syncer.
			syncTester = testutils.NewSyncerTester()
			syncer = bgpsyncer.New(be, syncTester, "mynode", true)
			syncer.Start()

			// Verify the data is the same as the data from the previous cache.  We got the cache in the previous
			// step.
			syncTester.ExpectStatusUpdate(api.WaitForDatastore)
			syncTester.ExpectStatusUpdate(api.ResyncInProgress)
			syncTester.ExpectCacheSize(len(current))
			for _, e := range current {
				syncTester.ExpectData(e)
			}
			syncTester.ExpectStatusUpdate(api.InSync)
		})
	})
})
