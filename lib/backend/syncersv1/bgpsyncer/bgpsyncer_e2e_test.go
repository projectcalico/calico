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
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
var _ = testutils.E2eDatastoreDescribe("BGP syncer tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {

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
			syncer := bgpsyncer.New(be, syncTester, "127.0.0.1", true)
			syncer.Start()
			expectedCacheSize := 0

			By("Checking status is updated to sync'd at start of day")
			syncTester.ExpectStatusUpdate(api.WaitForDatastore)
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectStatusUpdate(api.ResyncInProgress)
			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				// k8s seems to have some latency with its API server, so let's pause for a little
				// to let things settle.
				expectedCacheSize += 3
			}
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectStatusUpdate(api.InSync)
			syncTester.ExpectCacheSize(expectedCacheSize)

			// For Kubernetes test the three entries already in the cache - one
			// affinity block and two blank IP addresses from the pre-provisioned node.
			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				// We don't compare the revision number since it's not hugely stable.
				syncTester.ExpectData(model.KVPair{
					Key:   model.NodeBGPConfigKey{Nodename: "127.0.0.1", Name: "ip_addr_v4"},
					Value: "",
				})
				syncTester.ExpectData(model.KVPair{
					Key:   model.NodeBGPConfigKey{Nodename: "127.0.0.1", Name: "ip_addr_v6"},
					Value: "",
				})
				syncTester.ExpectData(model.KVPair{
					Key:   model.BlockAffinityKey{Host: "127.0.0.1", CIDR: net.MustParseCIDR("10.10.10.0/24")},
					Value: "{}",
				})
			}

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
			expectedCacheSize += 2

			// We should have entries for each config option (i.e. 2)
			syncTester.ExpectCacheSize(expectedCacheSize)
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

			var node *apiv2.Node
			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				// For Kubernetes, update the existing node config to have some BGP configuration.
				By("Configuring a node with BGP configuration")
				node, err = c.Nodes().Get(ctx, "127.0.0.1", options.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				node.Spec.BGP = &apiv2.NodeBGPSpec{
					IPv4Address: "1.2.3.4/24",
					IPv6Address: "aa:bb::cc/120",
				}
				node, err = c.Nodes().Update(ctx, node, options.SetOptions{})

				// This will add two network entries, and the existing two IP entries will be
				// updated.
				expectedCacheSize += 2
			} else {
				// For non-Kubernetes, add a new node with valid BGP configuration.
				By("Creating a node with BGP configuration")
				node, err = c.Nodes().Create(
					ctx,
					&apiv2.Node{
						ObjectMeta: metav1.ObjectMeta{Name: "127.0.0.1"},
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
				expectedCacheSize += 4
			}

			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectData(model.KVPair{
				Key:   model.NodeBGPConfigKey{Nodename: "127.0.0.1", Name: "ip_addr_v4"},
				Value: "1.2.3.4",
			})
			syncTester.ExpectData(model.KVPair{
				Key:   model.NodeBGPConfigKey{Nodename: "127.0.0.1", Name: "ip_addr_v6"},
				Value: "aa:bb::cc",
			})
			syncTester.ExpectData(model.KVPair{
				Key:   model.NodeBGPConfigKey{Nodename: "127.0.0.1", Name: "network_v4"},
				Value: "1.2.3.0/24",
			})
			syncTester.ExpectData(model.KVPair{
				Key:   model.NodeBGPConfigKey{Nodename: "127.0.0.1", Name: "network_v6"},
				Value: "aa:bb::/120",
			})

			By("Updating the BGPConfiguration to remove the default ASNumber")
			bgpCfg.Spec.ASNumber = nil
			_, err = c.BGPConfigurations().Update(ctx, bgpCfg, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			// Removing one config option ( -1 )
			expectedCacheSize -= 1
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectNoData(model.GlobalBGPConfigKey{"as_num"})

			By("Creating an IPPool")
			poolCIDR := "192.124.0.0/21"
			poolCIDRNet := net.MustParseCIDR(poolCIDR)
			pool, err := c.IPPools().Create(
				ctx,
				&apiv2.IPPool{
					ObjectMeta: metav1.ObjectMeta{Name: "mypool"},
					Spec: apiv2.IPPoolSpec{
						CIDR:        poolCIDR,
						IPIPMode:    apiv2.IPIPModeCrossSubnet,
						NATOutgoing: true,
					},
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			// The pool will add as single entry ( +1 )
			poolKeyV1 := model.IPPoolKey{CIDR: net.MustParseCIDR("192.124.0.0/21")}
			expectedCacheSize += 1
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectData(model.KVPair{
				Key: poolKeyV1,
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
			expectedCacheSize += 1
			syncTester.ExpectCacheSize(expectedCacheSize)
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
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectData(peer1kvp)

			By("Updating the first peer to be a Node specific peer (get updates for both peers)")
			peer1.Spec.Node = "127.0.0.1"
			peer1, err = c.BGPPeers().Update(ctx, peer1, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			peer1kvp = model.KVPair{
				Key: model.NodeBGPPeerKey{Nodename: "127.0.0.1", PeerIP: net.MustParseIP("192.124.10.20")},
				Value: &model.BGPPeer{
					PeerIP: net.MustParseIP("192.124.10.20"),
					ASNum:  numorstring.ASNumber(75758),
				},
				Revision: peer1.ResourceVersion,
			}

			// The first peer has moved to be a node-specific peer and no longer clashes with
			// the second.  We should have an extra data store entry, and both peers should be present.
			expectedCacheSize += 1
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectData(peer1kvp)
			syncTester.ExpectData(peer2kvp)

			// For non-kubernetes, check that we can allocate an IP address and get a syncer update
			// for the allocation block.
			var blockAffinityKeyV1 model.BlockAffinityKey
			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Allocating an IP address and checking that we get an allocation block")
				ips1, _, err := c.IPAM().AutoAssign(ctx, ipam.AutoAssignArgs{
					Num4:     1,
					Hostname: "127.0.0.1",
				})
				Expect(err).NotTo(HaveOccurred())

				// Allocating an IP will create an affinity block that we should be notified of.  Not sure
				// what CIDR will be chosen, so search the cached entries.
				expectedCacheSize += 1
				syncTester.ExpectCacheSize(expectedCacheSize)
				current := syncTester.GetCacheEntries()
				for _, kvp := range current {
					if kab, ok := kvp.Key.(model.BlockAffinityKey); ok {
						if kab.Host == "127.0.0.1" && poolCIDRNet.Contains(kab.CIDR.IP) {
							blockAffinityKeyV1 = kab
							break
						}
					}
				}
				Expect(blockAffinityKeyV1).NotTo(BeNil(), "Did not find affinity block in sync data")

				By("Allocating an IP address on a different host and checking for no updates")
				// The syncer only monitors affine blocks for one host, so IP allocations for a different
				// host should not result in updates.
				ips2, _, err := c.IPAM().AutoAssign(ctx, ipam.AutoAssignArgs{
					Num4:     1,
					Hostname: "not-this-host",
				})
				Expect(err).NotTo(HaveOccurred())
				syncTester.ExpectCacheSize(expectedCacheSize)

				By("Releasing the IP addresses and checking for no updates")
				// Releasing IPs should leave the affine blocks assigned, so releasing the IPs
				// should result in no updates.
				_, err = c.IPAM().ReleaseIPs(ctx, ips1)
				Expect(err).NotTo(HaveOccurred())
				_, err = c.IPAM().ReleaseIPs(ctx, ips2)
				Expect(err).NotTo(HaveOccurred())
				syncTester.ExpectCacheSize(expectedCacheSize)

				By("Deleting the IPPool and checking for pool and affine block deletion")
				// Deleting the pool will also release all affine blocks associated with the pool.
				_, err = c.IPPools().Delete(ctx, "mypool", options.DeleteOptions{})
				Expect(err).NotTo(HaveOccurred())

				// The pool and the affine block for 127.0.0.1 should have deletion events.
				expectedCacheSize -= 2
				syncTester.ExpectCacheSize(expectedCacheSize)
				syncTester.ExpectNoData(blockAffinityKeyV1)
				syncTester.ExpectNoData(poolKeyV1)
			}

			By("Starting a new syncer and verifying that all current entries are returned before sync status")
			// We need to create a new syncTester and syncer.
			current := syncTester.GetCacheEntries()
			syncTester = testutils.NewSyncerTester()
			syncer = bgpsyncer.New(be, syncTester, "127.0.0.1", true)
			syncer.Start()

			// Verify the data is the same as the data from the previous cache.  We got the cache in the previous
			// step.
			syncTester.ExpectStatusUpdate(api.WaitForDatastore)
			syncTester.ExpectStatusUpdate(api.ResyncInProgress)
			syncTester.ExpectCacheSize(expectedCacheSize)
			for _, e := range current {
				if config.Spec.DatastoreType == apiconfig.Kubernetes {
					// Don't check revisions for K8s since the node data gets updated constantly.
					e.Revision = ""
				}
				syncTester.ExpectData(e)
			}
			syncTester.ExpectStatusUpdate(api.InSync)
		})
	})
})
