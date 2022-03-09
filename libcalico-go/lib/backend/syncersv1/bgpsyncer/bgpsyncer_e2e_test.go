// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/bgpsyncer"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

const (
	controlPlaneNodeName = "kind-single-control-plane"
)

// These tests validate that the various resources that the BGP watches are
// handled correctly by the syncer.  We don't validate in detail the behavior of
// each of update handlers that are invoked, since these are tested more thoroughly
// elsewhere.
var _ = testutils.E2eDatastoreDescribe("BGP syncer tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {
	ctx := context.Background()

	Describe("BGP syncer functionality", func() {
		It("should receive the synced after return all current data", func() {
			// Create a v3 client to drive data changes (luckily because this is the _test module,
			// we don't get circular imports.
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			// Create the backend client to obtain a syncer interface.
			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			// Create a SyncerTester to receive the BGP syncer callback events and to allow us
			// to assert state.
			syncTester := testutils.NewSyncerTester()
			syncer := bgpsyncer.New(be, syncTester, "127.0.0.1", config.Spec)
			syncer.Start()
			expectedCacheSize := 0

			By("Checking status is updated to sync'd at start of day")
			syncTester.ExpectStatusUpdate(api.WaitForDatastore)
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectStatusUpdate(api.ResyncInProgress)
			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				expectedCacheSize += 1

				if config.Spec.DatastoreType == apiconfig.Kubernetes {
					// Should have two nodes from kind. However in etcd mode
					// Nodes are created by calico/node, which we don't run here.
					expectedCacheSize += 1
				}
			}
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectStatusUpdate(api.InSync)
			syncTester.ExpectCacheSize(expectedCacheSize)

			// For Kubernetes test one entry already in the cache for the node.
			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				syncTester.ExpectPath("/calico/resources/v3/projectcalico.org/nodes/127.0.0.1")
				syncTester.ExpectPath(fmt.Sprintf("/calico/resources/v3/projectcalico.org/nodes/%s", controlPlaneNodeName))
			}

			By("Disabling node to node mesh and adding a default ASNumber")
			n2n := false
			asn := numorstring.ASNumber(12345)
			bgpCfg, err := c.BGPConfigurations().Create(
				ctx,
				&apiv3.BGPConfiguration{
					ObjectMeta: metav1.ObjectMeta{Name: "default"},
					Spec: apiv3.BGPConfigurationSpec{
						NodeToNodeMeshEnabled: &n2n,
						ASNumber:              &asn,
					},
				},
				options.SetOptions{},
			)

			Expect(err).NotTo(HaveOccurred())
			expectedCacheSize += 1

			// We should have entries for each config option (i.e. 2)
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectPath("/calico/resources/v3/projectcalico.org/bgpconfigurations/default")

			var node *libapiv3.Node
			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				// For Kubernetes, update the existing node config to have some BGP configuration.
				By("Configuring a node with BGP configuration")
				node, err = c.Nodes().Get(ctx, "127.0.0.1", options.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				node.Spec.BGP = &libapiv3.NodeBGPSpec{
					IPv4Address: "1.2.3.4/24",
					IPv6Address: "aa:bb::cc/120",
				}
				node, err = c.Nodes().Update(ctx, node, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
				// The existing Node resource is updated; no change in cache size.
			} else {
				// For non-Kubernetes, add a new node with valid BGP configuration.
				By("Creating a node with BGP configuration")
				node, err = c.Nodes().Create(
					ctx,
					&libapiv3.Node{
						ObjectMeta: metav1.ObjectMeta{Name: "127.0.0.1"},
						Spec: libapiv3.NodeSpec{
							BGP: &libapiv3.NodeBGPSpec{
								IPv4Address: "1.2.3.4/24",
								IPv6Address: "aa:bb::cc/120",
							},
						},
					},
					options.SetOptions{},
				)
				Expect(err).NotTo(HaveOccurred())
				expectedCacheSize += 1
			}

			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectPath("/calico/resources/v3/projectcalico.org/nodes/127.0.0.1")

			By("Updating the BGPConfiguration to remove the default ASNumber")
			bgpCfg.Spec.ASNumber = nil
			_, err = c.BGPConfigurations().Update(ctx, bgpCfg, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectNoData(model.GlobalBGPConfigKey{"as_num"})

			By("Creating an IPPool")
			poolCIDR := "192.124.0.0/21"
			poolCIDRNet := net.MustParseCIDR(poolCIDR)
			pool, err := c.IPPools().Create(
				ctx,
				&apiv3.IPPool{
					ObjectMeta: metav1.ObjectMeta{Name: "mypool"},
					Spec: apiv3.IPPoolSpec{
						CIDR:        poolCIDR,
						IPIPMode:    apiv3.IPIPModeCrossSubnet,
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
					IPIPMode:      encap.CrossSubnet,
					Masquerade:    true,
					IPAM:          true,
					Disabled:      false,
				},
				Revision: pool.ResourceVersion,
			})

			By("Creating a BGPPeer")
			_, err = c.BGPPeers().Create(
				ctx,
				&apiv3.BGPPeer{
					ObjectMeta: metav1.ObjectMeta{Name: "peer1"},
					Spec: apiv3.BGPPeerSpec{
						PeerIP:   "192.124.10.20",
						ASNumber: numorstring.ASNumber(75758),
					},
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			// The peer will add as single entry ( +1 )
			expectedCacheSize += 1
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectPath("/calico/resources/v3/projectcalico.org/bgppeers/peer1")

			// For non-kubernetes, check that we can allocate an IP address and get a syncer update
			// for the allocation block.
			var blockAffinityKeyV1 model.BlockAffinityKey
			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Allocating an IP address and checking that we get an allocation block")
				v4ia1, _, err := c.IPAM().AutoAssign(ctx, ipam.AutoAssignArgs{
					Num4:        1,
					Hostname:    "127.0.0.1",
					IntendedUse: apiv3.IPPoolAllowedUseWorkload,
				})
				Expect(v4ia1).ToNot(BeNil())
				Expect(err).NotTo(HaveOccurred())

				var ips1 []ipam.ReleaseOptions
				for _, ipnet := range v4ia1.IPs {
					ips1 = append(ips1, ipam.ReleaseOptions{Address: ipnet.IP.String()})
				}

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
				hostname := "not-this-host"
				node, err = c.Nodes().Create(ctx, &libapiv3.Node{ObjectMeta: metav1.ObjectMeta{Name: hostname}}, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
				expectedCacheSize += 1
				syncTester.ExpectCacheSize(expectedCacheSize)

				v4ia2, _, err := c.IPAM().AutoAssign(ctx, ipam.AutoAssignArgs{
					Num4:        1,
					Hostname:    hostname,
					IntendedUse: apiv3.IPPoolAllowedUseWorkload,
				})
				Expect(v4ia2).ToNot(BeNil())
				Expect(err).NotTo(HaveOccurred())

				var ips2 []ipam.ReleaseOptions
				for _, ipnet := range v4ia2.IPs {
					ips2 = append(ips2, ipam.ReleaseOptions{Address: ipnet.IP.String()})
				}

				syncTester.ExpectCacheSize(expectedCacheSize)

				By("Releasing the IP addresses and checking for no updates")
				// Releasing IPs should leave the affine blocks assigned, so releasing the IPs
				// should result in no updates.
				_, err = c.IPAM().ReleaseIPs(ctx, ips1...)
				Expect(err).NotTo(HaveOccurred())
				_, err = c.IPAM().ReleaseIPs(ctx, ips2...)
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
			syncer = bgpsyncer.New(be, syncTester, "127.0.0.1", config.Spec)
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
