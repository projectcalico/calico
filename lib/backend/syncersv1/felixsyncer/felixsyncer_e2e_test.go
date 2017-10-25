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

package felixsyncer_test

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
	"github.com/projectcalico/libcalico-go/lib/clientv2"
	"github.com/projectcalico/libcalico-go/lib/ipip"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/testutils"
)

var _ = testutils.E2eDatastoreDescribe("Felix syncer tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {

	ctx := context.Background()

	Describe("Felix syncer functionality", func() {
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
			syncer := be.Syncer(syncTester)
			syncer.Start()
			expectedCacheSize := 0

			By("Checking status is updated to sync'd at start of day")
			syncTester.ExpectStatusUpdate(api.WaitForDatastore)
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectStatusUpdate(api.ResyncInProgress)
			syncTester.ExpectStatusUpdate(api.InSync)
			// Kubernetes will have a profile for each of the namespaces that is configured.
			// We expect:  default, kube-system, kube-public, namespace-1, namespace-2
			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				expectedCacheSize += 5
				syncTester.ExpectCacheSize(expectedCacheSize)
				syncTester.ExpectData(model.KVPair{
					Key: model.ProfileRulesKey{ProfileKey: model.ProfileKey{Name: "kns.default"}},
					Value: &model.ProfileRules{
						InboundRules:  []model.Rule{{Action: "allow"}},
						OutboundRules: []model.Rule{{Action: "allow"}},
					},
				})
				syncTester.ExpectData(model.KVPair{
					Key: model.ProfileRulesKey{ProfileKey: model.ProfileKey{Name: "kns.kube-public"}},
					Value: &model.ProfileRules{
						InboundRules:  []model.Rule{{Action: "allow"}},
						OutboundRules: []model.Rule{{Action: "allow"}},
					},
				})
				syncTester.ExpectData(model.KVPair{
					Key: model.ProfileRulesKey{ProfileKey: model.ProfileKey{Name: "kns.kube-system"}},
					Value: &model.ProfileRules{
						InboundRules:  []model.Rule{{Action: "allow"}},
						OutboundRules: []model.Rule{{Action: "allow"}},
					},
				})
				syncTester.ExpectData(model.KVPair{
					Key: model.ProfileRulesKey{ProfileKey: model.ProfileKey{Name: "kns.namespace-1"}},
					Value: &model.ProfileRules{
						InboundRules:  []model.Rule{{Action: "allow"}},
						OutboundRules: []model.Rule{{Action: "allow"}},
					},
				})
				syncTester.ExpectData(model.KVPair{
					Key: model.ProfileRulesKey{ProfileKey: model.ProfileKey{Name: "kns.namespace-2"}},
					Value: &model.ProfileRules{
						InboundRules:  []model.Rule{{Action: "allow"}},
						OutboundRules: []model.Rule{{Action: "allow"}},
					},
				})
			}
			syncTester.ExpectCacheSize(expectedCacheSize)

			var node *apiv2.Node
			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				// For Kubernetes, update the existing node config to have some BGP configuration.
				By("Configuring a node with an IP address")
				node, err = c.Nodes().Get(ctx, "127.0.0.1", options.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				node.Spec.BGP = &apiv2.NodeBGPSpec{
					IPv4Address: "1.2.3.4/24",
					IPv6Address: "aa:bb::cc/120",
				}
				node, err = c.Nodes().Update(ctx, node, options.SetOptions{})
			} else {
				// For non-Kubernetes, add a new node with valid BGP configuration.
				By("Creating a node with an IP address")
				node, err = c.Nodes().Create(
					ctx,
					&apiv2.Node{
						ObjectMeta: metav1.ObjectMeta{Name: "127.0.0.1"},
						Spec: apiv2.NodeSpec{
							BGP: &apiv2.NodeBGPSpec{
								IPv4Address:        "1.2.3.4/24",
								IPv6Address:        "aa:bb::cc/120",
								IPv4IPIPTunnelAddr: "10.10.10.1",
							},
						},
					},
					options.SetOptions{},
				)
				Expect(err).NotTo(HaveOccurred())
			}

			// The HostIP will be added for the IPv4 address
			expectedCacheSize += 2
			ip := net.MustParseIP("1.2.3.4")
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectData(model.KVPair{
				Key:   model.HostIPKey{Hostname: "127.0.0.1"},
				Value: &ip,
			})
			syncTester.ExpectData(model.KVPair{
				Key:   model.HostConfigKey{Hostname: "127.0.0.1", Name: "IpInIpTunnelAddr"},
				Value: "10.10.10.1",
			})

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
			// The pool will add as single entry ( +1 ), plus will also create the default
			// Felix config with IPIP enabled.
			expectedCacheSize += 2
			syncTester.ExpectCacheSize(expectedCacheSize)
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
			syncTester.ExpectData(model.KVPair{
				Key: model.GlobalConfigKey{"IpInIpEnabled"},
				Value: "true",
			})

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Creating a HostEndpoint")
				hep, err := c.HostEndpoints().Create(
					ctx,
					&apiv2.HostEndpoint{
						ObjectMeta: metav1.ObjectMeta{
							Name: "hosta.eth0-a",
							Labels: map[string]string{
								"label1": "value1",
							},
						},
						Spec: apiv2.HostEndpointSpec{
							Node:          "127.0.0.1",
							InterfaceName: "eth0",
							ExpectedIPs:   []string{"1.2.3.4", "aa:bb::cc:dd"},
							Profiles:      []string{"profile1", "profile2"},
							Ports: []apiv2.EndpointPort{
								{
									Name:     "port1",
									Protocol: numorstring.ProtocolFromString("tcp"),
									Port:     1234,
								},
								{
									Name:     "port2",
									Protocol: numorstring.ProtocolFromString("udp"),
									Port:     1010,
								},
							},
						},
					},
					options.SetOptions{},
				)

				Expect(err).NotTo(HaveOccurred())
				// The host endpoint will add as single entry ( +1 )
				expectedCacheSize += 1
				syncTester.ExpectCacheSize(expectedCacheSize)
				syncTester.ExpectData(model.KVPair{
					Key: model.HostEndpointKey{Hostname: "127.0.0.1", EndpointID: "hosta.eth0-a"},
					Value: &model.HostEndpoint{
						Name:              "eth0",
						ExpectedIPv4Addrs: []net.IP{net.MustParseIP("1.2.3.4")},
						ExpectedIPv6Addrs: []net.IP{net.MustParseIP("aa:bb::cc:dd")},
						Labels: map[string]string{
							"label1": "value1",
						},
						ProfileIDs: []string{"profile1", "profile2"},
						Ports: []model.EndpointPort{
							{
								Name:     "port1",
								Protocol: numorstring.ProtocolFromString("tcp"),
								Port:     1234,
							},
							{
								Name:     "port2",
								Protocol: numorstring.ProtocolFromString("udp"),
								Port:     1010,
							},
						},
					},
					Revision: hep.ResourceVersion,
				})
			}

			By("Starting a new syncer and verifying that all current entries are returned before sync status")
			// We need to create a new syncTester and syncer.
			current := syncTester.GetCacheEntries()
			syncTester = testutils.NewSyncerTester()
			syncer = be.Syncer(syncTester)
			syncer.Start()

			// Verify the data is the same as the data from the previous cache.  We got the cache in the previous
			// step.
			syncTester.ExpectStatusUpdate(api.WaitForDatastore)
			syncTester.ExpectStatusUpdate(api.ResyncInProgress)
			syncTester.ExpectCacheSize(len(current))
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
