// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package tunnelipsyncer_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/tunnelipsyncer"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

// These tests validate that the various resources that the BGP watches are
// handled correctly by the syncer.  We don't validate in detail the behavior of
// each of update handlers that are invoked, since these are tested more thoroughly
// elsewhere.
var _ = testutils.E2eDatastoreDescribe("Tunnel IP allocation syncer tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {

	ctx := context.Background()

	Describe("Tunnel IP allocation syncer functionality", func() {
		It("should receive the synced after return all current data", func() {
			// Create a v3 client to drive data changes (luckily because this is the _test module,
			// we don't get circular imports.
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			// Create the backend client to obtain a syncer interface.
			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			// Create a SyncerTester to receive the tunnel IP allocation syncer callback events and to allow us
			// to assert state.
			syncTester := testutils.NewSyncerTester()
			syncer := tunnelipsyncer.New(be, syncTester, "127.0.0.1")
			syncer.Start()
			expectedCacheSize := 0

			By("Checking status is updated to sync'd at start of day")
			syncTester.ExpectStatusUpdate(api.WaitForDatastore)
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectStatusUpdate(api.ResyncInProgress)
			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				expectedCacheSize += 1
			}
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectStatusUpdate(api.InSync)
			syncTester.ExpectCacheSize(expectedCacheSize)

			// For Kubernetes test one entry already in the cache for the node.
			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				syncTester.ExpectPath("/calico/resources/v3/projectcalico.org/nodes/127.0.0.1")
			}

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

			By("Starting a new syncer and verifying that all current entries are returned before sync status")
			// We need to create a new syncTester and syncer.
			current := syncTester.GetCacheEntries()
			syncTester = testutils.NewSyncerTester()
			syncer = tunnelipsyncer.New(be, syncTester, "127.0.0.1")
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
