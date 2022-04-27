// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package nodestatussyncer_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/nodestatussyncer"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

// These tests validate that the resource that the NodeStatus watches are
// handled correctly by the syncer.  We don't validate in detail the behavior of
// each of update handlers that are invoked, since these are tested more thoroughly
// elsewhere.
var _ = testutils.E2eDatastoreDescribe("Calico node status syncer tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {

	ctx := context.Background()

	Describe("Node status syncer functionality", func() {
		It("should receive the synced after return all current data", func() {
			// Create a v3 client to drive data changes (luckily because this is the _test module,
			// we don't get circular imports.
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			// Create the backend client to obtain a syncer interface.
			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			// Create a SyncerTester to receive the Calico node status syncer callback events and to allow us
			// to assert state.
			syncTester := testutils.NewSyncerTester()
			syncer := nodestatussyncer.New(be, syncTester)
			syncer.Start()
			expectedCacheSize := 0

			By("Checking status is updated to sync'd at start of day")
			syncTester.ExpectStatusUpdate(api.WaitForDatastore)
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectStatusUpdate(api.ResyncInProgress)
			syncTester.ExpectStatusUpdate(api.InSync)
			syncTester.ExpectCacheSize(expectedCacheSize)

			By("Creating an CalicoNodeStatus")
			seconds := uint32(15)
			status, err := c.CalicoNodeStatus().Create(
				ctx,
				&apiv3.CalicoNodeStatus{
					ObjectMeta: metav1.ObjectMeta{Name: "mynodestatus"},
					Spec: apiv3.CalicoNodeStatusSpec{
						Node: "node1",
						Classes: []apiv3.NodeStatusClassType{
							apiv3.NodeStatusClassTypeAgent,
							apiv3.NodeStatusClassTypeBGP,
							apiv3.NodeStatusClassTypeRoutes,
						},
						UpdatePeriodSeconds: &seconds,
					},
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			// The status will add as single entry ( +1 )
			statusKeyV1 := model.ResourceKey{
				Name: "mynodestatus",
				Kind: apiv3.KindCalicoNodeStatus,
			}
			expectedCacheSize += 1
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectData(model.KVPair{
				Key: statusKeyV1,
				Value: &apiv3.CalicoNodeStatus{
					ObjectMeta: metav1.ObjectMeta{Name: "mynodestatus"},
					Spec: apiv3.CalicoNodeStatusSpec{
						Node: "node1",
						Classes: []apiv3.NodeStatusClassType{
							apiv3.NodeStatusClassTypeAgent,
							apiv3.NodeStatusClassTypeBGP,
							apiv3.NodeStatusClassTypeRoutes,
						},
						UpdatePeriodSeconds: &seconds,
					},
				},
				Revision: status.ResourceVersion,
			})

			By("Starting a new syncer and verifying that all current entries are returned before sync status")
			// We need to create a new syncTester and syncer.
			current := syncTester.GetCacheEntries()
			syncTester = testutils.NewSyncerTester()
			syncer = nodestatussyncer.New(be, syncTester)
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
