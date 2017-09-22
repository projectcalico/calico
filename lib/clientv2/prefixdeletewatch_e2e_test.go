// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

package clientv2_test

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/libcalico-go/lib/apiv2"
	"github.com/projectcalico/libcalico-go/lib/backend"
	"github.com/projectcalico/libcalico-go/lib/clientv2"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/testutils"
	"github.com/projectcalico/libcalico-go/lib/watch"
)

// Perform CRUD operations on Global and Node-specific BGP Peer Resources.
var _ = testutils.E2eDatastoreDescribe("Prefix deletion watch test", testutils.DatastoreEtcdV3, func(config apiconfig.CalicoAPIConfig) {

	ctx := context.Background()
	numEvents := 10000

	Describe("Test prefix deletion of the datastore", func() {
		It("should receive watch events for each of the deleted keys", func() {
			c, err := clientv2.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Creating 10000 resources")
			deleteEvents := []watch.Event{}
			for ii := 1; ii <= numEvents; ii++ {
				name := fmt.Sprintf("peer-%08d", ii)
				peer := &apiv2.BGPPeer{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec: apiv2.BGPPeerSpec{
						PeerIP:   "1.2.3.4",
						ASNumber: numorstring.ASNumber(ii),
					},
				}
				_, outError := c.BGPPeers().Create(ctx, peer, options.SetOptions{})
				Expect(outError).NotTo(HaveOccurred())
				deleteEvents = append(deleteEvents, watch.Event{
					Type:     watch.Deleted,
					Previous: peer,
				})
			}

			By("Listing all the resources")
			outList, outError := c.BGPPeers().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(numEvents))

			By("Creating a watcher, watching the current resource version")
			w, _ := c.BGPPeers().Watch(ctx, options.ListOptions{ResourceVersion: outList.ResourceVersion})
			testWatcher := testutils.TestResourceWatch(w)
			defer testWatcher.Stop()

			By("Cleaning the datastore and expecting deletion events for each configured resource (tests prefix deletes results in individual events for each key)")
			be.Clean()
			testWatcher.ExpectEvents(apiv2.KindBGPPeer, deleteEvents)
		})
	})
})
