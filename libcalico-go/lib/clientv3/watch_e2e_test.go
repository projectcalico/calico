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

package clientv3

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// Perform additional watch tests
var _ = testutils.E2eDatastoreDescribe("Additional watch tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {

	ctx := context.Background()
	numEvents := 5000
	numWatchers := 100

	Describe("Test prefix deletion of the datastore", func() {
		It("should receive watch events for each of the deleted keys", func() {
			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				Skip("Watch not supported yet with Kubernetes Backend")
			}
			c, err := New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Creating 10000 resources")
			deleteEvents := []watch.Event{}
			for ii := 1; ii <= numEvents; ii++ {
				name := fmt.Sprintf("peer-%08d", ii)
				peer := &apiv3.BGPPeer{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec: apiv3.BGPPeerSpec{
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
			w, outError := c.BGPPeers().Watch(ctx, options.ListOptions{ResourceVersion: outList.ResourceVersion})
			Expect(outError).NotTo(HaveOccurred())
			testWatcher := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher.Stop()

			By("Cleaning the datastore and expecting deletion events for each configured resource (tests prefix deletes results in individual events for each key)")
			be.Clean()
			testWatcher.ExpectEvents(apiv3.KindBGPPeer, deleteEvents)

			By("Stopping the watcher and checking for full termination")
			testWatcher.Stop()
			Eventually(w.(*watcher).hasTerminated).Should(BeTrue())
		})
	})

	Describe("Test constant stream of events whilst closing watcher", func() {
		It("should handle gracefully closing watchers while events are occurring", func() {
			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				Skip("Watch not supported yet with Kubernetes Backend")
			}
			c, err := New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			// We create a number of threads in this test.  Use a context as a simple mechanism
			// for cancelling those threads.
			finishctx, finish := context.WithCancel(ctx)

			By("Creating an asynchronous events generator")
			wg := sync.WaitGroup{}

			// Create a goroutine to generate add/delete events.
			wg.Add(1)
			go func() {
				log.Info("Running test event generator")
				defer wg.Done()
				for {
					// Loop until told to exit creating and deleting a BGPPeer to create some
					// watch events.
					bgpPeer := &apiv3.BGPPeer{
						ObjectMeta: metav1.ObjectMeta{Name: "name1"},
						Spec: apiv3.BGPPeerSpec{
							PeerIP:   "1.2.3.4",
							ASNumber: numorstring.ASNumber(12345),
						},
					}
					_, err := c.BGPPeers().Create(ctx, bgpPeer, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())

					_, err = c.BGPPeers().Delete(ctx, "name1", options.DeleteOptions{})
					Expect(err).NotTo(HaveOccurred())

					if finishctx.Err() != nil {
						log.Info("Exiting test event generator goroutine")
						break
					}

					// Pause to prevent tight-looping.
					time.Sleep(5 * time.Millisecond)
				}

			}()

			// Create a number of goroutines to handle a Watcher.  Each go routine will pull
			// events off the watcher and exit once the results channel is closed.
			watchers := make([]watch.Interface, numWatchers)
			for i := 0; i < numWatchers; i++ {
				watchers[i], err = c.BGPPeers().Watch(ctx, options.ListOptions{})
				Expect(err).NotTo(HaveOccurred())
				defer watchers[i].Stop()

				wg.Add(1)
				go func(w watch.Interface) {
					log.Info("Running test event consumer")
					defer GinkgoRecover()
					defer wg.Done()
					for e := range w.ResultChan() {
						if e.Type == watch.Deleted {
							Expect(e.Previous).NotTo(BeNil())
							Expect(e.Previous.(*apiv3.BGPPeer).Name).To(Equal("name1"))
						}
						if e.Type == watch.Added {
							Expect(e.Object).NotTo(BeNil())
							Expect(e.Object.(*apiv3.BGPPeer).Name).To(Equal("name1"))
						}
					}
					log.Info("Exiting test event consumer goroutine")
				}(watchers[i])
			}

			// Loop through the watchers and start stopping them with a random sized pause
			// interval between each.
			for i := 0; i < numWatchers; i++ {
				d := time.Millisecond * time.Duration(5+rand.Int()%50)
				log.Infof("Sleeping for %v ms and then stopping watcher", d)
				time.Sleep(d)
				watchers[i].Stop()
			}

			// Finish the events goroutine and wait for all of the goroutines to complete.
			finish()
			wg.Wait()
		})
	})
})
