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

package clientv3_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"context"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

var _ = testutils.E2eDatastoreDescribe("CalicoNodeStatus tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {

	ctx := context.Background()
	name1 := "caliconodestatus-1"
	name2 := "caliconodestatus-2"
	seconds1 := uint32(11)
	seconds2 := uint32(12)
	spec1 := apiv3.CalicoNodeStatusSpec{
		Node: "node1",
		Classes: []apiv3.NodeStatusClassType{
			apiv3.NodeStatusClassTypeAgent,
			apiv3.NodeStatusClassTypeBGP,
			apiv3.NodeStatusClassTypeRoutes,
		},
		UpdatePeriodSeconds: &seconds1,
	}
	spec2 := apiv3.CalicoNodeStatusSpec{
		Node: "node2",
		Classes: []apiv3.NodeStatusClassType{
			apiv3.NodeStatusClassTypeAgent,
			apiv3.NodeStatusClassTypeBGP,
			apiv3.NodeStatusClassTypeRoutes,
		},
		UpdatePeriodSeconds: &seconds2,
	}

	updateTime := metav1.Time{Time: justBeforeTheHour()}
	status1 := apiv3.CalicoNodeStatusStatus{
		LastUpdated: updateTime,
		Agent: apiv3.CalicoNodeAgentStatus{
			BIRDV4: apiv3.BGPDaemonStatus{
				State:                   apiv3.BGPDaemonStateReady,
				Version:                 "birdv1.23",
				RouterID:                "123456",
				LastBootTime:            "lastboottime1",
				LastReconfigurationTime: "lastreconfigtime1",
			},
			BIRDV6: apiv3.BGPDaemonStatus{
				State:                   apiv3.BGPDaemonStateNotReady,
				Version:                 "birdv1.23",
				RouterID:                "123456",
				LastBootTime:            "lastboottime1",
				LastReconfigurationTime: "lastreconfigtime1",
			},
		},
		BGP: apiv3.CalicoNodeBGPStatus{
			NumberEstablishedV4:    2,
			NumberNotEstablishedV4: 0,
			NumberEstablishedV6:    0,
			NumberNotEstablishedV6: 0,
			PeersV4: []apiv3.CalicoNodePeer{
				{
					PeerIP: "172.17.0.5",
					Type:   "nodeMesh",
					State:  apiv3.BGPSessionStateEstablished,
					Since:  "09:19:28",
				},
			},
			PeersV6: []apiv3.CalicoNodePeer{
				{
					PeerIP: "2001:20::8",
					Type:   "nodeMesh",
					State:  apiv3.BGPSessionStateEstablished,
					Since:  "09:19:28",
				},
			},
		},
		Routes: apiv3.CalicoNodeBGPRouteStatus{
			RoutesV4: []apiv3.CalicoNodeRoute{
				{
					Type:        "FIB",
					Destination: "192.168.110.128/26",
					Gateway:     "172.17.0.5",
					Interface:   "eth0",
					LearnedFrom: apiv3.CalicoNodeRouteLearnedFrom{
						SourceType: apiv3.RouteSourceTypeNodeMesh,
						PeerIP:     "172.17.0.5",
					},
				},
				{
					Type:        "FIB",
					Destination: "192.168.162.129/32",
					Gateway:     "N/A",
					Interface:   "calie58e37f9a7f",
					LearnedFrom: apiv3.CalicoNodeRouteLearnedFrom{
						SourceType: apiv3.RouteSourceTypeKernel,
					},
				},
			},
		},
	}
	status2 := apiv3.CalicoNodeStatusStatus{
		LastUpdated: updateTime,
		Agent: apiv3.CalicoNodeAgentStatus{
			BIRDV4: apiv3.BGPDaemonStatus{
				State:                   apiv3.BGPDaemonStateReady,
				Version:                 "birdv1.23",
				RouterID:                "654321",
				LastBootTime:            "lastboottime1",
				LastReconfigurationTime: "lastreconfigtime1",
			},
			BIRDV6: apiv3.BGPDaemonStatus{
				State:                   apiv3.BGPDaemonStateNotReady,
				Version:                 "birdv1.23",
				RouterID:                "654321",
				LastBootTime:            "lastboottime1",
				LastReconfigurationTime: "lastreconfigtime1",
			},
		},
		BGP: apiv3.CalicoNodeBGPStatus{
			NumberEstablishedV4:    2,
			NumberNotEstablishedV4: 0,
			NumberEstablishedV6:    0,
			NumberNotEstablishedV6: 0,
			PeersV4: []apiv3.CalicoNodePeer{
				{
					PeerIP: "172.17.0.6",
					Type:   "nodeMesh",
					State:  apiv3.BGPSessionStateEstablished,
					Since:  "09:19:28",
				},
			},
			PeersV6: []apiv3.CalicoNodePeer{
				{
					PeerIP: "2001:10::8",
					Type:   "nodeMesh",
					State:  apiv3.BGPSessionStateEstablished,
					Since:  "09:19:28",
				},
			},
		},
		Routes: apiv3.CalicoNodeBGPRouteStatus{
			RoutesV4: []apiv3.CalicoNodeRoute{
				{
					Type:        "FIB",
					Destination: "192.168.112.128/26",
					Gateway:     "172.17.0.6",
					Interface:   "eth0",
					LearnedFrom: apiv3.CalicoNodeRouteLearnedFrom{
						SourceType: apiv3.RouteSourceTypeNodeMesh,
						PeerIP:     "172.17.0.6",
					},
				},
				{
					Type:        "FIB",
					Destination: "192.168.182.129/32",
					Gateway:     "N/A",
					Interface:   "calie58e37f9a7f",
					LearnedFrom: apiv3.CalicoNodeRouteLearnedFrom{
						SourceType: apiv3.RouteSourceTypeKernel,
					},
				},
			},
		},
	}

	DescribeTable("CalicoNodeStatus e2e CRUD tests",
		func(name1, name2 string, status1, status2 apiv3.CalicoNodeStatusStatus) {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Updating the CalicoNodeStatus before it is created")
			_, outError := c.CalicoNodeStatus().Update(ctx, &apiv3.CalicoNodeStatus{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now(), UID: "test-fail-caliconodestatus"},
				Spec:       spec1,
				Status:     status1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: CalicoNodeStatus(" + name1 + ") with error:"))

			By("Attempting to creating a new CalicoNodeStatus with name1/spec1/status1 and a non-empty ResourceVersion")
			_, outError = c.CalicoNodeStatus().Create(ctx, &apiv3.CalicoNodeStatus{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "12345"},
				Spec:       spec1,
				Status:     status1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))

			By("Creating a new CalicoNodeStatus with name1/spec1/status1")
			res1, outError := c.CalicoNodeStatus().Create(ctx, &apiv3.CalicoNodeStatus{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec1,
				Status:     status1,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())

			// The location field of LastUpdated (loc:(*time.Location)(0x2d1e7e0)}) will be populated
			// by datastore on write. Hence we need to copy over it to original status before comparing against it.
			status1.LastUpdated = res1.Status.LastUpdated
			Expect(res1).To(MatchResourceWithStatus(apiv3.KindCalicoNodeStatus, testutils.ExpectNoNamespace, name1, spec1, status1))

			// Track the version of the original data for name1.
			rv1_1 := res1.ResourceVersion

			By("Attempting to create the same CalicoNodeStatus with name1 but with spec2/status2")
			_, outError = c.CalicoNodeStatus().Create(ctx, &apiv3.CalicoNodeStatus{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec2,
				Status:     status2,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource already exists: CalicoNodeStatus(" + name1 + ")"))

			By("Getting CalicoNodeStatus (name1) and comparing the output against spec1/status1")
			res, outError := c.CalicoNodeStatus().Get(ctx, name1, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResourceWithStatus(apiv3.KindCalicoNodeStatus, testutils.ExpectNoNamespace, name1, spec1, status1))
			Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))

			By("Getting CalicoNodeStatus (name2) before it is created")
			_, outError = c.CalicoNodeStatus().Get(ctx, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: CalicoNodeStatus(" + name2 + ") with error:"))

			By("Listing all the CalicoNodeStatus, expecting a single result with name1/spec1/status1")
			outList, outError := c.CalicoNodeStatus().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.ResourceWithStatus(apiv3.KindCalicoNodeStatus, testutils.ExpectNoNamespace, name1, spec1, status1),
			))

			By("Creating a new CalicoNodeStatus with name2/status2")
			res2, outError := c.CalicoNodeStatus().Create(ctx, &apiv3.CalicoNodeStatus{
				ObjectMeta: metav1.ObjectMeta{Name: name2},
				Spec:       spec2,
				Status:     status2,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			status2.LastUpdated = res2.Status.LastUpdated
			Expect(res2).To(MatchResourceWithStatus(apiv3.KindCalicoNodeStatus, testutils.ExpectNoNamespace, name2, spec2, status2))

			By("Getting CalicoNodeStatus (name2) and comparing the output against spec2/status2")
			res, outError = c.CalicoNodeStatus().Get(ctx, name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res2).To(MatchResourceWithStatus(apiv3.KindCalicoNodeStatus, testutils.ExpectNoNamespace, name2, spec2, status2))
			Expect(res.ResourceVersion).To(Equal(res2.ResourceVersion))

			By("Listing all the CalicoNodeStatus, expecting two results with name1/spec1/status1 and name2/spec2/status2")
			outList, outError = c.CalicoNodeStatus().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.ResourceWithStatus(apiv3.KindCalicoNodeStatus, testutils.ExpectNoNamespace, name1, spec1, status1),
				testutils.ResourceWithStatus(apiv3.KindCalicoNodeStatus, testutils.ExpectNoNamespace, name2, spec2, status2),
			))

			By("Updating CalicoNodeStatus name1 with status2")
			res1.Status = status2
			res1, outError = c.CalicoNodeStatus().Update(ctx, res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResourceWithStatus(apiv3.KindCalicoNodeStatus, testutils.ExpectNoNamespace, name1, spec1, status2))

			By("Attempting to update the CalicoNodeStatus without a Creation Timestamp")
			res, outError = c.CalicoNodeStatus().Update(ctx, &apiv3.CalicoNodeStatus{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", UID: "test-fail-caliconodestatus"},
				Spec:       spec1,
				Status:     status1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.CreationTimestamp = '0001-01-01 00:00:00 +0000 UTC' (field must be set for an Update request)"))

			By("Attempting to update the CalicoNodeStatus without a UID")
			res, outError = c.CalicoNodeStatus().Update(ctx, &apiv3.CalicoNodeStatus{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now()},
				Spec:       spec1,
				Status:     status1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.UID = '' (field must be set for an Update request)"))

			// Track the version of the updated name1 data.
			rv1_2 := res1.ResourceVersion

			By("Updating CalicoNodeStatus name1 without specifying a resource version")
			res1.Spec = spec1
			res1.Status = status1
			res1.ObjectMeta.ResourceVersion = ""
			_, outError = c.CalicoNodeStatus().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '' (field must be set for an Update request)"))

			By("Updating CalicoNodeStatus name1 using the previous resource version")
			res1.Spec = spec1
			res1.Status = status1
			res1.ResourceVersion = rv1_1
			_, outError = c.CalicoNodeStatus().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: CalicoNodeStatus(" + name1 + ")"))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Getting CalicoNodeStatus (name1) with the original resource version and comparing the output against status1")
				res, outError = c.CalicoNodeStatus().Get(ctx, name1, options.GetOptions{ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(res).To(MatchResourceWithStatus(apiv3.KindCalicoNodeStatus, testutils.ExpectNoNamespace, name1, spec1, status1))
				Expect(res.ResourceVersion).To(Equal(rv1_1))
			}

			By("Getting CalicoNodeStatus (name1) with the updated resource version and comparing the output against status2")
			res, outError = c.CalicoNodeStatus().Get(ctx, name1, options.GetOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResourceWithStatus(apiv3.KindCalicoNodeStatus, testutils.ExpectNoNamespace, name1, spec1, status2))
			Expect(res.ResourceVersion).To(Equal(rv1_2))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Listing CalicoNodeStatus with the original resource version and checking for a single result with name1/spec1/status1")
				outList, outError = c.CalicoNodeStatus().List(ctx, options.ListOptions{ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(outList.Items).To(ConsistOf(
					testutils.ResourceWithStatus(apiv3.KindCalicoNodeStatus, testutils.ExpectNoNamespace, name1, spec1, status1),
				))
			}

			By("Listing CalicoNodeStatus with the latest resource version and checking for two results with name1/spec1/status2 and name2/spec2/status2")
			outList, outError = c.CalicoNodeStatus().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.ResourceWithStatus(apiv3.KindCalicoNodeStatus, testutils.ExpectNoNamespace, name1, spec1, status2),
				testutils.ResourceWithStatus(apiv3.KindCalicoNodeStatus, testutils.ExpectNoNamespace, name2, spec2, status2),
			))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Deleting CalicoNodeStatus (name1) with the old resource version")
				_, outError = c.CalicoNodeStatus().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: rv1_1})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(Equal("update conflict: CalicoNodeStatus(" + name1 + ")"))
			}

			By("Deleting CalicoNodeStatus (name1) with the new resource version")
			dres, outError := c.CalicoNodeStatus().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(dres).To(MatchResourceWithStatus(apiv3.KindCalicoNodeStatus, testutils.ExpectNoNamespace, name1, spec1, status2))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Updating CalicoNodeStatus name2 with a 2s TTL and waiting for the entry to be deleted")
				_, outError = c.CalicoNodeStatus().Update(ctx, res2, options.SetOptions{TTL: 2 * time.Second})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(1 * time.Second)
				_, outError = c.CalicoNodeStatus().Get(ctx, name2, options.GetOptions{})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(2 * time.Second)
				_, outError = c.CalicoNodeStatus().Get(ctx, name2, options.GetOptions{})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(ContainSubstring("resource does not exist: CalicoNodeStatus(" + name2 + ") with error:"))

				By("Creating CalicoNodeStatus name2 with a 2s TTL and waiting for the entry to be deleted")
				_, outError = c.CalicoNodeStatus().Create(ctx, &apiv3.CalicoNodeStatus{
					ObjectMeta: metav1.ObjectMeta{Name: name2},
					Spec:       spec2,
					Status:     status2,
				}, options.SetOptions{TTL: 2 * time.Second})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(1 * time.Second)
				_, outError = c.CalicoNodeStatus().Get(ctx, name2, options.GetOptions{})
				Expect(outError).NotTo(HaveOccurred())
				time.Sleep(2 * time.Second)
				_, outError = c.CalicoNodeStatus().Get(ctx, name2, options.GetOptions{})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(ContainSubstring("resource does not exist: CalicoNodeStatus(" + name2 + ") with error:"))
			}

			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				By("Attempting to deleting CalicoNodeStatus (name2)")
				dres, outError = c.CalicoNodeStatus().Delete(ctx, name2, options.DeleteOptions{})
				Expect(outError).NotTo(HaveOccurred())
				Expect(dres).To(MatchResourceWithStatus(apiv3.KindCalicoNodeStatus, testutils.ExpectNoNamespace, name2, spec2, status2))
			}

			By("Attempting to deleting CalicoNodeStatus (name2) again")
			_, outError = c.CalicoNodeStatus().Delete(ctx, name2, options.DeleteOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: CalicoNodeStatus(" + name2 + ") with error:"))

			By("Listing all CalicoNodeStatus and expecting no items")
			outList, outError = c.CalicoNodeStatus().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))

			By("Getting CalicoNodeStatus (name2) and expecting an error")
			_, outError = c.CalicoNodeStatus().Get(ctx, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: CalicoNodeStatus(" + name2 + ") with error:"))
		},

		Entry("CalicoNodeStatus 1,2", name1, name2, status1, status2),
	)

	Describe("CalicoNodeStatus watch functionality", func() {
		It("should handle watch events for different resource versions and event types", func() {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Listing CalicoNodeStatus with the latest resource version and checking for two results with name1/status2 and name2/status2")
			outList, outError := c.CalicoNodeStatus().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))
			rev0 := outList.ResourceVersion

			By("Configuring a CalicoNodeStatus name1/status1 and storing the response")
			outRes1, err := c.CalicoNodeStatus().Create(
				ctx,
				&apiv3.CalicoNodeStatus{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       spec1,
					Status:     status1,
				},
				options.SetOptions{},
			)
			rev1 := outRes1.ResourceVersion

			By("Configuring a CalicoNodeStatus name2/spec2/status2 and storing the response")
			outRes2, err := c.CalicoNodeStatus().Create(
				ctx,
				&apiv3.CalicoNodeStatus{
					ObjectMeta: metav1.ObjectMeta{Name: name2},
					Spec:       spec2,
					Status:     status2,
				},
				options.SetOptions{},
			)

			By("Starting a watcher from revision rev1 - this should skip the first creation")
			w, err := c.CalicoNodeStatus().Watch(ctx, options.ListOptions{ResourceVersion: rev1})
			Expect(err).NotTo(HaveOccurred())
			testWatcher1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher1.Stop()

			By("Deleting res1")
			_, err = c.CalicoNodeStatus().Delete(ctx, name1, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Checking for two events, create res2 and delete re1")
			testWatcher1.ExpectEvents(apiv3.KindCalicoNodeStatus, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes2,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
			})
			testWatcher1.Stop()

			By("Starting a watcher from rev0 - this should get all events")
			w, err = c.CalicoNodeStatus().Watch(ctx, options.ListOptions{ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher2.Stop()

			By("Modifying res2")
			outRes3, err := c.CalicoNodeStatus().Update(
				ctx,
				&apiv3.CalicoNodeStatus{
					ObjectMeta: outRes2.ObjectMeta,
					Spec:       spec2,
					Status:     status1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			testWatcher2.ExpectEvents(apiv3.KindCalicoNodeStatus, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes1,
				},
				{
					Type:   watch.Added,
					Object: outRes2,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
				{
					Type:     watch.Modified,
					Previous: outRes2,
					Object:   outRes3,
				},
			})
			testWatcher2.Stop()

			// Only etcdv3 supports watching a specific instance of a resource.
			if config.Spec.DatastoreType == apiconfig.EtcdV3 {
				By("Starting a watcher from rev0 watching name1 - this should get all events for name1")
				w, err = c.CalicoNodeStatus().Watch(ctx, options.ListOptions{Name: name1, ResourceVersion: rev0})
				Expect(err).NotTo(HaveOccurred())
				testWatcher2_1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
				defer testWatcher2_1.Stop()
				testWatcher2_1.ExpectEvents(apiv3.KindCalicoNodeStatus, []watch.Event{
					{
						Type:   watch.Added,
						Object: outRes1,
					},
					{
						Type:     watch.Deleted,
						Previous: outRes1,
					},
				})
				testWatcher2_1.Stop()
			}

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.CalicoNodeStatus().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher3 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher3.Stop()
			testWatcher3.ExpectEvents(apiv3.KindCalicoNodeStatus, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})
			testWatcher3.Stop()

			By("Configuring CalicoNodeStatus name1/spec1/status1 again and storing the response")
			outRes1, err = c.CalicoNodeStatus().Create(
				ctx,
				&apiv3.CalicoNodeStatus{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       spec1,
					Status:     status1,
				},
				options.SetOptions{},
			)

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.CalicoNodeStatus().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher4 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher4.Stop()
			testWatcher4.ExpectEventsAnyOrder(apiv3.KindCalicoNodeStatus, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes1,
				},
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})

			By("Cleaning the datastore and expecting deletion events for each configured resource (tests prefix deletes results in individual events for each key)")
			be.Clean()
			testWatcher4.ExpectEvents(apiv3.KindCalicoNodeStatus, []watch.Event{
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes3,
				},
			})
			testWatcher4.Stop()
		})
	})
})

func justBeforeTheHour() time.Time {
	T1, err := time.Parse(time.RFC3339, "2016-05-19T09:59:00Z")
	if err != nil {
		panic("test setup error")
	}
	return T1
}
