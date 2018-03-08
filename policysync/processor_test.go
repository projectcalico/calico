// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

package policysync_test

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/policysync"
	"github.com/projectcalico/felix/proto"
)

var _ = Describe("Processor", func() {
	var uut *policysync.Processor
	var updates chan interface{}
	var updateServiceAccount func(name, namespace string)
	var removeServiceAccount func(name, namespace string)
	var updateNamespace func(name string)
	var removeNamespace func(name string)
	var join func(w string) (chan proto.ToDataplane, policysync.JoinMetadata)

	BeforeEach(func() {
		updates = make(chan interface{})
		uut = policysync.NewProcessor(updates)

		updateServiceAccount = func(name, namespace string) {
			msg := &proto.ServiceAccountUpdate{
				Id: &proto.ServiceAccountID{Name: name, Namespace: namespace},
			}
			updates <- msg
		}
		removeServiceAccount = func(name, namespace string) {
			msg := &proto.ServiceAccountRemove{
				Id: &proto.ServiceAccountID{Name: name, Namespace: namespace},
			}
			updates <- msg
		}
		updateNamespace = func(name string) {
			msg := &proto.NamespaceUpdate{
				Id: &proto.NamespaceID{Name: name},
			}
			updates <- msg
		}
		removeNamespace = func(name string) {
			msg := &proto.NamespaceRemove{
				Id: &proto.NamespaceID{Name: name},
			}
			updates <- msg
		}
		join = func(w string) (chan proto.ToDataplane, policysync.JoinMetadata) {
			// Buffer outputs so that Processor won't block.
			output := make(chan proto.ToDataplane, 100)
			joinMeta := policysync.JoinMetadata{
				EndpointID: testId(w),
			}
			jr := policysync.JoinRequest{JoinMetadata: joinMeta, C: output}
			uut.JoinUpdates <- jr
			return output, joinMeta
		}
	})

	Context("with Processor started", func() {

		BeforeEach(func() {
			uut.Start()
		})

		Describe("ServiceAccount update/remove", func() {

			Context("updates before any join", func() {

				BeforeEach(func() {
					// Add, delete, re-add
					updateServiceAccount("test_serviceaccount0", "test_namespace0")
					removeServiceAccount("test_serviceaccount0", "test_namespace0")
					updateServiceAccount("test_serviceaccount0", "test_namespace0")

					// Some simple adds
					updateServiceAccount("test_serviceaccount0", "test_namespace1")
					updateServiceAccount("test_serviceaccount1", "test_namespace0")

					// Add, delete
					updateServiceAccount("removed", "removed")
					removeServiceAccount("removed", "removed")
				})

				Context("on new join", func() {
					var output chan proto.ToDataplane
					var accounts [3]proto.ServiceAccountID

					BeforeEach(func() {
						output, _ = join("test")
						for i := 0; i < 3; i++ {
							msg := <-output
							accounts[i] = *msg.GetServiceAccountUpdate().Id
						}
					})

					It("should get 3 updates", func() {
						Expect(accounts).To(ContainElement(proto.ServiceAccountID{
							Name: "test_serviceaccount0", Namespace: "test_namespace0"}))
						Expect(accounts).To(ContainElement(proto.ServiceAccountID{
							Name: "test_serviceaccount0", Namespace: "test_namespace1"}))
						Expect(accounts).To(ContainElement(proto.ServiceAccountID{
							Name: "test_serviceaccount1", Namespace: "test_namespace0"}))
					})

					It("should pass updates", func() {
						updateServiceAccount("t0", "t5")
						msg := <-output
						Expect(msg.GetServiceAccountUpdate().GetId()).To(Equal(
							&proto.ServiceAccountID{Name: "t0", Namespace: "t5"},
						))
					})

					It("should pass removes", func() {
						removeServiceAccount("test_serviceaccount0", "test_namespace0")
						msg := <-output
						Expect(msg.GetServiceAccountRemove().GetId()).To(Equal(&proto.ServiceAccountID{
							Name: "test_serviceaccount0", Namespace: "test_namespace0"},
						))
					})
				})
			})

			Context("with two joined endpoints", func() {
				var output [2]chan proto.ToDataplane

				BeforeEach(func() {
					for i := 0; i < 2; i++ {
						w := fmt.Sprintf("test%d", i)
						d := testId(w)
						output[i], _ = join(w)

						// Ensure the joins are completed by sending a workload endpoint for each.
						updates <- &proto.WorkloadEndpointUpdate{
							Id:       &d,
							Endpoint: &proto.WorkloadEndpoint{},
						}
						<-output[i]
					}
				})

				It("should forward updates to both endpoints", func() {
					updateServiceAccount("t23", "t2")
					Eventually(output[0]).Should(Receive(&proto.ToDataplane{
						Payload: &proto.ToDataplane_ServiceAccountUpdate{
							&proto.ServiceAccountUpdate{
								Id: &proto.ServiceAccountID{Name: "t23", Namespace: "t2"},
							},
						},
					}))
					Eventually(output[1]).Should(Receive(&proto.ToDataplane{
						Payload: &proto.ToDataplane_ServiceAccountUpdate{
							&proto.ServiceAccountUpdate{
								Id: &proto.ServiceAccountID{Name: "t23", Namespace: "t2"},
							},
						},
					}))
				})

				It("should forward removes to both endpoints", func() {
					removeServiceAccount("t23", "t2")
					Eventually(output[0]).Should(Receive(&proto.ToDataplane{
						Payload: &proto.ToDataplane_ServiceAccountRemove{
							&proto.ServiceAccountRemove{
								Id: &proto.ServiceAccountID{Name: "t23", Namespace: "t2"},
							},
						},
					}))
					Eventually(output[1]).Should(Receive(&proto.ToDataplane{
						Payload: &proto.ToDataplane_ServiceAccountRemove{
							&proto.ServiceAccountRemove{
								Id: &proto.ServiceAccountID{Name: "t23", Namespace: "t2"},
							},
						},
					}))
				})

			})
		})

		Describe("Namespace update/remove", func() {

			Context("updates before any join", func() {

				BeforeEach(func() {
					// Add, delete, re-add
					updateNamespace("test_namespace0")
					removeNamespace("test_namespace0")
					updateNamespace("test_namespace0")

					// Some simple adds
					updateNamespace("test_namespace1")
					updateNamespace("test_namespace2")

					// Add, delete
					updateNamespace("removed")
					removeNamespace("removed")
				})

				Context("on new join", func() {
					var output chan proto.ToDataplane
					var accounts [3]proto.NamespaceID

					BeforeEach(func() {
						output, _ = join("test")
						for i := 0; i < 3; i++ {
							msg := <-output
							accounts[i] = *msg.GetNamespaceUpdate().Id
						}
					})

					It("should get 3 updates", func() {
						Expect(accounts).To(ContainElement(proto.NamespaceID{Name: "test_namespace0"}))
						Expect(accounts).To(ContainElement(proto.NamespaceID{Name: "test_namespace1"}))
						Expect(accounts).To(ContainElement(proto.NamespaceID{Name: "test_namespace2"}))
					})

					It("should pass updates", func() {
						updateNamespace("t0")
						msg := <-output
						Expect(msg.GetNamespaceUpdate().GetId()).To(Equal(&proto.NamespaceID{Name: "t0"}))
					})

					It("should pass removes", func() {
						removeNamespace("test_namespace0")
						msg := <-output
						Expect(msg.GetNamespaceRemove().GetId()).To(Equal(&proto.NamespaceID{Name: "test_namespace0"}))
					})
				})
			})

			Context("with two joined endpoints", func() {
				var output [2]chan proto.ToDataplane

				BeforeEach(func() {
					for i := 0; i < 2; i++ {
						w := fmt.Sprintf("test%d", i)
						d := testId(w)
						output[i], _ = join(w)

						// Ensure the joins are completed by sending a workload endpoint for each.
						updates <- &proto.WorkloadEndpointUpdate{
							Id:       &d,
							Endpoint: &proto.WorkloadEndpoint{},
						}
						<-output[i]
					}
				})

				It("should forward updates to both endpoints", func() {
					updateNamespace("t23")
					Eventually(output[0]).Should(Receive(&proto.ToDataplane{
						Payload: &proto.ToDataplane_NamespaceUpdate{
							&proto.NamespaceUpdate{Id: &proto.NamespaceID{Name: "t23"}},
						},
					}))
					Eventually(output[1]).Should(Receive(&proto.ToDataplane{
						Payload: &proto.ToDataplane_NamespaceUpdate{
							&proto.NamespaceUpdate{Id: &proto.NamespaceID{Name: "t23"}},
						},
					}))
				})

				It("should forward removes to both endpoints", func() {
					removeNamespace("t23")
					Eventually(output[0]).Should(Receive(&proto.ToDataplane{
						Payload: &proto.ToDataplane_NamespaceRemove{
							&proto.NamespaceRemove{Id: &proto.NamespaceID{Name: "t23"}},
						},
					}))
					Eventually(output[1]).Should(Receive(&proto.ToDataplane{
						Payload: &proto.ToDataplane_NamespaceRemove{
							&proto.NamespaceRemove{Id: &proto.NamespaceID{Name: "t23"}},
						},
					}))
				})

			})
		})
	})
})

func testId(w string) proto.WorkloadEndpointID {
	return proto.WorkloadEndpointID{
		OrchestratorId: "test",
		WorkloadId:     w,
		EndpointId:     "test",
	}
}
