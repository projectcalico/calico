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
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/policysync"
	"github.com/projectcalico/felix/proto"
)

const IPSetName = "testset"
const ProfileName = "testpro"

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

		Describe("IP Set updates", func() {

			Context("with two joined endpoints, one with active profile", func() {
				var refdOutput chan proto.ToDataplane
				var unrefdOutput chan proto.ToDataplane
				var refdId proto.WorkloadEndpointID
				var unrefdId proto.WorkloadEndpointID
				var assertInactiveNoUpdate func()

				BeforeEach(func(done Done) {
					refdId = testId("refd")
					refdOutput, _ = join("refd")
					unrefdId = testId("unrefd")
					unrefdOutput, _ = join("unrefd")

					// Ensure the joins are completed by sending a workload endpoint for each.
					updates <- &proto.WorkloadEndpointUpdate{
						Id:       &refdId,
						Endpoint: &proto.WorkloadEndpoint{},
					}
					<-refdOutput
					updates <- &proto.WorkloadEndpointUpdate{
						Id:       &unrefdId,
						Endpoint: &proto.WorkloadEndpoint{},
					}
					<-unrefdOutput

					// Send the IPSet, a Profile referring to it, and a WEP update referring to the
					// Profile. This "activates" the WEP relative to the IPSet
					updates <- updateIpSet(IPSetName, 0)
					updates <- &proto.ActiveProfileUpdate{
						Id: &proto.ProfileID{Name: ProfileName},
						Profile: &proto.Profile{InboundRules: []*proto.Rule{
							{
								Action:      "allow",
								SrcIpSetIds: []string{IPSetName},
							},
						}},
					}
					updates <- &proto.WorkloadEndpointUpdate{
						Id:       &refdId,
						Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{ProfileName}},
					}
					// All three updates get pushed to the active endpoint (1)
					<-refdOutput
					<-refdOutput
					<-refdOutput

					assertInactiveNoUpdate = func() {
						// Send a WEP update for the inactive and check we get it from the output
						// channel. This ensures that the inactive endpoint didn't get the IPSetUpdate
						// without having to wait for a timeout.
						updates <- &proto.WorkloadEndpointUpdate{
							Id:       &unrefdId,
							Endpoint: &proto.WorkloadEndpoint{},
						}
						wep := <-unrefdOutput
						Expect(wep.GetWorkloadEndpointUpdate().GetId()).To(Equal(&unrefdId))
					}

					close(done)
				})

				It("should send IPSetUpdate to only to ref'd endpoint", func(done Done) {
					msg := updateIpSet(IPSetName, 2)
					updates <- msg
					g := <-refdOutput
					Expect(g).To(Equal(proto.ToDataplane{Payload: &proto.ToDataplane_IpsetUpdate{msg}}))

					assertInactiveNoUpdate()
					close(done)
				})

				It("should split large IPSetUpdate", func(done Done) {
					msg := updateIpSet(IPSetName, 82250)
					updates <- msg

					out := <-refdOutput
					Expect(len(out.GetIpsetUpdate().GetMembers())).To(Equal(82200))
					out = <-refdOutput
					Expect(len(out.GetIpsetDeltaUpdate().GetAddedMembers())).To(Equal(50))
					close(done)
				})

				It("should send IPSetDeltaUpdate to ref'd endpoint", func(done Done) {

					// Try combinations of adds, removes, and both to ensure the splitting logic
					// doesn't split these up strangely.

					msg2 := deltaUpdateIpSet(IPSetName, 2, 2)
					updates <- msg2
					g := <-refdOutput
					Expect(g).To(Equal(proto.ToDataplane{
						Payload: &proto.ToDataplane_IpsetDeltaUpdate{msg2}}))

					msg2 = deltaUpdateIpSet(IPSetName, 2, 0)
					updates <- msg2
					g = <-refdOutput
					// Split these tests to separate expects for add and delete so that
					// we don't distinguish nil vs [] for empty lists.
					Expect(g.GetIpsetDeltaUpdate().GetAddedMembers()).To(Equal(msg2.AddedMembers))
					Expect(len(g.GetIpsetDeltaUpdate().GetRemovedMembers())).To(Equal(0))

					msg2 = deltaUpdateIpSet(IPSetName, 0, 2)
					updates <- msg2
					g = <-refdOutput
					// Split these tests to separate expects for add and delete so that
					// we don't distinguish nil vs [] for empty lists.
					Expect(len(g.GetIpsetDeltaUpdate().GetAddedMembers())).To(Equal(0))
					Expect(g.GetIpsetDeltaUpdate().GetRemovedMembers()).To(Equal(msg2.RemovedMembers))

					assertInactiveNoUpdate()

					close(done)
				})

				It("should split IpSetDeltaUpdates with large adds", func(done Done) {
					msg2 := deltaUpdateIpSet(IPSetName, 82250, 0)
					updates <- msg2
					out := <-refdOutput
					Expect(len(out.GetIpsetDeltaUpdate().GetAddedMembers())).To(Equal(82200))
					Expect(len(out.GetIpsetDeltaUpdate().GetRemovedMembers())).To(Equal(0))
					out = <-refdOutput
					Expect(len(out.GetIpsetDeltaUpdate().GetAddedMembers())).To(Equal(50))
					Expect(len(out.GetIpsetDeltaUpdate().GetRemovedMembers())).To(Equal(0))

					close(done)
				})

				It("should split IpSetDeltaUpdates with large removes", func(done Done) {
					msg2 := deltaUpdateIpSet(IPSetName, 0, 82250)
					updates <- msg2
					out := <-refdOutput
					Expect(len(out.GetIpsetDeltaUpdate().GetAddedMembers())).To(Equal(0))
					Expect(len(out.GetIpsetDeltaUpdate().GetRemovedMembers())).To(Equal(50))
					out = <-refdOutput
					Expect(len(out.GetIpsetDeltaUpdate().GetAddedMembers())).To(Equal(0))
					Expect(len(out.GetIpsetDeltaUpdate().GetRemovedMembers())).To(Equal(82200))

					close(done)
				})

				It("should split IpSetDeltaUpdates with both large adds and removes", func(done Done) {
					msg2 := deltaUpdateIpSet(IPSetName, 82250, 82250)
					updates <- msg2
					out := <-refdOutput
					Expect(len(out.GetIpsetDeltaUpdate().GetAddedMembers())).To(Equal(82200))
					Expect(len(out.GetIpsetDeltaUpdate().GetRemovedMembers())).To(Equal(0))
					out = <-refdOutput
					Expect(len(out.GetIpsetDeltaUpdate().GetAddedMembers())).To(Equal(50))
					Expect(len(out.GetIpsetDeltaUpdate().GetRemovedMembers())).To(Equal(50))
					out = <-refdOutput
					Expect(len(out.GetIpsetDeltaUpdate().GetAddedMembers())).To(Equal(0))
					Expect(len(out.GetIpsetDeltaUpdate().GetRemovedMembers())).To(Equal(82200))

					close(done)
				})

				It("should send IPSetUpdate when endpoint newly refs wep update", func(done Done) {
					updates <- &proto.WorkloadEndpointUpdate{
						Id:       &unrefdId,
						Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{ProfileName}},
					}
					g := <-unrefdOutput
					Expect(g.GetIpsetUpdate().GetId()).To(Equal(IPSetName))
					Expect(len(g.GetIpsetUpdate().GetMembers())).To(Equal(0))
					<-unrefdOutput // should also send WEP Update

					close(done)
				})

				It("should send IPSetRemove when endpoint stops ref wep update", func(done Done) {
					updates <- &proto.WorkloadEndpointUpdate{
						Id:       &refdId,
						Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{}},
					}
					g := <-refdOutput
					Expect(g.GetWorkloadEndpointUpdate().GetId()).To(Equal(&refdId))
					g = <-refdOutput
					Expect(g.GetActiveProfileRemove().GetId().GetName()).To(Equal(ProfileName))
					g = <-refdOutput
					Expect(g.GetIpsetRemove().GetId()).To(Equal(IPSetName))

					// Remove the IPSet since nothing references it.
					updates <- removeIpSet(IPSetName)

					// Send & receive a repeat WEPUpdate to ensure we didn't get a second remove.
					updates <- &proto.WorkloadEndpointUpdate{
						Id:       &refdId,
						Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{}},
					}
					g = <-refdOutput
					Expect(g.GetWorkloadEndpointUpdate().GetId()).To(Equal(&refdId))

					assertInactiveNoUpdate()
					close(done)
				})

				It("should send IPSetUpdate when endpoint newly refs profile update", func(done Done) {
					newSetName := "new-set"
					updates <- updateIpSet(newSetName, 6)
					updates <- &proto.ActiveProfileUpdate{
						Id: &proto.ProfileID{Name: ProfileName},
						Profile: &proto.Profile{
							InboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{IPSetName, newSetName}},
							},
						},
					}

					// We should get the IPSetUpdate first, then the Profile that newly references it.
					g := <-refdOutput
					Expect(g.GetIpsetUpdate().GetId()).To(Equal(newSetName))
					Expect(len(g.GetIpsetUpdate().GetMembers())).To(Equal(6))

					g = <-refdOutput
					Expect(g.GetActiveProfileUpdate().GetId().GetName()).To(Equal(ProfileName))

					assertInactiveNoUpdate()

					close(done)
				})

				It("should send IPSetRemove when endpoint stops ref profile update", func(done Done) {
					updates <- &proto.ActiveProfileUpdate{
						Id: &proto.ProfileID{Name: ProfileName},
						Profile: &proto.Profile{
							InboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{}},
							},
						},
					}

					// We should get ActiveProfileUpdate first, then IPSetRemove.
					g := <-refdOutput
					Expect(g.GetActiveProfileUpdate().GetId().GetName()).To(Equal(ProfileName))
					g = <-refdOutput
					Expect(g.GetIpsetRemove().GetId()).To(Equal(IPSetName))

					assertInactiveNoUpdate()

					close(done)
				})

				It("should send IPSetUpdate/Remove when endpoint newly refs policy update", func(done Done) {
					// Create the policy without the ref, and link it to the unref'd WEP.
					policyID := &proto.PolicyID{Tier: "tier0", Name: "testpolicy"}
					updates <- &proto.ActivePolicyUpdate{
						Id: policyID,
						Policy: &proto.Policy{
							OutboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{}},
							},
						},
					}
					updates <- &proto.WorkloadEndpointUpdate{
						Id: &unrefdId,
						Endpoint: &proto.WorkloadEndpoint{
							Tiers: []*proto.TierInfo{
								{
									Name:            policyID.Tier,
									IngressPolicies: []string{policyID.Name},
								},
							},
						},
					}
					g := <-unrefdOutput
					Expect(g.GetActivePolicyUpdate().GetId()).To(Equal(policyID))
					g = <-unrefdOutput
					Expect(g.GetWorkloadEndpointUpdate()).ToNot(BeNil())

					// Now the WEP has an active policy that doesn't reference the IPSet. Send in
					// a Policy update that references the IPSet.
					updates <- &proto.ActivePolicyUpdate{
						Id: policyID,
						Policy: &proto.Policy{
							OutboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{IPSetName}},
							},
						},
					}

					// Should get IPSetUpdate, followed by Policy update
					g = <-unrefdOutput
					Expect(g.GetIpsetUpdate().GetId()).To(Equal(IPSetName))
					g = <-unrefdOutput
					Expect(g.GetActivePolicyUpdate().GetId()).To(Equal(policyID))

					// Now, remove the ref and get an IPSetRemove
					updates <- &proto.ActivePolicyUpdate{
						Id: policyID,
						Policy: &proto.Policy{
							OutboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{}},
							},
						},
					}

					g = <-unrefdOutput
					Expect(g.GetActivePolicyUpdate().GetId()).To(Equal(policyID))
					g = <-unrefdOutput
					Expect(g.GetIpsetRemove().GetId()).To(Equal(IPSetName))
					close(done)
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

func updateIpSet(id string, num int) *proto.IPSetUpdate {
	msg := &proto.IPSetUpdate{
		Id:   id,
		Type: proto.IPSetUpdate_IP,
	}
	for i := 0; i < num; i++ {
		msg.Members = append(msg.Members, makeIP(i))
	}
	return msg
}

func removeIpSet(id string) *proto.IPSetRemove {
	msg := &proto.IPSetRemove{
		Id: id,
	}
	return msg
}

func deltaUpdateIpSet(id string, add, del int) *proto.IPSetDeltaUpdate {
	msg := &proto.IPSetDeltaUpdate{
		Id: id,
	}
	for i := 0; i < add; i++ {
		msg.AddedMembers = append(msg.AddedMembers, makeIP(i))
	}
	for i := add; i < add+del; i++ {
		msg.RemovedMembers = append(msg.RemovedMembers, makeIP(i))
	}
	return msg
}

func makeIP(i int) string {
	o := make([]string, 4)
	o[0] = strconv.Itoa(i & 0xff000000 >> 24)
	o[1] = strconv.Itoa(i & 0x00ff0000 >> 16)
	o[2] = strconv.Itoa(i & 0x0000ff00 >> 8)
	o[3] = strconv.Itoa(i & 0x000000ff)
	return strings.Join(o, ".")
}
