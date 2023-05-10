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
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"reflect"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/projectcalico/calico/felix/policysync"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/pod2daemon/binder"
)

const IPSetName = "testset"
const ProfileName = "testpro"
const TierName = "testtier"
const PolicyName = "testpolicy"

var _ = Describe("Processor", func() {
	var uut *policysync.Processor
	var updates chan interface{}
	var updateServiceAccount func(name, namespace string)
	var removeServiceAccount func(name, namespace string)
	var updateNamespace func(name string)
	var removeNamespace func(name string)
	var join func(w string, jid uint64) (chan proto.ToDataplane, policysync.JoinMetadata)
	var leave func(jm policysync.JoinMetadata)

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
		join = func(w string, jid uint64) (chan proto.ToDataplane, policysync.JoinMetadata) {
			// Buffer outputs so that Processor won't block.
			output := make(chan proto.ToDataplane, 100)
			joinMeta := policysync.JoinMetadata{
				EndpointID: testId(w),
				JoinUID:    jid,
			}
			jr := policysync.JoinRequest{JoinMetadata: joinMeta, C: output}
			uut.JoinUpdates <- jr
			return output, joinMeta
		}
		leave = func(jm policysync.JoinMetadata) {
			lr := policysync.LeaveRequest{JoinMetadata: jm}
			uut.JoinUpdates <- lr
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
						output, _ = join("test", 1)
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
						output[i], _ = join(w, uint64(i))

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
							ServiceAccountUpdate: &proto.ServiceAccountUpdate{
								Id: &proto.ServiceAccountID{Name: "t23", Namespace: "t2"},
							},
						},
					}))
					Eventually(output[1]).Should(Receive(&proto.ToDataplane{
						Payload: &proto.ToDataplane_ServiceAccountUpdate{
							ServiceAccountUpdate: &proto.ServiceAccountUpdate{
								Id: &proto.ServiceAccountID{Name: "t23", Namespace: "t2"},
							},
						},
					}))
				})

				It("should forward removes to both endpoints", func() {
					removeServiceAccount("t23", "t2")
					Eventually(output[0]).Should(Receive(&proto.ToDataplane{
						Payload: &proto.ToDataplane_ServiceAccountRemove{
							ServiceAccountRemove: &proto.ServiceAccountRemove{
								Id: &proto.ServiceAccountID{Name: "t23", Namespace: "t2"},
							},
						},
					}))
					Eventually(output[1]).Should(Receive(&proto.ToDataplane{
						Payload: &proto.ToDataplane_ServiceAccountRemove{
							ServiceAccountRemove: &proto.ServiceAccountRemove{
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
						output, _ = join("test", 1)
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
						output[i], _ = join(w, uint64(i))

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
							NamespaceUpdate: &proto.NamespaceUpdate{Id: &proto.NamespaceID{Name: "t23"}},
						},
					}))
					Eventually(output[1]).Should(Receive(&proto.ToDataplane{
						Payload: &proto.ToDataplane_NamespaceUpdate{
							NamespaceUpdate: &proto.NamespaceUpdate{Id: &proto.NamespaceID{Name: "t23"}},
						},
					}))
				})

				It("should forward removes to both endpoints", func() {
					removeNamespace("t23")
					Eventually(output[0]).Should(Receive(&proto.ToDataplane{
						Payload: &proto.ToDataplane_NamespaceRemove{
							NamespaceRemove: &proto.NamespaceRemove{Id: &proto.NamespaceID{Name: "t23"}},
						},
					}))
					Eventually(output[1]).Should(Receive(&proto.ToDataplane{
						Payload: &proto.ToDataplane_NamespaceRemove{
							NamespaceRemove: &proto.NamespaceRemove{Id: &proto.NamespaceID{Name: "t23"}},
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
				var proUpd *proto.ActiveProfileUpdate
				var ipSetUpd *proto.IPSetUpdate

				BeforeEach(func(done Done) {
					refdId = testId("refd")
					refdOutput, _ = join("refd", 1)
					unrefdId = testId("unrefd")
					unrefdOutput, _ = join("unrefd", 2)

					// Ensure the joins are completed by sending a workload endpoint for each.
					refUpd := &proto.WorkloadEndpointUpdate{
						Id:       &refdId,
						Endpoint: &proto.WorkloadEndpoint{},
					}
					updates <- refUpd
					g := <-refdOutput
					Expect(&g).To(HavePayload(refUpd))
					unrefUpd := &proto.WorkloadEndpointUpdate{
						Id:       &unrefdId,
						Endpoint: &proto.WorkloadEndpoint{},
					}
					updates <- unrefUpd
					g = <-unrefdOutput
					Expect(&g).To(HavePayload(unrefUpd))

					// Send the IPSet, a Profile referring to it, and a WEP update referring to the
					// Profile. This "activates" the WEP relative to the IPSet
					ipSetUpd = updateIpSet(IPSetName, 0)
					updates <- ipSetUpd
					proUpd = &proto.ActiveProfileUpdate{
						Id: &proto.ProfileID{Name: ProfileName},
						Profile: &proto.Profile{InboundRules: []*proto.Rule{
							{
								Action:      "allow",
								SrcIpSetIds: []string{IPSetName},
							},
						}},
					}
					updates <- proUpd
					wepUpd := &proto.WorkloadEndpointUpdate{
						Id:       &refdId,
						Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{ProfileName}},
					}
					updates <- wepUpd
					// All three updates get pushed to the active endpoint (1)
					g = <-refdOutput
					Expect(&g).To(HavePayload(ipSetUpd))
					g = <-refdOutput
					Expect(&g).To(HavePayload(proUpd))
					g = <-refdOutput
					Expect(&g).To(HavePayload(wepUpd))

					assertInactiveNoUpdate = func() {
						// Send a WEP update for the inactive and check we get it from the output
						// channel. This ensures that the inactive endpoint didn't get the IPSetUpdate
						// without having to wait for a timeout.
						u := &proto.WorkloadEndpointUpdate{
							Id:       &unrefdId,
							Endpoint: &proto.WorkloadEndpoint{},
						}
						updates <- u
						g := <-unrefdOutput
						Expect(&g).To(HavePayload(u))
					}

					close(done)
				})

				It("should send IPSetUpdate to only to ref'd endpoint", func(done Done) {
					msg := updateIpSet(IPSetName, 2)
					updates <- msg
					g := <-refdOutput
					Expect(g).To(Equal(proto.ToDataplane{Payload: &proto.ToDataplane_IpsetUpdate{IpsetUpdate: msg}}))

					assertInactiveNoUpdate()
					close(done)
				})

				It("should send IPSetDeltaUpdate to ref'd endpoint", func(done Done) {

					// Try combinations of adds, removes, and both to ensure the splitting logic
					// doesn't split these up strangely.

					msg2 := deltaUpdateIpSet(IPSetName, 2, 2)
					updates <- msg2
					g := <-refdOutput
					Expect(g).To(Equal(proto.ToDataplane{
						Payload: &proto.ToDataplane_IpsetDeltaUpdate{IpsetDeltaUpdate: msg2}}))

					msg2 = deltaUpdateIpSet(IPSetName, 2, 0)
					updates <- msg2
					g = <-refdOutput
					// Split these tests to separate expects for add and delete so that
					// we don't distinguish nil vs [] for empty lists.
					Expect(g.GetIpsetDeltaUpdate().GetAddedMembers()).To(Equal(msg2.AddedMembers))
					Expect(g.GetIpsetDeltaUpdate().GetRemovedMembers()).To(HaveLen(0))

					msg2 = deltaUpdateIpSet(IPSetName, 0, 2)
					updates <- msg2
					g = <-refdOutput
					// Split these tests to separate expects for add and delete so that
					// we don't distinguish nil vs [] for empty lists.
					Expect(g.GetIpsetDeltaUpdate().GetAddedMembers()).To(HaveLen(0))
					Expect(g.GetIpsetDeltaUpdate().GetRemovedMembers()).To(Equal(msg2.RemovedMembers))

					assertInactiveNoUpdate()

					close(done)
				})

				It("should send IPSetUpdate when endpoint newly refs wep update", func(done Done) {
					wepUpd := &proto.WorkloadEndpointUpdate{
						Id:       &unrefdId,
						Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{ProfileName}},
					}
					updates <- wepUpd
					g := <-unrefdOutput
					Expect(&g).To(HavePayload(ipSetUpd))

					g = <-unrefdOutput
					Expect(&g).To(HavePayload(proUpd))

					g = <-unrefdOutput
					Expect(&g).To(HavePayload(wepUpd))

					close(done)
				})

				It("should send IPSetRemove when endpoint stops ref wep update", func(done Done) {
					wepUpd := &proto.WorkloadEndpointUpdate{
						Id:       &refdId,
						Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{}},
					}
					updates <- wepUpd
					g := <-refdOutput
					Expect(&g).To(HavePayload(wepUpd))
					g = <-refdOutput
					Expect(&g).To(HavePayload(&proto.ActiveProfileRemove{Id: &proto.ProfileID{Name: ProfileName}}))
					g = <-refdOutput
					Expect(&g).To(HavePayload(&proto.IPSetRemove{Id: IPSetName}))

					// Remove the IPSet since nothing references it.
					updates <- removeIpSet(IPSetName)

					// Send & receive a repeat WEPUpdate to ensure we didn't get a second remove.
					updates <- wepUpd
					g = <-refdOutput
					Expect(&g).To(HavePayload(wepUpd))

					assertInactiveNoUpdate()
					close(done)
				})

				It("should send IPSetUpdate when endpoint newly refs profile update", func(done Done) {
					newSetName := "new-set"
					updates <- updateIpSet(newSetName, 6)
					pu := &proto.ActiveProfileUpdate{
						Id: &proto.ProfileID{Name: ProfileName},
						Profile: &proto.Profile{
							InboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{IPSetName, newSetName}},
							},
						},
					}
					updates <- pu

					// We should get the IPSetUpdate first, then the Profile that newly references it.
					g := <-refdOutput
					Expect(g.GetIpsetUpdate().GetId()).To(Equal(newSetName))
					Expect(g.GetIpsetUpdate().GetMembers()).To(HaveLen(6))

					g = <-refdOutput
					Expect(&g).To(HavePayload(pu))

					assertInactiveNoUpdate()

					close(done)
				})

				It("should send IPSetRemove when endpoint stops ref profile update", func(done Done) {
					pu := &proto.ActiveProfileUpdate{
						Id: &proto.ProfileID{Name: ProfileName},
						Profile: &proto.Profile{
							InboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{}},
							},
						},
					}
					updates <- pu

					// We should get ActiveProfileUpdate first, then IPSetRemove.
					g := <-refdOutput
					Expect(&g).To(HavePayload(pu))
					g = <-refdOutput
					Expect(&g).To(HavePayload(&proto.IPSetRemove{Id: IPSetName}))

					assertInactiveNoUpdate()

					close(done)
				})

				It("should send Update & remove profile update changes IPSet", func(done Done) {
					newSetName := "new-set"
					updates <- updateIpSet(newSetName, 6)
					pu := &proto.ActiveProfileUpdate{
						Id: &proto.ProfileID{Name: ProfileName},
						Profile: &proto.Profile{
							InboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{newSetName}},
							},
						},
					}
					updates <- pu

					// We should get the IPSetUpdate first, then the Profile that newly references it.
					g := <-refdOutput
					Expect(g.GetIpsetUpdate().GetId()).To(Equal(newSetName))
					Expect(g.GetIpsetUpdate().GetMembers()).To(HaveLen(6))

					g = <-refdOutput
					Expect(&g).To(HavePayload(pu))

					// Lastly, it should clean up the no-longer referenced set.
					g = <-refdOutput
					Expect(&g).To(HavePayload(&proto.IPSetRemove{Id: IPSetName}))

					assertInactiveNoUpdate()

					close(done)
				})

				It("should send IPSetUpdate/Remove when endpoint newly refs policy update", func(done Done) {
					// Create the policy without the ref, and link it to the unref'd WEP.
					policyID := &proto.PolicyID{Tier: "tier0", Name: "testpolicy"}
					pu := &proto.ActivePolicyUpdate{
						Id: policyID,
						Policy: &proto.Policy{
							OutboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{}},
							},
						},
					}
					updates <- pu
					wepu := &proto.WorkloadEndpointUpdate{
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
					updates <- wepu
					g := <-unrefdOutput
					Expect(&g).To(HavePayload(pu))
					g = <-unrefdOutput
					Expect(&g).To(HavePayload(wepu))

					// Now the WEP has an active policy that doesn't reference the IPSet. Send in
					// a Policy update that references the IPSet.
					pu = &proto.ActivePolicyUpdate{
						Id: policyID,
						Policy: &proto.Policy{
							OutboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{IPSetName}},
							},
						},
					}
					updates <- pu

					// Should get IPSetUpdate, followed by Policy update
					g = <-unrefdOutput
					Expect(&g).To(HavePayload(ipSetUpd))
					g = <-unrefdOutput
					Expect(&g).To(HavePayload(pu))

					// Now, remove the ref and get an IPSetRemove
					pu = &proto.ActivePolicyUpdate{
						Id: policyID,
						Policy: &proto.Policy{
							OutboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{}},
							},
						},
					}
					updates <- pu

					g = <-unrefdOutput
					Expect(&g).To(HavePayload(pu))
					g = <-unrefdOutput
					Expect(&g).To(HavePayload(&proto.IPSetRemove{Id: IPSetName}))
					close(done)
				})

				It("should send IPSetUpdate/Remove when policy changes IPset", func(done Done) {
					// Create policy referencing the existing IPSet and link to the unreferenced WEP
					policyID := &proto.PolicyID{Tier: "tier0", Name: "testpolicy"}
					pu := &proto.ActivePolicyUpdate{
						Id: policyID,
						Policy: &proto.Policy{
							OutboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{IPSetName}},
							},
						},
					}
					updates <- pu
					wepu := &proto.WorkloadEndpointUpdate{
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
					updates <- wepu
					g := <-unrefdOutput
					Expect(&g).To(HavePayload(ipSetUpd))
					g = <-unrefdOutput
					Expect(&g).To(HavePayload(pu))
					g = <-unrefdOutput
					Expect(&g).To(HavePayload(wepu))

					// Now the WEP has an active policy that references the old IPSet.  Create the new IPset and
					// then point the policy to it.
					newSetName := "new-set"
					updates <- updateIpSet(newSetName, 6)
					pu = &proto.ActivePolicyUpdate{
						Id: policyID,
						Policy: &proto.Policy{
							OutboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{newSetName}},
							},
						},
					}
					updates <- pu

					// Should get IPSetUpdate, followed by Policy update, followed by remove of old IPSet.
					g = <-unrefdOutput
					Expect(g.GetIpsetUpdate().GetId()).To(Equal(newSetName))
					Expect(g.GetIpsetUpdate().GetMembers()).To(HaveLen(6))
					g = <-unrefdOutput
					Expect(&g).To(HavePayload(pu))
					g = <-unrefdOutput
					Expect(&g).To(HavePayload(&proto.IPSetRemove{Id: IPSetName}))

					// Updates of new IPSet should be sent to the endpoint.
					updates <- updateIpSet(newSetName, 12)
					g = <-unrefdOutput
					Expect(g.GetIpsetUpdate().GetId()).To(Equal(newSetName))
					Expect(g.GetIpsetUpdate().GetMembers()).To(HaveLen(12))

					close(done)
				})
			})

			Context("with SyncServer", func() {
				var syncServer *policysync.Server
				var gRPCServer *grpc.Server
				var listener net.Listener
				var socketDir string

				BeforeEach(func() {
					uidAllocator := policysync.NewUIDAllocator()
					syncServer = policysync.NewServer(uut.JoinUpdates, uidAllocator.NextUID)

					gRPCServer = grpc.NewServer(grpc.Creds(testCreds{}))
					proto.RegisterPolicySyncServer(gRPCServer, syncServer)
					socketDir = makeTmpListenerDir()
					listener = openListener(socketDir)
					go func() {
						defer GinkgoRecover()
						err := gRPCServer.Serve(listener)

						// When we close down the listener, the server will return an error that it is closed. This is
						// expected behavior.
						Expect(err).To(BeAssignableToTypeOf(&net.OpError{}))
						opErr, ok := err.(*net.OpError)
						Expect(ok).To(BeTrue())
						Expect(opErr.Err.Error()).To(Equal("use of closed network connection"))
					}()
				})

				AfterEach(func() {
					listener.Close()
					os.RemoveAll(socketDir)
				})

				Context("with joined, active endpoint", func() {
					var wepId proto.WorkloadEndpointID
					var syncClient proto.PolicySyncClient
					var clientConn *grpc.ClientConn
					var syncContext context.Context
					var clientCancel func()
					var syncStream proto.PolicySync_SyncClient

					BeforeEach(func(done Done) {
						wepId = testId("default/withsync")

						opts := getDialOptions()
						var err error
						clientConn, err = grpc.Dial(path.Join(socketDir, ListenerSocket), opts...)
						Expect(err).ToNot(HaveOccurred())

						syncClient = proto.NewPolicySyncClient(clientConn)
						syncContext, clientCancel = context.WithCancel(context.Background())
						syncStream, err = syncClient.Sync(syncContext, &proto.SyncRequest{})
						Expect(err).ToNot(HaveOccurred())

						// Send the IPSet, a Profile referring to it, and a WEP update referring to the
						// Profile. This "activates" the WEP relative to the IPSet
						updates <- updateIpSet(IPSetName, 0)
						pu := &proto.ActiveProfileUpdate{
							Id: &proto.ProfileID{Name: ProfileName},
							Profile: &proto.Profile{InboundRules: []*proto.Rule{
								{
									Action:      "allow",
									SrcIpSetIds: []string{IPSetName},
								},
							}},
						}
						updates <- pu
						wepUpd := &proto.WorkloadEndpointUpdate{
							Id:       &wepId,
							Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{ProfileName}},
						}
						updates <- wepUpd
						// All three updates get pushed
						var g *proto.ToDataplane
						g, err = syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(g.GetIpsetUpdate().GetId()).To(Equal(IPSetName))
						Expect(g.GetIpsetUpdate().GetMembers()).To(HaveLen(0))
						g, err = syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(g).To(HavePayload(pu))
						g, err = syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(g).To(HavePayload(wepUpd))

						close(done)
					}, 2)

					It("should split large IPSetUpdate", func(done Done) {
						msg := updateIpSet(IPSetName, 82250)
						By("sending a large IPSetUpdate")
						updates <- msg

						By("receiving the first part")
						out, err := syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(out.GetIpsetUpdate().GetMembers()).To(HaveLen(82200))

						By("receiving the second part")
						out, err = syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(out.GetIpsetDeltaUpdate().GetAddedMembers()).To(HaveLen(50))
						close(done)
					}, 5)

					It("should split IpSetDeltaUpdates with both large adds and removes", func(done Done) {
						msg2 := deltaUpdateIpSet(IPSetName, 82250, 82250)
						By("sending a large IPSetDeltaUpdate")
						updates <- msg2

						By("receiving the first part with added members")
						out, err := syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(out.GetIpsetDeltaUpdate().GetAddedMembers()).To(HaveLen(82200))
						Expect(out.GetIpsetDeltaUpdate().GetRemovedMembers()).To(HaveLen(0))

						By("receiving the second part with added and removed members")
						out, err = syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(out.GetIpsetDeltaUpdate().GetAddedMembers()).To(HaveLen(50))
						Expect(out.GetIpsetDeltaUpdate().GetRemovedMembers()).To(HaveLen(50))

						By("receiving the third part with removed members")
						out, err = syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(out.GetIpsetDeltaUpdate().GetAddedMembers()).To(HaveLen(0))
						Expect(out.GetIpsetDeltaUpdate().GetRemovedMembers()).To(HaveLen(82200))

						close(done)
					}, 5)

					It("should split IpSetDeltaUpdates with large adds", func(done Done) {
						msg2 := deltaUpdateIpSet(IPSetName, 82250, 0)
						By("sending a large IPSetDeltaUpdate")
						updates <- msg2

						By("receiving the first part")
						out, err := syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(out.GetIpsetDeltaUpdate().GetAddedMembers()).To(HaveLen(82200))
						Expect(out.GetIpsetDeltaUpdate().GetRemovedMembers()).To(HaveLen(0))

						By("receiving the second part")
						out, err = syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(out.GetIpsetDeltaUpdate().GetAddedMembers()).To(HaveLen(50))
						Expect(out.GetIpsetDeltaUpdate().GetRemovedMembers()).To(HaveLen(0))

						close(done)
					}, 5)

					It("should split IpSetDeltaUpdates with large removes", func(done Done) {
						msg2 := deltaUpdateIpSet(IPSetName, 0, 82250)
						By("sending a large IPSetDeltaUpdate")
						updates <- msg2

						By("receiving the first part")
						out, err := syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(out.GetIpsetDeltaUpdate().GetAddedMembers()).To(HaveLen(0))
						Expect(out.GetIpsetDeltaUpdate().GetRemovedMembers()).To(HaveLen(50))

						By("receiving the second part")
						out, err = syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(out.GetIpsetDeltaUpdate().GetAddedMembers()).To(HaveLen(0))
						Expect(out.GetIpsetDeltaUpdate().GetRemovedMembers()).To(HaveLen(82200))

						close(done)
					}, 5)

					AfterEach(func() {
						clientCancel()
						clientConn.Close()
					})
				})
			})
		})

		Describe("Profile & Policy updates", func() {

			Context("with two joined endpoints", func() {
				var output [2]chan proto.ToDataplane
				var wepID [2]proto.WorkloadEndpointID
				var assertNoUpdate func(i int)

				BeforeEach(func() {
					assertNoUpdate = func(i int) {
						wepu := &proto.WorkloadEndpointUpdate{
							Id:       &wepID[i],
							Endpoint: &proto.WorkloadEndpoint{},
						}
						updates <- wepu
						g := <-output[i]
						Expect(&g).To(HavePayload(wepu))
					}

					for i := 0; i < 2; i++ {
						w := fmt.Sprintf("test%d", i)
						wepID[i] = testId(w)
						output[i], _ = join(w, uint64(i))

						// Ensure the joins are completed by sending a workload endpoint for each.
						assertNoUpdate(i)
					}

				})

				Context("with active profile", func() {
					var profileID = proto.ProfileID{Name: ProfileName}
					var proUpdate *proto.ActiveProfileUpdate

					BeforeEach(func() {
						proUpdate = &proto.ActiveProfileUpdate{
							Id: &profileID,
						}
						updates <- proUpdate
					})

					It("should add & remove profile when ref'd or not by WEP", func(done Done) {
						msg := &proto.WorkloadEndpointUpdate{
							Id:       &wepID[0],
							Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{ProfileName}},
						}
						updates <- msg
						g := <-output[0]
						Expect(&g).To(HavePayload(proUpdate))

						g = <-output[0]
						Expect(&g).To(HavePayload(msg))

						// Remove reference
						msg = &proto.WorkloadEndpointUpdate{
							Id:       &wepID[0],
							Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{}},
						}
						updates <- msg

						g = <-output[0]
						Expect(&g).To(HavePayload(msg))
						g = <-output[0]
						Expect(&g).To(HavePayload(&proto.ActiveProfileRemove{Id: &profileID}))

						assertNoUpdate(1)

						// Calc graph removes the profile, but we should not get another Remove.
						updates <- &proto.ActiveProfileRemove{Id: &profileID}

						// Test that there isn't a remove waiting by repeating the WEP update and getting it.
						updates <- msg
						g = <-output[0]
						Expect(&g).To(HavePayload(msg))

						close(done)
					})

					It("should add new & remove old when ref changes", func(done Done) {
						// Add new profile
						newName := "new-profile-name"
						newProfileID := proto.ProfileID{Name: newName}
						msg := &proto.ActiveProfileUpdate{Id: &newProfileID}
						updates <- msg

						msg2 := &proto.WorkloadEndpointUpdate{
							Id:       &wepID[0],
							Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{ProfileName}},
						}
						updates <- msg2
						g := <-output[0]
						Expect(&g).To(HavePayload(proUpdate))

						g = <-output[0]
						Expect(&g).To(HavePayload(msg2))

						// Switch profiles
						msg2 = &proto.WorkloadEndpointUpdate{
							Id:       &wepID[0],
							Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{newName}},
						}
						updates <- msg2

						g = <-output[0]
						Expect(&g).To(HavePayload(msg))

						g = <-output[0]
						Expect(&g).To(HavePayload(msg2))

						g = <-output[0]
						Expect(&g).To(HavePayload(&proto.ActiveProfileRemove{Id: &profileID}))

						assertNoUpdate(1)

						// Calc graph removes old profile, but we should not get another remove.
						updates <- &proto.ActiveProfileRemove{Id: &profileID}

						// Test that there isn't a remove queued by sending a WEP update
						updates <- msg2
						g = <-output[0]
						Expect(&g).To(HavePayload(msg2))

						close(done)
					})
				})

				Context("with active policy", func() {
					var policyID = proto.PolicyID{Tier: TierName, Name: PolicyName}
					var polUpd *proto.ActivePolicyUpdate

					BeforeEach(func() {
						polUpd = &proto.ActivePolicyUpdate{
							Id: &policyID,
						}
						updates <- polUpd
					})

					It("should add & remove policy when ref'd or not by WEP", func(done Done) {
						msg := &proto.WorkloadEndpointUpdate{
							Id: &wepID[0],
							Endpoint: &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{
								{
									Name:            TierName,
									IngressPolicies: []string{PolicyName},
								},
							}},
						}
						updates <- msg
						g := <-output[0]
						Expect(&g).To(HavePayload(polUpd))

						g = <-output[0]
						Expect(&g).To(HavePayload(msg))

						// Remove reference
						msg = &proto.WorkloadEndpointUpdate{
							Id: &wepID[0],
							Endpoint: &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{
								{
									Name: TierName,
								},
							}},
						}
						updates <- msg

						g = <-output[0]
						Expect(&g).To(HavePayload(msg))
						g = <-output[0]
						Expect(&g).To(HavePayload(&proto.ActivePolicyRemove{Id: &policyID}))

						assertNoUpdate(1)

						// Calc graph removes the policy.
						updates <- &proto.ActivePolicyRemove{Id: &policyID}

						// Test we don't get another remove by sending another WEP update
						updates <- msg
						g = <-output[0]
						Expect(&g).To(HavePayload(msg))

						close(done)
					})

					It("should add new & remove old when ref changes", func(done Done) {
						// Add new policy
						newName := "new-policy-name"
						newPolicyID := proto.PolicyID{Tier: TierName, Name: newName}
						msg := &proto.ActivePolicyUpdate{Id: &newPolicyID}
						updates <- msg

						msg2 := &proto.WorkloadEndpointUpdate{
							Id: &wepID[0],
							Endpoint: &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{
								{
									Name:           TierName,
									EgressPolicies: []string{PolicyName},
								},
							}},
						}
						updates <- msg2
						g := <-output[0]
						Expect(&g).To(HavePayload(polUpd))

						g = <-output[0]
						Expect(&g).To(HavePayload(msg2))

						// Switch profiles
						msg2 = &proto.WorkloadEndpointUpdate{
							Id: &wepID[0],
							Endpoint: &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{
								{
									Name:           TierName,
									EgressPolicies: []string{newName},
								},
							}},
						}
						updates <- msg2

						g = <-output[0]
						Expect(&g).To(HavePayload(msg))

						g = <-output[0]
						Expect(&g).To(HavePayload(msg2))

						g = <-output[0]
						Expect(&g).To(HavePayload(&proto.ActivePolicyRemove{Id: &policyID}))

						// Calc graph removes the old policy.
						updates <- &proto.ActivePolicyRemove{Id: &policyID}

						// Test we don't get another remove by sending another WEP update
						updates <- msg2
						g = <-output[0]
						Expect(&g).To(HavePayload(msg2))

						close(done)
					})

				})
			})

			Context("with profile & wep added before joining", func() {
				var profileID = proto.ProfileID{Name: ProfileName}
				var wepId = testId("test")
				var wepUpd *proto.WorkloadEndpointUpdate
				var proUpdate *proto.ActiveProfileUpdate

				BeforeEach(func() {
					proUpdate = &proto.ActiveProfileUpdate{
						Id: &profileID,
					}
					wepUpd = &proto.WorkloadEndpointUpdate{
						Id:       &wepId,
						Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{ProfileName}},
					}
					updates <- proUpdate
					updates <- wepUpd
				})

				It("should sync profile & wep when wep joins", func(done Done) {
					output, _ := join("test", 1)

					g := <-output
					Expect(&g).To(HavePayload(proUpdate))

					g = <-output
					Expect(&g).To(HavePayload(wepUpd))

					close(done)
				})

				It("should resync profile & wep", func(done Done) {
					output, jm := join("test", 1)
					g := <-output
					Expect(&g).To(HavePayload(proUpdate))
					g = <-output
					Expect(&g).To(HavePayload(wepUpd))

					// Leave
					leave(jm)

					output, _ = join("test", 2)
					g = <-output
					Expect(&g).To(HavePayload(proUpdate))
					g = <-output
					Expect(&g).To(HavePayload(wepUpd))

					close(done)
				})

				It("should not resync removed profile", func(done Done) {
					output, jm := join("test", 1)
					g := <-output
					Expect(&g).To(HavePayload(proUpdate))
					g = <-output
					Expect(&g).To(HavePayload(wepUpd))

					// Leave
					leave(jm)

					// Remove reference to profile from WEP
					wepUpd2 := &proto.WorkloadEndpointUpdate{
						Id:       &wepId,
						Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{}},
					}
					updates <- wepUpd2

					output, _ = join("test", 2)
					g = <-output
					Expect(&g).To(HavePayload(wepUpd2))

					close(done)
				})

			})

			Context("with policy & wep added before joining", func() {
				var policyID = proto.PolicyID{Tier: TierName, Name: PolicyName}
				var wepId = testId("test")
				var wepUpd *proto.WorkloadEndpointUpdate
				var polUpd *proto.ActivePolicyUpdate

				BeforeEach(func() {
					polUpd = &proto.ActivePolicyUpdate{
						Id: &policyID,
					}
					updates <- polUpd
					wepUpd = &proto.WorkloadEndpointUpdate{
						Id: &wepId,
						Endpoint: &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{
							{
								Name:           TierName,
								EgressPolicies: []string{PolicyName},
							},
						}},
					}
					updates <- wepUpd
				})

				It("should sync policy & wep when wep joins", func(done Done) {
					output, _ := join("test", 1)

					g := <-output
					Expect(&g).To(HavePayload(polUpd))

					g = <-output
					Expect(&g).To(HavePayload(wepUpd))

					close(done)
				})

				It("should resync policy & wep", func(done Done) {
					output, jm := join("test", 1)
					g := <-output
					Expect(&g).To(HavePayload(polUpd))
					g = <-output
					Expect(&g).To(HavePayload(wepUpd))

					// Leave
					leave(jm)

					output, _ = join("test", 2)
					g = <-output
					Expect(&g).To(HavePayload(polUpd))
					g = <-output
					Expect(&g).To(HavePayload(wepUpd))

					close(done)
				})

				It("should not resync removed policy", func(done Done) {
					output, jm := join("test", 1)
					g := <-output
					Expect(&g).To(HavePayload(polUpd))
					g = <-output
					Expect(&g).To(HavePayload(wepUpd))

					// Leave
					leave(jm)

					// Remove reference to policy from WEP
					wepUpd2 := &proto.WorkloadEndpointUpdate{
						Id: &wepId,
					}
					updates <- wepUpd2

					output, _ = join("test", 2)
					g = <-output
					Expect(&g).To(HavePayload(wepUpd2))

					close(done)
				})
			})
		})

		Describe("join / leave processing", func() {

			Context("with WEP before any join", func() {
				var wepId = testId("test")
				var wepUpd *proto.WorkloadEndpointUpdate

				BeforeEach(func() {
					wepUpd = &proto.WorkloadEndpointUpdate{
						Id: &wepId,
					}
					updates <- wepUpd
				})

				It("should close old channel on new join", func(done Done) {
					oldChan, _ := join("test", 1)
					g := <-oldChan
					Expect(&g).To(HavePayload(wepUpd))

					newChan, _ := join("test", 2)
					g = <-newChan
					Expect(&g).To(HavePayload(wepUpd))

					Expect(oldChan).To(BeClosed())

					close(done)
				})

				It("should ignore stale leave requests", func(done Done) {
					oldChan, oldMeta := join("test", 1)
					g := <-oldChan
					Expect(&g).To(HavePayload(wepUpd))

					newChan, _ := join("test", 2)
					g = <-newChan
					Expect(&g).To(HavePayload(wepUpd))

					leave(oldMeta)

					// New channel should still be open.
					updates <- wepUpd
					g = <-newChan
					Expect(&g).To(HavePayload(wepUpd))

					close(done)
				})

				It("should close active connection on clean leave", func(done Done) {
					c, m := join("test", 1)

					g := <-c
					Expect(&g).To(HavePayload(wepUpd))

					rm := &proto.WorkloadEndpointRemove{Id: &wepId}
					updates <- rm
					g = <-c
					Expect(&g).To(HavePayload(rm))

					leave(m)

					Eventually(c).Should(BeClosed())

					close(done)
				})
			})

			It("should handle join & leave without WEP update", func() {
				c, m := join("test", 1)
				leave(m)
				Eventually(c).Should(BeClosed())
			})
		})

		Describe("InSync processing", func() {
			It("should send InSync on all open outputs", func(done Done) {
				var c [2]chan proto.ToDataplane
				for i := 0; i < 2; i++ {
					c[i], _ = join(fmt.Sprintf("test%d", i), uint64(i))
				}
				is := &proto.InSync{}
				updates <- is
				for i := 0; i < 2; i++ {
					g := <-c[i]
					Expect(&g).To(HavePayload(is))
				}
				close(done)
			})
		})
	})
})

func testId(w string) proto.WorkloadEndpointID {
	return proto.WorkloadEndpointID{
		OrchestratorId: policysync.OrchestratorId,
		WorkloadId:     w,
		EndpointId:     policysync.EndpointId,
	}
}

func updateIpSet(id string, num int) *proto.IPSetUpdate {
	msg := &proto.IPSetUpdate{
		Id:      id,
		Type:    proto.IPSetUpdate_IP_AND_PORT,
		Members: []string{},
	}
	for i := 0; i < num; i++ {
		msg.Members = append(msg.Members, makeIPAndPort(i))
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
		msg.AddedMembers = append(msg.AddedMembers, makeIPAndPort(i))
	}
	for i := add; i < add+del; i++ {
		msg.RemovedMembers = append(msg.RemovedMembers, makeIPAndPort(i))
	}
	return msg
}

func makeIPAndPort(i int) string {
	// Goal here is to make the IPSet members as long as possible when stringified.
	// assume 20 bits of variable and 108 bits of fixed prefix
	lsbHex := fmt.Sprintf("%05x", i)

	return "fe80:1111:2222:3333:4444:5555:666" + string(lsbHex[0]) + ":" + lsbHex[1:] + ",tcp:65535"
}

func getDialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(getDialer("unix"))}
}

func getDialer(proto string) func(context.Context, string) (net.Conn, error) {
	d := &net.Dialer{}
	return func(ctx context.Context, target string) (net.Conn, error) {
		return d.DialContext(ctx, proto, target)
	}
}

const ListenerSocket = "policysync.sock"

func makeTmpListenerDir() string {
	dirPath, err := os.MkdirTemp("/tmp", "felixut")
	Expect(err).ToNot(HaveOccurred())
	return dirPath
}

func openListener(dir string) net.Listener {
	socketPath := path.Join(dir, ListenerSocket)
	lis, err := net.Listen("unix", socketPath)
	Expect(err).ToNot(HaveOccurred())
	return lis
}

type testCreds struct {
}

func (t testCreds) ClientHandshake(cxt context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, binder.Credentials{}, errors.New("client handshake unsupported")
}
func (t testCreds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, binder.Credentials{
		Uid:            "test",
		Workload:       "withsync",
		Namespace:      "default",
		ServiceAccount: "default",
	}, nil
}

func (t testCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "felixut",
		SecurityVersion:  "test",
		ServerName:       "test",
	}
}

func (t testCreds) Clone() credentials.TransportCredentials {
	return t
}

func (t testCreds) OverrideServerName(string) error { return nil }

func HavePayload(expected interface{}) types.GomegaMatcher {
	return &payloadMatcher{equal: Equal(expected)}
}

type payloadMatcher struct {
	equal   types.GomegaMatcher
	payload interface{}
}

func (p *payloadMatcher) Match(actual interface{}) (success bool, err error) {
	td, ok := actual.(*proto.ToDataplane)
	if !ok {
		return false, fmt.Errorf("HasPayload expects a *proto.ToDataplane")
	}
	p.payload = reflect.ValueOf(td.Payload).Elem().Field(0).Interface()
	return p.equal.Match(p.payload)
}

func (p *payloadMatcher) FailureMessage(actual interface{}) (message string) {
	return p.equal.FailureMessage(p.payload)
}

func (p *payloadMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return p.equal.NegatedFailureMessage(p.payload)
}
