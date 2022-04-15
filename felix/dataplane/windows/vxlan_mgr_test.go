// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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

package windataplane

import (
	"encoding/json"
	"errors"
	"regexp"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/dataplane/windows/hcn"
	"github.com/projectcalico/calico/felix/proto"
)

var _ = Describe("VXLAN manager tests", func() {
	var mgr *vxlanManager
	var dataplane *mockHCN

	BeforeEach(func() {
		dataplane = &mockHCN{}
		mgr = newVXLANManager(dataplane, "my-host", regexp.MustCompile("Calico"), 4096, 8000)
	})

	Describe("with an old policy in place", func() {
		BeforeEach(func() {
			polSettings := hcn.RemoteSubnetRoutePolicySetting{
				IsolationId:                 4096,
				DistributedRouterMacAddress: "aa-bb-cc-dd-ee-ff",
				ProviderAddress:             "10.0.0.1",
				DestinationPrefix:           "11.0.0.0/26",
			}
			polJSON, err := json.Marshal(polSettings)
			Expect(err).NotTo(HaveOccurred())
			dataplane.networks = []hcn.HostComputeNetwork{
				{
					Name: "Calico",
					Type: "Overlay",
					Policies: []hcn.NetworkPolicy{
						{
							// Wrong type, should be left alone.
							Type:     "Foo",
							Settings: json.RawMessage("{}"),
						},
						{
							// Correct type, should be removed.
							Type:     hcn.RemoteSubnetRoute,
							Settings: polJSON,
						},
						{
							// Wrong type, should be left alone.
							Type:     "Bar",
							Settings: json.RawMessage("{}"),
						},
					},
				},
			}
		})

		Describe("after CompleteDeferredWork", func() {
			BeforeEach(func() {
				err := mgr.CompleteDeferredWork()
				Expect(err).NotTo(HaveOccurred())
			})

			It("should clean up the old route policy", func() {
				Expect(dataplane.networks[0].Policies).To(Equal([]hcn.NetworkPolicy{
					{
						Type:     "Foo",
						Settings: json.RawMessage("{}"),
					},
					{
						Type:     "Bar",
						Settings: json.RawMessage("{}"),
					},
				}))
			})

			It("should not be dirty", func() {
				Expect(mgr.dirty).To(BeFalse())
			})

			Describe("after receiving a route", func() {
				BeforeEach(func() {
					mgr.OnUpdate(&proto.RouteUpdate{
						Type:        proto.RouteType_REMOTE_WORKLOAD,
						IpPoolType:  proto.IPPoolType_VXLAN,
						Dst:         "10.0.0.0/26",
						DstNodeName: "other-node",
						DstNodeIp:   "10.0.0.1",
					})
				})
				It("should be dirty", func() {
					Expect(mgr.dirty).To(BeTrue())
				})

				Describe("after receiving a route deletion", func() {
					BeforeEach(func() {
						mgr.OnUpdate(&proto.RouteRemove{
							Dst: "10.0.0.0/26",
						})
					})
					It("should be dirty", func() {
						Expect(mgr.dirty).To(BeTrue())
					})
				})

				Describe("after receiving a matching VTEP", func() {
					BeforeEach(func() {
						mgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
							Node:             "other-node",
							ParentDeviceIpv4: "11.0.0.1",
							Ipv4Addr:         "10.0.0.1",
							MacV4:            "00-11-22-33-44-55",
						})
					})
					It("should be dirty", func() {
						Expect(mgr.dirty).To(BeTrue())
					})

					itShouldApplyTheRoute := func() {
						It("should apply the route", func() {
							expectedRouteSettings := hcn.RemoteSubnetRoutePolicySetting{
								DestinationPrefix:           "10.0.0.0/26",
								IsolationId:                 4096,
								ProviderAddress:             "11.0.0.1",
								DistributedRouterMacAddress: "00-11-22-33-44-55",
							}
							expectedRawJSON, err := json.Marshal(expectedRouteSettings)
							Expect(err).NotTo(HaveOccurred())

							Expect(dataplane.networks[0].Policies).To(Equal([]hcn.NetworkPolicy{
								{
									Type:     "Foo",
									Settings: json.RawMessage("{}"),
								},
								{
									Type:     "Bar",
									Settings: json.RawMessage("{}"),
								},
								{
									Type:     hcn.RemoteSubnetRoute,
									Settings: expectedRawJSON,
								},
							}))
						})
					}

					Describe("with a failure", func() {
						var dummyErr = errors.New("dummy error")
						BeforeEach(func() {
							dataplane.networks[0].Err = dummyErr
						})
						It("should return an error and stay dirty", func() {
							Expect(mgr.CompleteDeferredWork()).To(HaveOccurred())
							Expect(mgr.dirty).To(BeTrue())
						})

						Describe("after a successful retry", func() {
							BeforeEach(func() {
								dataplane.networks[0].Err = nil
								Expect(mgr.CompleteDeferredWork()).NotTo(HaveOccurred())
							})

							It("should not be dirty", func() {
								Expect(mgr.dirty).To(BeFalse())
							})

							itShouldApplyTheRoute()
						})
					})

					Describe("after CompleteDeferredWork", func() {
						BeforeEach(func() {
							err := mgr.CompleteDeferredWork()
							Expect(err).NotTo(HaveOccurred())
						})

						itShouldApplyTheRoute()

						It("should not be dirty", func() {
							Expect(mgr.dirty).To(BeFalse())
						})

						Describe("after removing the route and calling CompleteDeferredWork", func() {
							BeforeEach(func() {
								mgr.OnUpdate(&proto.RouteRemove{
									Dst: "10.0.0.0/26",
								})
								Expect(mgr.CompleteDeferredWork()).NotTo(HaveOccurred())
							})

							It("should remove the route", func() {
								Expect(dataplane.networks[0].Policies).To(Equal([]hcn.NetworkPolicy{
									{
										Type:     "Foo",
										Settings: json.RawMessage("{}"),
									},
									{
										Type:     "Bar",
										Settings: json.RawMessage("{}"),
									},
								}))
							})
						})

						Describe("after updating the VTEP and calling CompleteDeferredWork", func() {
							BeforeEach(func() {
								mgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
									Node:             "other-node",
									ParentDeviceIpv4: "11.0.0.2",
									Ipv4Addr:         "10.0.0.2",
									MacV4:            "00-11-22-33-44-56",
								})
								Expect(mgr.CompleteDeferredWork()).NotTo(HaveOccurred())
							})

							It("should update the route", func() {
								expectedRouteSettings := hcn.RemoteSubnetRoutePolicySetting{
									DestinationPrefix:           "10.0.0.0/26",
									IsolationId:                 4096,
									ProviderAddress:             "11.0.0.2",
									DistributedRouterMacAddress: "00-11-22-33-44-56",
								}
								expectedRawJSON, err := json.Marshal(expectedRouteSettings)
								Expect(err).NotTo(HaveOccurred())

								Expect(dataplane.networks[0].Policies).To(Equal([]hcn.NetworkPolicy{
									{
										Type:     "Foo",
										Settings: json.RawMessage("{}"),
									},
									{
										Type:     "Bar",
										Settings: json.RawMessage("{}"),
									},
									{
										Type:     hcn.RemoteSubnetRoute,
										Settings: expectedRawJSON,
									},
								}))
							})
						})
					})
				})
			})

			Describe("after receiving a VTEP", func() {
				BeforeEach(func() {
					mgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
						Node: "other-node",
					})
				})
				It("should be dirty", func() {
					Expect(mgr.dirty).To(BeTrue())
				})
			})

			Describe("after receiving our VTEP", func() {
				BeforeEach(func() {
					mgr.OnUpdate(&proto.VXLANTunnelEndpointUpdate{
						Node: "my-host",
					})
				})
				It("should not be dirty", func() {
					Expect(mgr.dirty).To(BeFalse())
				})
			})

			Describe("after receiving a VTEP remove", func() {
				BeforeEach(func() {
					mgr.OnUpdate(&proto.VXLANTunnelEndpointRemove{
						Node: "other-node",
					})
				})

				It("should be dirty", func() {
					Expect(mgr.dirty).To(BeTrue())
				})
			})

			Describe("after receiving our VTEP remove", func() {
				BeforeEach(func() {
					mgr.OnUpdate(&proto.VXLANTunnelEndpointRemove{
						Node: "my-host",
					})
				})
				It("should not be dirty", func() {
					Expect(mgr.dirty).To(BeFalse())
				})
			})
		})
	})
})

type mockHCN struct {
	networks []hcn.HostComputeNetwork
}

func (h *mockHCN) ListNetworks() ([]hcn.HostComputeNetwork, error) {
	// Make sure all the networks have a back-pointer.
	for i := range h.networks {
		h.networks[i].Ptr = &h.networks[i]
	}
	return h.networks, nil
}
