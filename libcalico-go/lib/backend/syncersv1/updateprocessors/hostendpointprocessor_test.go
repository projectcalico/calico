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

package updateprocessors_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = Describe("Test the HostEndpoint update processor", func() {
	name1 := "name1"
	name2 := "name2"
	hn1 := "host1"
	hn2 := "host2"
	v3HostEndpointKey1 := model.ResourceKey{
		Kind: apiv3.KindHostEndpoint,
		Name: name1,
	}
	v3HostEndpointKey2 := model.ResourceKey{
		Kind: apiv3.KindHostEndpoint,
		Name: name2,
	}
	v1HostEndpointKey1 := model.HostEndpointKey{
		Hostname:   hn1,
		EndpointID: name1,
	}
	v1HostEndpointKey2 := model.HostEndpointKey{
		Hostname:   hn2,
		EndpointID: name2,
	}

	It("should handle conversion of valid HostEndpoints", func() {
		up := updateprocessors.NewHostEndpointUpdateProcessor()

		By("converting a HostEndpoint with minimum configuration")
		res := apiv3.NewHostEndpoint()
		res.Name = v3HostEndpointKey1.Name
		res.Spec.Node = hn1
		res.Spec.InterfaceName = name1

		kvps, err := up.Process(&model.KVPair{
			Key:      v3HostEndpointKey1,
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(HaveLen(1))
		Expect(kvps[0]).To(Equal(&model.KVPair{
			Key: v1HostEndpointKey1,
			Value: &model.HostEndpoint{
				Name:  name1,
				Ports: []model.EndpointPort{},
			},
			Revision: "abcde",
		}))

		By("adding another HostEndpoint with a full configuration")
		res = apiv3.NewHostEndpoint()
		res.Name = v3HostEndpointKey2.Name
		res.Labels = map[string]string{"testLabel": "label"}
		res.Spec.Node = hn2
		res.Spec.InterfaceName = name2
		res.Spec.ExpectedIPs = []string{"10.100.10.1"}
		expectedIpv4 := *net.ParseIP("10.100.10.1")
		res.Spec.Profiles = []string{"testProfile"}
		res.Spec.Ports = []apiv3.EndpointPort{
			apiv3.EndpointPort{
				Name:     "portname",
				Protocol: numorstring.ProtocolFromInt(uint8(30)),
				Port:     uint16(8080),
			},
		}

		kvps, err = up.Process(&model.KVPair{
			Key:      v3HostEndpointKey2,
			Value:    res,
			Revision: "1234",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key: v1HostEndpointKey2,
				Value: &model.HostEndpoint{
					Name:              name2,
					ExpectedIPv4Addrs: []net.IP{expectedIpv4},
					Labels:            map[string]string{"testLabel": "label"},
					ProfileIDs:        []string{"testProfile"},
					Ports: []model.EndpointPort{
						model.EndpointPort{
							Name:     "portname",
							Protocol: numorstring.ProtocolFromInt(uint8(30)),
							Port:     uint16(8080),
						},
					},
				},
				Revision: "1234",
			},
		}))

		By("deleting the first host endpoint")
		kvps, err = up.Process(&model.KVPair{
			Key: v3HostEndpointKey1,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(kvps).To(Equal([]*model.KVPair{
			{
				Key: v1HostEndpointKey1,
			},
		}))

		By("clearing the cache (by starting sync) and failing to delete the second host endpoint")
		up.OnSyncerStarting()
		kvps, err = up.Process(&model.KVPair{
			Key: v3HostEndpointKey2,
		})
		Expect(err).To(HaveOccurred())
	})

	It("should fail to convert an invalid resource", func() {
		up := updateprocessors.NewHostEndpointUpdateProcessor()

		By("trying to convert with the wrong key type")
		res := apiv3.NewHostEndpoint()
		res.Spec.Node = hn1

		_, err := up.Process(&model.KVPair{
			Key: model.GlobalBGPPeerKey{
				PeerIP: net.MustParseIP("1.2.3.4"),
			},
			Value:    res,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())

		By("trying to convert with the wrong value type")
		wres := apiv3.NewIPPool()

		_, err = up.Process(&model.KVPair{
			Key:      v3HostEndpointKey1,
			Value:    wres,
			Revision: "abcde",
		})
		Expect(err).To(HaveOccurred())
	})
})
