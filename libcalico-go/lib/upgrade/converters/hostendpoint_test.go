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

package converters

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	apiv1 "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = DescribeTable("v1->v3 HostEndpoint conversion tests",
	func(v1API *apiv1.HostEndpoint, v1KVP *model.KVPair, v3API apiv3.HostEndpoint) {
		p := HostEndpoint{}

		// Check v1API->v1KVP.
		convertedKvp, err := p.APIV1ToBackendV1(v1API)
		Expect(err).NotTo(HaveOccurred())

		Expect(convertedKvp.Key.(model.HostEndpointKey)).To(Equal(v1KVP.Key.(model.HostEndpointKey)))
		Expect(convertedKvp.Value.(*model.HostEndpoint)).To(Equal(v1KVP.Value))

		// Check v1KVP->v3API.
		convertedv3, err := p.BackendV1ToAPIV3(v1KVP)
		Expect(err).NotTo(HaveOccurred())
		Expect(convertedv3.(*apiv3.HostEndpoint).ObjectMeta).To(Equal(v3API.ObjectMeta))
		Expect(convertedv3.(*apiv3.HostEndpoint).Spec).To(Equal(v3API.Spec))
	},
	Entry("Valid basic v1 hep has data moved to right place",
		&apiv1.HostEndpoint{
			Metadata: apiv1.HostEndpointMetadata{
				Name: "my-hep",
				Node: "my-node",
			},
			Spec: apiv1.HostEndpointSpec{
				InterfaceName: "eth3",
			},
		},
		&model.KVPair{
			Key: model.HostEndpointKey{
				EndpointID: "my-hep",
				Hostname:   "my-node",
			},
			Value: &model.HostEndpoint{
				Name: "eth3",
			},
		},
		apiv3.HostEndpoint{
			ObjectMeta: v1.ObjectMeta{
				Name: "my-node.my-hep",
			},
			Spec: apiv3.HostEndpointSpec{
				InterfaceName: "eth3",
				Node:          "my-node",
			},
		},
	),
	Entry("Valid filled v1 hep has data moved to right place",
		&apiv1.HostEndpoint{
			Metadata: apiv1.HostEndpointMetadata{
				Name: "my-hep",
				Node: "my-node",
				Labels: map[string]string{
					"foo": "bar",
				},
			},
			Spec: apiv1.HostEndpointSpec{
				ExpectedIPs: []cnet.IP{
					cnet.MustParseIP("192.168.1.1"),
					cnet.MustParseIP("fe80::"),
				},
				Profiles:      []string{"my-prof"},
				InterfaceName: "eth3",
				Ports: []apiv1.EndpointPort{
					{
						Name:     "my-port",
						Protocol: numorstring.ProtocolFromStringV1("tcp"),
						Port:     12345,
					},
				},
			},
		},
		&model.KVPair{
			Key: model.HostEndpointKey{
				EndpointID: "my-hep",
				Hostname:   "my-node",
			},
			Value: &model.HostEndpoint{
				Name: "eth3",
				Labels: map[string]string{
					"foo": "bar",
				},
				Ports: []model.EndpointPort{
					{
						Name:     "my-port",
						Port:     12345,
						Protocol: numorstring.ProtocolFromStringV1("tcp"),
					},
				},
				ProfileIDs:        []string{"my-prof"},
				ExpectedIPv4Addrs: []cnet.IP{cnet.MustParseIP("192.168.1.1")},
				ExpectedIPv6Addrs: []cnet.IP{cnet.MustParseIP("fe80::")},
			},
		},
		apiv3.HostEndpoint{
			ObjectMeta: v1.ObjectMeta{
				Name: fmt.Sprintf("%s.%s", "my-node", "my-hep"),
				Labels: map[string]string{
					"foo": "bar",
				},
			},
			Spec: apiv3.HostEndpointSpec{
				InterfaceName: "eth3",
				Node:          "my-node",
				Profiles:      []string{"my-prof"},
				ExpectedIPs: []string{
					"192.168.1.1",
					"fe80::",
				},
				Ports: []apiv3.EndpointPort{
					{
						Protocol: numorstring.ProtocolFromString("tcp"),
						Port:     12345,
						Name:     "my-port",
					},
				},
			},
		},
	),
)

var _ = Describe("v1-v3 HostEndpoint conversion tests", func() {
	It("correctly builds new name", func() {
		a := basicHep()
		a.Metadata.Node = "noD2{"
		a.Metadata.Name = "H3P.N/me"

		b, err := convertHEPV1ToV3(a)

		Expect(err).ToNot(HaveOccurred())
		Expect(b.ObjectMeta.Name).To(Equal("nod2.h3p.n.me-7188e863"), "Should convert new name")
	})

	It("converts protocol names", func() {
		a := basicHep()
		a.Spec.Ports = []apiv1.EndpointPort{
			{
				Name:     "my-port",
				Protocol: numorstring.ProtocolFromStringV1("tcp"),
				Port:     5,
			},
		}

		b, err := convertHEPV1ToV3(a)

		Expect(err).ToNot(HaveOccurred())
		Expect(len(b.Spec.Ports)).To(Equal(1))
		Expect(b.Spec.Ports[0].Protocol.StrVal).To(Equal("TCP"), "Should convert protocol name")
	})

	It("retains ports when only protocol is given", func() {
		a := basicHep()
		a.Spec.Ports = []apiv1.EndpointPort{
			{
				Protocol: numorstring.ProtocolFromStringV1("udp"),
			},
		}

		b, err := convertHEPV1ToV3(a)

		Expect(err).ToNot(HaveOccurred())
		Expect(len(b.Spec.Ports)).To(Equal(1))
		Expect(b.Spec.Ports[0].Protocol.StrVal).To(Equal("UDP"))
	})

	It("retains ports when only port number is given", func() {
		a := basicHep()
		a.Spec.Ports = []apiv1.EndpointPort{
			{
				Port: 5,
			},
		}

		b, err := convertHEPV1ToV3(a)

		Expect(err).ToNot(HaveOccurred())
		Expect(len(b.Spec.Ports)).To(Equal(1))
		Expect(b.Spec.Ports[0].Port).To(Equal(uint16(5)))
	})

	It("converts profile names", func() {
		a := basicHep()
		a.Spec.Profiles = []string{
			"pRo/le",
		}

		b, err := convertHEPV1ToV3(a)

		Expect(err).ToNot(HaveOccurred())
		Expect(len(b.Spec.Profiles)).To(Equal(1))
		Expect(b.Spec.Profiles[0]).To(Equal("pro.le-b1554692"), "Should convert profile name")
	})

	It("converts profile names", func() {
		a := basicHep()
		a.Spec.Profiles = []string{
			"k8s_ns.my-prof",
		}

		b, err := convertHEPV1ToV3(a)

		Expect(err).ToNot(HaveOccurred())
		Expect(len(b.Spec.Profiles)).To(Equal(1))
		Expect(b.Spec.Profiles[0]).To(Equal("kns.my-prof"), "Should convert profile name")
	})
})

func basicHep() *apiv1.HostEndpoint {
	return &apiv1.HostEndpoint{
		Metadata: apiv1.HostEndpointMetadata{
			Name: "my-hep",
			Node: "my-node",
		},
		Spec: apiv1.HostEndpointSpec{
			InterfaceName: "eth3",
		},
	}
}

func convertHEPV1ToV3(a *apiv1.HostEndpoint) (*apiv3.HostEndpoint, error) {
	h := HostEndpoint{}

	b, err := h.APIV1ToBackendV1(a)
	if err != nil {
		return nil, err
	}

	c, err := h.BackendV1ToAPIV3(b)
	if err != nil {
		return nil, err
	}

	return c.(*apiv3.HostEndpoint), nil
}
