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
	"testing"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv1 "github.com/projectcalico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/libcalico-go/lib/apis/v1/unversioned"
	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

var hepTable = []struct {
	description string
	v1API       unversioned.Resource
	v1KVP       *model.KVPair
	v3API       apiv3.HostEndpoint
}{
	{
		description: "Valid basic v1 hep has data moved to right place",
		v1API: &apiv1.HostEndpoint{
			Metadata: apiv1.HostEndpointMetadata{
				Name: "my-hep",
				Node: "my-node",
			},
			Spec: apiv1.HostEndpointSpec{
				InterfaceName: "eth3",
			},
		},
		v1KVP: &model.KVPair{
			Key: model.HostEndpointKey{
				EndpointID: "my-hep",
				Hostname:   "my-node",
			},
			Value: &model.HostEndpoint{
				Name: "eth3",
			},
		},
		v3API: apiv3.HostEndpoint{
			ObjectMeta: v1.ObjectMeta{
				Name: "my-node.my-hep",
			},
			Spec: apiv3.HostEndpointSpec{
				InterfaceName: "eth3",
				Node:          "my-node",
			},
		},
	},
	{
		description: "Valid filled v1 hep has data moved to right place",
		v1API: &apiv1.HostEndpoint{
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
		v1KVP: &model.KVPair{
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
		v3API: apiv3.HostEndpoint{
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
	},
}

func TestHEPDataIsMovedCorrectly(t *testing.T) {
	for _, tdata := range hepTable {
		t.Run(tdata.description, func(t *testing.T) {
			RegisterTestingT(t)

			p := HostEndpoint{}

			// Check v1API->v1KVP.
			convertedKvp, err := p.APIV1ToBackendV1(tdata.v1API)
			Expect(err).NotTo(HaveOccurred(), tdata.description)

			Expect(convertedKvp.Key.(model.HostEndpointKey)).To(Equal(tdata.v1KVP.Key.(model.HostEndpointKey)))
			Expect(convertedKvp.Value.(*model.HostEndpoint)).To(Equal(tdata.v1KVP.Value))

			// Check v1KVP->v3API.
			convertedv3, err := p.BackendV1ToAPIV3(tdata.v1KVP)
			Expect(err).NotTo(HaveOccurred(), tdata.description)
			Expect(convertedv3.(*apiv3.HostEndpoint).ObjectMeta).To(Equal(tdata.v3API.ObjectMeta), tdata.description)
			Expect(convertedv3.(*apiv3.HostEndpoint).Spec).To(Equal(tdata.v3API.Spec), tdata.description)
		})
	}
}

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

func TestHEPDataIsConvertedCorrectly(t *testing.T) {
	t.Run("correctly builds new name", func(t *testing.T) {
		RegisterTestingT(t)
		a := basicHep()
		a.Metadata.Node = "noD2{"
		a.Metadata.Name = "H3P.N/me"

		b, err := convertHEPV1ToV3(a)

		Expect(err).ToNot(HaveOccurred())
		Expect(b.ObjectMeta.Name).To(Equal("nod2.h3p.n.me-7188e863"), "Should convert new name")
	})

	t.Run("converts protocol names", func(t *testing.T) {
		RegisterTestingT(t)
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

	t.Run("retains ports when only protocol is given", func(t *testing.T) {
		RegisterTestingT(t)
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

	t.Run("retains ports when only port number is given", func(t *testing.T) {
		RegisterTestingT(t)
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

	t.Run("converts profile names", func(t *testing.T) {
		RegisterTestingT(t)
		a := basicHep()
		a.Spec.Profiles = []string{
			"pRo/le",
		}

		b, err := convertHEPV1ToV3(a)

		Expect(err).ToNot(HaveOccurred())
		Expect(len(b.Spec.Profiles)).To(Equal(1))
		Expect(b.Spec.Profiles[0]).To(Equal("pro.le-b1554692"), "Should convert profile name")
	})

	t.Run("converts profile names", func(t *testing.T) {
		RegisterTestingT(t)
		a := basicHep()
		a.Spec.Profiles = []string{
			"k8s_ns.my-prof",
		}

		b, err := convertHEPV1ToV3(a)

		Expect(err).ToNot(HaveOccurred())
		Expect(len(b.Spec.Profiles)).To(Equal(1))
		Expect(b.Spec.Profiles[0]).To(Equal("kns.my-prof"), "Should convert profile name")
	})
}
