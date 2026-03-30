// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.
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

package winpol

import (
	"encoding/json/jsontext"
	"net"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils/hcn"
)

var mgmtIPNet *net.IPNet
var mgmtIP net.IP

func init() {
	var err error
	mgmtIP, mgmtIPNet, err = net.ParseCIDR("10.11.128.13/19")
	if err != nil {
		panic(err)
	}
	mgmtIPNet.IP = mgmtIP // We want the full IP, not the masked version.
}

func TestCalculateEndpointPolicies(t *testing.T) {
	RegisterTestingT(t)

	marshaller := newMockPolMarshaller(
		`{"Type": "OutBoundNAT", "ExceptionList": ["10.96.0.0/12"]}`,
		`{"Type": "SomethingElse"}`,
	)
	logger := logrus.WithField("test", "true")

	_, net1, _ := net.ParseCIDR("10.0.1.0/24")
	_, net2, _ := net.ParseCIDR("10.0.2.0/24")

	t.Log("With NAT disabled, OutBoundNAT should be filtered out")
	pols, hcnPols, err := CalculateEndpointPolicies(marshaller, []*net.IPNet{net1, net2, mgmtIPNet}, false, mgmtIP, logger)
	Expect(err).NotTo(HaveOccurred())
	Expect(pols).To(Equal([]jsontext.Value{
		jsontext.Value(`{"Type": "SomethingElse"}`),
	}), "OutBoundNAT should have been filtered out")
	Expect(hcnPols).To(Equal([]hcn.EndpointPolicy{
		hcn.EndpointPolicy{
			Type:     "SomethingElse",
			Settings: jsontext.Value(`{}`),
		},
	}), "OutBoundNAT should have been filtered out")

	t.Log("With NAT enabled, OutBoundNAT should be augmented")
	pols, hcnPols, err = CalculateEndpointPolicies(marshaller, []*net.IPNet{net1, net2, mgmtIPNet}, true, mgmtIP, logger)
	Expect(err).NotTo(HaveOccurred())
	Expect(pols).To(Equal([]jsontext.Value{
		jsontext.Value(`{"ExceptionList":["10.96.0.0/12","10.0.1.0/24","10.0.2.0/24","10.11.128.0/19"],"Type":"OutBoundNAT"}`),
		jsontext.Value(`{"Type": "SomethingElse"}`),
	}))
	Expect(hcnPols).To(Equal([]hcn.EndpointPolicy{
		hcn.EndpointPolicy{
			Type:     "OutBoundNAT",
			Settings: jsontext.Value(`{"Exceptions":["10.96.0.0/12","10.0.1.0/24","10.0.2.0/24","10.11.128.0/19"]}`),
		},
		hcn.EndpointPolicy{
			Type:     "SomethingElse",
			Settings: jsontext.Value(`{}`),
		},
	}))

	t.Log("With NAT enabled, and no OutBoundNAT stanza, OutBoundNAT should be added")
	marshaller = newMockPolMarshaller(
		`{"Type": "SomethingElse"}`,
	)
	pols, hcnPols, err = CalculateEndpointPolicies(marshaller, []*net.IPNet{net1, net2, mgmtIPNet}, true, mgmtIP, logger)
	Expect(err).NotTo(HaveOccurred())
	Expect(pols).To(Equal([]jsontext.Value{
		jsontext.Value(`{"Type": "SomethingElse"}`),
		jsontext.Value(`{"ExceptionList":["10.0.1.0/24","10.0.2.0/24","10.11.128.0/19"],"Type":"OutBoundNAT"}`),
	}))
	Expect(hcnPols).To(Equal([]hcn.EndpointPolicy{
		hcn.EndpointPolicy{
			Type:     "SomethingElse",
			Settings: jsontext.Value(`{}`),
		},
		hcn.EndpointPolicy{
			Type:     "OutBoundNAT",
			Settings: jsontext.Value(`{"Exceptions":["10.0.1.0/24","10.0.2.0/24","10.11.128.0/19"]}`),
		},
	}))

	t.Log("With NAT disabled, and no OutBoundNAT stanza, OutBoundNAT should not be added")
	pols, hcnPols, err = CalculateEndpointPolicies(marshaller, []*net.IPNet{net1, net2, mgmtIPNet}, false, mgmtIP, logger)
	Expect(err).NotTo(HaveOccurred())
	Expect(pols).To(Equal([]jsontext.Value{
		jsontext.Value(`{"Type": "SomethingElse"}`),
	}))
	Expect(hcnPols).To(Equal([]hcn.EndpointPolicy{
		hcn.EndpointPolicy{
			Type:     "SomethingElse",
			Settings: jsontext.Value(`{}`),
		},
	}), "OutBoundNAT should have been filtered out")
}

func newMockPolMarshaller(pols ...string) mockPolMarshaller {
	return mockPolMarshaller(pols)
}

type mockPolMarshaller []string

func (m mockPolMarshaller) GetHNSEndpointPolicies() (out []jsontext.Value) {
	for _, p := range m {
		out = append(out, jsontext.Value(p))
	}
	return
}
