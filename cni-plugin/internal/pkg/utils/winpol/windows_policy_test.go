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
	"encoding/json"
	"net"
	"testing"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils/hcn"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
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
	Expect(pols).To(Equal([]json.RawMessage{
		json.RawMessage(`{"Type": "SomethingElse"}`),
	}), "OutBoundNAT should have been filtered out")
	Expect(hcnPols).To(Equal([]hcn.EndpointPolicy{
		hcn.EndpointPolicy{
			Type:     "SomethingElse",
			Settings: json.RawMessage(`{}`),
		},
	}), "OutBoundNAT should have been filtered out")

	t.Log("With NAT enabled, OutBoundNAT should be augmented")
	pols, hcnPols, err = CalculateEndpointPolicies(marshaller, []*net.IPNet{net1, net2, mgmtIPNet}, true, mgmtIP, logger)
	Expect(err).NotTo(HaveOccurred())
	Expect(pols).To(Equal([]json.RawMessage{
		json.RawMessage(`{"ExceptionList":["10.96.0.0/12","10.0.1.0/24","10.0.2.0/24","10.11.128.0/19"],"Type":"OutBoundNAT"}`),
		json.RawMessage(`{"Type": "SomethingElse"}`),
	}))
	Expect(hcnPols).To(Equal([]hcn.EndpointPolicy{
		hcn.EndpointPolicy{
			Type:     "OutBoundNAT",
			Settings: json.RawMessage(`{"Exceptions":["10.96.0.0/12","10.0.1.0/24","10.0.2.0/24","10.11.128.0/19"]}`),
		},
		hcn.EndpointPolicy{
			Type:     "SomethingElse",
			Settings: json.RawMessage(`{}`),
		},
	}))

	t.Log("With NAT enabled, and no OutBoundNAT stanza, OutBoundNAT should be added")
	marshaller = newMockPolMarshaller(
		`{"Type": "SomethingElse"}`,
	)
	pols, hcnPols, err = CalculateEndpointPolicies(marshaller, []*net.IPNet{net1, net2, mgmtIPNet}, true, mgmtIP, logger)
	Expect(err).NotTo(HaveOccurred())
	Expect(pols).To(Equal([]json.RawMessage{
		json.RawMessage(`{"Type": "SomethingElse"}`),
		json.RawMessage(`{"ExceptionList":["10.0.1.0/24","10.0.2.0/24","10.11.128.0/19"],"Type":"OutBoundNAT"}`),
	}))
	Expect(hcnPols).To(Equal([]hcn.EndpointPolicy{
		hcn.EndpointPolicy{
			Type:     "SomethingElse",
			Settings: json.RawMessage(`{}`),
		},
		hcn.EndpointPolicy{
			Type:     "OutBoundNAT",
			Settings: json.RawMessage(`{"Exceptions":["10.0.1.0/24","10.0.2.0/24","10.11.128.0/19"]}`),
		},
	}))

	t.Log("With NAT disabled, and no OutBoundNAT stanza, OutBoundNAT should not be added")
	pols, hcnPols, err = CalculateEndpointPolicies(marshaller, []*net.IPNet{net1, net2, mgmtIPNet}, false, mgmtIP, logger)
	Expect(err).NotTo(HaveOccurred())
	Expect(pols).To(Equal([]json.RawMessage{
		json.RawMessage(`{"Type": "SomethingElse"}`),
	}))
	Expect(hcnPols).To(Equal([]hcn.EndpointPolicy{
		hcn.EndpointPolicy{
			Type:     "SomethingElse",
			Settings: json.RawMessage(`{}`),
		},
	}), "OutBoundNAT should have been filtered out")
}

func newMockPolMarshaller(pols ...string) mockPolMarshaller {
	return mockPolMarshaller(pols)
}

type mockPolMarshaller []string

func (m mockPolMarshaller) GetHNSEndpointPolicies() (out []json.RawMessage) {
	for _, p := range m {
		out = append(out, json.RawMessage(p))
	}
	return
}
