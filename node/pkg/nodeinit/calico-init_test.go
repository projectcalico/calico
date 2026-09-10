// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package nodeinit

import (
	"net"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/mock"
	bpfnat "github.com/projectcalico/calico/felix/bpf/nat"
)

func TestIPPortParsing(t *testing.T) {
	RegisterTestingT(t)
	testCases := []struct {
		addr            string
		expectedIPPorts []IPPort
		errorExpected   bool
	}{
		{"", nil, true},
		{
			"1.1.1.1:443",
			[]IPPort{{net.ParseIP("1.1.1.1"), 443, true}},
			false,
		},
		{
			"[2001:db8::1]:6443",
			[]IPPort{{net.ParseIP("2001:db8::1"), 6443, false}},
			false,
		},
		{
			"192.168.0.1:6443,[2001:db8::1]:6443",
			[]IPPort{
				{net.ParseIP("192.168.0.1"), 6443, true},
				{net.ParseIP("2001:db8::1"), 6443, false},
			},
			false,
		},
		{"1.1.1.1:port", nil, true},
		{"1.1.1:80", nil, true},
		{"1.1.1.1", nil, true},
		{":80", nil, true},
		{"made-up-addr", nil, true},
		{"[2001:db8::1]:443,", nil, true},
		{",[2001:db8::1]:443", nil, true},
	}

	for _, testCase := range testCases {
		ipPorts, err := parseCommaSeparatedIPPorts(testCase.addr)
		Expect(err != nil).To(Equal(testCase.errorExpected))
		Expect(ipPorts).To(Equal(testCase.expectedIPPorts))
	}
}

// The NAT maps are pinned and outlive calico-node, so this container often runs
// against maps Felix has already programmed. A service ID indexes the service's
// own block of the backend map, so claiming one that another service holds makes
// the two overwrite each other's backends. See projectcalico/calico#13279.
func TestNATServiceID(t *testing.T) {
	RegisterTestingT(t)

	apiService := IPPort{net.ParseIP("10.96.0.1"), 443, true}
	tcp := uint8(6)

	type entry struct {
		service IPPort
		id      uint32
	}

	frontend := func(entries []entry) *mock.Map {
		m := mock.NewMockMap(bpfnat.FrontendMapParameters)
		for _, e := range entries {
			key := bpfnat.NewNATKeyIntf(e.service.IP, e.service.Port, tcp)
			Expect(m.Update(key.AsBytes(), bpfnat.NewNATValue(e.id, 1, 0, 0).AsBytes())).NotTo(HaveOccurred())
		}
		return m
	}

	otherService := IPPort{net.ParseIP("10.96.0.99"), 6789, true}
	thirdService := IPPort{net.ParseIP("10.96.0.98"), 80, true}
	v6Service := IPPort{net.ParseIP("2001:db8::1"), 443, false}

	testCases := []struct {
		name       string
		entries    []entry
		expectedID uint32
	}{
		{"empty map claims the first ID", nil, 0},
		{
			"the service's own ID is reused",
			[]entry{{apiService, 3}, {otherService, 7}},
			3,
		},
		{
			"an ID another service holds is never claimed",
			[]entry{{otherService, 0}},
			1,
		},
		{
			"the lowest free ID is claimed, not one past the highest",
			[]entry{{otherService, 0}, {thirdService, 12}},
			1,
		},
		{
			"a gap in the IDs in use is filled",
			[]entry{{otherService, 0}, {thirdService, 1}, {IPPort{net.ParseIP("10.96.0.97"), 80, true}, 3}},
			2,
		},
	}

	for _, testCase := range testCases {
		// The IPv6 service is passed in every time to check it is filtered out
		// of the IPv4 lookup: the two families have independent ID spaces.
		id, err := natServiceID(frontend(testCase.entries), []IPPort{apiService, v6Service},
			true, bpfnat.NewNATKeyIntf)
		Expect(err).NotTo(HaveOccurred(), testCase.name)
		Expect(id).To(Equal(testCase.expectedID), testCase.name)
	}
}
