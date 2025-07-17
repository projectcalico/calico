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
