// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package net

import (
	"fmt"
	"testing"

	. "github.com/onsi/gomega"
)

func TestIPNet_Covers(t *testing.T) {
	for _, test := range []struct {
		A, B     string
		ACoversB bool
	}{
		{A: "0.0.0.0/0", B: "0.0.0.0/0", ACoversB: true},
		{A: "0.0.0.0/0", B: "10.0.0.0/8", ACoversB: true},
		{A: "10.0.0.0/8", B: "10.0.0.0/9", ACoversB: true},
		{A: "0.0.0.0/1", B: "128.0.0.0/1", ACoversB: false},
		{A: "10.0.0.0/8", B: "0.0.0.0/0", ACoversB: false},
		{A: "10.0.0.0/9", B: "10.0.0.0/8", ACoversB: false},
		{A: "11.0.0.0/9", B: "10.0.0.0/9", ACoversB: false},
	} {
		test := test
		t.Run(fmt.Sprintf("%s_Covers_%s", test.A, test.B), func(t *testing.T) {
			RegisterTestingT(t)
			larger := MustParseCIDR(test.A)
			smaller := MustParseCIDR(test.B)
			Expect(larger.Covers(smaller.IPNet)).To(Equal(test.ACoversB),
				fmt.Sprintf("IPNet(%s).Cover(%s) != expected value (%v)", test.A, test.B, test.ACoversB))
		})
	}
}

func TestIPNet_NthIP(t *testing.T) {
	for _, test := range []struct {
		CIDR       string
		N          int
		ExpectedIP string
	}{
		{CIDR: "10.0.0.0/8", N: 0, ExpectedIP: "10.0.0.0"},
		{CIDR: "10.0.0.0/8", N: 1, ExpectedIP: "10.0.0.1"},
		{CIDR: "10.0.0.0/8", N: 256, ExpectedIP: "10.0.1.0"},
		{CIDR: "10.0.0.0/8", N: 257, ExpectedIP: "10.0.1.1"},
		{CIDR: "0.0.0.0/0", N: 0, ExpectedIP: "0.0.0.0"},
		{CIDR: "0.0.0.0/0", N: 0xffffffff, ExpectedIP: "255.255.255.255"},
		{CIDR: "0.0.0.0/0", N: 0x01000000, ExpectedIP: "1.0.0.0"},
		{CIDR: "::/0", N: 0, ExpectedIP: "::"},
		{CIDR: "::/0", N: 1, ExpectedIP: "::1"},
		{CIDR: "::/0", N: 0xf00d, ExpectedIP: "::f00d"},
		{CIDR: "255.255.255.255/32", N: 0, ExpectedIP: "255.255.255.255"},
		{CIDR: "255.255.255.254/32", N: 1, ExpectedIP: "255.255.255.255"},
	} {
		test := test
		t.Run(fmt.Sprintf("IPNet(%s).NthIP(%v) should be %v", test.CIDR, test.N, test.ExpectedIP), func(t *testing.T) {
			RegisterTestingT(t)
			cidr := MustParseCIDR(test.CIDR)
			expected := MustParseIP(test.ExpectedIP)
			ip := cidr.NthIP(test.N)
			Expect(ip.Equal(expected.IP)).To(BeTrue(),
				fmt.Sprintf("%v != %v", ip.String(), expected.String()))
		})
	}
}
