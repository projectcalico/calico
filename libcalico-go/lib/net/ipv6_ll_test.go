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

package net

import (
	"net"
	"testing"
)

func TestMACToIPv6LinkLocal(t *testing.T) {
	for _, test := range []struct {
		in          string
		expected    string
		shouldPanic bool
	}{
		{
			in:       "00:00:00:00:00:00",
			expected: "fe80::0200:00ff:fe00:0000",
		},
		{
			// Normal 48-bit MAC address, should get expanded to 64 bits by
			// inserting ff:ee.
			in:       "11:22:33:44:55:66",
			expected: "fe80::1322:33ff:fe44:5566",
		},
		{
			// EUI-64; no expansion needed.
			in:       "11:22:33:44:55:66:77:88",
			expected: "fe80::1322:3344:5566:7788",
		},
		{
			in:          "nil",
			shouldPanic: true,
		},
	} {
		t.Run(test.in, func(t *testing.T) {
			var mac net.HardwareAddr
			if test.in != "nil" {
				var err error
				mac, err = net.ParseMAC(test.in)
				if err != nil {
					t.Errorf("Error parsing MAC %q", test.in)
				}
			}
			if test.shouldPanic {
				panicked := false
				func() {
					defer func() {
						if r := recover(); r != nil {
							panicked = true
						}
					}()
					MustMACToIPv6LinkLocal(mac)
				}()
				if !panicked {
					t.Errorf("should have panicked on %q", test.in)
				}
			} else {
				out := MustMACToIPv6LinkLocal(mac)
				if !net.ParseIP(test.expected).Equal(out) {
					t.Errorf("MustMACToIPv6LinkLocal(%q) = %v; want %v", test.in, out, test.expected)
				}
			}
		})
	}
}
