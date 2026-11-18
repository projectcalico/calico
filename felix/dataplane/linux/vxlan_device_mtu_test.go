// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	"testing"

	"github.com/projectcalico/calico/felix/rules"
)

// The shared device must cover the larger enabled family, and must not take
// the MTU of a family that has VXLAN off.
func TestBPFVXLANDeviceMTU(t *testing.T) {
	for _, tst := range []struct {
		name        string
		ipv6Enabled bool
		vxlanV4     bool
		vxlanV6     bool
		expected    int
	}{
		{name: "dual-stack", ipv6Enabled: true, vxlanV4: true, vxlanV6: true, expected: 8951},
		{name: "IPv4 only", ipv6Enabled: false, vxlanV4: true, vxlanV6: false, expected: 8951},
		{name: "IPv6 only", ipv6Enabled: true, vxlanV4: false, vxlanV6: true, expected: 8931},
		{name: "IPv6 VXLAN without IPv6 enabled", ipv6Enabled: false, vxlanV4: true, vxlanV6: true, expected: 8951},
		{name: "IPv6 enabled, VXLAN on IPv4 only", ipv6Enabled: true, vxlanV4: true, vxlanV6: false, expected: 8951},
	} {
		t.Run(tst.name, func(t *testing.T) {
			config := Config{
				IPv6Enabled: tst.ipv6Enabled,
				VXLANMTU:    8951,
				VXLANMTUV6:  8931,
				RulesConfig: rules.Config{
					VXLANEnabled:   tst.vxlanV4,
					VXLANEnabledV6: tst.vxlanV6,
				},
			}
			if got := bpfVXLANDeviceMTU(config); got != tst.expected {
				t.Errorf("bpfVXLANDeviceMTU() = %d, want %d", got, tst.expected)
			}
		})
	}

	// The IPv6 MTU only wins if it is the larger one, e.g. when set by hand.
	config := Config{
		IPv6Enabled: true,
		VXLANMTU:    1400,
		VXLANMTUV6:  1450,
		RulesConfig: rules.Config{VXLANEnabled: true, VXLANEnabledV6: true},
	}
	if got := bpfVXLANDeviceMTU(config); got != 1450 {
		t.Errorf("bpfVXLANDeviceMTU() with a larger IPv6 MTU = %d, want 1450", got)
	}
}
