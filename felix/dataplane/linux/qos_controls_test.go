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

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/bpf/tc"
)

// Bandwidth QoS needs the workload devices to be TCX-driven. The configured
// attach type is not the mechanism: netkit only applies to workload netkit
// devices and resolves to TCX everywhere else, so it must not read as "no TCX".
func TestIsQoSBandwidthSupported(t *testing.T) {
	for _, tst := range []struct {
		name         string
		bpfEnabled   bool
		attachType   apiv3.BPFAttachOption
		tcxSupported bool
		expected     bool
	}{
		{name: "iptables mode", bpfEnabled: false, attachType: apiv3.BPFAttachOptionTCX, tcxSupported: true, expected: true},
		{name: "iptables mode on a kernel without tcx", bpfEnabled: false, attachType: apiv3.BPFAttachOptionTCX, tcxSupported: false, expected: true},
		{name: "bpf tcx", bpfEnabled: true, attachType: apiv3.BPFAttachOptionTCX, tcxSupported: true, expected: true},
		{name: "bpf netkit", bpfEnabled: true, attachType: apiv3.BPFAttachOptionNetkit, tcxSupported: true, expected: true},
		{name: "bpf tc", bpfEnabled: true, attachType: apiv3.BPFAttachOptionTC, tcxSupported: true, expected: false},
		{name: "bpf tcx on a kernel without tcx", bpfEnabled: true, attachType: apiv3.BPFAttachOptionTCX, tcxSupported: false, expected: false},
		{name: "bpf netkit on a kernel without tcx", bpfEnabled: true, attachType: apiv3.BPFAttachOptionNetkit, tcxSupported: false, expected: false},
	} {
		t.Run(tst.name, func(t *testing.T) {
			origIsTcxSupported := tc.IsTcxSupported
			tc.IsTcxSupported = func() bool { return tst.tcxSupported }
			defer func() { tc.IsTcxSupported = origIsTcxSupported }()

			m := &endpointManager{cfg: &endpointManagerConfig{
				bpfEnabled:    tst.bpfEnabled,
				bpfAttachType: tst.attachType,
			}}

			if actual := m.isQoSBandwidthSupported(); actual != tst.expected {
				t.Errorf("isQoSBandwidthSupported() = %v, want %v (bpfEnabled=%v attachType=%v tcxSupported=%v)",
					actual, tst.expected, tst.bpfEnabled, tst.attachType, tst.tcxSupported)
			}
		})
	}
}
