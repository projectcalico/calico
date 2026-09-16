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

package hook

import (
	"testing"

	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

// Calico's own overlay devices carry no endpoint of their own to police, so
// they default to allow. A device of the same kind that Calico does not own is
// an ordinary host endpoint and must still get real policy.
func TestDefaultPolicy(t *testing.T) {
	for _, tc := range []struct {
		name        string
		at          AttachType
		ifaceEncaps bool
		want        DefPolicy
	}{
		{"host ep", AttachType{Type: tcdefs.EpTypeHost, Hook: Ingress}, false, DefPolicyNone},
		{"host ep that encapsulates", AttachType{Type: tcdefs.EpTypeHost, Hook: Ingress}, true, DefPolicyAllow},
		{"host ep egress", AttachType{Type: tcdefs.EpTypeHost, Hook: Egress}, false, DefPolicyNone},
		{"host ep egress that encapsulates", AttachType{Type: tcdefs.EpTypeHost, Hook: Egress}, true, DefPolicyAllow},
		{"workload", AttachType{Type: tcdefs.EpTypeWorkload, Hook: Ingress}, false, DefPolicyDeny},
		{"ipip", AttachType{Type: tcdefs.EpTypeIPIP, Hook: Ingress}, true, DefPolicyAllow},
		{"l3 device", AttachType{Type: tcdefs.EpTypeL3Device, Hook: Ingress}, true, DefPolicyAllow},
		{"plain l3 NIC", AttachType{Type: tcdefs.EpTypeL3Device, Hook: Ingress}, false, DefPolicyAllow},
		{"nat", AttachType{Type: tcdefs.EpTypeNAT, Hook: Ingress}, false, DefPolicyNone},
		{"lo", AttachType{Type: tcdefs.EpTypeLO, Hook: Ingress}, false, DefPolicyNone},
		{"xdp", AttachType{Type: tcdefs.EpTypeHost, Hook: XDP}, true, DefPolicyNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.at.DefaultPolicy(tc.ifaceEncaps); got != tc.want {
				t.Errorf("DefaultPolicy(%v) = %v, want %v", tc.ifaceEncaps, got, tc.want)
			}
		})
	}
}
