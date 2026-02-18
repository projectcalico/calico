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

func TestGetSubProgNames(t *testing.T) {
	// Test TC hook
	tcNames := GetSubProgNames(Ingress)
	if len(tcNames) != 11 {
		t.Errorf("Expected 11 TC sub-programs, got %d", len(tcNames))
	}
	if tcNames[0] != "calico_tc_main" {
		t.Errorf("Expected first TC program to be 'calico_tc_main', got '%s'", tcNames[0])
	}

	// Test XDP hook
	xdpNames := GetSubProgNames(XDP)
	if len(xdpNames) != 5 {
		t.Errorf("Expected 5 XDP sub-programs, got %d", len(xdpNames))
	}
	if xdpNames[0] != "calico_xdp_main" {
		t.Errorf("Expected first XDP program to be 'calico_xdp_main', got '%s'", xdpNames[0])
	}
}

func TestGetApplicableSubProgs(t *testing.T) {
	tests := []struct {
		name         string
		at           AttachType
		skipIPDefrag bool
		wantCount    int
		wantProgs    []string
	}{
		{
			name: "workload ingress ipv4",
			at: AttachType{
				Hook:   Ingress,
				Family: 4,
				Type:   tcdefs.EpTypeWorkload,
			},
			skipIPDefrag: false,
			wantCount:    8, // All except host ct conflict, includes IP defrag
			wantProgs:    []string{"calico_tc_main", "calico_tc_skb_accepted_entrypoint", "calico_tc_skb_send_icmp_replies", "calico_tc_skb_drop"},
		},
		{
			name: "workload ingress ipv4 skip defrag",
			at: AttachType{
				Hook:   Ingress,
				Family: 4,
				Type:   tcdefs.EpTypeWorkload,
			},
			skipIPDefrag: true,
			wantCount:    7, // All except host ct conflict and IP defrag
			wantProgs:    []string{"calico_tc_main", "calico_tc_skb_accepted_entrypoint"},
		},
		{
			name: "host egress ipv4",
			at: AttachType{
				Hook:   Egress,
				Family: 4,
				Type:   tcdefs.EpTypeHost,
			},
			skipIPDefrag: false,
			wantCount:    7, // Includes host ct conflict, no IP defrag on egress
			wantProgs:    []string{"calico_tc_main", "calico_tc_host_ct_conflict"},
		},
		{
			name: "host ingress ipv4",
			at: AttachType{
				Hook:   Ingress,
				Family: 4,
				Type:   tcdefs.EpTypeHost,
			},
			skipIPDefrag: false,
			wantCount:    9, // Includes both host ct conflict (no - on ingress) and IP defrag and maglev
			wantProgs:    []string{"calico_tc_main", "calico_tc_maglev"},
		},
		{
			name: "xdp",
			at: AttachType{
				Hook:   XDP,
				Family: 4,
				Type:   tcdefs.EpTypeHost,
			},
			skipIPDefrag: false,
			wantCount:    3, // XDP has only 3 non-empty programs
			wantProgs:    []string{"calico_xdp_main", "calico_xdp_accepted_entrypoint", "calico_xdp_drop"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			progs := GetApplicableSubProgs(tt.at, tt.skipIPDefrag)
			if len(progs) != tt.wantCount {
				t.Errorf("GetApplicableSubProgs() count = %d, want %d", len(progs), tt.wantCount)
			}

			// Check that expected programs are present
			progNames := make(map[string]bool)
			for _, p := range progs {
				progNames[p.Name] = true
				// Verify all fields are populated
				if p.Name == "" {
					t.Errorf("Program has empty name")
				}
				if p.Index < 0 {
					t.Errorf("Program %s has invalid index %d", p.Name, p.Index)
				}
			}

			for _, wantProg := range tt.wantProgs {
				if !progNames[wantProg] {
					t.Errorf("Expected program '%s' not found in results", wantProg)
				}
			}
		})
	}
}

func TestGetApplicableSubProgsDebugMode(t *testing.T) {
	// Test debug mode offset
	at := AttachType{
		Hook:     Ingress,
		Family:   4,
		Type:     tcdefs.EpTypeWorkload,
		LogLevel: "debug",
	}

	progs := GetApplicableSubProgs(at, false)
	
	// Find the main program and check its SubProg value
	for _, p := range progs {
		if p.Name == "calico_tc_main" {
			// In debug mode, the SubProg should be offset by SubProgTCMainDebug
			if p.SubProg != SubProgTCMainDebug {
				t.Errorf("Debug mode main program SubProg = %d, want %d", p.SubProg, SubProgTCMainDebug)
			}
			return
		}
	}
	t.Error("Main program not found in debug mode results")
}
