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

package commands

import "testing"

func TestFormatRuleStart(t *testing.T) {
	tests := []struct {
		name     string
		comment  string
		expected string
	}{
		{
			name:     "allow action",
			comment:  `Start of rule policy-tcp action:"allow"`,
			expected: "Rule: policy-tcp  Action: allow",
		},
		{
			name:     "deny action",
			comment:  `Start of rule policy-tcp action:"deny"`,
			expected: "Rule: policy-tcp  Action: deny",
		},
		{
			name:     "namespaced rule",
			comment:  `Start of rule ns/policy-tcp action:"allow"`,
			expected: "Rule: ns/policy-tcp  Action: allow",
		},
		{
			name:     "pass action",
			comment:  `Start of rule my-policy action:"pass"`,
			expected: "Rule: my-policy  Action: pass",
		},
		{
			name:     "action with extra proto fields",
			comment:  `Start of rule policy-tcp action:"allow" protocol:{number:6}`,
			expected: "Rule: policy-tcp  Action: allow",
		},
		{
			name:     "no action field",
			comment:  "Start of rule policy-tcp",
			expected: "Rule: policy-tcp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatRuleStart(tt.comment)
			if got != tt.expected {
				t.Errorf("formatRuleStart(%q) = %q, want %q", tt.comment, got, tt.expected)
			}
		})
	}
}

func TestExtractProtoField(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		field    string
		expected string
	}{
		{
			name:     "action field",
			s:        `action:"allow"`,
			field:    "action",
			expected: "allow",
		},
		{
			name:     "action with other fields",
			s:        `action:"deny" protocol:{number:6}`,
			field:    "action",
			expected: "deny",
		},
		{
			name:     "missing field",
			s:        `protocol:{number:6}`,
			field:    "action",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractProtoField(tt.s, tt.field)
			if got != tt.expected {
				t.Errorf("extractProtoField(%q, %q) = %q, want %q", tt.s, tt.field, got, tt.expected)
			}
		})
	}
}

func TestFormatIPSets(t *testing.T) {
	tests := []struct {
		name     string
		comment  string
		members  map[uint64][]string
		expected string
	}{
		{
			name:     "src only, no resolution",
			comment:  "IPSets src_ip_set_ids:<0x1234abcd>",
			members:  nil,
			expected: "IP sets: src=0x1234abcd",
		},
		{
			name:     "src and dst, no resolution",
			comment:  "IPSets src_ip_set_ids:<0x1234> dst_ip_set_ids:<0x5678>",
			members:  nil,
			expected: "IP sets: src=0x1234 dst=0x5678",
		},
		{
			name:     "negated sets, no resolution",
			comment:  "IPSets not_src_ip_set_ids:<0xaaaa> not_dst_ip_set_ids:<0xbbbb>",
			members:  nil,
			expected: "IP sets: !src=0xaaaa !dst=0xbbbb",
		},
		{
			name:    "resolved src",
			comment: "IPSets src_ip_set_ids:<0xff>",
			members: map[uint64][]string{
				0xff: {"10.0.0.0/8", "192.168.0.0/16"},
			},
			expected: "IP sets: src={10.0.0.0/8, 192.168.0.0/16}",
		},
		{
			name:    "resolved src and dst",
			comment: "IPSets src_ip_set_ids:<0xaa> dst_ip_set_ids:<0xbb>",
			members: map[uint64][]string{
				0xaa: {"10.0.0.1/32"},
				0xbb: {"172.16.0.0/12", "192.168.1.0/24"},
			},
			expected: "IP sets: src={10.0.0.1/32} dst={172.16.0.0/12, 192.168.1.0/24}",
		},
		{
			name:    "partial resolution",
			comment: "IPSets src_ip_set_ids:<0xaa> dst_ip_set_ids:<0xcc>",
			members: map[uint64][]string{
				0xaa: {"10.0.0.1/32"},
			},
			expected: "IP sets: src={10.0.0.1/32} dst=0xcc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatIPSets(tt.comment, tt.members)
			if got != tt.expected {
				t.Errorf("formatIPSets(%q) = %q, want %q", tt.comment, got, tt.expected)
			}
		})
	}
}

func TestFormatTierEnd(t *testing.T) {
	tests := []struct {
		name     string
		comment  string
		expected string
	}{
		{
			name:     "with action",
			comment:  "End of tier default: pass",
			expected: "End Tier: default  (action: pass)",
		},
		{
			name:     "deny action",
			comment:  "End of tier security: deny",
			expected: "End Tier: security  (action: deny)",
		},
		{
			name:     "no action",
			comment:  "End of tier default",
			expected: "End Tier: default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatTierEnd(tt.comment)
			if got != tt.expected {
				t.Errorf("formatTierEnd(%q) = %q, want %q", tt.comment, got, tt.expected)
			}
		})
	}
}
