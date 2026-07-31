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

func TestResolveMatchIPSets(t *testing.T) {
	tests := []struct {
		name     string
		comment  string
		members  map[uint64][]string
		expected string
	}{
		{
			name:     "no members map, hex IDs left as-is",
			comment:  "Match: proto=tcp src={11.0.0.8/32,0x1234abcd}",
			members:  nil,
			expected: "Match: proto=tcp src={11.0.0.8/32,0x1234abcd}",
		},
		{
			name:    "resolved src set folded next to nets",
			comment: "Match: proto=tcp src={11.0.0.8/32,0xff} dport={9055}",
			members: map[uint64][]string{
				0xff: {"10.0.0.0/8", "192.168.0.0/16"},
			},
			expected: "Match: proto=tcp src={11.0.0.8/32,10.0.0.0/8,192.168.0.0/16} dport={9055}",
		},
		{
			name:    "resolved src and negated dst sets",
			comment: "Match: src={0xaa} !dst={12.0.0.8/32,0xbb}",
			members: map[uint64][]string{
				0xaa: {"10.0.0.1/32"},
				0xbb: {"172.16.0.0/12", "192.168.1.0/24"},
			},
			expected: "Match: src={10.0.0.1/32} !dst={12.0.0.8/32,172.16.0.0/12,192.168.1.0/24}",
		},
		{
			name:    "partial resolution leaves unknown ID",
			comment: "Match: src={0xaa} dst={0xcc}",
			members: map[uint64][]string{
				0xaa: {"10.0.0.1/32"},
			},
			expected: "Match: src={10.0.0.1/32} dst={0xcc}",
		},
		{
			name:     "no hex IDs is a no-op",
			comment:  "Match: proto=tcp src={11.0.0.8/32} dports={9055,200-205}",
			members:  map[uint64][]string{0xff: {"10.0.0.1/32"}},
			expected: "Match: proto=tcp src={11.0.0.8/32} dports={9055,200-205}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveMatchIPSets(tt.comment, tt.members)
			if got != tt.expected {
				t.Errorf("resolveMatchIPSets(%q) = %q, want %q", tt.comment, got, tt.expected)
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
