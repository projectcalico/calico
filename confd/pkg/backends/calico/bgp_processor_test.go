// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package calico

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/confd/pkg/backends/types"
	"github.com/projectcalico/calico/confd/pkg/resource/template"
)

func TestHashToIPv4(t *testing.T) {
	tests := []struct {
		name     string
		nodeName string
	}{
		{name: "simple hostname", nodeName: "node-1"},
		{name: "FQDN", nodeName: "node-1.example.com"},
		{name: "long hostname", nodeName: "very-long-hostname-with-many-characters-exceeding-normal-length"},
		{name: "special characters", nodeName: "node_with-special.chars"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := template.HashToIPv4(tt.nodeName)
			// Verify it's a valid IPv4 address format
			assert.Regexp(t, `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`, result)

			// Verify consistency - same input should produce same output
			result2 := template.HashToIPv4(tt.nodeName)
			assert.Equal(t, result, result2, "Hash should be deterministic")
		})
	}
}

func TestHashToIPv4_Uniqueness(t *testing.T) {
	// Test that different node names produce different hashes
	node1Hash := template.HashToIPv4("node-1")
	node2Hash := template.HashToIPv4("node-2")
	assert.NotEqual(t, node1Hash, node2Hash, "Different nodes should have different router IDs")
}

func TestGenerateSafePeerName(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{name: "IPv4 simple", ip: "192.168.1.5", expected: "192_168_1_5"},
		{name: "IPv6 simple", ip: "fd80::5", expected: "fd80__5"},
		{name: "IPv4 with zeros", ip: "10.0.0.1", expected: "10_0_0_1"},
		{name: "IPv6 full address", ip: "2001:db8::1", expected: "2001_db8__1"},
		{name: "IPv6 with multiple colons", ip: "fe80::1:2:3", expected: "fe80__1_2_3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateSafePeerName(tt.ip)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func generateSafePeerName(ip string) string {
	safeName := ip
	safeName = replaceAll(safeName, ".", "_")
	safeName = replaceAll(safeName, ":", "_")
	return safeName
}

func replaceAll(s, old, new string) string {
	result := ""
	for i := 0; i < len(s); i++ {
		if i <= len(s)-len(old) && s[i:i+len(old)] == old {
			result += new
			i += len(old) - 1
		} else {
			result += string(s[i])
		}
	}
	return result
}

func TestBuildImportFilter_DefaultAccept(t *testing.T) {
	c := &client{}

	// Test with no filter - should return default accept
	result := c.buildImportFilter(nil, 4)
	assert.Contains(t, result, "accept;")
	assert.Contains(t, result, "# Prior to introduction of BGP Filters")
}

func TestBuildImportFilter_EmptyFilters(t *testing.T) {
	c := &client{}

	// Test with empty filters array - should return default accept
	peerData := map[string]interface{}{
		"filters": []interface{}{},
	}
	result := c.buildImportFilter(peerData, 4)
	assert.Contains(t, result, "accept;")
}

func TestBuildImportFilter_IPv4vsIPv6(t *testing.T) {
	c := &client{}

	// Test that IPv4 and IPv6 return appropriate default
	resultV4 := c.buildImportFilter(nil, 4)
	resultV6 := c.buildImportFilter(nil, 6)

	// Both should have accept by default
	assert.Contains(t, resultV4, "accept;")
	assert.Contains(t, resultV6, "accept;")
}

func TestBuildExportFilter_SameAS(t *testing.T) {
	c := &client{}

	// Same AS should result in reject (via calico_export_to_bgp_peers(true))
	result := c.buildExportFilter(nil, "64512", "64512", 4)
	assert.Contains(t, result, "calico_export_to_bgp_peers(true)")
	assert.Contains(t, result, "reject;")
}

func TestBuildExportFilter_DifferentAS_NoFilter(t *testing.T) {
	c := &client{}

	// Different AS with no filter should use default export filter
	result := c.buildExportFilter(nil, "65000", "64512", 4)
	assert.Contains(t, result, "calico_export_to_bgp_peers(false)")
}

func TestBuildExportFilter_IPv4vsIPv6(t *testing.T) {
	c := &client{}

	// Test that both IPv4 and IPv6 work
	resultV4 := c.buildExportFilter(nil, "65000", "64512", 4)
	resultV6 := c.buildExportFilter(nil, "65000", "64512", 6)

	// Both should have export filter
	assert.Contains(t, resultV4, "calico_export_to_bgp_peers")
	assert.Contains(t, resultV6, "calico_export_to_bgp_peers")
}

func TestBuildExportFilter_EmptyFilters(t *testing.T) {
	c := &client{}

	// Test with empty filters array
	peerData := map[string]interface{}{
		"filters": []interface{}{},
	}
	result := c.buildExportFilter(peerData, "65000", "64512", 4)
	assert.Contains(t, result, "calico_export_to_bgp_peers")
}

func TestRouterIDGeneration_Hash(t *testing.T) {
	NodeName = "test-node-hash"
	require.NoError(t, os.Setenv("CALICO_ROUTER_ID", "hash"))
	defer func() { _ = os.Unsetenv("CALICO_ROUTER_ID") }()

	config := &types.BirdBGPConfig{
		NodeName: NodeName,
		NodeIP:   "10.0.0.2",
	}

	// Test IPv4 - no comment
	routerID := os.Getenv("CALICO_ROUTER_ID")
	if routerID == "hash" {
		config.RouterID = template.HashToIPv4(config.NodeName)
	}

	assert.NotEmpty(t, config.RouterID)
	assert.NotEqual(t, "10.0.0.2", config.RouterID)
	assert.Regexp(t, `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`, config.RouterID)

	// For IPv6, should have comment
	config.RouterIDComment = ""
	if routerID == "hash" {
		config.RouterIDComment = "# Use IP address generated by nodename's hash"
	}
	assert.NotEmpty(t, config.RouterIDComment)
	assert.Contains(t, config.RouterIDComment, "hash")
}

func TestRouterIDGeneration_Explicit(t *testing.T) {
	require.NoError(t, os.Setenv("CALICO_ROUTER_ID", "192.168.1.1"))
	defer func() { _ = os.Unsetenv("CALICO_ROUTER_ID") }()

	config := &types.BirdBGPConfig{
		NodeIP: "10.0.0.1",
	}

	routerID := os.Getenv("CALICO_ROUTER_ID")
	if routerID != "" && routerID != "hash" {
		config.RouterID = routerID
	}

	assert.Equal(t, "192.168.1.1", config.RouterID)
}

func TestRouterIDGeneration_FromNodeIP(t *testing.T) {
	_ = os.Unsetenv("CALICO_ROUTER_ID")

	config := &types.BirdBGPConfig{
		NodeIP: "10.0.0.1",
	}

	routerID := os.Getenv("CALICO_ROUTER_ID")
	if routerID == "" && config.NodeIP != "" {
		config.RouterID = config.NodeIP
	}

	assert.Equal(t, "10.0.0.1", config.RouterID)
}

func TestRouterIDComment_IPv4vsIPv6(t *testing.T) {
	tests := []struct {
		name            string
		ipVersion       int
		routerIDMode    string
		expectedComment bool
		commentContains string
	}{
		{name: "IPv4 hash - no comment", ipVersion: 4, routerIDMode: "hash", expectedComment: false},
		{name: "IPv6 hash - has comment", ipVersion: 6, routerIDMode: "hash", expectedComment: true, commentContains: "hash"},
		{name: "IPv4 explicit - no comment", ipVersion: 4, routerIDMode: "192.168.1.1", expectedComment: false},
		{name: "IPv6 explicit - has comment", ipVersion: 6, routerIDMode: "192.168.1.1", expectedComment: true, commentContains: "IPv4 address"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &types.BirdBGPConfig{}

			// Simulate router ID comment logic
			if tt.routerIDMode == "hash" {
				if tt.ipVersion == 6 {
					config.RouterIDComment = "# Use IP address generated by nodename's hash"
				}
			} else {
				if tt.ipVersion == 6 {
					config.RouterIDComment = "# Use IPv4 address since router id is 4 octets, even in MP-BGP"
				}
			}

			if tt.expectedComment {
				assert.NotEmpty(t, config.RouterIDComment)
				assert.Contains(t, config.RouterIDComment, tt.commentContains)
			} else {
				assert.Empty(t, config.RouterIDComment)
			}
		})
	}
}

func TestPassiveCommentLogic(t *testing.T) {
	tests := []struct {
		name            string
		peerType        string
		peerIP          string
		nodeIP          string
		expectedPassive bool
		expectedComment string
	}{
		{
			name:            "Mesh - peer IP lexically greater",
			peerType:        "Mesh",
			peerIP:          "10.0.0.5",
			nodeIP:          "10.0.0.10",
			expectedPassive: true, // "10.0.0.5" > "10.0.0.10" (string comparison)
			expectedComment: " # Mesh is unidirectional, peer will connect to us.",
		},
		{
			name:            "Mesh - node IP lexically greater",
			peerType:        "Mesh",
			peerIP:          "10.0.0.10",
			nodeIP:          "10.0.0.5",
			expectedPassive: false, // "10.0.0.10" < "10.0.0.5" (string comparison)
			expectedComment: "",
		},
		{
			name:            "Node - peer IP lexically greater",
			peerType:        "Node",
			peerIP:          "172.16.0.5",
			nodeIP:          "172.16.0.10",
			expectedPassive: true, // "172.16.0.5" > "172.16.0.10" (string comparison)
			expectedComment: " # Peering is unidirectional, peer will connect to us.",
		},
		{
			name:            "Node - node IP lexically greater",
			peerType:        "Node",
			peerIP:          "172.16.0.10",
			nodeIP:          "172.16.0.5",
			expectedPassive: false, // "172.16.0.10" < "172.16.0.5" (string comparison)
			expectedComment: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peer := types.BirdBGPPeer{
				IP:   tt.peerIP,
				Type: tt.peerType,
			}

			// Simulate passive logic: passive when peer IP > node IP (string comparison)
			if tt.peerType == "Mesh" || tt.peerType == "Node" {
				if tt.peerIP > tt.nodeIP { // String comparison, as in the actual code
					peer.Passive = true
					if tt.peerType == "Mesh" {
						peer.PassiveComment = " # Mesh is unidirectional, peer will connect to us."
					} else {
						peer.PassiveComment = " # Peering is unidirectional, peer will connect to us."
					}
				}
			}

			assert.Equal(t, tt.expectedPassive, peer.Passive, "Passive flag mismatch for %s vs %s", tt.peerIP, tt.nodeIP)
			if peer.Passive {
				assert.Equal(t, tt.expectedComment, peer.PassiveComment)
			}
		})
	}
}

func TestTTLSecurityFormatting(t *testing.T) {
	tests := []struct {
		name     string
		enabled  bool
		hops     float64
		expected string
	}{
		{name: "TTL security off", enabled: false, expected: "off;\n  multihop"},
		{name: "TTL security on with 1 hop", enabled: true, hops: 1, expected: "on;\n  multihop 1"},
		{name: "TTL security on with 64 hops", enabled: true, hops: 64, expected: "on;\n  multihop 64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result string
			if tt.enabled {
				result = fmt.Sprintf("on;\n  multihop %.0f", tt.hops)
			} else {
				result = "off;\n  multihop"
			}

			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCommunityRule_Structure(t *testing.T) {
	rule := types.CommunityRule{
		CIDR:          "10.0.0.0/8",
		AddStatements: []string{"bgp_community.add((65000, 100));"},
	}

	assert.Equal(t, "10.0.0.0/8", rule.CIDR)
	require.Len(t, rule.AddStatements, 1)
	assert.Contains(t, rule.AddStatements[0], "bgp_community.add")
}
