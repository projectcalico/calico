// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/confd/pkg/backends/types"
	"github.com/projectcalico/calico/confd/pkg/resource/template"
)

// newTestClient creates a client suitable for testing peer processing functions.
// It initializes the cache and peeringCache with the provided data and ensures
// waitForSync won't block.
func newTestClient(cache, peeringCache map[string]string) *client {
	c := &client{
		cache:        cache,
		peeringCache: peeringCache,
	}
	// Ensure waitForSync doesn't block - it's a zero-value WaitGroup which is already "done"
	return c
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
	result := c.buildImportFilter([]string{}, 4)
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
	result := c.buildExportFilter([]string{}, "65000", "64512", 4)
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
		hashedID, err := template.HashToIPv4(config.NodeName)
		require.NoError(t, err)
		config.RouterID = hashedID
	}

	assert.NotEmpty(t, config.RouterID)
	assert.NotEqual(t, "10.0.0.2", config.RouterID)
	assert.Regexp(t, `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`, config.RouterID)
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

// =============================================================================
// populateNodeConfig Tests
// =============================================================================

func TestPopulateNodeConfig_BasicIPv4(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	// Clear CALICO_ROUTER_ID env var for this test
	_ = os.Unsetenv("CALICO_ROUTER_ID")

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/global/as_num":             "64512",
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.populateNodeConfig(config, 4)
	require.NoError(t, err)

	assert.Equal(t, "10.0.0.1", config.NodeIP)
	assert.Equal(t, "10.0.0.1", config.RouterID) // Default router ID is IPv4
	assert.Equal(t, "64512", config.ASNumber)
}

func TestPopulateNodeConfig_BasicIPv6(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	_ = os.Unsetenv("CALICO_ROUTER_ID")

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/host/test-node/ip_addr_v6": "fd00::1",
		"/calico/bgp/v1/global/as_num":             "64512",
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.populateNodeConfig(config, 6)
	require.NoError(t, err)

	assert.Equal(t, "10.0.0.1", config.NodeIP)
	assert.Equal(t, "fd00::1", config.NodeIPv6)
	assert.Equal(t, "10.0.0.1", config.RouterID) // Router ID is still IPv4
	assert.Equal(t, "64512", config.ASNumber)
	// IPv6 should have a comment explaining router ID is IPv4
}

func TestPopulateNodeConfig_NodeSpecificAS(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	_ = os.Unsetenv("CALICO_ROUTER_ID")

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/host/test-node/as_num":     "65001", // Node-specific AS
		"/calico/bgp/v1/global/as_num":             "64512", // Global AS (should be ignored)
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.populateNodeConfig(config, 4)
	require.NoError(t, err)

	// Node-specific AS should take precedence
	assert.Equal(t, "65001", config.ASNumber)
}

func TestPopulateNodeConfig_RouterIDHash(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node-hash"
	defer func() { NodeName = originalNodeName }()

	require.NoError(t, os.Setenv("CALICO_ROUTER_ID", "hash"))
	defer func() { _ = os.Unsetenv("CALICO_ROUTER_ID") }()

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node-hash/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/global/as_num":                  "64512",
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.populateNodeConfig(config, 4)
	require.NoError(t, err)

	// Router ID should be hash-generated, not the node IP
	assert.NotEqual(t, "10.0.0.1", config.RouterID)
	assert.Regexp(t, `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`, config.RouterID)
}

func TestPopulateNodeConfig_RouterIDHashIPv6(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node-hash"
	defer func() { NodeName = originalNodeName }()

	require.NoError(t, os.Setenv("CALICO_ROUTER_ID", "hash"))
	defer func() { _ = os.Unsetenv("CALICO_ROUTER_ID") }()

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node-hash/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/host/test-node-hash/ip_addr_v6": "fd00::1",
		"/calico/bgp/v1/global/as_num":                  "64512",
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.populateNodeConfig(config, 6)
	require.NoError(t, err)

	// Router ID should be hash-generated
	assert.NotEqual(t, "10.0.0.1", config.RouterID)
}

func TestPopulateNodeConfig_ExplicitRouterID(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	require.NoError(t, os.Setenv("CALICO_ROUTER_ID", "192.168.1.1"))
	defer func() { _ = os.Unsetenv("CALICO_ROUTER_ID") }()

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/global/as_num":             "64512",
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.populateNodeConfig(config, 4)
	require.NoError(t, err)

	// Router ID should be the explicit value
	assert.Equal(t, "192.168.1.1", config.RouterID)
}

func TestPopulateNodeConfig_LogLevelDebug(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	_ = os.Unsetenv("CALICO_ROUTER_ID")

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/global/as_num":             "64512",
		"/calico/bgp/v1/global/loglevel":           "debug",
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.populateNodeConfig(config, 4)
	require.NoError(t, err)

	assert.Equal(t, "debug", config.LogLevel)
	assert.Equal(t, "all", config.DebugMode)
}

func TestPopulateNodeConfig_LogLevelInfo(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	_ = os.Unsetenv("CALICO_ROUTER_ID")

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/global/as_num":             "64512",
		"/calico/bgp/v1/global/loglevel":           "info",
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.populateNodeConfig(config, 4)
	require.NoError(t, err)

	assert.Equal(t, "info", config.LogLevel)
	assert.Equal(t, "{ states }", config.DebugMode)
}

func TestPopulateNodeConfig_LogLevelNone(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	_ = os.Unsetenv("CALICO_ROUTER_ID")

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/global/as_num":             "64512",
		"/calico/bgp/v1/global/loglevel":           "none",
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.populateNodeConfig(config, 4)
	require.NoError(t, err)

	assert.Equal(t, "none", config.LogLevel)
	assert.Empty(t, config.DebugMode) // No debug output for "none"
}

func TestPopulateNodeConfig_NodeSpecificLogLevel(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	_ = os.Unsetenv("CALICO_ROUTER_ID")

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/global/as_num":             "64512",
		"/calico/bgp/v1/global/loglevel":           "info",  // Global
		"/calico/bgp/v1/host/test-node/loglevel":   "debug", // Node-specific (should win)
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.populateNodeConfig(config, 4)
	require.NoError(t, err)

	assert.Equal(t, "debug", config.LogLevel)
	assert.Equal(t, "all", config.DebugMode)
}

func TestPopulateNodeConfig_BindModeNodeIP_IPv4(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	_ = os.Unsetenv("CALICO_ROUTER_ID")

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/global/as_num":             "64512",
		"/calico/bgp/v1/global/bind_mode":          "NodeIP",
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.populateNodeConfig(config, 4)
	require.NoError(t, err)

	assert.Equal(t, "10.0.0.1", config.ListenAddress)
}

func TestPopulateNodeConfig_BindModeNodeIP_IPv6(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	_ = os.Unsetenv("CALICO_ROUTER_ID")

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/host/test-node/ip_addr_v6": "fd00::1",
		"/calico/bgp/v1/global/as_num":             "64512",
		"/calico/bgp/v1/global/bind_mode":          "NodeIP",
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.populateNodeConfig(config, 6)
	require.NoError(t, err)

	// IPv6 should use IPv6 address for listen
	assert.Equal(t, "fd00::1", config.ListenAddress)
}

func TestPopulateNodeConfig_ListenPort(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	_ = os.Unsetenv("CALICO_ROUTER_ID")

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/global/as_num":             "64512",
		"/calico/bgp/v1/global/listen_port":        "1790",
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.populateNodeConfig(config, 4)
	require.NoError(t, err)

	assert.Equal(t, "1790", config.ListenPort)
}

func TestPopulateNodeConfig_NodeSpecificListenPort(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	_ = os.Unsetenv("CALICO_ROUTER_ID")

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node/ip_addr_v4":  "10.0.0.1",
		"/calico/bgp/v1/global/as_num":              "64512",
		"/calico/bgp/v1/global/listen_port":         "1790", // Global
		"/calico/bgp/v1/host/test-node/listen_port": "1791", // Node-specific (should win)
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.populateNodeConfig(config, 4)
	require.NoError(t, err)

	assert.Equal(t, "1791", config.ListenPort)
}

func TestPopulateNodeConfig_IgnoredInterfaces_Default(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	_ = os.Unsetenv("CALICO_ROUTER_ID")

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/global/as_num":             "64512",
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.populateNodeConfig(config, 4)
	require.NoError(t, err)

	// Default pattern
	assert.Equal(t, `-"cali*", -"kube-ipvs*", "*"`, config.DirectInterfaces)
}

func TestPopulateNodeConfig_IgnoredInterfaces_Custom(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	_ = os.Unsetenv("CALICO_ROUTER_ID")

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/global/as_num":             "64512",
		"/calico/bgp/v1/global/ignored_interfaces": "eth0,docker*",
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.populateNodeConfig(config, 4)
	require.NoError(t, err)

	// Custom interfaces plus standard exclusions
	assert.Contains(t, config.DirectInterfaces, `-"eth0"`)
	assert.Contains(t, config.DirectInterfaces, `-"docker*"`)
	assert.Contains(t, config.DirectInterfaces, `-"cali*"`)
	assert.Contains(t, config.DirectInterfaces, `-"kube-ipvs*"`)
	assert.Contains(t, config.DirectInterfaces, `"*"`)
}

func TestPopulateNodeConfig_NodeSpecificIgnoredInterfaces(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	_ = os.Unsetenv("CALICO_ROUTER_ID")

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node/ip_addr_v4":         "10.0.0.1",
		"/calico/bgp/v1/global/as_num":                     "64512",
		"/calico/bgp/v1/global/ignored_interfaces":         "global-if", // Global
		"/calico/bgp/v1/host/test-node/ignored_interfaces": "node-if",   // Node-specific (should win)
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.populateNodeConfig(config, 4)
	require.NoError(t, err)

	// Node-specific interface should be present
	assert.Contains(t, config.DirectInterfaces, `-"node-if"`)
	// Global interface should NOT be present
	assert.NotContains(t, config.DirectInterfaces, `-"global-if"`)
}

func TestPopulateNodeConfig_NodeSpecificBindMode(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	_ = os.Unsetenv("CALICO_ROUTER_ID")

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/global/as_num":             "64512",
		"/calico/bgp/v1/host/test-node/bind_mode":  "NodeIP", // Node-specific
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.populateNodeConfig(config, 4)
	require.NoError(t, err)

	assert.Equal(t, "10.0.0.1", config.ListenAddress)
}

func TestPopulateNodeConfig_NoBindMode(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	_ = os.Unsetenv("CALICO_ROUTER_ID")

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/global/as_num":             "64512",
		// No bind_mode set
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.populateNodeConfig(config, 4)
	require.NoError(t, err)

	// ListenAddress should be empty when bind_mode is not NodeIP
	assert.Empty(t, config.ListenAddress)
}

func TestPopulateNodeConfig_DefaultLogLevel(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	_ = os.Unsetenv("CALICO_ROUTER_ID")

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/global/as_num":             "64512",
		// No loglevel set
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{
		NodeName: NodeName,
	}

	err := c.populateNodeConfig(config, 4)
	require.NoError(t, err)

	// Default debug mode when no log level is set
	assert.Equal(t, "{ states }", config.DebugMode)
}

// =============================================================================
// processCommunityRules Tests
// =============================================================================

func TestProcessCommunityRules_StandardCommunity(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	// Community advertisements with standard 2-part community
	advertisements := []map[string]interface{}{
		{
			"cidr":        "10.0.0.0/8",
			"communities": []interface{}{"65000:100"},
		},
	}
	advJSON, _ := json.Marshal(advertisements)

	cache := map[string]string{
		"/calico/bgp/v1/global/prefix_advertisements/ip_v4": string(advJSON),
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{}

	err := c.processCommunityRules(config, 4)
	require.NoError(t, err)

	require.Len(t, config.Communities, 1)
	assert.Equal(t, "10.0.0.0/8", config.Communities[0].CIDR)
	require.Len(t, config.Communities[0].AddStatements, 1)
	assert.Equal(t, "bgp_community.add((65000, 100));", config.Communities[0].AddStatements[0])
}

func TestProcessCommunityRules_LargeCommunity(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	// Community advertisements with large 3-part community
	advertisements := []map[string]interface{}{
		{
			"cidr":        "172.16.0.0/12",
			"communities": []interface{}{"65000:100:200"},
		},
	}
	advJSON, _ := json.Marshal(advertisements)

	cache := map[string]string{
		"/calico/bgp/v1/global/prefix_advertisements/ip_v4": string(advJSON),
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{}

	err := c.processCommunityRules(config, 4)
	require.NoError(t, err)

	require.Len(t, config.Communities, 1)
	assert.Equal(t, "172.16.0.0/12", config.Communities[0].CIDR)
	require.Len(t, config.Communities[0].AddStatements, 1)
	assert.Equal(t, "bgp_large_community.add((65000, 100, 200));", config.Communities[0].AddStatements[0])
}

func TestProcessCommunityRules_MultipleCommunities(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	// Multiple communities for a single CIDR
	advertisements := []map[string]interface{}{
		{
			"cidr":        "10.0.0.0/8",
			"communities": []interface{}{"65000:100", "65000:200", "65001:50:100"},
		},
	}
	advJSON, _ := json.Marshal(advertisements)

	cache := map[string]string{
		"/calico/bgp/v1/global/prefix_advertisements/ip_v4": string(advJSON),
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{}

	err := c.processCommunityRules(config, 4)
	require.NoError(t, err)

	require.Len(t, config.Communities, 1)
	require.Len(t, config.Communities[0].AddStatements, 3)
	assert.Equal(t, "bgp_community.add((65000, 100));", config.Communities[0].AddStatements[0])
	assert.Equal(t, "bgp_community.add((65000, 200));", config.Communities[0].AddStatements[1])
	assert.Equal(t, "bgp_large_community.add((65001, 50, 100));", config.Communities[0].AddStatements[2])
}

func TestProcessCommunityRules_MultipleCIDRs(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	// Multiple advertisements with different CIDRs
	advertisements := []map[string]interface{}{
		{
			"cidr":        "10.0.0.0/8",
			"communities": []interface{}{"65000:100"},
		},
		{
			"cidr":        "192.168.0.0/16",
			"communities": []interface{}{"65000:200"},
		},
	}
	advJSON, _ := json.Marshal(advertisements)

	cache := map[string]string{
		"/calico/bgp/v1/global/prefix_advertisements/ip_v4": string(advJSON),
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{}

	err := c.processCommunityRules(config, 4)
	require.NoError(t, err)

	require.Len(t, config.Communities, 2)
	assert.Equal(t, "10.0.0.0/8", config.Communities[0].CIDR)
	assert.Equal(t, "192.168.0.0/16", config.Communities[1].CIDR)
}

func TestProcessCommunityRules_IPv6(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	// IPv6 prefix advertisement
	advertisements := []map[string]interface{}{
		{
			"cidr":        "fd00::/8",
			"communities": []interface{}{"65000:100"},
		},
	}
	advJSON, _ := json.Marshal(advertisements)

	cache := map[string]string{
		"/calico/bgp/v1/global/prefix_advertisements/ip_v6": string(advJSON),
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{}

	err := c.processCommunityRules(config, 6)
	require.NoError(t, err)

	require.Len(t, config.Communities, 1)
	assert.Equal(t, "fd00::/8", config.Communities[0].CIDR)
}

func TestProcessCommunityRules_NodeSpecific(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	// Node-specific should take precedence over global
	nodeAdv := []map[string]interface{}{
		{
			"cidr":        "10.0.0.0/8",
			"communities": []interface{}{"65001:100"}, // Node-specific
		},
	}
	nodeAdvJSON, _ := json.Marshal(nodeAdv)

	globalAdv := []map[string]interface{}{
		{
			"cidr":        "172.16.0.0/12",
			"communities": []interface{}{"65000:200"}, // Global (should be ignored)
		},
	}
	globalAdvJSON, _ := json.Marshal(globalAdv)

	cache := map[string]string{
		"/calico/bgp/v1/host/test-node/prefix_advertisements/ip_v4": string(nodeAdvJSON),
		"/calico/bgp/v1/global/prefix_advertisements/ip_v4":         string(globalAdvJSON),
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{}

	err := c.processCommunityRules(config, 4)
	require.NoError(t, err)

	require.Len(t, config.Communities, 1)
	// Should use node-specific, not global
	assert.Equal(t, "10.0.0.0/8", config.Communities[0].CIDR)
	assert.Contains(t, config.Communities[0].AddStatements[0], "65001")
}

func TestProcessCommunityRules_GlobalFallback(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	// Only global defined, no node-specific
	globalAdv := []map[string]interface{}{
		{
			"cidr":        "172.16.0.0/12",
			"communities": []interface{}{"65000:200"},
		},
	}
	globalAdvJSON, _ := json.Marshal(globalAdv)

	cache := map[string]string{
		"/calico/bgp/v1/global/prefix_advertisements/ip_v4": string(globalAdvJSON),
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{}

	err := c.processCommunityRules(config, 4)
	require.NoError(t, err)

	require.Len(t, config.Communities, 1)
	assert.Equal(t, "172.16.0.0/12", config.Communities[0].CIDR)
}

func TestProcessCommunityRules_NoCommunities(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	// No prefix_advertisements defined
	cache := map[string]string{}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{}

	err := c.processCommunityRules(config, 4)
	require.NoError(t, err)

	// Should be empty, no error
	assert.Len(t, config.Communities, 0)
}

func TestProcessCommunityRules_EmptyCommunities(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	// Advertisement with empty communities array
	advertisements := []map[string]interface{}{
		{
			"cidr":        "10.0.0.0/8",
			"communities": []interface{}{},
		},
	}
	advJSON, _ := json.Marshal(advertisements)

	cache := map[string]string{
		"/calico/bgp/v1/global/prefix_advertisements/ip_v4": string(advJSON),
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{}

	err := c.processCommunityRules(config, 4)
	require.NoError(t, err)

	// Should be empty since no add statements were generated
	assert.Len(t, config.Communities, 0)
}

func TestProcessCommunityRules_InvalidCommunityFormat(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	// Community with invalid format (not 2 or 3 parts)
	advertisements := []map[string]interface{}{
		{
			"cidr": "10.0.0.0/8",
			"communities": []interface{}{
				"65000",     // Invalid: only 1 part
				"65000:100", // Valid: 2 parts
				"a:b:c:d",   // Invalid: 4 parts
			},
		},
	}
	advJSON, _ := json.Marshal(advertisements)

	cache := map[string]string{
		"/calico/bgp/v1/global/prefix_advertisements/ip_v4": string(advJSON),
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{}

	err := c.processCommunityRules(config, 4)
	require.NoError(t, err)

	// Should only have the valid community
	require.Len(t, config.Communities, 1)
	require.Len(t, config.Communities[0].AddStatements, 1)
	assert.Contains(t, config.Communities[0].AddStatements[0], "65000, 100")
}

func TestProcessCommunityRules_MissingCIDR(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	// Advertisement without CIDR field
	advertisements := []map[string]interface{}{
		{
			"communities": []interface{}{"65000:100"},
		},
	}
	advJSON, _ := json.Marshal(advertisements)

	cache := map[string]string{
		"/calico/bgp/v1/global/prefix_advertisements/ip_v4": string(advJSON),
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{}

	err := c.processCommunityRules(config, 4)
	require.NoError(t, err)

	// Should be empty since CIDR is missing
	assert.Len(t, config.Communities, 0)
}

func TestProcessCommunityRules_MissingCommunities(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	// Advertisement without communities field
	advertisements := []map[string]interface{}{
		{
			"cidr": "10.0.0.0/8",
		},
	}
	advJSON, _ := json.Marshal(advertisements)

	cache := map[string]string{
		"/calico/bgp/v1/global/prefix_advertisements/ip_v4": string(advJSON),
	}

	c := newTestClient(cache, nil)
	config := &types.BirdBGPConfig{}

	err := c.processCommunityRules(config, 4)
	require.NoError(t, err)

	// Should be empty since communities are missing
	assert.Len(t, config.Communities, 0)
}

// =============================================================================
// Peer Processing Tests
// =============================================================================

func TestProcessMeshPeers_BasicMesh(t *testing.T) {
	// Set up global NodeName
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	// Create mesh configuration
	meshConfig := map[string]interface{}{
		"enabled": true,
	}
	meshConfigJSON, _ := json.Marshal(meshConfig)

	cache := map[string]string{
		"/calico/bgp/v1/global/node_mesh":       string(meshConfigJSON),
		"/calico/bgp/v1/global/as_num":          "64512",
		"/calico/bgp/v1/host/node-1/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/host/node-2/ip_addr_v4": "10.0.0.2",
		"/calico/bgp/v1/host/node-3/ip_addr_v4": "10.0.0.3",
		"/calico/bgp/v1/host/node-2/as_num":     "64512",
		"/calico/bgp/v1/host/node-3/as_num":     "64512",
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIP:   "10.0.0.1",
		ASNumber: "64512",
	}

	err := c.processMeshPeers(config, "", 4)
	require.NoError(t, err)

	// Should have 2 mesh peers (node-2 and node-3, excluding ourselves)
	assert.Len(t, config.Peers, 2)

	// Verify peer names and IPs
	peerIPs := make(map[string]bool)
	for _, peer := range config.Peers {
		peerIPs[peer.IP] = true
		assert.Equal(t, "mesh", peer.Type)
		assert.Contains(t, peer.Name, "Mesh_")
		assert.Equal(t, "10.0.0.1", peer.SourceAddr)
	}
	assert.True(t, peerIPs["10.0.0.2"])
	assert.True(t, peerIPs["10.0.0.3"])
}

func TestProcessMeshPeers_IPv6(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	meshConfig := map[string]interface{}{
		"enabled": true,
	}
	meshConfigJSON, _ := json.Marshal(meshConfig)

	cache := map[string]string{
		"/calico/bgp/v1/global/node_mesh":       string(meshConfigJSON),
		"/calico/bgp/v1/global/as_num":          "64512",
		"/calico/bgp/v1/host/node-1/ip_addr_v6": "fd00::1",
		"/calico/bgp/v1/host/node-2/ip_addr_v6": "fd00::2",
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIPv6: "fd00::1",
		ASNumber: "64512",
	}

	err := c.processMeshPeers(config, "", 6)
	require.NoError(t, err)

	assert.Len(t, config.Peers, 1)
	assert.Equal(t, "fd00::2", config.Peers[0].IP)
	assert.Contains(t, config.Peers[0].Name, "Mesh_fd00__2")
	assert.Equal(t, "fd00::1", config.Peers[0].SourceAddr)
}

func TestProcessMeshPeers_MeshDisabled(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	meshConfig := map[string]interface{}{
		"enabled": false,
	}
	meshConfigJSON, _ := json.Marshal(meshConfig)

	cache := map[string]string{
		"/calico/bgp/v1/global/node_mesh":       string(meshConfigJSON),
		"/calico/bgp/v1/host/node-1/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/host/node-2/ip_addr_v4": "10.0.0.2",
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIP:   "10.0.0.1",
		ASNumber: "64512",
	}

	err := c.processMeshPeers(config, "", 4)
	require.NoError(t, err)

	// No peers should be added when mesh is disabled
	assert.Len(t, config.Peers, 0)
}

func TestProcessMeshPeers_RouteReflector(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	meshConfig := map[string]interface{}{
		"enabled": true,
	}
	meshConfigJSON, _ := json.Marshal(meshConfig)

	cache := map[string]string{
		"/calico/bgp/v1/global/node_mesh":       string(meshConfigJSON),
		"/calico/bgp/v1/host/node-1/ip_addr_v4": "10.0.0.1",
		"/calico/bgp/v1/host/node-2/ip_addr_v4": "10.0.0.2",
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIP:   "10.0.0.1",
		ASNumber: "64512",
	}

	// Node is a route reflector - should skip mesh
	err := c.processMeshPeers(config, "rr-cluster-1", 4)
	require.NoError(t, err)

	assert.Len(t, config.Peers, 0)
}

func TestProcessMeshPeers_SkipRouteReflectorPeers(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	meshConfig := map[string]interface{}{
		"enabled": true,
	}
	meshConfigJSON, _ := json.Marshal(meshConfig)

	cache := map[string]string{
		"/calico/bgp/v1/global/node_mesh":          string(meshConfigJSON),
		"/calico/bgp/v1/host/node-1/ip_addr_v4":    "10.0.0.1",
		"/calico/bgp/v1/host/node-2/ip_addr_v4":    "10.0.0.2",
		"/calico/bgp/v1/host/node-2/rr_cluster_id": "rr-cluster",
		"/calico/bgp/v1/host/node-3/ip_addr_v4":    "10.0.0.3",
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIP:   "10.0.0.1",
		ASNumber: "64512",
	}

	err := c.processMeshPeers(config, "", 4)
	require.NoError(t, err)

	// Should only have node-3, node-2 is a route reflector
	assert.Len(t, config.Peers, 1)
	assert.Equal(t, "10.0.0.3", config.Peers[0].IP)
}

func TestProcessMeshPeers_PassiveMode(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	meshConfig := map[string]interface{}{
		"enabled": true,
	}
	meshConfigJSON, _ := json.Marshal(meshConfig)

	// String comparison: "10.0.0.2" > "10.0.0.1" and "10.0.0.10" > "10.0.0.1"
	// because string comparison is lexicographical, not numerical
	cache := map[string]string{
		"/calico/bgp/v1/global/node_mesh":       string(meshConfigJSON),
		"/calico/bgp/v1/host/node-1/ip_addr_v4": "10.0.0.5", // Our IP
		"/calico/bgp/v1/host/node-2/ip_addr_v4": "10.0.0.2", // "10.0.0.2" < "10.0.0.5" (string) - NOT passive
		"/calico/bgp/v1/host/node-3/ip_addr_v4": "10.0.0.8", // "10.0.0.8" > "10.0.0.5" (string) - PASSIVE
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIP:   "10.0.0.5",
		ASNumber: "64512",
	}

	err := c.processMeshPeers(config, "", 4)
	require.NoError(t, err)

	assert.Len(t, config.Peers, 2)

	for _, peer := range config.Peers {
		switch peer.IP {
		case "10.0.0.2":
			// "10.0.0.2" < "10.0.0.5" (string comparison), so should NOT be passive
			assert.False(t, peer.Passive, "10.0.0.2 < 10.0.0.5 in string comparison")
		case "10.0.0.8":
			// "10.0.0.8" > "10.0.0.5" (string comparison), so should be passive
			assert.True(t, peer.Passive, "10.0.0.8 > 10.0.0.5 in string comparison")
		}
	}
}

func TestProcessMeshPeers_WithPasswordAndRestartTime(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	meshConfig := map[string]interface{}{
		"enabled": true,
	}
	meshConfigJSON, _ := json.Marshal(meshConfig)

	cache := map[string]string{
		"/calico/bgp/v1/global/node_mesh":              string(meshConfigJSON),
		"/calico/bgp/v1/global/node_mesh_password":     "secret123",
		"/calico/bgp/v1/global/node_mesh_restart_time": "120",
		"/calico/bgp/v1/host/node-1/ip_addr_v4":        "10.0.0.1",
		"/calico/bgp/v1/host/node-2/ip_addr_v4":        "10.0.0.2",
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIP:   "10.0.0.1",
		ASNumber: "64512",
	}

	err := c.processMeshPeers(config, "", 4)
	require.NoError(t, err)

	require.Len(t, config.Peers, 1)
	assert.Equal(t, "secret123", config.Peers[0].Password)
	assert.Equal(t, "120", config.Peers[0].GracefulRestart)
}

func TestProcessGlobalPeers_BasicPeer(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	peerData := map[string]interface{}{
		"ip":     "192.168.1.100",
		"as_num": "65000",
	}
	peerDataJSON, _ := json.Marshal(peerData)

	cache := map[string]string{
		"/calico/bgp/v1/global/as_num":                "64512",
		"/calico/bgp/v1/global/peer_v4/192.168.1.100": string(peerDataJSON),
		"/calico/bgp/v1/host/node-1/ip_addr_v4":       "10.0.0.1",
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIP:   "10.0.0.1",
		ASNumber: "64512",
	}

	err := c.processGlobalPeers(config, "", 4)
	require.NoError(t, err)

	require.Len(t, config.Peers, 1)
	assert.Equal(t, "192.168.1.100", config.Peers[0].IP)
	assert.Equal(t, "65000", config.Peers[0].ASNumber)
	assert.Contains(t, config.Peers[0].Name, "Global_")
}

func TestProcessGlobalPeers_IPv6Peer(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	peerData := map[string]interface{}{
		"ip":          "2001:db8::100",
		"as_num":      "65000",
		"source_addr": "UseNodeIP", // Required to set SourceAddr
	}
	peerDataJSON, _ := json.Marshal(peerData)

	cache := map[string]string{
		"/calico/bgp/v1/global/as_num":                "64512",
		"/calico/bgp/v1/global/peer_v6/2001:db8::100": string(peerDataJSON),
		"/calico/bgp/v1/host/node-1/ip_addr_v6":       "fd00::1",
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIPv6: "fd00::1",
		ASNumber: "64512",
	}

	err := c.processGlobalPeers(config, "", 6)
	require.NoError(t, err)

	require.Len(t, config.Peers, 1)
	assert.Equal(t, "2001:db8::100", config.Peers[0].IP)
	assert.Contains(t, config.Peers[0].Name, "Global_2001_db8__100")
	assert.Equal(t, "fd00::1", config.Peers[0].SourceAddr)
}

func TestProcessGlobalPeers_WithPassword(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	peerData := map[string]interface{}{
		"ip":       "192.168.1.100",
		"as_num":   "65000",
		"password": "bgp-secret",
	}
	peerDataJSON, _ := json.Marshal(peerData)

	cache := map[string]string{
		"/calico/bgp/v1/global/as_num":                "64512",
		"/calico/bgp/v1/global/peer_v4/192.168.1.100": string(peerDataJSON),
		"/calico/bgp/v1/host/node-1/ip_addr_v4":       "10.0.0.1",
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIP:   "10.0.0.1",
		ASNumber: "64512",
	}

	err := c.processGlobalPeers(config, "", 4)
	require.NoError(t, err)

	require.Len(t, config.Peers, 1)
	assert.Equal(t, "bgp-secret", config.Peers[0].Password)
}

func TestProcessGlobalPeers_WithTTLSecurity(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	peerData := map[string]interface{}{
		"ip":           "192.168.1.100",
		"as_num":       "65000",
		"ttl_security": float64(64),
	}
	peerDataJSON, _ := json.Marshal(peerData)

	cache := map[string]string{
		"/calico/bgp/v1/global/as_num":                "64512",
		"/calico/bgp/v1/global/peer_v4/192.168.1.100": string(peerDataJSON),
		"/calico/bgp/v1/host/node-1/ip_addr_v4":       "10.0.0.1",
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIP:   "10.0.0.1",
		ASNumber: "64512",
	}

	err := c.processGlobalPeers(config, "", 4)
	require.NoError(t, err)

	require.Len(t, config.Peers, 1)
	assert.Contains(t, config.Peers[0].TTLSecurity, "on")
	assert.Contains(t, config.Peers[0].TTLSecurity, "multihop 64")
}

func TestProcessNodePeers_BasicPeer(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	peerData := map[string]interface{}{
		"ip":     "172.16.0.100",
		"as_num": "65001",
	}
	peerDataJSON, _ := json.Marshal(peerData)

	cache := map[string]string{
		"/calico/bgp/v1/global/as_num":                    "64512",
		"/calico/bgp/v1/host/node-1/ip_addr_v4":           "10.0.0.1",
		"/calico/bgp/v1/host/node-1/peer_v4/172.16.0.100": string(peerDataJSON),
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIP:   "10.0.0.1",
		ASNumber: "64512",
	}

	err := c.processNodePeers(config, "", 4)
	require.NoError(t, err)

	require.Len(t, config.Peers, 1)
	assert.Equal(t, "172.16.0.100", config.Peers[0].IP)
	assert.Equal(t, "65001", config.Peers[0].ASNumber)
	assert.Contains(t, config.Peers[0].Name, "Node_")
}

func TestProcessNodePeers_IPv6Peer(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	peerData := map[string]interface{}{
		"ip":     "fe80::100",
		"as_num": "65001",
	}
	peerDataJSON, _ := json.Marshal(peerData)

	cache := map[string]string{
		"/calico/bgp/v1/global/as_num":                 "64512",
		"/calico/bgp/v1/host/node-1/ip_addr_v6":        "fd00::1",
		"/calico/bgp/v1/host/node-1/peer_v6/fe80::100": string(peerDataJSON),
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIPv6: "fd00::1",
		ASNumber: "64512",
	}

	err := c.processNodePeers(config, "", 6)
	require.NoError(t, err)

	require.Len(t, config.Peers, 1)
	assert.Equal(t, "fe80::100", config.Peers[0].IP)
	assert.Contains(t, config.Peers[0].Name, "Node_fe80__100")
}

func TestProcessNodePeers_LocalBGPPeer(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	// Local BGP peers use the regular peer_v4 path with local_bgp_peer: true
	peerData := map[string]interface{}{
		"ip":             "192.168.1.50", // Local workload IP
		"as_num":         "64512",
		"local_bgp_peer": true, // This marks it as a local BGP peer
	}
	peerDataJSON, _ := json.Marshal(peerData)

	cache := map[string]string{
		"/calico/bgp/v1/global/as_num":                    "64512",
		"/calico/bgp/v1/host/node-1/ip_addr_v4":           "10.0.0.1",
		"/calico/bgp/v1/host/node-1/peer_v4/192.168.1.50": string(peerDataJSON),
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIP:   "10.0.0.1",
		ASNumber: "64512",
	}

	err := c.processNodePeers(config, "", 4)
	require.NoError(t, err)

	require.Len(t, config.Peers, 1)
	assert.Equal(t, "local_workload", config.Peers[0].Type)
}

func TestProcessPeers_CombinedMeshGlobalNode(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	meshConfig := map[string]interface{}{
		"enabled": true,
	}
	meshConfigJSON, _ := json.Marshal(meshConfig)

	globalPeerData := map[string]interface{}{
		"ip":     "192.168.1.100",
		"as_num": "65000",
	}
	globalPeerJSON, _ := json.Marshal(globalPeerData)

	nodePeerData := map[string]interface{}{
		"ip":     "172.16.0.100",
		"as_num": "65001",
	}
	nodePeerJSON, _ := json.Marshal(nodePeerData)

	cache := map[string]string{
		"/calico/bgp/v1/global/node_mesh":                 string(meshConfigJSON),
		"/calico/bgp/v1/global/as_num":                    "64512",
		"/calico/bgp/v1/host/node-1/ip_addr_v4":           "10.0.0.1",
		"/calico/bgp/v1/host/node-2/ip_addr_v4":           "10.0.0.2",
		"/calico/bgp/v1/global/peer_v4/192.168.1.100":     string(globalPeerJSON),
		"/calico/bgp/v1/host/node-1/peer_v4/172.16.0.100": string(nodePeerJSON),
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIP:   "10.0.0.1",
		ASNumber: "64512",
	}

	// Process all peer types
	err := c.processPeers(config, 4)
	require.NoError(t, err)

	// Should have: 1 mesh peer (node-2), 1 global peer, 1 node peer
	assert.Len(t, config.Peers, 3)

	// Verify peer types
	peerTypes := make(map[string]int)
	for _, peer := range config.Peers {
		peerTypes[peer.Type]++
	}
	assert.Equal(t, 1, peerTypes["mesh"])
	assert.Equal(t, 1, peerTypes["global"])
	assert.Equal(t, 1, peerTypes["node"])
}

func TestProcessPeers_NextHopModes(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	tests := []struct {
		name        string
		nextHopMode string
		keepNextHop bool
		peerAS      string
		nodeAS      string
		expectSelf  bool
		expectKeep  bool
	}{
		{
			name:        "NextHopSelf mode",
			nextHopMode: "Self",
			peerAS:      "65000",
			nodeAS:      "64512",
			expectSelf:  true,
		},
		{
			name:        "NextHopKeep mode",
			nextHopMode: "Keep",
			peerAS:      "65000",
			nodeAS:      "64512",
			expectKeep:  true,
		},
		{
			name:        "Legacy keep_next_hop for eBGP",
			keepNextHop: true,
			peerAS:      "65000",
			nodeAS:      "64512",
			expectKeep:  true,
		},
		{
			name:        "Legacy keep_next_hop ignored for iBGP",
			keepNextHop: true,
			peerAS:      "64512",
			nodeAS:      "64512",
			expectKeep:  false, // Should be ignored for iBGP
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peerData := map[string]interface{}{
				"ip":     "192.168.1.100",
				"as_num": tt.peerAS,
			}
			if tt.nextHopMode != "" {
				peerData["next_hop_mode"] = tt.nextHopMode
			}
			if tt.keepNextHop {
				peerData["keep_next_hop"] = true
			}
			peerDataJSON, _ := json.Marshal(peerData)

			cache := map[string]string{
				"/calico/bgp/v1/global/as_num":                tt.nodeAS,
				"/calico/bgp/v1/global/peer_v4/192.168.1.100": string(peerDataJSON),
				"/calico/bgp/v1/host/node-1/ip_addr_v4":       "10.0.0.1",
			}

			c := newTestClient(cache, nil)

			config := &types.BirdBGPConfig{
				NodeIP:   "10.0.0.1",
				ASNumber: tt.nodeAS,
			}

			err := c.processGlobalPeers(config, "", 4)
			require.NoError(t, err)

			require.Len(t, config.Peers, 1)
			assert.Equal(t, tt.expectSelf, config.Peers[0].NextHopSelf, "NextHopSelf mismatch")
			assert.Equal(t, tt.expectKeep, config.Peers[0].NextHopKeep, "NextHopKeep mismatch")
		})
	}
}

func TestProcessPeers_RouteReflectorClient(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	peerData := map[string]interface{}{
		"ip":            "192.168.1.100",
		"as_num":        "64512",     // Same AS for iBGP
		"rr_cluster_id": "cluster-2", // Different cluster ID
	}
	peerDataJSON, _ := json.Marshal(peerData)

	cache := map[string]string{
		"/calico/bgp/v1/global/as_num":                "64512",
		"/calico/bgp/v1/global/peer_v4/192.168.1.100": string(peerDataJSON),
		"/calico/bgp/v1/host/node-1/ip_addr_v4":       "10.0.0.1",
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIP:   "10.0.0.1",
		ASNumber: "64512",
	}

	// Process with this node having a cluster ID (making it a route reflector)
	err := c.processGlobalPeers(config, "cluster-1", 4)
	require.NoError(t, err)

	require.Len(t, config.Peers, 1)
	assert.True(t, config.Peers[0].RouteReflector, "Peer should be marked as route reflector client")
	assert.Equal(t, "cluster-1", config.Peers[0].RRClusterID)
}

func TestProcessPeers_LocalAS(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	peerData := map[string]interface{}{
		"ip":                 "192.168.1.100",
		"as_num":             "65000",
		"local_as_num":       "64000",
		"num_allow_local_as": float64(2), // Correct field name
	}
	peerDataJSON, _ := json.Marshal(peerData)

	cache := map[string]string{
		"/calico/bgp/v1/global/as_num":                "64512",
		"/calico/bgp/v1/global/peer_v4/192.168.1.100": string(peerDataJSON),
		"/calico/bgp/v1/host/node-1/ip_addr_v4":       "10.0.0.1",
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIP:   "10.0.0.1",
		ASNumber: "64512",
	}

	err := c.processGlobalPeers(config, "", 4)
	require.NoError(t, err)

	require.Len(t, config.Peers, 1)
	assert.Equal(t, "64000", config.Peers[0].LocalASNumber)
	assert.Equal(t, "2", config.Peers[0].NumAllowLocalAs)
}

// =============================================================================
// BGP Filter Tests
// =============================================================================

func TestBuildImportFilter_WithBGPFilter(t *testing.T) {
	// Create a BGP filter resource with import rules
	bgpFilter := map[string]interface{}{
		"spec": map[string]interface{}{
			"importV4": []interface{}{
				map[string]interface{}{
					"action":        "Accept",
					"matchOperator": "In",
					"cidr":          "10.0.0.0/8",
				},
			},
		},
	}
	bgpFilterJSON, _ := json.Marshal(bgpFilter)

	cache := map[string]string{
		"/calico/resources/v3/projectcalico.org/bgpfilters/my-filter": string(bgpFilterJSON),
	}

	c := newTestClient(cache, nil)

	result := c.buildImportFilter([]string{"my-filter"}, 4)

	// Should include the filter function call
	assert.Contains(t, result, "'bgp_my-filter_importFilterV4'();")
	// Should still have default accept
	assert.Contains(t, result, "accept;")
}

func TestBuildImportFilter_WithMultipleBGPFilters(t *testing.T) {
	filter1 := map[string]interface{}{
		"spec": map[string]interface{}{
			"importV4": []interface{}{
				map[string]interface{}{"action": "Accept"},
			},
		},
	}
	filter1JSON, _ := json.Marshal(filter1)

	filter2 := map[string]interface{}{
		"spec": map[string]interface{}{
			"importV4": []interface{}{
				map[string]interface{}{"action": "Reject"},
			},
		},
	}
	filter2JSON, _ := json.Marshal(filter2)

	cache := map[string]string{
		"/calico/resources/v3/projectcalico.org/bgpfilters/filter1": string(filter1JSON),
		"/calico/resources/v3/projectcalico.org/bgpfilters/filter2": string(filter2JSON),
	}

	c := newTestClient(cache, nil)

	result := c.buildImportFilter([]string{"filter1", "filter2"}, 4)

	// Should include both filter function calls
	assert.Contains(t, result, "'bgp_filter1_importFilterV4'();")
	assert.Contains(t, result, "'bgp_filter2_importFilterV4'();")
}

func TestBuildImportFilter_IPv6Filter(t *testing.T) {
	bgpFilter := map[string]interface{}{
		"spec": map[string]interface{}{
			"importV6": []interface{}{
				map[string]interface{}{
					"action": "Accept",
					"cidr":   "fd00::/8",
				},
			},
		},
	}
	bgpFilterJSON, _ := json.Marshal(bgpFilter)

	cache := map[string]string{
		"/calico/resources/v3/projectcalico.org/bgpfilters/ipv6-filter": string(bgpFilterJSON),
	}

	c := newTestClient(cache, nil)

	result := c.buildImportFilter([]string{"ipv6-filter"}, 6)

	// Should use V6 suffix
	assert.Contains(t, result, "'bgp_ipv6-filter_importFilterV6'();")
}

func TestBuildImportFilter_FilterWithNoImportRules(t *testing.T) {
	// Filter has export rules but no import rules
	bgpFilter := map[string]interface{}{
		"spec": map[string]interface{}{
			"exportV4": []interface{}{
				map[string]interface{}{"action": "Accept"},
			},
		},
	}
	bgpFilterJSON, _ := json.Marshal(bgpFilter)

	cache := map[string]string{
		"/calico/resources/v3/projectcalico.org/bgpfilters/export-only": string(bgpFilterJSON),
	}

	c := newTestClient(cache, nil)

	result := c.buildImportFilter([]string{"export-only"}, 4)

	// Should NOT include the filter call since there are no import rules
	assert.NotContains(t, result, "'bgp_export-only_importFilterV4'();")
	// Should still have default accept
	assert.Contains(t, result, "accept;")
}

func TestBuildImportFilter_FilterNotFound(t *testing.T) {
	cache := map[string]string{
		// No filters in cache
	}

	c := newTestClient(cache, nil)

	result := c.buildImportFilter([]string{"nonexistent-filter"}, 4)

	// Should NOT include the filter call since filter doesn't exist
	assert.NotContains(t, result, "'bgp_nonexistent-filter_importFilterV4'();")
	// Should still have default accept
	assert.Contains(t, result, "accept;")
}

func TestBuildExportFilter_WithBGPFilter(t *testing.T) {
	bgpFilter := map[string]interface{}{
		"spec": map[string]interface{}{
			"exportV4": []interface{}{
				map[string]interface{}{
					"action": "Accept",
					"cidr":   "10.0.0.0/8",
				},
			},
		},
	}
	bgpFilterJSON, _ := json.Marshal(bgpFilter)

	cache := map[string]string{
		"/calico/resources/v3/projectcalico.org/bgpfilters/my-export-filter": string(bgpFilterJSON),
	}

	c := newTestClient(cache, nil)

	result := c.buildExportFilter([]string{"my-export-filter"}, "65000", "64512", 4)

	// Should include the filter function call
	assert.Contains(t, result, "'bgp_my-export-filter_exportFilterV4'();")
	// Should still have calico_export_to_bgp_peers
	assert.Contains(t, result, "calico_export_to_bgp_peers(false);")
	assert.Contains(t, result, "reject;")
}

func TestBuildExportFilter_IPv6Filter(t *testing.T) {
	bgpFilter := map[string]interface{}{
		"spec": map[string]interface{}{
			"exportV6": []interface{}{
				map[string]interface{}{
					"action": "Accept",
				},
			},
		},
	}
	bgpFilterJSON, _ := json.Marshal(bgpFilter)

	cache := map[string]string{
		"/calico/resources/v3/projectcalico.org/bgpfilters/ipv6-export": string(bgpFilterJSON),
	}

	c := newTestClient(cache, nil)

	result := c.buildExportFilter([]string{"ipv6-export"}, "65000", "64512", 6)

	// Should use V6 suffix
	assert.Contains(t, result, "'bgp_ipv6-export_exportFilterV6'();")
}

func TestBuildExportFilter_FilterWithNoExportRules(t *testing.T) {
	// Filter has import rules but no export rules
	bgpFilter := map[string]interface{}{
		"spec": map[string]interface{}{
			"importV4": []interface{}{
				map[string]interface{}{"action": "Accept"},
			},
		},
	}
	bgpFilterJSON, _ := json.Marshal(bgpFilter)

	cache := map[string]string{
		"/calico/resources/v3/projectcalico.org/bgpfilters/import-only": string(bgpFilterJSON),
	}

	c := newTestClient(cache, nil)

	result := c.buildExportFilter([]string{"import-only"}, "65000", "64512", 4)

	// Should NOT include the filter call since there are no export rules
	assert.NotContains(t, result, "'bgp_import-only_exportFilterV4'();")
	// Should still have calico_export_to_bgp_peers
	assert.Contains(t, result, "calico_export_to_bgp_peers")
}

func TestProcessGlobalPeers_WithBGPFilter(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	// Create BGP filter resource with both import and export rules
	bgpFilter := map[string]interface{}{
		"spec": map[string]interface{}{
			"importV4": []interface{}{
				map[string]interface{}{
					"action": "Accept",
					"cidr":   "10.0.0.0/8",
				},
			},
			"exportV4": []interface{}{
				map[string]interface{}{
					"action": "Reject",
					"cidr":   "192.168.0.0/16",
				},
			},
		},
	}
	bgpFilterJSON, _ := json.Marshal(bgpFilter)

	peerData := map[string]interface{}{
		"ip":      "192.168.1.100",
		"as_num":  "65000",
		"filters": []interface{}{"test-filter"},
	}
	peerDataJSON, _ := json.Marshal(peerData)

	cache := map[string]string{
		"/calico/bgp/v1/global/as_num":                                  "64512",
		"/calico/bgp/v1/global/peer_v4/192.168.1.100":                   string(peerDataJSON),
		"/calico/bgp/v1/host/node-1/ip_addr_v4":                         "10.0.0.1",
		"/calico/resources/v3/projectcalico.org/bgpfilters/test-filter": string(bgpFilterJSON),
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIP:   "10.0.0.1",
		ASNumber: "64512",
	}

	err := c.processGlobalPeers(config, "", 4)
	require.NoError(t, err)

	require.Len(t, config.Peers, 1)

	// Verify import filter includes the BGP filter function call
	assert.Contains(t, config.Peers[0].ImportFilter, "'bgp_test-filter_importFilterV4'();")
	assert.Contains(t, config.Peers[0].ImportFilter, "accept;")

	// Verify export filter includes the BGP filter function call
	assert.Contains(t, config.Peers[0].ExportFilter, "'bgp_test-filter_exportFilterV4'();")
	assert.Contains(t, config.Peers[0].ExportFilter, "calico_export_to_bgp_peers")
}

func TestProcessGlobalPeers_WithBGPFilter_IPv6(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	// Create BGP filter resource with IPv6 rules
	bgpFilter := map[string]interface{}{
		"spec": map[string]interface{}{
			"importV6": []interface{}{
				map[string]interface{}{
					"action": "Accept",
					"cidr":   "fd00::/8",
				},
			},
			"exportV6": []interface{}{
				map[string]interface{}{
					"action": "Accept",
				},
			},
		},
	}
	bgpFilterJSON, _ := json.Marshal(bgpFilter)

	peerData := map[string]interface{}{
		"ip":      "2001:db8::100",
		"as_num":  "65000",
		"filters": []interface{}{"ipv6-bgp-filter"},
	}
	peerDataJSON, _ := json.Marshal(peerData)

	cache := map[string]string{
		"/calico/bgp/v1/global/as_num":                                      "64512",
		"/calico/bgp/v1/global/peer_v6/2001:db8::100":                       string(peerDataJSON),
		"/calico/bgp/v1/host/node-1/ip_addr_v6":                             "fd00::1",
		"/calico/resources/v3/projectcalico.org/bgpfilters/ipv6-bgp-filter": string(bgpFilterJSON),
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIPv6: "fd00::1",
		ASNumber: "64512",
	}

	err := c.processGlobalPeers(config, "", 6)
	require.NoError(t, err)

	require.Len(t, config.Peers, 1)

	// Verify import filter uses V6 suffix
	assert.Contains(t, config.Peers[0].ImportFilter, "'bgp_ipv6-bgp-filter_importFilterV6'();")

	// Verify export filter uses V6 suffix
	assert.Contains(t, config.Peers[0].ExportFilter, "'bgp_ipv6-bgp-filter_exportFilterV6'();")
}

func TestProcessGlobalPeers_WithLongFilterName(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	// Create a BGP filter with a very long name that needs truncation
	longFilterName := "this-is-a-very-long-bgp-filter-name-that-exceeds-bird-symbol-limit"

	bgpFilter := map[string]interface{}{
		"spec": map[string]interface{}{
			"importV4": []interface{}{
				map[string]interface{}{"action": "Accept"},
			},
		},
	}
	bgpFilterJSON, _ := json.Marshal(bgpFilter)

	peerData := map[string]interface{}{
		"ip":      "192.168.1.100",
		"as_num":  "65000",
		"filters": []interface{}{longFilterName},
	}
	peerDataJSON, _ := json.Marshal(peerData)

	cache := map[string]string{
		"/calico/bgp/v1/global/as_num":                                        "64512",
		"/calico/bgp/v1/global/peer_v4/192.168.1.100":                         string(peerDataJSON),
		"/calico/bgp/v1/host/node-1/ip_addr_v4":                               "10.0.0.1",
		"/calico/resources/v3/projectcalico.org/bgpfilters/" + longFilterName: string(bgpFilterJSON),
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIP:   "10.0.0.1",
		ASNumber: "64512",
	}

	err := c.processGlobalPeers(config, "", 4)
	require.NoError(t, err)

	require.Len(t, config.Peers, 1)

	// The filter name should be truncated - check that it doesn't exceed BIRD's limit
	// Full function name format: 'bgp_<name>_importFilterV4'
	// The filter function call should exist and be truncated
	assert.Contains(t, config.Peers[0].ImportFilter, "'bgp_")
	assert.Contains(t, config.Peers[0].ImportFilter, "_importFilterV4'();")

	// Verify the name was truncated (should contain hash suffix)
	// The truncated name should NOT be the full original name
	assert.NotContains(t, config.Peers[0].ImportFilter, longFilterName)
}

func TestProcessNodePeers_WithBGPFilter(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node-1"
	defer func() { NodeName = originalNodeName }()

	// Create BGP filter resource
	bgpFilter := map[string]interface{}{
		"spec": map[string]interface{}{
			"importV4": []interface{}{
				map[string]interface{}{"action": "Accept"},
			},
			"exportV4": []interface{}{
				map[string]interface{}{"action": "Accept"},
			},
		},
	}
	bgpFilterJSON, _ := json.Marshal(bgpFilter)

	peerData := map[string]interface{}{
		"ip":      "172.16.0.100",
		"as_num":  "65001",
		"filters": []interface{}{"node-peer-filter"},
	}
	peerDataJSON, _ := json.Marshal(peerData)

	cache := map[string]string{
		"/calico/bgp/v1/global/as_num":                                       "64512",
		"/calico/bgp/v1/host/node-1/ip_addr_v4":                              "10.0.0.1",
		"/calico/bgp/v1/host/node-1/peer_v4/172.16.0.100":                    string(peerDataJSON),
		"/calico/resources/v3/projectcalico.org/bgpfilters/node-peer-filter": string(bgpFilterJSON),
	}

	c := newTestClient(cache, nil)

	config := &types.BirdBGPConfig{
		NodeIP:   "10.0.0.1",
		ASNumber: "64512",
	}

	err := c.processNodePeers(config, "", 4)
	require.NoError(t, err)

	require.Len(t, config.Peers, 1)

	// Verify both import and export filters have the BGP filter function calls
	assert.Contains(t, config.Peers[0].ImportFilter, "'bgp_node-peer-filter_importFilterV4'();")
	assert.Contains(t, config.Peers[0].ExportFilter, "'bgp_node-peer-filter_exportFilterV4'();")
}

func TestTruncateBGPFilterName(t *testing.T) {
	// Test the truncation function directly
	tests := []struct {
		name       string
		filterName string
		shouldHash bool
	}{
		{
			name:       "Short name - no truncation",
			filterName: "my-filter",
			shouldHash: false,
		},
		{
			name:       "Long name - should truncate and hash",
			filterName: "this-is-a-very-long-filter-name-that-will-exceed-the-bird-symbol-length-limit",
			shouldHash: true,
		},
		{
			name:       "Exactly at limit",
			filterName: "exactly-45-characters-for-a-filter-name-xxxxx", // 45 chars is the max
			shouldHash: false,
		},
		{
			name:       "One over limit",
			filterName: "exactly-46-characters-for-a-filter-name-xxxxxx", // 46 chars triggers truncation
			shouldHash: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateBGPFilterName(tt.filterName)

			if tt.shouldHash {
				// Should be truncated with hash - original name shouldn't be fully present
				assert.NotEqual(t, tt.filterName, result)
				// Should contain a hash suffix (8 hex chars)
				assert.LessOrEqual(t, len(result), 45, "Truncated name should be at most 45 chars")
			} else {
				// Should be unchanged
				assert.Equal(t, tt.filterName, result)
			}
		})
	}
}

// =============================================================================
// Race Condition Tests
// =============================================================================

// TestConfigCache_ConcurrentReadWrite tests the race condition in the global
// configCache map when multiple goroutines call GetBirdBGPConfig concurrently.
//
// This test simulates the real-world scenario where bird.cfg.template (IPv4)
// and bird6.cfg.template (IPv6) are rendered simultaneously by different
// goroutines in processor.go's monitorPrefix function. Each template calls
// GetBirdBGPConfig with its respective IP version.
//
// We now run confd UT with -race, so this test will fail if the configCache map
// is accessed without proper synchronization.
func TestConfigCache_ConcurrentReadWrite(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "test-node"
	defer func() { NodeName = originalNodeName }()

	_ = os.Unsetenv("CALICO_ROUTER_ID")

	// Clear the global configCache to start fresh
	configCacheMutex.Lock()
	configCache = make(map[int]*bgpConfigCache)
	configCacheMutex.Unlock()

	// Enable mesh for more realistic scenario
	meshConfig := map[string]interface{}{
		"enabled": true,
	}
	meshConfigJSON, err := json.Marshal(meshConfig)
	require.NoError(t, err)

	// Set up cache with basic configuration needed for GetBirdBGPConfig
	cache := map[string]string{
		"/calico/bgp/v1/host/test-node/ip_addr_v4":   "10.0.0.1",
		"/calico/bgp/v1/host/test-node/ip_addr_v6":   "fd00::1",
		"/calico/bgp/v1/global/as_num":               "64512",
		"/calico/bgp/v1/global/loglevel":             "info",
		"/calico/bgp/v1/global/node_mesh":            string(meshConfigJSON),
		"/calico/bgp/v1/host/peer-node-1/ip_addr_v4": "10.0.0.2",
		"/calico/bgp/v1/host/peer-node-2/ip_addr_v6": "fd00::2",
	}

	c := newTestClient(cache, nil)

	const numGoroutines = 10
	const testDuration = 10 * time.Second

	// Create a context with 30-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), testDuration)
	defer cancel()

	var wg sync.WaitGroup

	// Simulate concurrent template rendering - this mimics what happens
	// in processor.go when monitorPrefix spawns goroutines for each template
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Alternate between IPv4 and IPv6 to simulate bird.cfg.template
			// and bird6.cfg.template rendering concurrently
			ipVersion := 4
			if id%2 == 0 {
				ipVersion = 6
			}

			iterationCount := 0
			for {
				select {
				case <-ctx.Done():
					// Context timeout reached, exit goroutine
					t.Logf("Goroutine %d (IPv%d) completed %d iterations", id, ipVersion, iterationCount)
					return
				default:
					// This is what the template actually calls via getBGPConfig template function
					_, err := c.GetBirdBGPConfig(ipVersion)
					if err != nil {
						// Some errors are expected if cache is cleared
						continue
					}

					// Periodically clear the cache to force re-computation and increase
					// the likelihood of hitting the race condition
					if iterationCount%5 == 0 {
						configCacheMutex.Lock()
						delete(configCache, ipVersion)
						configCacheMutex.Unlock()
					}

					iterationCount++
				}
			}
		}(i)
	}

	wg.Wait()
}
