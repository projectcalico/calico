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
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/confd/pkg/backends/types"
	"github.com/projectcalico/calico/confd/pkg/resource/template"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// NodeName gets the node name from environment
var NodeName = os.Getenv("NODENAME")

// BGP configuration cache
type bgpConfigCache struct {
	config   *types.BirdBGPConfig
	revision uint64
}

// configCache is indexed by IP version (4 or 6)
var configCache map[int]*bgpConfigCache

// configCacheMutex protects concurrent access to configCache
var configCacheMutex sync.RWMutex

func init() {
	configCache = make(map[int]*bgpConfigCache)
}

// GetBirdBGPConfig processes raw datastore data into a clean BGP configuration structure
// ipVersion should be 4 for IPv4 or 6 for IPv6
func (c *client) GetBirdBGPConfig(ipVersion int) (*types.BirdBGPConfig, error) {
	logc := log.WithField("ipVersion", ipVersion)
	currentRevision := c.GetCurrentRevision()

	configCacheMutex.RLock()
	if cached, ok := configCache[ipVersion]; ok && cached.revision == currentRevision {
		configCacheMutex.RUnlock()
		logc.Debug("BGP config cache hit, returning cached configuration")
		return cached.config, nil
	}
	configCacheMutex.RUnlock()

	logc.Debug("BGP config cache miss or expired, processing new configuration")

	config := &types.BirdBGPConfig{
		NodeName:    NodeName,
		Peers:       make([]types.BirdBGPPeer, 0),
		Filters:     make(map[string]string),
		Communities: make([]types.CommunityRule, 0),
	}

	// Get basic node configuration
	if err := c.populateNodeConfig(config, ipVersion); err != nil {
		logc.WithError(err).Warn("Failed to populate node configuration")
		return nil, err
	}
	logc.Debugf("Populated node configuration: node=%s, ip=%s, ipv6=%s, as=%s", config.NodeName, config.NodeIP, config.NodeIPv6, config.ASNumber)

	// Process all peer types
	if err := c.processPeers(config, ipVersion); err != nil {
		logc.WithError(err).Warn("Failed to process BGP peers")
		return nil, err
	}
	logc.Debugf("Processed BGP peers: found %d peers", len(config.Peers))

	// Sort peers by name for consistent output ordering
	sort.Slice(config.Peers, func(i, j int) bool {
		return config.Peers[i].Name < config.Peers[j].Name
	})

	// Process community rules
	if err := c.processCommunityRules(config, ipVersion); err != nil {
		logc.WithError(err).Warn("Failed to process community rules")
		return nil, err
	}
	logc.Debugf("Processed community rules: found %d rules", len(config.Communities))

	// Process ippools.
	if err := c.processIPPools(config, ipVersion); err != nil {
		logc.WithError(err).Warn("Failed to process ippools")
		return nil, err
	}
	logc.WithFields(log.Fields{
		"numOfFiltersForProgrammingKernel": len(config.KernelFilterForIPPools),
		"numOfRejectedFiltersForBGPExport": len(config.BGPExportFilterForDisabledIPPools),
		"numOfAcceptedFiltersForBGPExport": len(config.BGPExportFilterForEnabledIPPools),
	}).Debug("Processed ippools")

	// Update cache with write lock
	configCacheMutex.Lock()
	configCache[ipVersion] = &bgpConfigCache{
		config:   config,
		revision: currentRevision,
	}
	configCacheMutex.Unlock()
	logc.Debug("Updated BGP config cache")

	return config, nil
}

// populateNodeConfig fills in basic node configuration
func (c *client) populateNodeConfig(config *types.BirdBGPConfig, ipVersion int) error {
	// Get node IPv4 address
	nodeIPv4Key := fmt.Sprintf("/calico/bgp/v1/host/%s/ip_addr_v4", NodeName)
	if nodeIP, err := c.GetValue(nodeIPv4Key); err == nil {
		config.NodeIP = nodeIP
	} else {
		return fmt.Errorf("failed to get node IPv4 address from %s: %w", nodeIPv4Key, err)
	}

	// Get node IPv6 address (optional - not all nodes have IPv6)
	nodeIPv6Key := fmt.Sprintf("/calico/bgp/v1/host/%s/ip_addr_v6", NodeName)
	if nodeIPv6, err := c.GetValue(nodeIPv6Key); err == nil {
		config.NodeIPv6 = nodeIPv6
	}

	// Get AS number (try node-specific first, then global). Return error if both fail.
	asNum, err := c.getNodeOrGlobalValue(NodeName, "as_num")
	if err != nil {
		return fmt.Errorf("failed to get AS number: %w", err)
	}
	config.ASNumber = asNum

	// Get logging configuration. If not found, logLevel will be empty string (uses default).
	logLevel, err := c.getNodeOrGlobalValue(NodeName, "loglevel")
	if err == nil {
		config.LogLevel = logLevel
	}

	// Compute debug mode based on log level.
	switch logLevel {
	case "none":
		// DebugMode stays empty (no debug output)
	case "debug":
		config.DebugMode = "all"
	default:
		// Default behavior for empty string or any other log level
		config.DebugMode = "{ states }"
	}

	// Handle router ID logic
	routerID := os.Getenv("CALICO_ROUTER_ID")
	if routerID == "hash" {
		// Use IP address generated by nodename's hash.
		hashedID, err := template.HashToIPv4(config.NodeName)
		if err != nil {
			return fmt.Errorf("failed to hash node name to IPv4: %w", err)
		}
		config.RouterID = hashedID
	} else if routerID != "" {
		config.RouterID = routerID
	} else {
		// Default router ID to node's IPv4 address.  We do this even in the BIRD config for
		// IPv6 because router ID has to be 4 octets (even in MP-BGP).
		config.RouterID = config.NodeIP
	}

	// Process bind mode and listen address
	bindMode, err := c.getNodeOrGlobalValue(NodeName, "bind_mode")
	// Set listen address if bind mode is NodeIP and we have a node IP
	if err == nil && bindMode == "NodeIP" {
		if ipVersion == 6 && config.NodeIPv6 != "" {
			config.ListenAddress = config.NodeIPv6
		} else if ipVersion == 4 && config.NodeIP != "" {
			config.ListenAddress = config.NodeIP
		}
	}

	// Process listen port (node-specific takes precedence over global)
	port, err := c.getNodeOrGlobalValue(NodeName, "listen_port")
	if err == nil {
		config.ListenPort = port
	}

	// Process ignored interfaces and build complete interface string
	ignoredInterfaces, err := c.getNodeOrGlobalValue(NodeName, "ignored_interfaces")

	// Build the complete interface pattern string
	if err == nil && ignoredInterfaces != "" {
		// Parse comma-separated list and build pattern
		ifaceList := strings.Split(ignoredInterfaces, ",")
		var patterns []string
		for _, iface := range ifaceList {
			patterns = append(patterns, fmt.Sprintf(`-"%s"`, iface))
		}
		// Add standard exclusions and wildcard
		patterns = append(patterns, `-"cali*"`, `-"kube-ipvs*"`, `"*"`)
		config.DirectInterfaces = strings.Join(patterns, ", ")
	} else {
		// Default pattern with explanatory comment
		config.DirectInterfaces = `-"cali*", -"kube-ipvs*", "*"`
	}

	return nil
}

// processPeers processes all BGP peers (mesh, global, and node-specific)
func (c *client) processPeers(config *types.BirdBGPConfig, ipVersion int) error {
	// Get node's route reflector cluster ID
	nodeClusterID, _ := c.GetValue(fmt.Sprintf("/calico/bgp/v1/host/%s/rr_cluster_id", NodeName))

	// Process node-to-node mesh peers
	if err := c.processMeshPeers(config, nodeClusterID, ipVersion); err != nil {
		return fmt.Errorf("failed to process mesh peers: %w", err)
	}

	// Process global peers (remote and local BGP peers)
	if err := c.processGlobalPeers(config, nodeClusterID, ipVersion); err != nil {
		return fmt.Errorf("failed to process global peers: %w", err)
	}

	// Process node-specific peers (remote and local BGP peers)
	if err := c.processNodePeers(config, nodeClusterID, ipVersion); err != nil {
		return fmt.Errorf("failed to process node-specific peers: %w", err)
	}

	return nil
}

// processMeshPeers processes node-to-node mesh BGP peers
func (c *client) processMeshPeers(config *types.BirdBGPConfig, nodeClusterID string, ipVersion int) error {
	logc := log.WithField("ipVersion", ipVersion)

	// If this node is a route reflector, skip mesh processing
	if nodeClusterID != "" {
		logc.Infof("Node %s is a route reflector with cluster ID %s, skipping mesh", NodeName, nodeClusterID)
		return nil
	}

	// Skip mesh processing if not enabled
	meshConfigValue, err := c.GetValue("/calico/bgp/v1/global/node_mesh")
	if err != nil {
		return nil // No mesh configuration
	}

	var meshConfig struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal([]byte(meshConfigValue), &meshConfig); err != nil {
		logc.WithError(err).Debug("Failed to unmarshal mesh config")
		return err
	}

	logc.Debugf("Parsed mesh config: %+v", meshConfig)

	if !meshConfig.Enabled {
		logc.Debug("Node-to-node mesh disabled")
		return nil
	}

	// Get global mesh settings
	meshPassword, _ := c.GetValue("/calico/bgp/v1/global/node_mesh_password")
	meshRestartTime, _ := c.GetValue("/calico/bgp/v1/global/node_mesh_restart_time")

	// Determine which IP address field to use
	ipAddrSuffix := "ip_addr_v4"
	if ipVersion == 6 {
		ipAddrSuffix = "ip_addr_v6"
	}

	// Get the current node's IP for this version
	currentNodeIP := config.NodeIP
	if ipVersion == 6 {
		currentNodeIP = config.NodeIPv6
	}

	// Get all host IP addresses
	hostIPsMap, err := c.GetValues([]string{"/calico/bgp/v1/host"})
	if err != nil {
		return err
	}

	// Extract unique hosts and their IPs from the keys
	hostsMap := make(map[string]string)
	for key, value := range hostIPsMap {
		// Keys are like /calico/bgp/v1/host/<hostname>/ip_addr_v4
		// Only process keys that match the current IP version suffix
		if strings.HasSuffix(key, ipAddrSuffix) {
			parts := strings.Split(key, "/")
			if len(parts) >= 6 {
				hostsMap[parts[5]] = value
			}
		}
	}

	for host, peerIP := range hostsMap {
		if peerIP == "" {
			continue
		}

		// Skip ourselves
		if peerIP == currentNodeIP {
			continue
		}

		// Check if peer is a route reflector
		peerClusterIDKey := fmt.Sprintf("/calico/bgp/v1/host/%s/rr_cluster_id", host)
		peerClusterID, _ := c.GetValue(peerClusterIDKey)
		if peerClusterID != "" {
			logc.Debugf("Skipping peer %s as it is a route reflector", peerIP)
			continue
		}

		// Get peer's AS number
		peerASKey := fmt.Sprintf("/calico/bgp/v1/host/%s/as_num", host)
		peerAS, err := c.GetValue(peerASKey)
		if err != nil {
			peerAS = config.ASNumber // Use global AS
		}

		// Get peer's listen port
		peerListenPortKey := fmt.Sprintf("/calico/bgp/v1/host/%s/listen_port", host)
		peerListenPort, err := c.GetValue(peerListenPortKey)
		if err != nil {
			peerListenPort, _ = c.GetValue("/calico/bgp/v1/global/listen_port")
		}

		// Create mesh peer name based on IP version
		var peerName string
		if ipVersion == 4 {
			peerName = fmt.Sprintf("Mesh_%s", strings.ReplaceAll(peerIP, ".", "_"))
		} else {
			peerName = fmt.Sprintf("Mesh_%s", strings.ReplaceAll(peerIP, ":", "_"))
		}

		// Mesh peers are iBGP (same AS), so pass true (peer has same AS) to calico_export_to_bgp_peers
		exportFilter := "calico_export_to_bgp_peers(true);\n    reject;"

		peer := types.BirdBGPPeer{
			Name:            peerName,
			IP:              peerIP,
			Port:            peerListenPort,
			ASNumber:        peerAS,
			Type:            "mesh",
			SourceAddr:      currentNodeIP,
			ImportFilter:    "", // Empty means "import all;" in template
			ExportFilter:    exportFilter,
			Password:        meshPassword,
			GracefulRestart: meshRestartTime,
		}

		// Make mesh unidirectional to avoid race conditions
		if peerIP > currentNodeIP {
			peer.Passive = true
		}

		config.Peers = append(config.Peers, peer)
	}

	return nil
}

// processGlobalPeers processes global BGP peers (remote and local)
func (c *client) processGlobalPeers(config *types.BirdBGPConfig, nodeClusterID string, ipVersion int) error {
	peerPath := "/calico/bgp/v1/global/peer_v4"
	if ipVersion == 6 {
		peerPath = "/calico/bgp/v1/global/peer_v6"
	}
	return c.processPeersFromPath(peerPath, "Global", config, nodeClusterID, ipVersion)
}

// processNodePeers processes node-specific BGP peers (both remote and local)
func (c *client) processNodePeers(config *types.BirdBGPConfig, nodeClusterID string, ipVersion int) error {
	peerPath := fmt.Sprintf("/calico/bgp/v1/host/%s/peer_v4", NodeName)
	if ipVersion == 6 {
		peerPath = fmt.Sprintf("/calico/bgp/v1/host/%s/peer_v6", NodeName)
	}
	return c.processPeersFromPath(peerPath, "Node", config, nodeClusterID, ipVersion)
}

// processPeersFromPath is a helper that processes both remote and local BGP peers from a given datastore path
func (c *client) processPeersFromPath(peerPath, peerType string, config *types.BirdBGPConfig, nodeClusterID string, ipVersion int) error {
	logc := log.WithFields(map[string]any{
		"ipVersion": ipVersion,
		"peerType":  peerType,
		"path":      peerPath,
	})

	kvPairs, err := c.GetValues([]string{peerPath})
	if err != nil {
		logc.WithError(err).Debug("No peers found or error retrieving them")
		return nil
	}

	logc.Debugf("Found %d peer entries", len(kvPairs))

	// Unmarshal all peers once and separate into remote and local
	var remotePeers, localPeers []bgpPeer
	for key, value := range kvPairs {
		var peerData bgpPeer
		if err := json.Unmarshal([]byte(value), &peerData); err != nil {
			logc.WithError(err).Warnf("Failed to unmarshal peer data for key %s", key)
			continue
		}

		if peerData.LocalBGPPeer {
			localPeers = append(localPeers, peerData)
		} else {
			remotePeers = append(remotePeers, peerData)
		}
	}

	// Process remote peers first
	for _, peerData := range remotePeers {
		peer := c.buildPeerFromData(&peerData, peerType, config, nodeClusterID, ipVersion)
		if peer != nil {
			config.Peers = append(config.Peers, *peer)
			logc.Debugf("Added %s peer: %s", peerType, peer.Name)
		}
	}

	// Then process local BGP peers
	for _, peerData := range localPeers {
		peer := c.buildPeerFromData(&peerData, "Local_Workload", config, nodeClusterID, ipVersion)
		if peer != nil {
			config.Peers = append(config.Peers, *peer)
			logc.Debugf("Added Local_Workload peer: %s", peer.Name)
		}
	}

	return nil
}

// buildPeerFromData constructs a BirdBGPPeer from bgpPeer data
func (c *client) buildPeerFromData(peer *bgpPeer, prefix string, config *types.BirdBGPConfig, nodeClusterID string, ipVersion int) *types.BirdBGPPeer {
	logc := log.WithField("ipVersion", ipVersion)

	peerIP := peer.PeerIP.String()
	if peerIP == "<nil>" || peerIP == "" {
		logc.Debugf("buildPeerFromData: no IP found in peer data, peerIP=%s", peerIP)
		return nil
	}

	// Skip ourselves - check appropriate IP based on version
	currentNodeIP := config.NodeIP
	if ipVersion == 6 {
		currentNodeIP = config.NodeIPv6
	}
	if peerIP == currentNodeIP {
		logc.Debugf("buildPeerFromData: skipping ourselves (peerIP=%s, currentNodeIP=%s)", peerIP, currentNodeIP)
		return nil
	}

	logc.Debugf("buildPeerFromData: building peer for IP=%s, prefix=%s", peerIP, prefix)

	// Generate peer name based on IP version
	var peerName string
	if ipVersion == 4 {
		peerName = fmt.Sprintf("%s_%s", prefix, strings.ReplaceAll(peerIP, ".", "_"))
	} else {
		peerName = fmt.Sprintf("%s_%s", prefix, strings.ReplaceAll(peerIP, ":", "_"))
	}
	if peer.Port > 0 {
		peerName = fmt.Sprintf("%s_port_%d", peerName, peer.Port)
	}

	result := &types.BirdBGPPeer{
		Name: peerName,
		IP:   peerIP,
		Type: strings.ToLower(prefix),
	}

	// Basic fields
	if peer.Port > 0 {
		result.Port = fmt.Sprintf("%d", peer.Port)
	}
	result.ASNumber = peer.ASNum.String()
	if peer.LocalASNum != 0 {
		result.LocalASNumber = peer.LocalASNum.String()
	}

	// TTL security
	if peer.TTLSecurity > 0 {
		result.TTLSecurity = fmt.Sprintf("on;\n  multihop %d", peer.TTLSecurity)
	} else {
		result.TTLSecurity = "off"
	}

	// Source address - use appropriate node IP based on version
	if peer.SourceAddr == "UseNodeIP" {
		result.SourceAddr = currentNodeIP
	}

	// Filters - build inline filter blocks
	result.ImportFilter = c.buildImportFilter(peer.Filters, ipVersion)
	// Use effective node AS number (local_as_num if set, otherwise node AS)
	effectiveNodeAS := config.ASNumber
	if result.LocalASNumber != "" {
		effectiveNodeAS = result.LocalASNumber
	}
	result.ExportFilter = c.buildExportFilter(peer.Filters, result.ASNumber, effectiveNodeAS, ipVersion)

	// Optional fields
	if peer.Password != nil {
		result.Password = *peer.Password
	}
	if peer.RestartTime != "" {
		result.GracefulRestart = peer.RestartTime
	}
	if peer.KeepaliveTime != "" {
		result.KeepaliveTime = peer.KeepaliveTime
	}
	result.Passive = peer.PassiveMode
	if peer.NumAllowLocalAS > 0 {
		result.NumAllowLocalAs = fmt.Sprintf("%d", peer.NumAllowLocalAS)
	}

	// Next hop mode
	switch peer.NextHopMode {
	case "Self":
		result.NextHopSelf = true
	case "Keep":
		result.NextHopKeep = true
	}
	// Legacy keep_next_hop field - only apply for eBGP peers
	if peer.KeepNextHop && result.ASNumber != effectiveNodeAS {
		result.NextHopKeep = true
	}

	// Route reflector handling
	// If this node is a route reflector (has a cluster ID) and the peer is iBGP
	// and the peer does not have a cluster ID (or has a different one),
	// then the peer is a route reflector client.
	if result.ASNumber == effectiveNodeAS && nodeClusterID != "" {
		if peer.RRClusterID == "" || peer.RRClusterID != nodeClusterID {
			result.RouteReflector = true
			result.RRClusterID = nodeClusterID
		}
	}

	// Passive mode handling
	// If the peer is a mesh, global, or local workload peer and passive is not set explicitly,
	// set passive to true if the peer IP is lexically greater than the current node IP.
	if (result.Type == "mesh" || result.Type == "global" || result.Type == "local_workload") && !result.Passive {
		if peer.CalicoNode && peerIP > currentNodeIP {
			result.Passive = true
		}
	}

	return result
}

// truncateBGPFilterName truncates a BGP filter name to fit BIRD's symbol length limit
// Uses the same truncation logic as template_funcs.go to ensure filter function
// definitions and calls use identical names.
// BIRD has a 64 character limit for symbols. The format is 'bgp_<name>_importFilterV4'
// Prefix 'bgp_' = 4 chars, Suffix '_importFilterV4' or '_exportFilterV4' = 15 chars
// Total overhead = 4 + 15 = 19 chars, Available for name = 64 - 19 = 45 chars
func truncateBGPFilterName(name string) string {
	const maxBIRDSymLen = 64
	// Calculate max length for the filter name part
	// Format: 'bgp_<name>_importFilterV4' or 'bgp_<name>_exportFilterV4'
	prefixAndSuffix := "bgp__importFilterV4" // 19 chars (same for export)
	maxNameLength := maxBIRDSymLen - len(prefixAndSuffix)

	// Use the shared truncation function from template package
	truncated, err := template.TruncateAndHashName(name, maxNameLength)
	if err != nil {
		// If truncation fails, return original name (shouldn't happen in practice)
		log.WithError(err).Warnf("Failed to truncate filter name %s, using original", name)
		return name
	}
	return truncated
}

// buildImportFilter builds the import filter block
func (c *client) buildImportFilter(filters []string, ipVersion int) string {
	var filterLines []string

	// Determine filter suffix based on IP version
	filterSuffix := "V4"
	if ipVersion == 6 {
		filterSuffix = "V6"
	}

	// Process BGP filters
	for _, filterName := range filters {
		filterKey := fmt.Sprintf("/calico/resources/v3/projectcalico.org/bgpfilters/%s", filterName)
		if filterValue, err := c.GetValue(filterKey); err == nil {
			var filter v3.BGPFilter
			if json.Unmarshal([]byte(filterValue), &filter) == nil {
				// Check if import rules exist based on IP version
				if (ipVersion == 4 && len(filter.Spec.ImportV4) > 0) || (ipVersion == 6 && len(filter.Spec.ImportV6) > 0) {
					truncatedName := truncateBGPFilterName(filterName)
					filterLines = append(filterLines, fmt.Sprintf("'bgp_%s_importFilter%s'();", truncatedName, filterSuffix))
				}
			}
		}
	}

	filterLines = append(filterLines, "accept; # Prior to introduction of BGP Filters we used \"import all\" so use default accept behaviour on import")
	return strings.Join(filterLines, "\n    ")
}

// buildExportFilter builds the export filter block
func (c *client) buildExportFilter(filters []string, peerAS, nodeAS string, ipVersion int) string {
	var filterLines []string

	// Determine filter suffix based on IP version
	filterSuffix := "V4"
	if ipVersion == 6 {
		filterSuffix = "V6"
	}

	// Process BGP filters
	for _, filterName := range filters {
		filterKey := fmt.Sprintf("/calico/resources/v3/projectcalico.org/bgpfilters/%s", filterName)
		if filterValue, err := c.GetValue(filterKey); err == nil {
			var filter v3.BGPFilter
			if json.Unmarshal([]byte(filterValue), &filter) == nil {
				// Check if export rules exist based on IP version
				if (ipVersion == 4 && len(filter.Spec.ExportV4) > 0) || (ipVersion == 6 && len(filter.Spec.ExportV6) > 0) {
					truncatedName := truncateBGPFilterName(filterName)
					filterLines = append(filterLines, fmt.Sprintf("'bgp_%s_exportFilter%s'();", truncatedName, filterSuffix))
				}
			}
		}
	}

	// Call calico_export_to_bgp_peers
	sameAS := peerAS == nodeAS
	filterLines = append(filterLines, fmt.Sprintf("calico_export_to_bgp_peers(%v);", sameAS))
	filterLines = append(filterLines, "reject;")

	return strings.Join(filterLines, "\n    ")
}

// getNodeOrGlobalValue attempts to get a value from a node-specific key first,
// then falls back to the global key. Returns the value and any error.
func (c *client) getNodeOrGlobalValue(nodeName, keySuffix string) (string, error) {
	nodeKey := fmt.Sprintf("/calico/bgp/v1/host/%s/%s", nodeName, keySuffix)
	if val, err := c.GetValue(nodeKey); err == nil {
		return val, nil
	}
	globalKey := fmt.Sprintf("/calico/bgp/v1/global/%s", keySuffix)
	return c.GetValue(globalKey)
}

// processCommunityRules processes BGP community advertisements
func (c *client) processCommunityRules(config *types.BirdBGPConfig, ipVersion int) error {
	logc := log.WithField("ipVersion", ipVersion)

	// Determine path suffix based on IP version
	ipSuffix := "ip_v4"
	if ipVersion == 6 {
		ipSuffix = "ip_v6"
	}

	// Try node-specific first, then fall back to global
	nodeKey := fmt.Sprintf("/calico/bgp/v1/host/%s/prefix_advertisements/%s", NodeName, ipSuffix)
	globalKey := fmt.Sprintf("/calico/bgp/v1/global/prefix_advertisements/%s", ipSuffix)

	var communitiesKey string
	if _, err := c.GetValue(nodeKey); err == nil {
		communitiesKey = nodeKey
	} else if _, err := c.GetValue(globalKey); err == nil {
		communitiesKey = globalKey
	}

	if communitiesKey == "" {
		return nil
	}

	kvPairs, err := c.GetValues([]string{communitiesKey})
	if err != nil {
		return err
	}

	for _, value := range kvPairs {
		var advertisements []v3.PrefixAdvertisement
		if err := json.Unmarshal([]byte(value), &advertisements); err != nil {
			logc.WithError(err).Warn("Failed to parse community advertisements")
			continue
		}

		for _, adv := range advertisements {
			// Skip advertisements without a CIDR
			if adv.CIDR == "" {
				continue
			}

			rule := types.CommunityRule{
				CIDR:          adv.CIDR,
				AddStatements: make([]string, 0, len(adv.Communities)),
			}

			// Pre-format BIRD community add statements
			for _, commStr := range adv.Communities {
				parts := strings.Split(commStr, ":")
				if len(parts) == 2 {
					// Standard community
					rule.AddStatements = append(rule.AddStatements,
						fmt.Sprintf("bgp_community.add((%s, %s));", parts[0], parts[1]))
				} else if len(parts) == 3 {
					// Large community
					rule.AddStatements = append(rule.AddStatements,
						fmt.Sprintf("bgp_large_community.add((%s, %s, %s));", parts[0], parts[1], parts[2]))
				}
			}

			if len(rule.AddStatements) > 0 {
				config.Communities = append(config.Communities, rule)
			}
		}
	}

	return nil
}

func (c *client) processIPPools(config *types.BirdBGPConfig, ipVersion int) error {
	poolKey := fmt.Sprintf("/calico/v1/ipam/v%d/pool", ipVersion)
	logCtx := log.WithFields(map[string]any{
		"ipVersion": ipVersion,
		"path":      poolKey,
	})

	kvPairs, err := c.GetValues([]string{poolKey})
	if err != nil {
		logCtx.WithError(err).Debug("No ippool found or error retrieving them")
		return nil
	}

	// In IPv6, we only need to include statements with "reject" action, since we include a default "accept" at the end.
	var filterActionForKernel string
	if ipVersion == 6 {
		filterActionForKernel = "reject"
	}

	localSubnet, localSubnetErr := c.localSubnet(ipVersion)
	if localSubnetErr != nil {
		logCtx.WithError(localSubnetErr).Debug("Failed to get local host subnet")
	}

	for key, value := range kvPairs {
		var ippool model.IPPool
		if err := json.Unmarshal([]byte(value), &ippool); err != nil {
			logCtx.WithError(err).Warnf("Failed to unmarshal ippool data for key %s", key)
			continue
		}

		// Generate statements for rejecting disabled ippools in the filter for exporting routes to other peers.
		statement := c.processIPPool(&ippool, false, "reject", "", ipVersion)
		if len(statement) != 0 {
			config.BGPExportFilterForDisabledIPPools = append(config.BGPExportFilterForDisabledIPPools, statement)
		}

		// Generate statements for accepting enabled ippools in the filter for exporting routes to other peers.
		statement = c.processIPPool(&ippool, false, "accept", "", ipVersion)
		if len(statement) != 0 {
			config.BGPExportFilterForEnabledIPPools = append(config.BGPExportFilterForEnabledIPPools, statement)
		}

		if ipVersion == 6 || ipVersion == 4 && localSubnetErr == nil {
			// Generate statements for kernel programming filter.
			statement = c.processIPPool(&ippool, true, filterActionForKernel, localSubnet, ipVersion)
			if len(statement) != 0 {
				config.KernelFilterForIPPools = append(config.KernelFilterForIPPools, statement)
			}
		}
	}

	// Sort statements.
	slices.Sort(config.KernelFilterForIPPools)
	slices.Sort(config.BGPExportFilterForDisabledIPPools)
	slices.Sort(config.BGPExportFilterForEnabledIPPools)

	return nil
}

// This function generates BIRD statements for an IPPool to be used as BIRD filters based on the following input:
//   - ippool: IPPool resource.
//   - forProgrammingKernel: Whether the generated statements are intended for programming routes to kernel or exporting to
//     other BGP Peers. As an example, we need to set "krt_tunnel" for programming IPIP and no-encap IPv4 routes.
//   - filterAction: specified action to filter generated statements. For exporting pools to BGP peers, we need to
//     first reject disabled ippools, and then accept the rest at the end after all other filters. Allowed values are
//     "accept", "reject", and "" (no filtering).
//   - localSubnet: the subnet of local node, which is needed by IPv4 IPIP pool in cross subnet mode.
//   - version: the statement ip family.
//
// As an example, For the following sample IPPool resource:
//
// apiVersion: projectcalico.org/v3
// kind: IPPool
// metadata:
//
//	name: my.ippool-1
//
// spec:
//
//	cidr: 10.1.0.0/16
//	ipipMode: Always
//
// this function generates the following statement for programming routes to kernel:
//
//	if (net ~ 10.10.0.0/16) then { krt_tunnel="tunl0"; accept; }
//
// and the following statement for exporting to BGP peers:
//
//	if (net ~ 10.10.0.0/16) then { accept; }
func (c *client) processIPPool(
	ippool *model.IPPool,
	forProgrammingKernel bool,
	filterAction string,
	localSubnet string,
	ipVersion int,
) string {
	cidr := ippool.CIDR.String()
	var action, comment, extraStatement string
	switch {
	case ippool.DisableBGPExport && !forProgrammingKernel:
		// IPPool's BGP export is disabled, and filter is for exporting to other peers.
		action = "reject"
		comment = "BGP export is disabled."
	case ippool.VXLANMode == encap.Always || ippool.VXLANMode == encap.CrossSubnet:
		// VXLAN encapsulation is always handled by Felix.
		if forProgrammingKernel {
			// Felix always handles programming VXLAN IPPools.
			action = "reject"
			comment = "VXLAN routes are handled by Felix."
		} else {
			action = "accept"
		}
	case ippool.IPIPMode == encap.Always || ippool.IPIPMode == encap.CrossSubnet, // IPIP Encapsulation.
		ippool.IPIPMode == encap.Never || ippool.VXLANMode == encap.Never: // No-encapsulation.
		// IPIP encapsulation or No-Encap.
		if forProgrammingKernel && ipVersion == 4 {
			// For IPv4 IPIP and no-encap routes, we need to set `krt_tunnel` variable which is needed by
			// our fork of BIRD.
			extraStatement = extraStatementForKernelProgrammingIPIPNoEncap(ippool.IPIPMode, localSubnet)
		}
		action = "accept"
	default:
		log.WithFields(log.Fields{
			"ippool":    ippool.CIDR,
			"ipVersion": ipVersion,
		}).Error("Invalid ippool")
		return ""
	}

	// Filter statements based on provided filterAction.
	if len(filterAction) != 0 && filterAction != action {
		return ""
	}
	return emitFilterStatementForIPPools(cidr, extraStatement, action, comment)
}

func (c *client) localSubnet(ipVersion int) (string, error) {
	key := fmt.Sprintf("/calico/bgp/v1/host/%s/network_v%d", NodeName, ipVersion)
	subnet, err := c.GetValue(key)
	if err != nil {
		return "", fmt.Errorf("failed to get local host subnet: %w", err)
	}
	return subnet, nil
}

func extraStatementForKernelProgrammingIPIPNoEncap(ipipMode encap.Mode, localSubnet string) string {
	switch v3.EncapMode(ipipMode) {
	case v3.Always:
		return `krt_tunnel="tunl0";`
	case v3.CrossSubnet:
		format := `if (defined(bgp_next_hop)&&(bgp_next_hop ~ %s)) then krt_tunnel=""; else krt_tunnel="tunl0";`
		return fmt.Sprintf(format, localSubnet)
	case v3.Never:
		// No-encap case.
		return `krt_tunnel="";`
	default:
		return ``
	}
}

func emitFilterStatementForIPPools(cidr, extraStatement, action, comment string) (statement string) {
	// Check mandatory inputs.
	if len(cidr) == 0 || len(action) == 0 {
		return
	}
	if len(extraStatement) != 0 {
		statement = fmt.Sprintf("  if (net ~ %s) then { %s %s; }", cidr, extraStatement, action)
	} else {
		statement = fmt.Sprintf("  if (net ~ %s) then { %s; }", cidr, action)
	}
	if len(comment) != 0 {
		statement = fmt.Sprintf("%s %s", statement, formatComment(comment))
	}
	return
}

func formatComment(comment string) string {
	return fmt.Sprintf("# %s", comment)
}
