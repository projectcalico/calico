package calico

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/confd/pkg/backends/types"
	"github.com/projectcalico/calico/confd/pkg/resource/template"
)

// NodeName gets the node name from environment
var NodeName = os.Getenv("NODENAME")

// BGP configuration cache
type bgpConfigCache struct {
	config   *types.BirdBGPConfig
	revision uint64
}

var (
	configCache   *bgpConfigCache
	configCacheV6 *bgpConfigCache
)

// GetBirdBGPConfig processes raw datastore data into a clean BGP configuration structure
// ipVersion should be 4 for IPv4 or 6 for IPv6
func (c *client) GetBirdBGPConfig(ipVersion int) (*types.BirdBGPConfig, error) {
	// Use separate caches for IPv4 and IPv6
	currentRevision := c.GetCurrentRevision()

	if ipVersion == 4 && configCache != nil &&
		configCache.revision == currentRevision {
		log.Debug("BGP config cache hit (IPv4), returning cached configuration")
		return configCache.config, nil
	}

	if ipVersion == 6 && configCacheV6 != nil &&
		configCacheV6.revision == currentRevision {
		log.Debug("BGP config cache hit (IPv6), returning cached configuration")
		return configCacheV6.config, nil
	}

	log.Debugf("BGP config cache miss or expired, processing new configuration for IPv%d", ipVersion)

	config := &types.BirdBGPConfig{
		NodeName:    NodeName,
		Peers:       make([]types.BirdBGPPeer, 0),
		Filters:     make(map[string]string),
		Communities: make([]types.CommunityRule, 0),
	}

	log.Debugf("Initialized BGP config structure for IPv%d", ipVersion)

	// Get basic node configuration
	if err := c.populateNodeConfig(config, ipVersion); err != nil {
		log.WithError(err).Warn("Failed to populate node configuration")
	}
	log.Debugf("Populated node configuration (IPv%d): node=%s, ip=%s, ipv6=%s, as=%s", ipVersion, config.NodeName, config.NodeIP, config.NodeIPv6, config.AsNumber)

	// Process all peer types
	if err := c.processPeers(config, ipVersion); err != nil {
		log.WithError(err).Warnf("Failed to process BGP peers for IPv%d", ipVersion)
	}
	log.Debugf("Processed BGP peers (IPv%d): found %d peers", ipVersion, len(config.Peers))

	// Sort peers by name for consistent output ordering
	sort.Slice(config.Peers, func(i, j int) bool {
		return config.Peers[i].Name < config.Peers[j].Name
	})

	// Process community rules
	if err := c.processCommunityRules(config, ipVersion); err != nil {
		log.WithError(err).Warnf("Failed to process community rules for IPv%d", ipVersion)
	}
	log.Debugf("Processed community rules (IPv%d): found %d rules", ipVersion, len(config.Communities))

	// Process BGP filters
	if err := c.processBGPFilters(config, ipVersion); err != nil {
		log.WithError(err).Warnf("Failed to process BGP filters for IPv%d", ipVersion)
	}
	log.Debugf("Processed BGP filters (IPv%d): found %d filters", ipVersion, len(config.Filters))

	// Update appropriate cache
	if ipVersion == 4 {
		configCache = &bgpConfigCache{
			config:   config,
			revision: currentRevision,
		}
		log.Debug("Updated BGP config cache for IPv4")
	} else {
		configCacheV6 = &bgpConfigCache{
			config:   config,
			revision: currentRevision,
		}
		log.Debug("Updated BGP config cache for IPv6")
	}

	return config, nil
}

// populateNodeConfig fills in basic node configuration
func (c *client) populateNodeConfig(config *types.BirdBGPConfig, ipVersion int) error {
	// Get node IPv4 address
	nodeIPv4Key := fmt.Sprintf("/calico/bgp/v1/host/%s/ip_addr_v4", NodeName)
	if nodeIP, err := c.GetValue(nodeIPv4Key); err == nil {
		config.NodeIP = nodeIP
		config.RouterID = nodeIP // Default router ID to IPv4 address
	} else {
		log.WithError(err).Warnf("Failed to get node IPv4 address from %s", nodeIPv4Key)
	}

	// Get node IPv6 address
	nodeIPv6Key := fmt.Sprintf("/calico/bgp/v1/host/%s/ip_addr_v6", NodeName)
	if nodeIPv6, err := c.GetValue(nodeIPv6Key); err == nil {
		config.NodeIPv6 = nodeIPv6
	} else {
		log.WithError(err).Debugf("Failed to get node IPv6 address from %s", nodeIPv6Key)
	}

	// Get AS number (try node-specific first, then global)
	nodeASKey := fmt.Sprintf("/calico/bgp/v1/host/%s/as_num", NodeName)
	if asNum, err := c.GetValue(nodeASKey); err == nil {
		config.AsNumber = asNum
	} else if globalAS, err := c.GetValue("/calico/bgp/v1/global/as_num"); err == nil {
		config.AsNumber = globalAS
	} else {
		log.Warnf("Failed to get AS number from node-specific (%s) or global key", nodeASKey)
	}

	// Get logging configuration (matching song-original.cfg.template LOGGING section)
	var logLevel string
	nodeLogKey := fmt.Sprintf("/calico/bgp/v1/host/%s/loglevel", NodeName)
	if level, err := c.GetValue(nodeLogKey); err == nil {
		logLevel = level
	} else if globalLog, err := c.GetValue("/calico/bgp/v1/global/loglevel"); err == nil {
		logLevel = globalLog
	}

	config.LogLevel = logLevel

	// Compute debug mode based on log level (matching song-original.cfg.template LOGGING section)
	if logLevel == "debug" {
		config.DebugMode = "all"
	} else if logLevel != "none" && logLevel != "" {
		config.DebugMode = "{ states }"
	} else if logLevel == "" {
		// Default behavior when no log level is set
		config.DebugMode = "{ states }"
	}
	// If logLevel == "none", DebugMode stays empty (no debug output)

	// Handle router ID logic (matching song-original.cfg.template)
	routerID := os.Getenv("CALICO_ROUTER_ID")
	if routerID == "hash" {
		config.RouterID = hashToIPv4(config.NodeName)
		if ipVersion == 6 {
			config.RouterIDComment = "# Use IP address generated by nodename's hash"
		}
	} else {
		if routerID != "" {
			config.RouterID = routerID
		} else if config.NodeIP != "" {
			config.RouterID = config.NodeIP
		}
		if ipVersion == 6 {
			config.RouterIDComment = "# Use IPv4 address since router id is 4 octets, even in MP-BGP"
		}
	}

	// Process bind mode and listen address (matching song-original.cfg.template)
	var bindMode string
	bindModeKey := fmt.Sprintf("/calico/bgp/v1/host/%s/bind_mode", NodeName)
	if mode, err := c.GetValue(bindModeKey); err == nil {
		bindMode = mode
	} else if globalMode, err := c.GetValue("/calico/bgp/v1/global/bind_mode"); err == nil {
		bindMode = globalMode
	}

	// Set listen address if bind mode is NodeIP and we have a node IP
	if bindMode == "NodeIP" {
		if ipVersion == 6 && config.NodeIPv6 != "" {
			config.ListenAddress = config.NodeIPv6
		} else if ipVersion == 4 && config.NodeIP != "" {
			config.ListenAddress = config.NodeIP
		}
	}

	// Process listen port (node-specific takes precedence over global)
	listenPortKey := fmt.Sprintf("/calico/bgp/v1/host/%s/listen_port", NodeName)
	if port, err := c.GetValue(listenPortKey); err == nil {
		config.ListenPort = port
	} else if globalPort, err := c.GetValue("/calico/bgp/v1/global/listen_port"); err == nil {
		config.ListenPort = globalPort
	}

	// Process ignored interfaces and build complete interface string (matching song-original.cfg.template)
	var ignoredInterfaces string
	nodeIgnoredKey := fmt.Sprintf("/calico/bgp/v1/host/%s/ignored_interfaces", NodeName)
	if ifaces, err := c.GetValue(nodeIgnoredKey); err == nil {
		ignoredInterfaces = ifaces
	} else if globalIfaces, err := c.GetValue("/calico/bgp/v1/global/ignored_interfaces"); err == nil {
		ignoredInterfaces = globalIfaces
	}

	// Build the complete interface pattern string
	if ignoredInterfaces != "" {
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

// hashToIPv4 hashes the given string and formats the resulting 4 bytes as an IPv4 address.
func hashToIPv4(nodeName string) string {
	hash := sha256.New()
	_, err := hash.Write([]byte(nodeName))
	if err != nil {
		return ""
	}
	hashBytes := hash.Sum(nil)
	ip := hashBytes[:4]
	// BGP doesn't allow router IDs in special IP ranges (e.g., 224.x.x.x)
	ip0Value := int(ip[0])
	if ip0Value > 223 {
		ip0Value = ip0Value - 32
	}
	routerId := strconv.Itoa(ip0Value) + "." +
		strconv.Itoa(int(ip[1])) + "." +
		strconv.Itoa(int(ip[2])) + "." +
		strconv.Itoa(int(ip[3]))
	return routerId
}

// processPeers processes all BGP peers (mesh, global, and node-specific)
func (c *client) processPeers(config *types.BirdBGPConfig, ipVersion int) error {
	// Get node's route reflector cluster ID
	nodeClusterID, _ := c.GetValue(fmt.Sprintf("/calico/bgp/v1/host/%s/rr_cluster_id", NodeName))

	// Process node-to-node mesh peers
	if err := c.processMeshPeers(config, nodeClusterID, ipVersion); err != nil {
		log.WithError(err).Warnf("Failed to process mesh peers for IPv%d", ipVersion)
	}

	// Process global peers (both regular and local BGP peers)
	if err := c.processGlobalPeers(config, nodeClusterID, ipVersion); err != nil {
		log.WithError(err).Warnf("Failed to process global peers for IPv%d", ipVersion)
	}

	// Process node-specific peers (both regular and local BGP peers)
	if err := c.processNodePeers(config, nodeClusterID, ipVersion); err != nil {
		log.WithError(err).Warnf("Failed to process node-specific peers for IPv%d", ipVersion)
	}

	return nil
}

// processMeshPeers processes node-to-node mesh BGP peers
func (c *client) processMeshPeers(config *types.BirdBGPConfig, nodeClusterID string, ipVersion int) error {
	// If this node is a route reflector, skip mesh processing
	if nodeClusterID != "" {
		log.Infof("Node %s is a route reflector with cluster ID %s, skipping mesh", NodeName, nodeClusterID)
		return nil
	}

	// Check if mesh is enabled
	meshConfigValue, err := c.GetValue("/calico/bgp/v1/global/node_mesh")
	if err != nil {
		return nil // No mesh configuration
	}

	log.Debugf("Mesh config value: %s", meshConfigValue)

	var meshConfig map[string]interface{}
	if err := json.Unmarshal([]byte(meshConfigValue), &meshConfig); err != nil {
		log.Debugf("Failed to unmarshal mesh config: %v", err)
		return err
	}

	log.Debugf("Parsed mesh config: %+v", meshConfig)

	enabled, _ := meshConfig["enabled"].(bool)
	log.Debugf("Mesh enabled value: %v", enabled)
	if !enabled {
		log.Debug("Node-to-node mesh disabled")
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

	// Extract unique hosts from the keys
	hostsMap := make(map[string]bool)
	for key := range hostIPsMap {
		// Keys are like /calico/bgp/v1/host/<hostname>/ip_addr_v4
		parts := strings.Split(key, "/")
		if len(parts) >= 6 {
			hostsMap[parts[5]] = true
		}
	}

	for host := range hostsMap {
		peerIPKey := fmt.Sprintf("/calico/bgp/v1/host/%s/%s", host, ipAddrSuffix)
		peerIP, err := c.GetValue(peerIPKey)
		if err != nil || peerIP == "" {
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
			log.Debugf("Skipping %s as it is a route reflector", peerIP)
			continue
		}

		// Get peer's AS number
		peerASKey := fmt.Sprintf("/calico/bgp/v1/host/%s/as_num", host)
		peerAS, err := c.GetValue(peerASKey)
		if err != nil {
			peerAS = config.AsNumber // Use global AS
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

		// Mesh peers have same AS, so use true for calico_export_to_bgp_peers
		exportFilter := "calico_export_to_bgp_peers(true);\n    reject;"

		peer := types.BirdBGPPeer{
			Name:            peerName,
			IP:              peerIP,
			Port:            peerListenPort,
			AsNumber:        peerAS,
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
			peer.PassiveComment = " # Mesh is unidirectional, peer will connect to us."
		}

		config.Peers = append(config.Peers, peer)
	}

	return nil
}

// processGlobalPeers processes global BGP peers (both regular and local)
func (c *client) processGlobalPeers(config *types.BirdBGPConfig, nodeClusterID string, ipVersion int) error {
	// Determine peer path based on IP version
	peerPath := "/calico/bgp/v1/global/peer_v4"
	if ipVersion == 6 {
		peerPath = "/calico/bgp/v1/global/peer_v6"
	}

	// Process regular global peers
	kvPairs, err := c.GetValues([]string{peerPath})
	if err != nil {
		log.WithError(err).Debugf("No global IPv%d peers found or error retrieving them", ipVersion)
		return nil
	}

	log.Debugf("Found %d global IPv%d peer entries", len(kvPairs), ipVersion)

	for key, value := range kvPairs {
		log.Debugf("Processing global peer key: %s", key)
		var peerData map[string]interface{}
		if err := json.Unmarshal([]byte(value), &peerData); err != nil {
			log.WithError(err).Warnf("Failed to unmarshal peer data for key %s", key)
			continue
		}

		// Skip local BGP peers in this pass
		if isLocal, _ := peerData["local_bgp_peer"].(bool); isLocal {
			log.Debugf("Skipping local BGP peer at %s", key)
			continue
		}

		peer := c.buildPeerFromData(peerData, "Global", config, nodeClusterID, ipVersion)
		if peer != nil {
			config.Peers = append(config.Peers, *peer)
			log.Debugf("Added global peer: %s", peer.Name)
		} else {
			log.Debugf("buildPeerFromData returned nil for key %s", key)
		}
	}

	// Process global local BGP peers
	for _, value := range kvPairs {
		var peerData map[string]interface{}
		if err := json.Unmarshal([]byte(value), &peerData); err != nil {
			continue
		}

		// Only process local BGP peers in this pass
		if isLocal, _ := peerData["local_bgp_peer"].(bool); !isLocal {
			continue
		}

		peer := c.buildPeerFromData(peerData, "Local_Workload", config, nodeClusterID, ipVersion)
		if peer != nil {
			config.Peers = append(config.Peers, *peer)
			log.Debugf("Added local workload peer: %s", peer.Name)
		}
	}

	return nil
}

// processNodePeers processes node-specific BGP peers (both regular and local)
func (c *client) processNodePeers(config *types.BirdBGPConfig, nodeClusterID string, ipVersion int) error {
	// Determine peer path based on IP version
	peerSuffix := "peer_v4"
	if ipVersion == 6 {
		peerSuffix = "peer_v6"
	}
	peerKey := fmt.Sprintf("/calico/bgp/v1/host/%s/%s", NodeName, peerSuffix)

	// Process regular node-specific peers
	kvPairs, err := c.GetValues([]string{peerKey})
	if err == nil {
		for _, value := range kvPairs {
			var peerData map[string]interface{}
			if err := json.Unmarshal([]byte(value), &peerData); err != nil {
				continue
			}

			// Skip local BGP peers in this pass
			if isLocal, _ := peerData["local_bgp_peer"].(bool); isLocal {
				continue
			}

			peer := c.buildPeerFromData(peerData, "Node", config, nodeClusterID, ipVersion)
			if peer != nil {
				config.Peers = append(config.Peers, *peer)
			}
		}
	}

	// Process node-specific local BGP peers
	if err == nil {
		for _, value := range kvPairs {
			var peerData map[string]interface{}
			if err := json.Unmarshal([]byte(value), &peerData); err != nil {
				continue
			}

			// Only process local BGP peers in this pass
			if isLocal, _ := peerData["local_bgp_peer"].(bool); !isLocal {
				continue
			}

			peer := c.buildPeerFromData(peerData, "Local_Workload", config, nodeClusterID, ipVersion)
			if peer != nil {
				config.Peers = append(config.Peers, *peer)
			}
		}
	}

	return nil
}

// buildPeerFromData constructs a BirdBGPPeer from raw peer data
func (c *client) buildPeerFromData(raw map[string]interface{}, prefix string, config *types.BirdBGPConfig, nodeClusterID string, ipVersion int) *types.BirdBGPPeer {
	peerIP, ok := raw["ip"].(string)
	if !ok || peerIP == "" {
		log.Debugf("buildPeerFromData: no IP found in peer data, ok=%v, peerIP=%s", ok, peerIP)
		return nil
	}

	// Skip ourselves - check appropriate IP based on version
	currentNodeIP := config.NodeIP
	if ipVersion == 6 {
		currentNodeIP = config.NodeIPv6
	}
	if peerIP == currentNodeIP {
		log.Debugf("buildPeerFromData: skipping ourselves (peerIP=%s, currentNodeIP=%s)", peerIP, currentNodeIP)
		return nil
	}

	log.Debugf("buildPeerFromData: building peer for IP=%s, prefix=%s", peerIP, prefix)

	// Generate peer name based on IP version
	var peerName string
	if ipVersion == 4 {
		peerName = fmt.Sprintf("%s_%s", prefix, strings.ReplaceAll(peerIP, ".", "_"))
	} else {
		peerName = fmt.Sprintf("%s_%s", prefix, strings.ReplaceAll(peerIP, ":", "_"))
	}
	if port, ok := raw["port"].(float64); ok && port > 0 {
		peerName = fmt.Sprintf("%s_port_%.0f", peerName, port)
	}

	peer := &types.BirdBGPPeer{
		Name: peerName,
		IP:   peerIP,
		Type: strings.ToLower(prefix),
	}

	// Basic fields
	if port, ok := raw["port"].(float64); ok && port > 0 {
		peer.Port = fmt.Sprintf("%.0f", port)
	}
	if asNum, ok := raw["as_num"].(string); ok {
		peer.AsNumber = asNum
	} else if asNum, ok := raw["as_num"].(float64); ok {
		peer.AsNumber = fmt.Sprintf("%.0f", asNum)
	}
	if localAS, ok := raw["local_as_num"].(string); ok && localAS != "0" {
		peer.LocalAsNumber = localAS
	} else if localAS, ok := raw["local_as_num"].(float64); ok && localAS != 0 {
		peer.LocalAsNumber = fmt.Sprintf("%.0f", localAS)
	}

	// TTL security
	if ttl, ok := raw["ttl_security"].(float64); ok && ttl > 0 {
		peer.TTLSecurity = fmt.Sprintf("on;\n  multihop %.0f", ttl)
	} else {
		peer.TTLSecurity = "off"
	}

	// Source address - use appropriate node IP based on version
	if src, ok := raw["source_addr"].(string); ok && src == "UseNodeIP" {
		peer.SourceAddr = currentNodeIP
	}

	// Filters - build inline filter blocks
	peer.ImportFilter = c.buildImportFilter(raw, ipVersion)
	// Use effective node AS number (local_as_num if set, otherwise node AS)
	effectiveNodeAS := config.AsNumber
	if peer.LocalAsNumber != "" {
		effectiveNodeAS = peer.LocalAsNumber
	}
	peer.ExportFilter = c.buildExportFilter(raw, peer.AsNumber, effectiveNodeAS, ipVersion)

	// Optional fields
	if pwd, ok := raw["password"].(string); ok {
		peer.Password = pwd
	}
	if restart, ok := raw["restart_time"].(string); ok && restart != "" {
		peer.GracefulRestart = restart
	}
	if keepalive, ok := raw["keepalive_time"].(string); ok && keepalive != "" {
		peer.KeepaliveTime = keepalive
	}
	if passive, ok := raw["passive_mode"].(bool); ok {
		peer.Passive = passive
	}
	if numLocalAS, ok := raw["num_allow_local_as"].(float64); ok && numLocalAS > 0 {
		peer.NumAllowLocalAs = fmt.Sprintf("%.0f", numLocalAS)
	}

	// Next hop mode
	if nhMode, ok := raw["next_hop_mode"].(string); ok && nhMode == "Self" {
		peer.NextHopSelf = true
	} else if ok && nhMode == "Keep" {
		peer.NextHopKeep = true
	}
	// Legacy keep_next_hop field - only apply for eBGP peers
	if keepNH, ok := raw["keep_next_hop"].(bool); ok && keepNH {
		// Only set NextHopKeep if peer AS != effective node AS (eBGP)
		if peer.AsNumber != effectiveNodeAS {
			peer.NextHopKeep = true
		}
	}

	// Route reflector handling
	if peer.AsNumber == effectiveNodeAS && nodeClusterID != "" {
		if peerRRClusterID, ok := raw["rr_cluster_id"].(string); ok {
			if peerRRClusterID != nodeClusterID {
				peer.RouteReflector = true
				peer.RRClusterID = nodeClusterID
			}
		}
	}

	if (peer.Type == "mesh" || peer.Type == "global" || peer.Type == "local_workload") && !peer.Passive {
		if calicoNode, ok := raw["calico_node"].(bool); ok && calicoNode {
			if peerIP > currentNodeIP {
				peer.Passive = true
				if peer.Type == "mesh" {
					peer.PassiveComment = " # Mesh is unidirectional, peer will connect to us."
				} else {
					peer.PassiveComment = " # Peering is unidirectional, peer will connect to us."
				}
			}
		}
	}

	return peer
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
func (c *client) buildImportFilter(raw map[string]interface{}, ipVersion int) string {
	var filterLines []string

	// Determine which import field to check based on IP version
	importField := "importV4"
	filterSuffix := "V4"
	if ipVersion == 6 {
		importField = "importV6"
		filterSuffix = "V6"
	}

	// Process BGP filters
	if filters, ok := raw["filters"].([]interface{}); ok {
		for _, filter := range filters {
			if filterName, ok := filter.(string); ok {
				filterKey := fmt.Sprintf("/calico/resources/v3/projectcalico.org/bgpfilters/%s", filterName)
				if filterValue, err := c.GetValue(filterKey); err == nil {
					var filterSpec map[string]interface{}
					if json.Unmarshal([]byte(filterValue), &filterSpec) == nil {
						if spec, ok := filterSpec["spec"].(map[string]interface{}); ok {
							if importRules, ok := spec[importField].([]interface{}); ok && len(importRules) > 0 {
								truncatedName := truncateBGPFilterName(filterName)
								filterLines = append(filterLines, fmt.Sprintf("'bgp_%s_importFilter%s'();", truncatedName, filterSuffix))
							}
						}
					}
				}
			}
		}
	}

	filterLines = append(filterLines, "accept; # Prior to introduction of BGP Filters we used \"import all\" so use default accept behaviour on import")
	return strings.Join(filterLines, "\n    ")
}

// buildExportFilter builds the export filter block
func (c *client) buildExportFilter(raw map[string]interface{}, peerAS, nodeAS string, ipVersion int) string {
	var filterLines []string

	// Determine which export field to check based on IP version
	exportField := "exportV4"
	filterSuffix := "V4"
	if ipVersion == 6 {
		exportField = "exportV6"
		filterSuffix = "V6"
	}

	// Process BGP filters
	if filters, ok := raw["filters"].([]interface{}); ok {
		for _, filter := range filters {
			if filterName, ok := filter.(string); ok {
				filterKey := fmt.Sprintf("/calico/resources/v3/projectcalico.org/bgpfilters/%s", filterName)
				if filterValue, err := c.GetValue(filterKey); err == nil {
					var filterSpec map[string]interface{}
					if json.Unmarshal([]byte(filterValue), &filterSpec) == nil {
						if spec, ok := filterSpec["spec"].(map[string]interface{}); ok {
							if exportRules, ok := spec[exportField].([]interface{}); ok && len(exportRules) > 0 {
								truncatedName := truncateBGPFilterName(filterName)
								filterLines = append(filterLines, fmt.Sprintf("'bgp_%s_exportFilter%s'();", truncatedName, filterSuffix))
							}
						}
					}
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

// processCommunityRules processes BGP community advertisements
func (c *client) processCommunityRules(config *types.BirdBGPConfig, ipVersion int) error {
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
		var advertisements []map[string]interface{}
		if err := json.Unmarshal([]byte(value), &advertisements); err != nil {
			log.WithError(err).Warn("Failed to parse community advertisements")
			continue
		}

		for _, adv := range advertisements {
			cidr, ok := adv["cidr"].(string)
			if !ok {
				continue
			}

			communities, ok := adv["communities"].([]interface{})
			if !ok {
				continue
			}

			rule := types.CommunityRule{
				CIDR:          cidr,
				AddStatements: make([]string, 0, len(communities)),
			}

			// Pre-format BIRD community add statements
			for _, comm := range communities {
				if commStr, ok := comm.(string); ok {
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
			}

			if len(rule.AddStatements) > 0 {
				config.Communities = append(config.Communities, rule)
			}
		}
	}

	return nil
}

// TODO: processBGPFilters processes BGP filter definitions
func (c *client) processBGPFilters(config *types.BirdBGPConfig, ipVersion int) error {
	// This would process BGP filter resources from the datastore
	// For now, we'll include standard filters.

	config.Filters["calico_pools"] = `filter calico_pools {
  if ( net ~ [ 10.0.0.0/8+, 172.16.0.0/12+, 192.168.0.0/16+ ] ) then {
    accept;
  }
  reject;
}`

	config.Filters["calico_export"] = `filter calico_export {
  if source = RTS_DEVICE then accept;
  reject;
}`

	config.Filters["all"] = `filter all {
  accept;
}`

	config.Filters["none"] = `filter none {
  reject;
}`

	return nil
}
