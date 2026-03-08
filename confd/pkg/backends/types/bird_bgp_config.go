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

package types

// BirdBGPConfig represents the processed BGP configuration for templates
type BirdBGPConfig struct {
	NodeName         string
	NodeIP           string
	NodeIPv6         string
	ASNumber         string
	RouterID         string
	Peers            []BirdBGPPeer
	Filters          map[string]string
	Communities      []CommunityRule
	LogLevel         string
	DebugMode        string // "all", "{ states }", or "" (none)
	ListenAddress    string
	ListenPort       string
	DirectInterfaces string // Complete interface pattern string for protocol direct

	BGPExportFilterForDisabledIPPools []string
	BGPExportFilterForEnabledIPPools  []string
	KernelFilterForIPPools            []string
}

// BirdBGPPeer represents a processed BGP peer configuration
type BirdBGPPeer struct {
	Name            string
	IP              string
	Port            string
	ASNumber        string
	LocalASNumber   string
	Type            string // "mesh", "global", "nodeLocal", "globalLocal"
	ImportFilter    string
	ExportFilter    string
	Password        string
	TTLSecurity     string // "on" with multihop value, or "off"
	RouteReflector  bool
	RRClusterID     string
	SourceAddr      string
	NextHopSelf     bool
	NextHopKeep     bool
	AddPaths        string
	Passive         bool
	GracefulRestart string // restart time value
	KeepaliveTime   string
	NumAllowLocalAs string
}

// CommunityRule represents BGP community application rules
type CommunityRule struct {
	CIDR          string
	AddStatements []string // Pre-formatted BIRD add statements
}
