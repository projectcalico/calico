package types

// BirdBGPConfigProvider is an interface for clients that can provide BIRD BGP configuration
type BirdBGPConfigProvider interface {
	GetBirdBGPConfig() (*BirdBGPConfig, error)
}

// BirdBGPConfig represents the processed BGP configuration for templates
type BirdBGPConfig struct {
	NodeName         string            `json:"node_name"`
	NodeIP           string            `json:"node_ip"`
	NodeIPv6         string            `json:"node_ipv6,omitempty"`
	AsNumber         string            `json:"as_number"`
	RouterID         string            `json:"router_id,omitempty"`
	Peers            []BirdBGPPeer     `json:"peers"`
	Filters          map[string]string `json:"filters"`
	Communities      []CommunityRule   `json:"communities"`
	LogLevel         string            `json:"log_level"`
	DebugMode        string            `json:"debug_mode,omitempty"` // "all", "{ states }", or "" (none)
	ListenAddress    string            `json:"listen_address,omitempty"`
	ListenPort       string            `json:"listen_port,omitempty"`
	DirectInterfaces string            `json:"direct_interfaces,omitempty"` // Complete interface pattern string for protocol direct
}

// BirdBGPPeer represents a processed BGP peer configuration
type BirdBGPPeer struct {
	Name            string `json:"name"`
	IP              string `json:"ip"`
	Port            string `json:"port,omitempty"`
	AsNumber        string `json:"as_number"`
	LocalAsNumber   string `json:"local_as_number,omitempty"`
	Type            string `json:"type"` // "mesh", "global", "nodeLocal", "globalLocal"
	ImportFilter    string `json:"import_filter"`
	ExportFilter    string `json:"export_filter"`
	Password        string `json:"password,omitempty"`
	TTLSecurity     string `json:"ttl_security,omitempty"` // "on" with multihop value, or "off"
	RouteReflector  bool   `json:"route_reflector,omitempty"`
	RRClusterID     string `json:"rr_cluster_id,omitempty"`
	SourceAddr      string `json:"source_address,omitempty"`
	NextHopSelf     bool   `json:"next_hop_self,omitempty"`
	NextHopKeep     bool   `json:"next_hop_keep,omitempty"`
	AddPaths        string `json:"add_paths,omitempty"`
	Passive         bool   `json:"passive,omitempty"`
	PassiveComment  string `json:"passive_comment,omitempty"`  // Comment for passive mode (only for auto-passive)
	GracefulRestart string `json:"graceful_restart,omitempty"` // restart time value
	KeepaliveTime   string `json:"keepalive_time,omitempty"`
	NumAllowLocalAs string `json:"num_allow_local_as,omitempty"`
	Comment         string `json:"comment,omitempty"` // Comment to output before the peer block
}

// CommunityRule represents BGP community application rules
type CommunityRule struct {
	CIDR          string   `json:"cidr"`
	AddStatements []string `json:"add_statements"` // Pre-formatted BIRD add statements
}
