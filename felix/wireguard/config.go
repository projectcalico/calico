package wireguard

import "time"

type Config struct {
	// Wireguard configuration
	Enabled             bool
	ListeningPort       int
	FirewallMark        int
	RoutingRulePriority int
	RoutingTableIndex   int
	InterfaceName       string
	MTU                 int
	RouteSource         string
	EncryptHostTraffic  bool
	PersistentKeepAlive time.Duration
	RouteSyncDisabled   bool
}
