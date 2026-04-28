package backends

import (
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

type BGPPeer struct {
	PeerIP          net.IP               `json:"ip"`
	ASNum           numorstring.ASNumber `json:"as_num,string"`
	LocalASNum      numorstring.ASNumber `json:"local_as_num,string"`
	RRClusterID     string               `json:"rr_cluster_id"`
	Password        *string              `json:"password"`
	SourceAddr      string               `json:"source_addr"`
	RestartTime     string               `json:"restart_time"`
	KeepaliveTime   string               `json:"keepalive_time"`
	Port            uint16               `json:"port"`
	KeepNextHop     bool                 `json:"keep_next_hop"`
	CalicoNode      bool                 `json:"calico_node"`
	NumAllowLocalAS int32                `json:"num_allow_local_as"`
	TTLSecurity     uint8                `json:"ttl_security"`
	Filters         []string             `json:"filters"`
	ReachableBy     string               `json:"reachable_by"`
	PassiveMode     bool                 `json:"passive_mode"`
	LocalBGPPeer    bool                 `json:"local_bgp_peer"`
	NextHopMode     string               `json:"next_hop_mode"`
}
