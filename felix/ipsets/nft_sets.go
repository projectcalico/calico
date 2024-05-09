package ipsets

import (
	"fmt"

	"github.com/projectcalico/calico/felix/ip"
)

// Constants for nftables, which uses alternative set types as well as
// additional set types that are not supported by iptables.
const (
	NFTSetTypeAddr     = "ipv%d_addr"
	NFTSetTypeAddrPort = "ipv%d_addr . inet_service"
)

type V4NFTIPPort struct {
	IP   ip.V4Addr
	Port uint16
}

func (p V4NFTIPPort) String() string {
	return fmt.Sprintf("%s . %d", p.IP.String(), p.Port)
}

type V6NFTIPPort struct {
	IP   ip.V6Addr
	Port uint16
}

func (p V6NFTIPPort) String() string {
	return fmt.Sprintf("%s . %d", p.IP.String(), p.Port)
}
