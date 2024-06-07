package ipsets

import (
	"fmt"

	"github.com/projectcalico/calico/felix/ip"
)

// Constants for nftables, which uses alternative set types as well as
// additional set types that are not supported by iptables.
const (
	NFTSetTypeAddr     = "ipv%d_addr"
	NFTSetTypeAddrPort = "ipv%d_addr . inet_proto . inet_service"
	NFTSetTypeNet      = "nft_net"
)

type V4NFTIPPort struct {
	IP       ip.V4Addr
	Port     uint16
	Protocol string
}

func (p V4NFTIPPort) String() string {
	return fmt.Sprintf("%s . %s . %d", p.IP.String(), p.Protocol, p.Port)
}

type V6NFTIPPort struct {
	IP       ip.V6Addr
	Port     uint16
	Protocol string
}

func (p V6NFTIPPort) String() string {
	return fmt.Sprintf("%s . %s . %d", p.IP.String(), p.Protocol, p.Port)
}