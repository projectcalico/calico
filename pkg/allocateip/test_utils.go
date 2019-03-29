package allocateip

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/net"
)

// makeNode creates an api.Node with some BGPSpec info populated.
func makeNode(ipv4 string, ipv6 string) *api.Node {
	ip4, ip4net, _ := net.ParseCIDR(ipv4)
	ip4net.IP = ip4.IP

	ip6Addr := ""
	if ipv6 != "" {
		ip6, ip6net, _ := net.ParseCIDR(ipv6)
		// Guard against nil here in case we pass in an empty string for IPv6.
		if ip6 != nil {
			ip6net.IP = ip6.IP
		}
		ip6Addr = ip6net.String()
	}

	n := &api.Node{
		Spec: api.NodeSpec{
			BGP: &api.NodeBGPSpec{
				IPv4Address: ip4net.String(),
				IPv6Address: ip6Addr,
			},
		},
	}
	return n
}

func makeIPv4Pool(ipv4cidr string) *api.IPPool {
	return &api.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dont-care",
		},
		Spec: api.IPPoolSpec{
			CIDR:        ipv4cidr,
			NATOutgoing: true,
			IPIPMode:    api.IPIPModeAlways,
		},
	}
}
