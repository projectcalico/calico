package allocateip

import (
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/net"

	log "github.com/sirupsen/logrus"
)

// determineVXLANEnabledPools returns all VXLAN enabled pools.
func determineVXLANEnabledPoolCIDRs(node api.Node, ipPoolList api.IPPoolList) []net.IPNet {
	var cidrs []net.IPNet
	for _, ipPool := range ipPoolList.Items {
		_, poolCidr, err := net.ParseCIDR(ipPool.Spec.CIDR)
		if err != nil {
			log.WithError(err).Fatalf("Failed to parse CIDR '%s' for IPPool '%s'", ipPool.Spec.CIDR, ipPool.Name)
		}

		// Check if IP pool selects the node
		if selects, err := ipPool.SelectsNode(node); err != nil {
			log.WithError(err).Errorf("Failed to compare nodeSelector '%s' for IPPool '%s', skipping", ipPool.Spec.NodeSelector, ipPool.Name)
			continue
		} else if !selects {
			log.Debugf("IPPool '%s' does not select Node '%s'", ipPool.Name, node.Name)
			continue
		}

		// Check if VXLAN is enabled in the IP pool, the IP pool is not disabled, and it is IPv4 pool since we don't support VXLAN with IPv6.
		if (ipPool.Spec.VXLANMode == api.VXLANModeAlways) && !ipPool.Spec.Disabled && poolCidr.Version() == 4 {
			cidrs = append(cidrs, *poolCidr)
		}
	}
	return cidrs
}
