package allocateip

import (
	"context"
	"fmt"
	"time"

	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/ipam"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/options"

	log "github.com/sirupsen/logrus"
)

func ensureHostTunnelAddressVXLAN(ctx context.Context, c client.Interface, nodename string, vxlanCidrs []net.IPNet) {
	log.WithField("Node", nodename).Debug("Ensure VXLAN tunnel address is set")

	// Get the currently configured VXLAN address.
	node, err := c.Nodes().Get(ctx, nodename, options.GetOptions{})
	if err != nil {
		log.WithError(err).Fatalf("Unable to retrieve VXLAN tunnel address. Error getting node '%s'", nodename)
	}

	if node.Spec.IPv4VXLANTunnelAddr == "" {
		// The VXLAN tunnel has no IP address assigned, assign one.
		log.Debug("VXLAN tunnel is not assigned - assign IP")
		assignHostTunnelAddrVXLAN(ctx, c, nodename, vxlanCidrs)
	} else if isIpInPool(node.Spec.IPv4VXLANTunnelAddr, vxlanCidrs) {
		// The VXLAN tunnel address is still valid, so leave as it.
		log.WithField("IP", node.Spec.IPv4VXLANTunnelAddr).Info("VXLAN tunnel address is still valid")
	} else {
		// The address that is currently assigned is no longer part
		// of an VXLAN pool, so release the IP, and reassign.
		log.WithField("IP", node.Spec.IPv4VXLANTunnelAddr).Info("Reassigning VXLAN tunnel address")
		ipAddr := net.ParseIP(node.Spec.IPv4VXLANTunnelAddr)
		if err != nil {
			log.WithError(err).Fatalf("Failed to parse the CIDR '%s'", node.Spec.IPv4VXLANTunnelAddr)
		}

		ipsToRelease := []net.IP{*ipAddr}
		_, err := c.IPAM().ReleaseIPs(ctx, ipsToRelease)
		if err != nil {
			log.WithField("IP", ipAddr.String()).WithError(err).Fatal("Error releasing non VXLAN address")
		}

		// Assign a new tunnel address.
		assignHostTunnelAddrVXLAN(ctx, c, nodename, vxlanCidrs)
	}
}

// removeHostTunnelAddr removes any existing IP address for this host's VXLAN
// tunnel device and releases the IP from IPAM.  If no IP is assigned this function
// is a no-op.
func removeHostTunnelAddrVXLAN(ctx context.Context, c client.Interface, nodename string) {
	var updateError error
	// If the update fails with ResourceConflict error then retry 5 times with 1 second delay before failing.
	for i := 0; i < 5; i++ {
		node, err := c.Nodes().Get(ctx, nodename, options.GetOptions{})
		if err != nil {
			log.WithError(err).Fatalf("Unable to retrieve VXLAN tunnel address for cleanup. Error getting node '%s'", nodename)
		}

		if node.Spec.IPv4VXLANTunnelAddr == "" {
			log.Debug("No VXLAN tunnel address assigned, and not required")
			return
		}

		ipAddr := net.ParseIP(node.Spec.IPv4VXLANTunnelAddr)
		if _, err := c.IPAM().ReleaseIPs(ctx, []net.IP{*ipAddr}); err != nil {
			log.WithError(err).WithField("IP", ipAddr.String()).Fatal("Error releasing VXLAN address from IPAM")
		}

		node.Spec.IPv4VXLANTunnelAddr = ""
		_, updateError = c.Nodes().Update(ctx, node, options.SetOptions{})
		if _, ok := updateError.(cerrors.ErrorResourceUpdateConflict); ok {
			// Wait for a second and try again if there was a conflict during the resource update.
			log.Infof("Error updating node %s: %s. Retrying.", node.Name, err)
			time.Sleep(1 * time.Second)
			continue
		}

		break
	}

	// Check to see if there was still an error after the retry loop,
	// and log and exit if there was an error.
	if updateError != nil {
		// We hit an error, so release the IP address before exiting.
		// Log the error and exit with exit code 1.
		log.WithError(updateError).Fatal("Unable to remove VXLAN tunnel address")
	}
}

// assignHostTunnelAddrVXLAN claims an VXLAN-enabled IP address from the first pool
// with some space. Stores the result in the host's config as its tunnel
// address.
func assignHostTunnelAddrVXLAN(ctx context.Context, c client.Interface, nodename string, vxlanCidrs []net.IPNet) {
	attrs := map[string]string{
		ipam.AttributeNode: nodename,
		ipam.AttributeType: "vxlanTunnelAddress",
	}
	// TODO: Update kube-controllers to handle this!
	handle := fmt.Sprintf("vxlan-tunnel-addr-%s", nodename)
	args := ipam.AutoAssignArgs{
		Num4:      1,
		Num6:      0,
		HandleID:  &handle,
		Attrs:     attrs,
		Hostname:  nodename,
		IPv4Pools: vxlanCidrs,
	}

	ipv4Addrs, _, err := c.IPAM().AutoAssign(ctx, args)
	if err != nil {
		log.WithError(err).Fatal("Unable to autoassign an address for VXLAN")
	}

	if len(ipv4Addrs) == 0 {
		log.Fatal("Unable to autoassign an address for VXLAN - pools are likely exhausted.")
	}

	var updateError error
	// If the update fails with ResourceConflict error then retry 5 times with 1 second delay before failing.
	for i := 0; i < 5; i++ {
		node, err := c.Nodes().Get(ctx, nodename, options.GetOptions{})
		if err != nil {
			log.WithError(err).Fatalf("Unable to retrieve VXLAN tunnel address for cleanup. Error getting node '%s'", nodename)
		}

		node.Spec.IPv4VXLANTunnelAddr = ipv4Addrs[0].IP.String()

		_, updateError = c.Nodes().Update(ctx, node, options.SetOptions{})
		if _, ok := updateError.(cerrors.ErrorResourceUpdateConflict); ok {
			// Wait for a second and try again if there was a conflict during the resource update.
			log.Infof("Error updating node %s: %s. Retrying.", node.Name, err)
			time.Sleep(1 * time.Second)
			continue
		}

		break
	}

	// Check to see if there was still an error after the retry loop,
	// and release the IP if there was an error.
	if updateError != nil {
		// We hit an error, so release the IP address before exiting.
		_, err := c.IPAM().ReleaseIPs(ctx, []net.IP{{IP: ipv4Addrs[0].IP}})
		if err != nil {
			log.WithError(err).WithField("IP", ipv4Addrs[0].IP.String()).Errorf("Error releasing IP address on failure")
		}

		// Log the error and exit with exit code 1.
		log.WithError(err).WithField("IP", ipv4Addrs[0].IP.String()).Fatal("Unable to set VXLAN tunnel address")
	}

	log.WithField("IP", ipv4Addrs[0].String()).Info("Set VXLAN tunnel address")
}

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
