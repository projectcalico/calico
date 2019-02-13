package allocateipip

import (
	"context"
	"os"
	"time"

	"github.com/projectcalico/node/pkg/calicoclient"

	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/ipam"
	"github.com/projectcalico/libcalico-go/lib/logutils"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/options"

	log "github.com/sirupsen/logrus"
)

// This file contains the main processing for the allocate_ipip_addr binary
// used by calico/node to set the host's tunnel address to an IPIP-enabled
// address if there are any available, otherwise it removes any tunnel address
// that is configured.

func Run() {
	// Log to stdout.  this prevents our logs from being interpreted as errors by, for example,
	// fluentd's default configuration.
	log.SetOutput(os.Stdout)

	// Set log formatting.
	log.SetFormatter(&logutils.Formatter{})

	// Install a hook that adds file and line number information.
	log.AddHook(&logutils.ContextHook{})

	// Load the client config from environment.
	_, c := calicoclient.CreateClient()

	// The allocate_ipip_addr binary is only ever invoked _after_ the
	// startup binary has been invoked and the modified environments have
	// been sourced.  Therefore, the NODENAME environment will always be
	// set at this point.
	nodename := os.Getenv("NODENAME")
	if nodename == "" {
		log.Panic("NODENAME environment is not set")
	}

	ctx := context.Background()
	// Get node resource for given nodename.
	node, err := c.Nodes().Get(ctx, nodename, options.GetOptions{})
	if err != nil {
		log.WithError(err).Fatalf("failed to fetch node resource '%s'", nodename)
	}

	// Get list of ip pools
	ipPoolList, err := c.IPPools().List(ctx, options.ListOptions{})
	if err != nil {
		log.WithError(err).Fatal("Unable to query IP pool configuration")
	}

	// Query the IPIP enabled pools and either configure the tunnel
	// address, or remove it.
	if cidrs := determineIPIPEnabledPoolCIDRs(*node, *ipPoolList); len(cidrs) > 0 {
		ensureHostTunnelAddress(ctx, c, nodename, cidrs)
	} else {
		removeHostTunnelAddr(ctx, c, nodename)
	}
}

// ensureHostTunnelAddress that ensures the host has a valid IP address for the
// IPIP tunnel device. This must be an IP address claimed from one of the IPIP
// pools.  This function handles re-allocating the address if it finds an
// existing address that is not from an IPIP pool.
func ensureHostTunnelAddress(ctx context.Context, c client.Interface, nodename string, ipipCidrs []net.IPNet) {
	log.WithField("Node", nodename).Debug("Ensure IPIP tunnel address is set")

	// Get the currently configured IPIP address.
	node, err := c.Nodes().Get(ctx, nodename, options.GetOptions{})
	if err != nil {
		log.WithError(err).Fatalf("Unable to retrieve IPIP tunnel address. Error getting node '%s'", nodename)
	}

	if node.Spec.BGP == nil || node.Spec.BGP.IPv4IPIPTunnelAddr == "" {
		// The IPIP tunnel has no IP address assigned, assign one.
		log.Debug("IPIP tunnel is not assigned - assign IP")
		assignHostTunnelAddr(ctx, c, nodename, ipipCidrs)
	} else if isIpInPool(node.Spec.BGP.IPv4IPIPTunnelAddr, ipipCidrs) {
		// The IPIP tunnel address is still valid, so leave as it.
		log.WithField("IP", node.Spec.BGP.IPv4IPIPTunnelAddr).Info("IPIP tunnel address is still valid")
	} else {
		// The address that is currently assigned is no longer part
		// of an IPIP pool, so release the IP, and reassign.
		log.WithField("IP", node.Spec.BGP.IPv4IPIPTunnelAddr).Info("Reassigning IPIP tunnel address")
		ipAddr := net.ParseIP(node.Spec.BGP.IPv4IPIPTunnelAddr)
		if err != nil {
			log.WithError(err).Fatalf("Failed to parse the CIDR '%s'", node.Spec.BGP.IPv4IPIPTunnelAddr)
		}

		ipsToRelease := []net.IP{*ipAddr}
		_, err := c.IPAM().ReleaseIPs(ctx, ipsToRelease)
		if err != nil {
			log.WithField("IP", ipAddr.String()).WithError(err).Fatal("Error releasing non IPIP address")
		}

		// Assign a new tunnel address.
		assignHostTunnelAddr(ctx, c, nodename, ipipCidrs)
	}
}

// removeHostTunnelAddr removes any existing IP address for this host's IPIP
// tunnel device and releases the IP from IPAM.  If no IP is assigned this function
// is a no-op.
func removeHostTunnelAddr(ctx context.Context, c client.Interface, nodename string) {
	var updateError error
	// If the update fails with ResourceConflict error then retry 5 times with 1 second delay before failing.
	for i := 0; i < 5; i++ {
		node, err := c.Nodes().Get(ctx, nodename, options.GetOptions{})
		if err != nil {
			log.WithError(err).Fatalf("Unable to retrieve IPIP tunnel address for cleanup. Error getting node '%s'", nodename)
		}

		if node.Spec.BGP == nil || node.Spec.BGP.IPv4IPIPTunnelAddr == "" {
			log.Debug("No IPIP tunnel address assigned, and not required")
			return
		}

		ipAddr := net.ParseIP(node.Spec.BGP.IPv4IPIPTunnelAddr)
		if _, err := c.IPAM().ReleaseIPs(ctx, []net.IP{*ipAddr}); err != nil {
			log.WithError(err).WithField("IP", ipAddr.String()).Fatal("Error releasing IPIP address from IPAM")
		}

		node.Spec.BGP.IPv4IPIPTunnelAddr = ""
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
		log.WithError(updateError).Fatal("Unable to remove IPIP tunnel address")
	}
}

// assignHostTunnelAddr claims an IPIP-enabled IP address from the first pool
// with some space. Stores the result in the host's config as its tunnel
// address.
func assignHostTunnelAddr(ctx context.Context, c client.Interface, nodename string, ipipCidrs []net.IPNet) {
	args := ipam.AutoAssignArgs{
		Num4:      1,
		Num6:      0,
		HandleID:  nil,
		Attrs:     nil,
		Hostname:  nodename,
		IPv4Pools: ipipCidrs,
	}

	ipv4Addrs, _, err := c.IPAM().AutoAssign(ctx, args)
	if err != nil {
		log.WithError(err).Fatal("Unable to autoassign an address for IPIP")
	}

	if len(ipv4Addrs) == 0 {
		log.Fatal("Unable to autoassign an address for IPIP - pools are likely exhausted.")
	}

	var updateError error
	// If the update fails with ResourceConflict error then retry 5 times with 1 second delay before failing.
	for i := 0; i < 5; i++ {
		node, err := c.Nodes().Get(ctx, nodename, options.GetOptions{})
		if err != nil {
			log.WithError(err).Fatalf("Unable to retrieve IPIP tunnel address for cleanup. Error getting node '%s'", nodename)
		}

		if node.Spec.BGP == nil {
			node.Spec.BGP = &api.NodeBGPSpec{}
		}
		node.Spec.BGP.IPv4IPIPTunnelAddr = ipv4Addrs[0].IP.String()

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
		log.WithError(err).WithField("IP", ipv4Addrs[0].IP.String()).Fatal("Unable to set IPIP tunnel address")
	}

	log.WithField("IP", ipv4Addrs[0].String()).Info("Set IPIP tunnel address")
}

// isIpInPool returns if the IP address is in one of the supplied pools.
func isIpInPool(ipAddrStr string, ipipCidrs []net.IPNet) bool {
	ipAddress := net.ParseIP(ipAddrStr)
	for _, cidr := range ipipCidrs {
		if cidr.Contains(ipAddress.IP) {
			return true
		}
	}
	return false
}

// determineIPIPEnabledPools returns all IPIP enabled pools.
func determineIPIPEnabledPoolCIDRs(node api.Node, ipPoolList api.IPPoolList) []net.IPNet {
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

		// Check if IPIP is enabled in the IP pool, the IP pool is not disabled, and it is IPv4 pool since we don't support IPIP with IPv6.
		if (ipPool.Spec.IPIPMode == api.IPIPModeCrossSubnet || ipPool.Spec.IPIPMode == api.IPIPModeAlways) && !ipPool.Spec.Disabled && poolCidr.Version() == 4 {
			cidrs = append(cidrs, *poolCidr)
		}
	}
	return cidrs
}
