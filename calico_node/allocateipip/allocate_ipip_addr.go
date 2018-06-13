package main

import (
	"math/rand"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/calico_node/calicoclient"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/logutils"
	"github.com/projectcalico/libcalico-go/lib/net"
)

// This file contains the main processing for the allocate_ipip_addr binary
// used by calico/node to set the host's tunnel address to an IPIP-enabled
// address if there are any available, otherwise it removes any tunnel address
// that is configured.

func main() {
	// Log to stdout.  this prevents our logs from being interpreted as errors by, for example,
	// fluentd's default configuration.
	log.SetOutput(os.Stdout)

	// Set log formatting.
	log.SetFormatter(&logutils.Formatter{})

	// Install a hook that adds file and line number information.
	log.AddHook(&logutils.ContextHook{})

	// Load the client config from environment.
	cfg, c := calicoclient.CreateClient()

	// This is a no-op for KDD.
	if cfg.Spec.DatastoreType == api.Kubernetes {
		log.Info("Kubernetes datastore driver handles IPIP allocation - no op")
		return
	}

	// The allocate_ipip_addr binary is only ever invoked _after_ the
	// startup binary has been invoked and the modified environments have
	// been sourced.  Therefore, the NODENAME environment will always be
	// set at this point.
	nodename := os.Getenv("NODENAME")
	if nodename == "" {
		log.Panic("NODENAME environment is not set")
	}

	// Query the IPIP enabled pools and either configure the tunnel
	// address, or remove it.
	if cidrs := getIPIPEnabledPoolCIDRs(c); len(cidrs) > 0 {
		ensureHostTunnelAddress(c, nodename, cidrs)
	} else {
		removeHostTunnelAddr(c, nodename)
	}
}

// ensureHostTunnelAddress that ensures the host has a valid IP address for the
// IPIP tunnel device. This must be an IP address claimed from one of the IPIP
// pools.  This function handles re-allocating the address if it finds an
// existing address that is not from an IPIP pool.
func ensureHostTunnelAddress(c *client.Client, nodename string, ipipCidrs []net.IPNet) {
	log.WithField("Node", nodename).Debug("Ensure IPIP tunnel address is set")

	// Get the currently configured IPIP address.
	if ipAddr, err := c.Config().GetNodeIPIPTunnelAddress(nodename); err != nil {
		log.WithError(err).Fatal("Unable to retrieve IPIP tunnel address")
	} else if ipAddr == nil {
		// The IPIP tunnel has no IP address assigned, assign one.
		log.Debug("IPIP tunnel is not assigned - assign IP")
		assignHostTunnelAddr(c, nodename, ipipCidrs)
	} else if isIpInPool(ipAddr, ipipCidrs) {
		// The IPIP tunnel address is still valid, so leave as it.
		log.WithField("IP", ipAddr.String()).Info("IPIP tunnel address is still valid")
	} else {
		// The address that is currently assigned is no longer part
		// of an IPIP pool, so release the IP, and reassign.
		log.WithField("IP", ipAddr.String()).Info("Reassigning IPIP tunnel address")

		ipsToRelease := []net.IP{*ipAddr}
		_, err := c.IPAM().ReleaseIPs(ipsToRelease)
		if err != nil {
			log.WithField("IP", ipAddr.String()).WithError(err).Fatal("Error releasing non IPIP address")
		}

		// Assign a new tunnel address.
		assignHostTunnelAddr(c, nodename, ipipCidrs)
	}
}

// removeHostTunnelAddr removes any existing IP address for this host's IPIP
// tunnel device and releases the IP from IPAM.  If no IP is assigned this function
// is a no-op.
func removeHostTunnelAddr(c *client.Client, nodename string) {
	if ipAddr, err := c.Config().GetNodeIPIPTunnelAddress(nodename); err != nil {
		log.WithError(err).Fatal("Unable to retrieve IPIP tunnel address for cleanup")
	} else if ipAddr == nil {
		log.Debug("No IPIP tunnel address assigned, and not required")
	} else if _, err := c.IPAM().ReleaseIPs([]net.IP{*ipAddr}); err != nil {
		log.WithError(err).WithField("IP", ipAddr.String()).Fatal("Error releasing IPIP address from IPAM")
	} else if err = c.Config().SetNodeIPIPTunnelAddress(nodename, nil); err != nil {
		log.WithError(err).Fatal("Unable to remove IPIP tunnel address")
	}
}

// assignHostTunnelAddr claims an IPIP-enabled IP address from the first pool
// with some space. Stores the result in the host's config as its tunnel
// address.
func assignHostTunnelAddr(c *client.Client, nodename string, ipipCidrs []net.IPNet) {
	args := client.AutoAssignArgs{
		Num4:      1,
		Num6:      0,
		HandleID:  nil,
		Attrs:     nil,
		Hostname:  nodename,
		IPv4Pools: ipipCidrs,
	}

	var ipv4Addrs []net.IP

	// Retry loop around AutoAssign to recover from a distributed race in case
	// all nodes in a large cluster respond to a change in /pools simultaneously.
	for a := 3; a > 0; a-- {
		var err error
		ipv4Addrs, _, err = c.IPAM().AutoAssign(args)

		if err != nil {
			log.WithError(err).Error("Unable to autoassign an address for IPIP:")
			time.Sleep(time.Duration(rand.Intn(1000)) * time.Millisecond)
		}

		break
	}

	if len(ipv4Addrs) == 0 {
		log.Fatal("Unable to autoassign an address for IPIP - pools are likely exhausted.")
	}

	if err := c.Config().SetNodeIPIPTunnelAddress(nodename, &ipv4Addrs[0]); err != nil {
		log.WithError(err).WithField("IP", ipv4Addrs[0].String()).Fatal("Unable to set IPIP tunnel address")
	} else {
		log.WithField("IP", ipv4Addrs[0].String()).Info("Set IPIP tunnel address")
	}
}

// isIpInPool returns if the IP address is in one of the supplied pools.
func isIpInPool(ipAddr *net.IP, ipipCidrs []net.IPNet) bool {
	for _, cidr := range ipipCidrs {
		if cidr.Contains(ipAddr.IP) {
			return true
		}
	}
	return false
}

// getIPIPEnabledPools returns all IPIP enabled pools.
func getIPIPEnabledPoolCIDRs(c *client.Client) []net.IPNet {
	meta := api.IPPoolMetadata{}
	ipPoolList, err := c.IPPools().List(meta)
	if err != nil {
		log.WithError(err).Fatal("Unable to query IP pool configuration")
	}

	var cidrs []net.IPNet
	for _, ipPool := range ipPoolList.Items {
		// Check if IPIP is enabled in the IP pool, the IP pool is not disabled, and it is IPv4 pool since we don't support IPIP with IPv6.
		if ipPool.Spec.IPIP != nil && ipPool.Spec.IPIP.Enabled && !ipPool.Spec.Disabled && ipPool.Metadata.CIDR.Version() == 4 {
			cidrs = append(cidrs, ipPool.Metadata.CIDR)
		}
	}
	return cidrs
}
