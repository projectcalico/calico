package allocateip

import (
	"context"
	"os"

	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/node/pkg/calicoclient"
	"github.com/projectcalico/typha/pkg/logutils"
	"github.com/sirupsen/logrus"
)

// This file contains the main processing for the allocate_ipip_addr binary
// used by calico/node to set the host's tunnel address to an IPIP-enabled
// address if there are any available, otherwise it removes any tunnel address
// that is configured.

func Run() {
	// Log to stdout.  this prevents our logs from being interpreted as errors by, for example,
	// fluentd's default configuration.
	logrus.SetOutput(os.Stdout)

	// Set log formatting.
	logrus.SetFormatter(&logutils.Formatter{})

	// Install a hook that adds file and line number information.
	logrus.AddHook(&logutils.ContextHook{})

	// Load the client config from environment.
	_, c := calicoclient.CreateClient()

	// The allocate_ipip_addr binary is only ever invoked _after_ the
	// startup binary has been invoked and the modified environments have
	// been sourced.  Therefore, the NODENAME environment will always be
	// set at this point.
	nodename := os.Getenv("NODENAME")
	if nodename == "" {
		logrus.Panic("NODENAME environment is not set")
	}

	ctx := context.Background()
	// Get node resource for given nodename.
	node, err := c.Nodes().Get(ctx, nodename, options.GetOptions{})
	if err != nil {
		logrus.WithError(err).Fatalf("failed to fetch node resource '%s'", nodename)
	}

	// Get list of ip pools
	ipPoolList, err := c.IPPools().List(ctx, options.ListOptions{})
	if err != nil {
		logrus.WithError(err).Fatal("Unable to query IP pool configuration")
	}

	// Query the IPIP enabled pools and either configure the tunnel
	// address, or remove it.
	if cidrs := determineIPIPEnabledPoolCIDRs(*node, *ipPoolList); len(cidrs) > 0 {
		ensureHostTunnelAddress(ctx, c, nodename, cidrs)
	} else {
		removeHostTunnelAddr(ctx, c, nodename)
	}

	// Query the VXLAN enabled pools and either configure the tunnel
	// address, or remove it.
	if cidrs := determineVXLANEnabledPoolCIDRs(*node, *ipPoolList); len(cidrs) > 0 {
		ensureHostTunnelAddressVXLAN(ctx, c, nodename, cidrs)
	} else {
		removeHostTunnelAddrVXLAN(ctx, c, nodename)
	}
}
