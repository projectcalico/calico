package allocateip

import (
	"context"
	"fmt"
	gnet "net"
	"os"
	"reflect"
	"time"

	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	v3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/ipam"
	"github.com/projectcalico/libcalico-go/lib/logutils"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/node/pkg/calicoclient"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

// This file contains the main processing and common logic for assigning tunnel addresses,
// used by calico/node to set the host's tunnel address if IPIP or VXLAN is enabled.
// It will assign an address address if there are any available, and remove any tunnel address
// that is configured if it should no longer be.

func Run() {
	// Log to stdout.  this prevents our logs from being interpreted as errors by, for example,
	// fluentd's default configuration.
	logrus.SetOutput(os.Stdout)

	// Set log formatting.
	logrus.SetFormatter(&logutils.Formatter{})

	// Install a hook that adds file and line number information.
	logrus.AddHook(&logutils.ContextHook{})

	// This binary is only ever invoked _after_ the
	// startup binary has been invoked and the modified environments have
	// been sourced.  Therefore, the NODENAME environment will always be
	// set at this point.
	nodename := os.Getenv("NODENAME")
	if nodename == "" {
		logrus.Panic("NODENAME environment is not set")
	}

	run(nodename)
}

func run(nodename string) {

	// Load the client config from environment.
	cfg, c := calicoclient.CreateClient()

	// If configured to use host-local IPAM, this script has nothing to do, so just return.
	if cfg.Spec.K8sUsePodCIDR {
		logrus.Debug("Using host-local IPAM, no need to allocate a tunnel IP")
		return
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
	if cidrs := determineEnabledPoolCIDRs(*node, *ipPoolList, false); len(cidrs) > 0 {
		ensureHostTunnelAddress(ctx, c, nodename, cidrs, false)
	} else {
		removeHostTunnelAddr(ctx, c, nodename, false)
	}

	// Query the VXLAN enabled pools and either configure the tunnel
	// address, or remove it.
	if cidrs := determineEnabledPoolCIDRs(*node, *ipPoolList, true); len(cidrs) > 0 {
		ensureHostTunnelAddress(ctx, c, nodename, cidrs, true)
	} else {
		removeHostTunnelAddr(ctx, c, nodename, true)
	}
}

func ensureHostTunnelAddress(ctx context.Context, c client.Interface, nodename string, cidrs []net.IPNet, vxlan bool) {
	logCtx := getLogger(vxlan)
	logCtx.WithField("Node", nodename).Debug("Ensure tunnel address is set")

	// Get the currently configured address.
	node, err := c.Nodes().Get(ctx, nodename, options.GetOptions{})
	if err != nil {
		logCtx.WithError(err).Fatalf("Unable to retrieve tunnel address. Error getting node '%s'", nodename)
	}

	// Get the address and ipam attribute string
	var addr string
	var attrString string
	if vxlan {
		addr = node.Spec.IPv4VXLANTunnelAddr
		attrString = ipam.AttributeTypeVXLAN
	} else if node.Spec.BGP != nil {
		addr = node.Spec.BGP.IPv4IPIPTunnelAddr
		attrString = ipam.AttributeTypeIPIP
	}

	// Work out if we need to assign a tunnel address.
	// In most cases we should not release current address and should assign new one.
	release := false
	assign := true
	if addr == "" {
		// The tunnel has no IP address assigned, assign one.
		logCtx.Info("Assign a new tunnel address")

		// Defensively release any IP addresses with this handle. This covers a theoretical case
		// where the node object has lost its reference to its IP, but the allocation still exists
		// in IPAM. For example, if the node object was manually edited.
		release = true
	} else {
		// Go ahead checking status of current address.
		ipAddr := gnet.ParseIP(addr)
		if ipAddr == nil {
			logCtx.WithError(err).Fatalf("Failed to parse the CIDR '%s'", addr)
		}

		// Check if we got correct assignment attributes.
		attr, handle, err := c.IPAM().GetAssignmentAttributes(ctx, net.IP{IP: ipAddr})
		if err == nil {
			if attr[ipam.AttributeType] == attrString && attr[ipam.AttributeNode] == nodename {
				// The tunnel address is still assigned to this node, but is it in the correct pool this time?
				if !isIpInPool(addr, cidrs) {
					// Wrong pool, release this address.
					logCtx.WithField("currentAddr", addr).Info("Current address is not in a valid pool, release it and reassign")
					release = true
				} else {
					// Correct pool, keep this address.
					logCtx.WithField("currentAddr", addr).Info("Current address is still valid, do nothing")
					assign = false
				}
			} else if len(attr) == 0 {
				// No attributes means that this is an old address, assigned by code that didn't use
				// allocation attributes. It might be a pod address, or it might be a node tunnel
				// address. The only way to tell is by the existence of a handle, since workload
				// addresses have always used a handle, whereas tunnel addresses didn't start
				// using handles until the same time as they got allocation attributes.
				if handle != nil {
					// Handle exists, so this address belongs to a workload. We need to assign
					// a new one for the node, but we shouldn't clean up the old address.
					logCtx.WithField("currentAddr", addr).Info("Current address is occupied, assign a new one")
				} else {
					// Handle does not exist. This is just an old tunnel address that comes from
					// a time before we used handles and allocation attributes. Attempt to
					// reassign the same address, but now with metadata. It's possible that someone
					// else takes the address while we do this, in which case we'll just
					// need to assign a new address.
					if err := correctAllocationWithHandle(ctx, c, addr, nodename, vxlan); err != nil {
						if _, ok := err.(cerrors.ErrorResourceAlreadyExists); !ok {
							// Unknown error attempting to allocate the address. Exit.
							logCtx.WithError(err).Fatal("Error correcting tunnel IP allocation")
						}

						// The address was taken by someone else. We need to assign a new one.
						logCtx.WithError(err).Warn("Failed to correct missing attributes, will assign a new address")
					} else {
						// We corrected the address, we can just return.
						logCtx.Info("Updated tunnel address with allocation attributes")
						return
					}
				}
			} else {
				// The allocation has attributes, but doesn't belong to us. Assign a new one.
				logCtx.WithField("currentAddr", addr).Info("Current address is occupied, assign a new one")
			}
		} else if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
			// The tunnel address is not assigned, reassign it.
			logCtx.WithField("currentAddr", addr).Info("Current address is not assigned, assign a new one")

			// Defensively release any IP addresses with this handle. This covers a theoretical case
			// where the node object has lost its reference to its correct IP, but the allocation still exists
			// in IPAM. For example, if the node object was manually edited.
			release = true
		} else {
			// Failed to get assignment attributes, datastore connection issues possible, panic
			logCtx.WithError(err).Panicf("Failed to get assignment attributes for CIDR '%s'", addr)
		}
	}

	if release {
		logCtx.WithField("IP", addr).Info("Release any old tunnel addresses")
		handle, _ := generateHandleAndAttributes(nodename, vxlan)
		if err := c.IPAM().ReleaseByHandle(ctx, handle); err != nil {
			if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
				logCtx.WithError(err).Fatal("Failed to release old addresses")
			}
			// No existing allocations for this node.
		}
	}

	if assign {
		logCtx.WithField("IP", addr).Info("Assign new tunnel address")
		assignHostTunnelAddr(ctx, c, nodename, cidrs, vxlan)
	}
}

func correctAllocationWithHandle(ctx context.Context, c client.Interface, addr, nodename string, vxlan bool) error {
	ipAddr := net.ParseIP(addr)
	if ipAddr == nil {
		log.Fatalf("Failed to parse node tunnel address '%s'", addr)
	}

	// Release the old allocation.
	ipsToRelease := []net.IP{*ipAddr}
	_, err := c.IPAM().ReleaseIPs(ctx, ipsToRelease)
	if err != nil {
		// If we fail to release the old allocation, we shouldn't continue any further. Just exit.
		log.WithField("IP", ipAddr.String()).WithError(err).Fatal("Error releasing address")
	}

	// Attempt to re-assign the same address, but with a handle this time.
	handle, attrs := generateHandleAndAttributes(nodename, vxlan)
	args := ipam.AssignIPArgs{
		IP:       *ipAddr,
		HandleID: &handle,
		Attrs:    attrs,
		Hostname: nodename,
	}

	// If we fail to allocate the same IP, return an error. We'll just
	// have to allocate a new one.
	return c.IPAM().AssignIP(ctx, args)
}

func generateHandleAndAttributes(nodename string, vxlan bool) (string, map[string]string) {
	attrs := map[string]string{ipam.AttributeNode: nodename}
	var handle string
	if vxlan {
		attrs[ipam.AttributeType] = ipam.AttributeTypeVXLAN
		handle = fmt.Sprintf("vxlan-tunnel-addr-%s", nodename)
	} else {
		attrs[ipam.AttributeType] = ipam.AttributeTypeIPIP
		handle = fmt.Sprintf("ipip-tunnel-addr-%s", nodename)
	}
	return handle, attrs
}

// assignHostTunnelAddr claims an IP address from the first pool
// with some space. Stores the result in the host's config as its tunnel
// address. It will assign a VXLAN address if vxlan is true, otherwise an IPIP address.
func assignHostTunnelAddr(ctx context.Context, c client.Interface, nodename string, cidrs []net.IPNet, vxlan bool) {
	// Build attributes and handle for this allocation.
	handle, attrs := generateHandleAndAttributes(nodename, vxlan)
	logCtx := getLogger(vxlan)

	args := ipam.AutoAssignArgs{
		Num4:      1,
		Num6:      0,
		HandleID:  &handle,
		Attrs:     attrs,
		Hostname:  nodename,
		IPv4Pools: cidrs,
	}

	ipv4Addrs, _, err := c.IPAM().AutoAssign(ctx, args)
	if err != nil {
		logCtx.WithError(err).Fatal("Unable to autoassign an address")
	}

	if len(ipv4Addrs) == 0 {
		logCtx.Fatal("Unable to autoassign an address - pools are likely exhausted.")
	}

	// Update the node object with the assigned address.
	ip := ipv4Addrs[0].IP.String()
	if err = updateNodeWithAddress(ctx, c, nodename, ip, vxlan); err != nil {
		// We hit an error, so release the IP address before exiting.
		err := c.IPAM().ReleaseByHandle(ctx, handle)
		if err != nil {
			logCtx.WithError(err).WithField("IP", ip).Errorf("Error releasing IP address on failure")
		}

		// Log the error and exit with exit code 1.
		logCtx.WithError(err).WithField("IP", ip).Fatal("Unable to set tunnel address")
	}

	logCtx.WithField("IP", ip).Info("Assigned tunnel address to node")
}

func updateNodeWithAddress(ctx context.Context, c client.Interface, nodename string, addr string, vxlan bool) error {
	// If the update fails with ResourceConflict error then retry 5 times with 1 second delay before failing.
	for i := 0; i < 5; i++ {
		node, err := c.Nodes().Get(ctx, nodename, options.GetOptions{})
		if err != nil {
			return err
		}

		if vxlan {
			node.Spec.IPv4VXLANTunnelAddr = addr
		} else {
			if node.Spec.BGP == nil {
				node.Spec.BGP = &v3.NodeBGPSpec{}
			}
			node.Spec.BGP.IPv4IPIPTunnelAddr = addr
		}

		_, err = c.Nodes().Update(ctx, node, options.SetOptions{})
		if _, ok := err.(cerrors.ErrorResourceUpdateConflict); ok {
			// Wait for a second and try again if there was a conflict during the resource update.
			log.WithField("node", node.Name).WithError(err).Info("Error updating node, retrying.")
			time.Sleep(1 * time.Second)
			continue
		}

		return nil
	}
	return fmt.Errorf("Too many retries attempting to update node with tunnel address")
}

// removeHostTunnelAddr removes any existing IP address for this host's
// tunnel device and releases the IP from IPAM.  If no IP is assigned this function
// is a no-op.
func removeHostTunnelAddr(ctx context.Context, c client.Interface, nodename string, vxlan bool) {
	var updateError error
	logCtx := getLogger(vxlan)

	// If the update fails with ResourceConflict error then retry 5 times with 1 second delay before failing.
	for i := 0; i < 5; i++ {
		node, err := c.Nodes().Get(ctx, nodename, options.GetOptions{})
		if err != nil {
			logCtx.WithError(err).Fatalf("Unable to retrieve tunnel address for cleanup. Error getting node '%s'", nodename)
		}

		// Determine if we need to do any work.
		ipipTunnelAddrExists := (node.Spec.BGP != nil && node.Spec.BGP.IPv4IPIPTunnelAddr != "")
		vxlanTunnelAddrExists := node.Spec.IPv4VXLANTunnelAddr != ""
		if (vxlan && !vxlanTunnelAddrExists) || (!vxlan && !ipipTunnelAddrExists) {
			logCtx.Debug("No tunnel address assigned, and not required")
			return
		}

		// Find out the currently assigned address and remove it from the node.
		var ipAddr *net.IP
		if vxlan {
			ipAddr = net.ParseIP(node.Spec.IPv4VXLANTunnelAddr)
			node.Spec.IPv4VXLANTunnelAddr = ""
		} else if node.Spec.BGP != nil {
			ipAddr = net.ParseIP(node.Spec.BGP.IPv4IPIPTunnelAddr)
			node.Spec.BGP.IPv4IPIPTunnelAddr = ""
		}

		// If removing the tunnel address causes the BGP spec to be empty, then nil it out.
		// libcalico asserts that if a BGP spec is present, that it not be empty.
		if node.Spec.BGP != nil && reflect.DeepEqual(*node.Spec.BGP, v3.NodeBGPSpec{}) {
			logCtx.Debug("BGP spec is now empty, setting to nil")
			node.Spec.BGP = nil
		}

		// Release tunnel IP address(es) for the node.
		handle, _ := generateHandleAndAttributes(nodename, vxlan)
		if err := c.IPAM().ReleaseByHandle(ctx, handle); err != nil {
			if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
				// Unknown error releasing the address.
				logCtx.WithError(err).WithField("IP", ipAddr.String()).Fatal("Error releasing address by handle")
			}

			// There are no addresses with this handle. Check to see if the IP on the node
			// belongs to us. If it has no handle and no attributes, then we can pretty confidently
			// say that it belongs to us rather than a pod and should be cleaned up.
			logCtx.WithField("handle", handle).Info("No IPs with handle, release exact IP")
			attr, handle, err := c.IPAM().GetAssignmentAttributes(ctx, *ipAddr)
			if err != nil {
				if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
					logCtx.WithError(err).Fatal("Failed to query attributes")
				}
				// No allocation exists, we don't have anything to do.
			} else if len(attr) == 0 && handle == nil {
				// The IP is ours. Release it by passing the exact IP.
				if _, err := c.IPAM().ReleaseIPs(ctx, []net.IP{*ipAddr}); err != nil {
					logCtx.WithError(err).WithField("IP", ipAddr.String()).Fatal("Error releasing address from IPAM")
				}
			}
		}

		// Update the node object.
		_, updateError = c.Nodes().Update(ctx, node, options.SetOptions{})
		if _, ok := updateError.(cerrors.ErrorResourceUpdateConflict); ok {
			// Wait for a second and try again if there was a conflict during the resource update.
			logCtx.Infof("Error updating node %s: %s. Retrying.", node.Name, err)
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
		logCtx.WithError(updateError).Fatal("Unable to remove tunnel address")
	}
}

// determineEnabledPools returns all enabled pools. If vxlan is true, then it will only return VXLAN pools. Otherwise
// it will only return IPIP enabled pools.
func determineEnabledPoolCIDRs(node api.Node, ipPoolList api.IPPoolList, vxlan bool) []net.IPNet {
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

		// Check if desired encap is enabled in the IP pool, the IP pool is not disabled, and it is IPv4 pool since we don't support encap with IPv6.
		if vxlan {
			if (ipPool.Spec.VXLANMode == api.VXLANModeAlways || ipPool.Spec.VXLANMode == api.VXLANModeCrossSubnet) && !ipPool.Spec.Disabled && poolCidr.Version() == 4 {
				cidrs = append(cidrs, *poolCidr)
			}
		} else {
			// Check if IPIP is enabled in the IP pool, the IP pool is not disabled, and it is IPv4 pool since we don't support IPIP with IPv6.
			if (ipPool.Spec.IPIPMode == api.IPIPModeCrossSubnet || ipPool.Spec.IPIPMode == api.IPIPModeAlways) && !ipPool.Spec.Disabled && poolCidr.Version() == 4 {
				cidrs = append(cidrs, *poolCidr)
			}
		}
	}
	return cidrs
}

// isIpInPool returns if the IP address is in one of the supplied pools.
func isIpInPool(ipAddrStr string, cidrs []net.IPNet) bool {
	ipAddress := net.ParseIP(ipAddrStr)
	for _, cidr := range cidrs {
		if cidr.Contains(ipAddress.IP) {
			return true
		}
	}
	return false
}

func getLogger(vxlan bool) *logrus.Entry {
	if vxlan {
		return logrus.WithField("type", "vxlanTunnelAddress")
	} else {
		return logrus.WithField("type", "ipipTunnelAddress")
	}
}
