package utils

import (
	"fmt"
	"net"

	log "github.com/Sirupsen/logrus"
	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/vishvananda/netlink"
)

// DoNetworking performs the networking for the given config and IPAM result
func DoNetworking(args *skel.CmdArgs, conf NetConf, res *types.Result, logger *log.Entry, desiredVethName string) (hostVethName, contVethMAC string, err error) {
	// Select the first 11 characters of the containerID for the host veth.
	hostVethName = "cali" + args.ContainerID[:min(11, len(args.ContainerID))]
	contVethName := args.IfName

	// If a desired veth name was passed in, use that instead.
	if desiredVethName != "" {
		hostVethName = desiredVethName
	}

	err = ns.WithNetNSPath(args.Netns, func(hostNS ns.NetNS) error {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name:  contVethName,
				Flags: net.FlagUp,
				MTU:   conf.MTU,
			},
			PeerName: hostVethName,
		}

		if err := netlink.LinkAdd(veth); err != nil {
			logger.Errorf("Error adding veth %+v: %s", veth, err)
			return err
		}

		hostVeth, err := netlink.LinkByName(hostVethName)
		if err != nil {
			err = fmt.Errorf("failed to lookup %q: %v", hostVethName, err)
			return err
		}

		// Explicitly set the veth to UP state, because netlink doesn't always do that on all the platforms with net.FlagUp.
		// veth won't get a link local address unless it's set to UP state.
		if err = netlink.LinkSetUp(hostVeth); err != nil {
			return fmt.Errorf("failed to set %q up: %v", hostVethName, err)
		}

		contVeth, err := netlink.LinkByName(contVethName)
		if err != nil {
			err = fmt.Errorf("failed to lookup %q: %v", contVethName, err)
			return err
		}

		// Fetch the MAC from the container Veth. This is needed by Calico.
		contVethMAC = contVeth.Attrs().HardwareAddr.String()
		logger.WithField("MAC", contVethMAC).Debug("Found MAC for container veth")

		// At this point, the virtual ethernet pair has been created, and both ends have the right names.
		// Both ends of the veth are still in the container's network namespace.

		// Before returning, create the routes inside the namespace, first for IPv4 then IPv6.
		if res.IP4 != nil {
			// Add a connected route to a dummy next hop so that a default route can be set
			gw := net.IPv4(169, 254, 1, 1)
			gwNet := &net.IPNet{IP: gw, Mask: net.CIDRMask(32, 32)}
			if err = netlink.RouteAdd(&netlink.Route{
				LinkIndex: contVeth.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
				Dst:       gwNet}); err != nil {
				return fmt.Errorf("failed to add route %v", err)
			}

			if err = ip.AddDefaultRoute(gw, contVeth); err != nil {
				return fmt.Errorf("failed to add route %v", err)
			}

			if err = netlink.AddrAdd(contVeth, &netlink.Addr{IPNet: &res.IP4.IP}); err != nil {
				return fmt.Errorf("failed to add IP addr to %q: %v", contVethName, err)
			}
		}

		// Handle IPv6 routes
		if res.IP6 != nil {
			// No need to add a dummy next hop route as the host veth device will already have an IPv6
			// link local address that can be used as a next hop.
			// Just fetch the address of the host end of the veth and use it as the next hop.
			addresses, err := netlink.AddrList(hostVeth, netlink.FAMILY_V6)
			if err != nil {
				logger.Errorf("Error listing IPv6 addresses: %s", err)
				return err
			}

			if len(addresses) < 1 {
				// If the hostVeth doesn't have an IPv6 address then this host probably doesn't
				// support IPv6. Since a IPv6 address has been allocated that can't be used,
				// return an error.
				return fmt.Errorf("Failed to get IPv6 addresses for host side of the veth pair")
			}

			hostIPv6Addr := addresses[0].IP

			_, defNet, _ := net.ParseCIDR("::/0")
			if err = ip.AddRoute(defNet, hostIPv6Addr, contVeth); err != nil {
				return fmt.Errorf("failed to add default gateway to %v %v", hostIPv6Addr, err)
			}

			if err = netlink.AddrAdd(contVeth, &netlink.Addr{IPNet: &res.IP6.IP}); err != nil {
				return fmt.Errorf("failed to add IP addr to %q: %v", contVeth, err)
			}
		}

		// Now that the everything has been successfully set up in the container, move the "host" end of the
		// veth into the host namespace.
		if err = netlink.LinkSetNsFd(hostVeth, int(hostNS.Fd())); err != nil {
			return fmt.Errorf("failed to move veth to host netns: %v", err)
		}

		return nil
	})

	if err != nil {
		logger.Errorf("Error creating veth: %s", err)
		return "", "", err
	}

	// Moving a veth between namespaces always leaves it in the "DOWN" state. Set it back to "UP" now that we're
	// back in the host namespace.
	hostVeth, err := netlink.LinkByName(hostVethName)
	if err != nil {
		return "", "", fmt.Errorf("failed to lookup %q: %v", hostVethName, err)
	}

	if err = netlink.LinkSetUp(hostVeth); err != nil {
		return "", "", fmt.Errorf("failed to set %q up: %v", hostVethName, err)
	}

	return hostVethName, contVethMAC, err
}
