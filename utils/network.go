package utils

import (
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/vishvananda/netlink"
)

// DoNetworking performs the networking for the given config and IPAM result
func DoNetworking(args *skel.CmdArgs, conf NetConf, result *types.Result) (string, string, error) {
	hostVethName, contVethMac, err := setupContainerNetworking(args.Netns, args.IfName, conf.MTU, result)
	if err != nil {
		return "", "", err
	}

	// Select the first 11 characters of the containerID for the host veth
	newHostVethName := "cali" + args.ContainerID[:min(11, len(args.ContainerID))]
	if err = setupHostNetworking(hostVethName, newHostVethName); err != nil {
		return "", "", err
	}
	return newHostVethName, contVethMac, nil
}

func setupContainerNetworking(netns, ifName string, mtu int, res *types.Result) (string, string, error) {
	var hostVethName, contVethMAC string
	err := ns.WithNetNSPath(netns, func(hostNS ns.NetNS) error {
		hostVeth, contVeth, err := ip.SetupVeth(ifName, mtu, hostNS)

		if err != nil {
			return err
		}

		// Handle IPv4
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
				return fmt.Errorf("failed to add IP addr to %q: %v", ifName, err)
			}
		}

		// Handle IPv6
		if res.IP6 != nil {
			// No need to add a dummy next hop route as the device will already have an IPv6 LL address.
			addresses, err := netlink.AddrList(contVeth, 6)
			if err != nil {
				return err
			}

			if len(addresses) < 1 {
				return fmt.Errorf("Failed to get IPv6 addresses for container veth")
			}

			_, defNet, _ := net.ParseCIDR("::/0")
			if err = ip.AddRoute(defNet, addresses[0].IP, contVeth); err != nil {
				return fmt.Errorf("failed to add route %v", err)
			}

			if err = netlink.AddrAdd(contVeth, &netlink.Addr{IPNet: &res.IP6.IP}); err != nil {
				return fmt.Errorf("failed to add IP addr to %q: %v", ifName, err)
			}
		}

		// Retrieve the details required by the Calico data model - the host veth name and the container MAC.
		contVeth, err = netlink.LinkByName(ifName)
		if err != nil {
			err = fmt.Errorf("failed to lookup %q: %v", ifName, err)
			return err
		}

		contVethMAC = contVeth.Attrs().HardwareAddr.String()
		hostVethName = hostVeth.Attrs().Name

		return nil
	})

	return hostVethName, contVethMAC, err
}

func setupHostNetworking(vethName, newVethName string) error {
	// The host side veth was originally created within the container netns and was subsequently moved to the host netns.
	// The name will be the same, but the ifindex may have changed so we must re-query it.
	veth, err := netlink.LinkByName(vethName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", vethName, err)
	}

	if err := netlink.LinkSetDown(veth); err != nil {
		return fmt.Errorf("failed to set %q DOWN: %v", vethName, err)
	}

	if err := netlink.LinkSetName(veth, newVethName); err != nil {
		return fmt.Errorf("failed to rename veth: %v to %v (%v)", vethName, newVethName, err)
	}

	if err := netlink.LinkSetUp(veth); err != nil {
		return fmt.Errorf("failed to set %q UP: %v", vethName, err)
	}

	return nil
}
