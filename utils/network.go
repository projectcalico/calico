package utils

import (
	"fmt"
	"net"

	"time"

	"syscall"

	log "github.com/Sirupsen/logrus"
	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/vishvananda/netlink"
)

// DoNetworking performs the networking for the given config and IPAM result
func DoNetworking(args *skel.CmdArgs, conf NetConf, result *types.Result, logger *log.Entry) (string, string, error) {
	hostVethName, contVethMac, err := setupContainerNetworking(args.Netns, args.IfName, conf.MTU, result)
	if err != nil {
		return "", "", err
	}

	// Select the first 11 characters of the containerID for the host veth
	newHostVethName := "cali" + args.ContainerID[:min(11, len(args.ContainerID))]
	if err = setupHostNetworking(hostVethName, newHostVethName, logger); err != nil {
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
			// No need to add a dummy next hop route as the host veth device will already have an IPv6
			// link local address that can be used as a next hop.
			// Just fetch the address of the host end of the veth and use it as the next hop.
			var hostIPv6Addr net.IP
			if err := hostNS.Do(func(_ ns.NetNS) error {
				addresses, err := netlink.AddrList(hostVeth, netlink.FAMILY_V6)
				if err != nil {
					return err
				}

				if len(addresses) < 1 {
					// If the hostVeth doesn't have an IPv6 address then this host probably doesn't
					// support IPv6. Since a IPv6 address has been allocated that can't be used,
					// return an error.
					return fmt.Errorf("Failed to get IPv6 addresses for container veth")
				}

				hostIPv6Addr = addresses[0].IP
				return nil
			}); err != nil {
				return err
			}

			_, defNet, _ := net.ParseCIDR("::/0")
			if err = ip.AddRoute(defNet, hostIPv6Addr, contVeth); err != nil {
				return fmt.Errorf("failed to add default gateway to %v %v", hostIPv6Addr, err)
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

func setupHostNetworking(vethName, newVethName string, logger *log.Entry) error {
	// The host side veth was originally created within the container netns and was subsequently moved to the host netns.
	// The name will be the same, but the ifindex may have changed so we must re-query it.
	veth, err := netlink.LinkByName(vethName)
	if err != nil {
		return fmt.Errorf("failed to lookup %s: %v", vethName, err)
	}

	if err := netlink.LinkSetDown(veth); err != nil {
		return fmt.Errorf("failed to set %s DOWN: %v", vethName, err)
	}

	// Sometimes renaming the veth can fail with a "busy" error. This is believed to be caused by other services
	// setting the up/down status of the device soon after it's created.
	for i := 0; i < 10; i++ {
		if err := netlink.LinkSetName(veth, newVethName); err != nil {
			switch err {
			case syscall.EBUSY:
				logger.WithField("vethName", vethName).Debug(
					"Failed to rename veth because device is busy. Sleeping and retrying.")
				time.Sleep(100 * time.Millisecond)
				continue
			default:
				return err
			}
		}

		// No error was hit renaming the device, try setting the device back "UP"
		if err := netlink.LinkSetUp(veth); err != nil {
			return fmt.Errorf("failed to set %s UP: %v", vethName, err)
		}

		return nil
	}

	// Fell out of the loop without returning. This means the devices failed to rename.
	return fmt.Errorf("failed to rename device from %s to %s. Device Busy.", vethName, newVethName)
}
