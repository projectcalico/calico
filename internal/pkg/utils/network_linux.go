// Copyright 2018 Tigera Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package utils

import (
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/projectcalico/cni-plugin/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

var (
	// IPv4AllNet represents the IPv4 all-addresses CIDR 0.0.0.0/0.
	IPv4AllNet *net.IPNet
	// IPv6AllNet represents the IPv6 all-addresses CIDR ::/0.
	IPv6AllNet    *net.IPNet
	DefaultRoutes []*net.IPNet
)

func init() {
	var err error
	_, IPv4AllNet, err = net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		panic(err)
	}
	_, IPv6AllNet, err = net.ParseCIDR("::/0")
	if err != nil {
		panic(err)
	}
	DefaultRoutes = []*net.IPNet{
		IPv4AllNet,
		IPv6AllNet, // Only used if we end up adding a v6 address.
	}
}

// DoNetworking performs the networking for the given config and IPAM result
func DoNetworking(
	args *skel.CmdArgs,
	conf types.NetConf,
	result *current.Result,
	logger *logrus.Entry,
	desiredVethName string,
	routes []*net.IPNet,
) (hostVethName, contVethMAC string, err error) {
	// Select the first 11 characters of the containerID for the host veth.
	hostVethName = "cali" + args.ContainerID[:Min(11, len(args.ContainerID))]
	contVethName := args.IfName
	var hasIPv4, hasIPv6 bool

	// If a desired veth name was passed in, use that instead.
	if desiredVethName != "" {
		hostVethName = desiredVethName
	}

	logger.Infof("Setting the host side veth name to %s", hostVethName)

	// Clean up if hostVeth exists.
	if oldHostVeth, err := netlink.LinkByName(hostVethName); err == nil {
		if err = netlink.LinkDel(oldHostVeth); err != nil {
			return "", "", fmt.Errorf("failed to delete old hostVeth %v: %v", hostVethName, err)
		}
		logger.Infof("Cleaning old hostVeth: %v", hostVethName)
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

		if mac, err := net.ParseMAC("EE:EE:EE:EE:EE:EE"); err != nil {
			logger.Infof("failed to parse MAC Address: %v. Using kernel generated MAC.", err)
		} else {
			// Set the MAC address on the host side interface so the kernel does not
			// have to generate a persistent address which fails some times.
			if err = netlink.LinkSetHardwareAddr(hostVeth, mac); err != nil {
				logger.Warnf("failed to Set MAC of %q: %v. Using kernel generated MAC.", hostVethName, err)
			}
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

		// Figure out whether we have IPv4 and/or IPv6 addresses.
		for _, addr := range result.IPs {
			if addr.Version == "4" {
				hasIPv4 = true
			} else if addr.Version == "6" {
				hasIPv6 = true
			}
		}

		// Do the per-IP version set-up.  Add gateway routes etc.
		if hasIPv4 {
			// Add a connected route to a dummy next hop so that a default route can be set
			gw := net.IPv4(169, 254, 1, 1)
			gwNet := &net.IPNet{IP: gw, Mask: net.CIDRMask(32, 32)}
			err := netlink.RouteAdd(
				&netlink.Route{
					LinkIndex: contVeth.Attrs().Index,
					Scope:     netlink.SCOPE_LINK,
					Dst:       gwNet,
				},
			)

			if err != nil {
				return fmt.Errorf("failed to add route inside the container: %v", err)
			}

			for _, r := range routes {
				if r.IP.To4() == nil {
					logger.WithField("route", r).Debug("Skipping non-IPv4 route")
					continue
				}
				logger.WithField("route", r).Debug("Adding IPv4 route")
				if err = ip.AddRoute(r, gw, contVeth); err != nil {
					return fmt.Errorf("failed to add IPv4 route for %v via %v: %v", r, gw, err)
				}
			}
		}

		if hasIPv6 {
			// Make sure ipv6 is enabled in the container/pod network namespace.
			// Without these sysctls enabled, interfaces will come up but they won't get a link local IPv6 address
			// which is required to add the default IPv6 route.
			if err = writeProcSys("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0"); err != nil {
				return fmt.Errorf("failed to set net.ipv6.conf.all.disable_ipv6=0: %s", err)
			}

			if err = writeProcSys("/proc/sys/net/ipv6/conf/default/disable_ipv6", "0"); err != nil {
				return fmt.Errorf("failed to set net.ipv6.conf.default.disable_ipv6=0: %s", err)
			}

			if err = writeProcSys("/proc/sys/net/ipv6/conf/lo/disable_ipv6", "0"); err != nil {
				return fmt.Errorf("failed to set net.ipv6.conf.lo.disable_ipv6=0: %s", err)
			}

			// Retry several times as the LL can take a several micro/miliseconds to initialize and we may be too fast
			// after these sysctls
			var err error
			var addresses []netlink.Addr
			for i := 0; i < 10; i++ {
				// No need to add a dummy next hop route as the host veth device will already have an IPv6
				// link local address that can be used as a next hop.
				// Just fetch the address of the host end of the veth and use it as the next hop.
				addresses, err = netlink.AddrList(hostVeth, netlink.FAMILY_V6)
				if err != nil {
					logger.Errorf("Error listing IPv6 addresses for the host side of the veth pair: %s", err)
				}

				if len(addresses) < 1 {
					// If the hostVeth doesn't have an IPv6 address then this host probably doesn't
					// support IPv6. Since a IPv6 address has been allocated that can't be used,
					// return an error.
					err = fmt.Errorf("failed to get IPv6 addresses for host side of the veth pair")
				}
				if err == nil {
					break
				}

				logger.Infof("No IPv6 set on interface, retrying..")
				time.Sleep(50 * time.Millisecond)
			}

			if err != nil {
				return err
			}

			hostIPv6Addr := addresses[0].IP

			for _, r := range routes {
				if r.IP.To4() != nil {
					logger.WithField("route", r).Debug("Skipping non-IPv6 route")
					continue
				}
				logger.WithField("route", r).Debug("Adding IPv6 route")
				if err = ip.AddRoute(r, hostIPv6Addr, contVeth); err != nil {
					return fmt.Errorf("failed to add IPv6 route for %v via %v: %v", r, hostIPv6Addr, err)
				}
			}
		}

		// Now add the IPs to the container side of the veth.
		for _, addr := range result.IPs {
			if err = netlink.AddrAdd(contVeth, &netlink.Addr{IPNet: &addr.Address}); err != nil {
				return fmt.Errorf("failed to add IP addr to %q: %v", contVeth, err)
			}
		}

		if err = configureContainerSysctls(logger, conf.ContainerSettings, hasIPv4, hasIPv6); err != nil {
			return fmt.Errorf("error configuring sysctls for the container netns, error: %s", err)
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

	err = configureSysctls(hostVethName, hasIPv4, hasIPv6)
	if err != nil {
		return "", "", fmt.Errorf("error configuring sysctls for interface: %s, error: %s", hostVethName, err)
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

	// Now that the host side of the veth is moved, state set to UP, and configured with sysctls, we can add the routes to it in the host namespace.
	err = SetupRoutes(hostVeth, result)
	if err != nil {
		return "", "", fmt.Errorf("error adding host side routes for interface: %s, error: %s", hostVeth.Attrs().Name, err)
	}

	return hostVethName, contVethMAC, err
}

// SetupRoutes sets up the routes for the host side of the veth pair.
func SetupRoutes(hostVeth netlink.Link, result *current.Result) error {

	// Go through all the IPs and add routes for each IP in the result.
	for _, ipAddr := range result.IPs {
		route := netlink.Route{
			LinkIndex: hostVeth.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       &ipAddr.Address,
		}
		err := netlink.RouteAdd(&route)

		if err != nil {
			switch err {

			// Route already exists, but not necessarily pointing to the same interface.
			case syscall.EEXIST:
				// List all the routes for the interface.
				routes, err := netlink.RouteList(hostVeth, netlink.FAMILY_ALL)
				if err != nil {
					return fmt.Errorf("error listing routes")
				}

				// Go through all the routes pointing to the interface, and see if any of them is
				// exactly what we are intending to program.
				// If the route we want is already there then most likely it's programmed by Felix, so we ignore it,
				// and we return an error if none of the routes match the route we're trying to program.
				logrus.WithFields(logrus.Fields{"route": route, "scope": route.Scope}).Debug("Constructed route")
				for _, r := range routes {
					logrus.WithFields(logrus.Fields{"interface": hostVeth.Attrs().Name, "route": r, "scope": r.Scope}).Debug("Routes for the interface")
					if r.LinkIndex == route.LinkIndex && r.Dst.IP.Equal(route.Dst.IP) && r.Scope == route.Scope {
						// Route was already present on the host.
						logrus.WithFields(logrus.Fields{"interface": hostVeth.Attrs().Name}).Infof("CNI skipping add route. Route already exists")
						return nil
					}
				}
				return fmt.Errorf("route (Ifindex: %d, Dst: %s, Scope: %v) already exists for an interface other than '%s'",
					route.LinkIndex, route.Dst.String(), route.Scope, hostVeth.Attrs().Name)
			default:
				return fmt.Errorf("failed to add route (Ifindex: %d, Dst: %s, Scope: %v, Iface: %s): %v",
					route.LinkIndex, route.Dst.String(), route.Scope, hostVeth.Attrs().Name, err)
			}
		}

		logrus.WithFields(logrus.Fields{"interface": hostVeth, "IP": ipAddr.Address}).Debugf("CNI adding route")
	}
	return nil
}

// configureSysctls configures necessary sysctls required for the host side of the veth pair for IPv4 and/or IPv6.
func configureSysctls(hostVethName string, hasIPv4, hasIPv6 bool) error {
	var err error

	if hasIPv4 {
		// Normally, the kernel has a delay before responding to proxy ARP but we know
		// that's not needed in a Calico network so we disable it.
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/neigh/%s/proxy_delay", hostVethName), "0"); err != nil {
			return fmt.Errorf("failed to set net.ipv4.neigh.%s.proxy_delay=0: %s", hostVethName, err)
		}

		// Enable proxy ARP, this makes the host respond to all ARP requests with its own
		// MAC. We install explicit routes into the containers network
		// namespace and we use a link-local address for the gateway.  Turing on proxy ARP
		// means that we don't need to assign the link local address explicitly to each
		// host side of the veth, which is one fewer thing to maintain and one fewer
		// thing we may clash over.
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/proxy_arp", hostVethName), "1"); err != nil {
			return fmt.Errorf("failed to set net.ipv4.conf.%s.proxy_arp=1: %s", hostVethName, err)
		}

		// Enable IP forwarding of packets coming _from_ this interface.  For packets to
		// be forwarded in both directions we need this flag to be set on the fabric-facing
		// interface too (or for the global default to be set).
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/forwarding", hostVethName), "1"); err != nil {
			return fmt.Errorf("failed to set net.ipv4.conf.%s.forwarding=1: %s", hostVethName, err)
		}
	}

	if hasIPv6 {
		// Make sure ipv6 is enabled on the hostVeth interface in the host network namespace.
		// Interfaces won't get a link local address without this sysctl set to 0.
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", hostVethName), "0"); err != nil {
			return fmt.Errorf("failed to set net.ipv6.conf.%s.disable_ipv6=0: %s", hostVethName, err)
		}

		// Enable proxy NDP, similarly to proxy ARP, described above in IPv4 section.
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/proxy_ndp", hostVethName), "1"); err != nil {
			return fmt.Errorf("failed to set net.ipv6.conf.%s.proxy_ndp=1: %s", hostVethName, err)
		}

		// Enable IP forwarding of packets coming _from_ this interface.  For packets to
		// be forwarded in both directions we need this flag to be set on the fabric-facing
		// interface too (or for the global default to be set).
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/forwarding", hostVethName), "1"); err != nil {
			return fmt.Errorf("failed to set net.ipv6.conf.%s.forwarding=1: %s", hostVethName, err)
		}
	}

	return nil
}

// configureContainerSysctls configures necessary sysctls required inside the container netns.
func configureContainerSysctls(logger *logrus.Entry, settings types.ContainerSettings, hasIPv4, hasIPv6 bool) error {
	// If an IPv4 address is assigned, then configure IPv4 sysctls.
	if hasIPv4 {
		if settings.AllowIPForwarding {
			logger.Info("Enabling IPv4 forwarding")
			if err := writeProcSys("/proc/sys/net/ipv4/ip_forward", "1"); err != nil {
				return err
			}
		} else {
			logger.Info("Disabling IPv4 forwarding")
			if err := writeProcSys("/proc/sys/net/ipv4/ip_forward", "0"); err != nil {
				return err
			}
		}
	}

	// If an IPv6 address is assigned, then configure IPv6 sysctls.
	if hasIPv6 {
		if settings.AllowIPForwarding {
			logger.Info("Enabling IPv6 forwarding")
			if err := writeProcSys("/proc/sys/net/ipv6/conf/all/forwarding", "1"); err != nil {
				return err
			}
		} else {
			logger.Info("Disabling IPv6 forwarding")
			if err := writeProcSys("/proc/sys/net/ipv6/conf/all/forwarding", "0"); err != nil {
				return err
			}
		}
	}
	return nil
}

// writeProcSys takes the sysctl path and a string value to set i.e. "0" or "1" and sets the sysctl.
func writeProcSys(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	n, err := f.Write([]byte(value))
	if err == nil && n < len(value) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}

// CleanUpNamespace deletes the devices in the network namespace.
func CleanUpNamespace(args *skel.CmdArgs, logger *logrus.Entry) error {
	// Only try to delete the device if a namespace was passed in.
	if args.Netns != "" {
		logger.WithFields(logrus.Fields{
			"netns": args.Netns,
			"iface": args.IfName,
		}).Debug("Checking namespace & device exist.")
		devErr := ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
			_, err := netlink.LinkByName(args.IfName)
			return err
		})

		if devErr == nil {
			logger.Infof("Calico CNI deleting device in netns %s", args.Netns)
			// Deleting the veth has been seen to hang on some kernel version. Timeout the command if it takes too long.
			ch := make(chan error, 1)

			go func() {
				err := ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
					return ip.DelLinkByName(args.IfName)
				})

				ch <- err
			}()

			select {
			case err := <-ch:
				if err != nil {
					return err
				} else {
					logger.Infof("Calico CNI deleted device in netns %s", args.Netns)
				}
			case <-time.After(5 * time.Second):
				return fmt.Errorf("Calico CNI timed out deleting device in netns %s", args.Netns)
			}
		} else {
			logger.WithField("ifName", args.IfName).Info("veth does not exist, no need to clean up.")
		}
	}

	return nil
}
