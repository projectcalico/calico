// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package linux

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	calicoclient "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

type linuxDataplane struct {
	allowIPForwarding bool
	mtu               int
	queues            int
	logger            *logrus.Entry
}

func NewLinuxDataplane(conf types.NetConf, logger *logrus.Entry) *linuxDataplane {
	return &linuxDataplane{
		allowIPForwarding: conf.ContainerSettings.AllowIPForwarding,
		mtu:               conf.MTU,
		queues:            conf.NumQueues,
		logger:            logger,
	}
}

func (d *linuxDataplane) DoNetworking(
	ctx context.Context,
	calicoClient calicoclient.Interface,
	args *skel.CmdArgs,
	result *cniv1.Result,
	desiredVethName string,
	routes []*net.IPNet,
	endpoint *api.WorkloadEndpoint,
	annotations map[string]string,
) (hostVethName, contVethMAC string, err error) {
	hostVethName = desiredVethName
	contVethName := args.IfName
	var hasIPv4, hasIPv6 bool

	d.logger.Infof("Setting the host side veth name to %s", hostVethName)

	// Clean up if hostVeth exists.
	if oldHostVeth, err := netlink.LinkByName(hostVethName); err == nil {
		if err = netlink.LinkDel(oldHostVeth); err != nil {
			return "", "", fmt.Errorf("failed to delete old hostVeth %v: %v", hostVethName, err)
		}
		d.logger.Infof("Cleaning old hostVeth: %v", hostVethName)
	}

	err = ns.WithNetNSPath(args.Netns, func(hostNS ns.NetNS) error {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name:        contVethName,
				MTU:         d.mtu,
				NumTxQueues: d.queues,
				NumRxQueues: d.queues,
			},
			PeerName: hostVethName,
		}

		if err := netlink.LinkAdd(veth); err != nil {
			d.logger.Errorf("Error adding veth %+v: %s", veth, err)
			return err
		}

		hostVeth, err := netlink.LinkByName(hostVethName)
		if err != nil {
			err = fmt.Errorf("failed to lookup %q: %v", hostVethName, err)
			return err
		}

		if mac, err := net.ParseMAC("EE:EE:EE:EE:EE:EE"); err != nil {
			d.logger.Infof("failed to parse MAC Address: %v. Using kernel generated MAC.", err)
		} else {
			// Set the MAC address on the host side interface so the kernel does not
			// have to generate a persistent address which fails some times.
			if err = netlink.LinkSetHardwareAddr(hostVeth, mac); err != nil {
				d.logger.Warnf("failed to Set MAC of %q: %v. Using kernel generated MAC.", hostVethName, err)
			}
		}

		// Figure out whether we have IPv4 and/or IPv6 addresses.
		for _, addr := range result.IPs {
			if addr.Address.IP.To4() != nil {
				hasIPv4 = true
				addr.Address.Mask = net.CIDRMask(32, 32)
			} else if addr.Address.IP.To16() != nil {
				hasIPv6 = true
				addr.Address.Mask = net.CIDRMask(128, 128)
			}
		}

		if hasIPv6 {
			// By default, the kernel does duplicate address detection for the IPv6 address. DAD delays use of the
			// IP for up to a second and we don't need it because it's a point-to-point link.
			//
			// This must be done before we set the links UP.
			logrus.Debug("Interface has IPv6 address, disabling DAD.")
			err = disableDAD(contVethName)
			if err != nil {
				return err
			}
			err = disableDAD(hostVethName)
			if err != nil {
				return err
			}
		}

		// Explicitly set the veth to UP state; the veth won't get a link local address unless it's set to UP state.
		if err = netlink.LinkSetUp(hostVeth); err != nil {
			return fmt.Errorf("failed to set %q up: %w", hostVethName, err)
		}

		contVeth, err := netlink.LinkByName(contVethName)
		if err != nil {
			err = fmt.Errorf("failed to lookup %q: %v", contVethName, err)
			return err
		}

		// Explicitly set the veth to UP state; the veth won't get a link local address unless it's set to UP state.
		if err = netlink.LinkSetUp(contVeth); err != nil {
			return fmt.Errorf("failed to set %q up: %w", contVethName, err)
		}

		// Fetch the MAC from the container Veth. This is needed by Calico.
		contVethMAC = contVeth.Attrs().HardwareAddr.String()
		d.logger.WithField("MAC", contVethMAC).Debug("Found MAC for container veth")

		// At this point, the virtual ethernet pair has been created, and both ends have the right names.
		// Both ends of the veth are still in the container's network namespace.

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
					d.logger.WithField("route", r).Debug("Skipping non-IPv4 route")
					continue
				}
				d.logger.WithField("route", r).Debug("Adding IPv4 route")
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
					d.logger.Errorf("Error listing IPv6 addresses for the host side of the veth pair: %s", err)
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

				d.logger.Infof("No IPv6 set on interface, retrying..")
				time.Sleep(50 * time.Millisecond)
			}

			if err != nil {
				return err
			}

			hostIPv6Addr := addresses[0].IP

			for _, r := range routes {
				if r.IP.To4() != nil {
					d.logger.WithField("route", r).Debug("Skipping non-IPv6 route")
					continue
				}
				d.logger.WithField("route", r).Debug("Adding IPv6 route")
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

		if err = d.configureContainerSysctls(hasIPv4, hasIPv6); err != nil {
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
		d.logger.Errorf("Error creating veth: %s", err)
		return "", "", err
	}

	err = d.configureSysctls(hostVethName, hasIPv4, hasIPv6)
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

func disableDAD(contVethName string) error {
	logrus.WithField("interface", contVethName).Info("Disabling DAD on interface.")
	dadSysctl := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_dad", contVethName)
	if err := writeProcSys(dadSysctl, "0"); err != nil {
		return fmt.Errorf("failed to disable DAD for %s: %w", contVethName, err)
	}
	return nil
}

// SetupRoutes sets up the routes for the host side of the veth pair.
func SetupRoutes(hostVeth netlink.Link, result *cniv1.Result) error {

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

				// Search all routes and report the conflict, search the name of the iface
				routes, err = netlink.RouteList(nil, netlink.FAMILY_ALL)
				if err != nil {
					return fmt.Errorf("error listing routes")
				}

				var conflict string

				for _, r := range routes {
					if r.Dst != nil && r.Dst.IP.Equal(route.Dst.IP) {
						linkName := "unknown"
						if link, err := netlink.LinkByIndex(r.LinkIndex); err == nil {
							linkName = link.Attrs().Name
						}

						conflict = fmt.Sprintf("route (Ifindex: %d, Dst: %s, Scope: %v, Iface: %s)",
							r.LinkIndex, r.Dst.String(), r.Scope, linkName)
						break
					}
				}

				return fmt.Errorf("route (Ifindex: %d, Dst: %s, Scope: %v) already exists for an interface other than '%s': %s",
					route.LinkIndex, route.Dst.String(), route.Scope, hostVeth.Attrs().Name, conflict)
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
func (d *linuxDataplane) configureSysctls(hostVethName string, hasIPv4, hasIPv6 bool) error {
	var err error

	if hasIPv4 {
		// Enable routing to localhost.  This is required to allow for NAT to the local
		// host.
		err := writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/route_localnet", hostVethName), "1")
		if err != nil {
			return fmt.Errorf("failed to set net.ipv4.conf.%s.route_localnet=1: %s", hostVethName, err)
		}

		// Normally, the kernel has a delay before responding to proxy ARP but we know
		// that's not needed in a Calico network so we disable it.
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/neigh/%s/proxy_delay", hostVethName), "0"); err != nil {
			d.logger.Warnf("failed to set net.ipv4.neigh.%s.proxy_delay=0: %s", hostVethName, err)
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

	if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_ra", hostVethName), "0"); err != nil {
		d.logger.Warnf("failed to set net.ipv6.conf.%s.accept_ra=0: %s", hostVethName, err)
	}

	return nil
}

// configureContainerSysctls configures necessary sysctls required inside the container netns.
func (d *linuxDataplane) configureContainerSysctls(hasIPv4, hasIPv6 bool) error {
	// If an IPv4 address is assigned, then configure IPv4 sysctls.
	if hasIPv4 {
		if d.allowIPForwarding {
			d.logger.Info("Enabling IPv4 forwarding")
			if err := writeProcSys("/proc/sys/net/ipv4/ip_forward", "1"); err != nil {
				return err
			}
		} else {
			d.logger.Info("Disabling IPv4 forwarding")
			if err := writeProcSys("/proc/sys/net/ipv4/ip_forward", "0"); err != nil {
				return err
			}
		}
	}

	// If an IPv6 address is assigned, then configure IPv6 sysctls.
	if hasIPv6 {
		if d.allowIPForwarding {
			d.logger.Info("Enabling IPv6 forwarding")
			if err := writeProcSys("/proc/sys/net/ipv6/conf/all/forwarding", "1"); err != nil {
				return err
			}
		} else {
			d.logger.Info("Disabling IPv6 forwarding")
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

func (d *linuxDataplane) CleanUpNamespace(args *skel.CmdArgs) error {
	// Only try to delete the device if a namespace was passed in.
	logCtx := d.logger.WithFields(logrus.Fields{
		"netns": args.Netns,
		"iface": args.IfName,
	})
	if args.Netns == "" {
		logCtx.Info("CleanUpNamespace called with no netns name, ignoring.")
		return nil
	}

	logCtx.Info("Deleting workload's device in netns.")

	// We've seen veth deletion hang on some very old kernels so we do it from a background goroutine.
	startTime := time.Now()
	done := make(chan struct{})

	var nsErr, linkErr error

	go func() {
		defer close(done)
		nsErr = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
			logCtx.Info("Entered netns, deleting veth.")
			ifName := args.IfName
			var iface netlink.Link
			iface, linkErr = netlink.LinkByName(ifName)
			if linkErr == nil {
				linkErr = netlink.LinkDel(iface)
			}

			// Always return nil so that we can tell the difference between an error from WithNetNSPath itself
			// and an error deleting the link.
			return nil
		})
	}()

	select {
	case <-done:
		if nsErr != nil {
			if _, ok := nsErr.(ns.NSPathNotExistErr); ok {
				logCtx.Info("Workload's netns already gone.  Nothing to do.")
				return nil
			}
			logCtx.WithError(nsErr).Error("Failed to enter workloads netns.")
			return fmt.Errorf("failed to enter netns: %w", nsErr)
		}

		if linkErr != nil {
			if _, ok := linkErr.(netlink.LinkNotFoundError); ok {
				logCtx.Info("Workload's veth was already gone.  Nothing to do.")
				return nil
			}
			logCtx.WithError(linkErr).Error("Failed to clean up workload's veth.")
			return fmt.Errorf("failed to clean up workload's veth inside netns: %w", linkErr)
		}

		logCtx.WithField("after", time.Since(startTime)).Infof("Deleted device in netns.")
	case <-time.After(20 * time.Second):
		return fmt.Errorf("timed out deleting device in netns %s", args.Netns)
	}

	return nil
}
