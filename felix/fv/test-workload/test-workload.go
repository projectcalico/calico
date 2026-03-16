// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.
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

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	nsutils "github.com/containernetworking/plugins/pkg/testutils"
	"github.com/docopt/docopt-go"
	"github.com/ishidawataru/sctp"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/cni-plugin/pkg/dataplane/linux"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	"github.com/projectcalico/calico/felix/fv/cgroup"
	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

const usage = `test-workload, test workload for Felix FV testing.

If <interface-name> is "", the workload will start in the current namespace.

Usage:
  test-workload [--protocol=<protocol>] [--namespace-path=<path>] [--sidecar-iptables] [--mtu=<mtu>] [--listen-any-ip] [--netkit] <interface-name> <ip-address> <ports>
`

func main() {
	log.SetLevel(log.DebugLevel)
	logutils.ConfigureFormatter("test-workload")

	// If we've been told to, move into this felix's cgroup.
	cgroup.MaybeMoveToFelixCgroupv2()

	arguments, err := docopt.ParseArgs(usage, nil, "v0.1")
	if err != nil {
		println(usage)
		log.WithError(err).Fatal("Failed to parse usage")
	}
	interfaceName := arguments["<interface-name>"].(string)
	ipAddressStr := arguments["<ip-address>"].(string)
	portsStr := arguments["<ports>"].(string)
	protocol := arguments["--protocol"].(string)
	nsPath := ""
	if arg, ok := arguments["--namespace-path"]; ok && arg != nil {
		nsPath = arg.(string)
	}
	sidecarIptables := arguments["--sidecar-iptables"].(bool)
	mtu := 1450
	if arg, ok := arguments["--mtu"]; ok && arg != nil {
		mtu, err = strconv.Atoi(arg.(string))
		panicIfError(err)
	}
	panicIfError(err)

	listenAnyIP := false
	if arg, ok := arguments["--listen-any-ip"]; ok && arg.(bool) {
		listenAnyIP = true
	}
	useNetkit := false
	if arg, ok := arguments["--netkit"]; ok && arg.(bool) {
		useNetkit = true
	}

	ports := strings.Split(portsStr, ",")
	ipAddrs := strings.Split(ipAddressStr, ",")
	ipv6Addr := ""
	ipv4Addr := ""
	for _, ipAddress := range ipAddrs {
		if strings.Contains(ipAddress, ":") {
			ipv6Addr = ipAddress
		} else {
			ipv4Addr = ipAddress
		}
	}

	var namespace ns.NetNS
	if nsPath != "" {
		namespace, err = ns.GetNS(nsPath)
		if err != nil {
			log.WithError(err).WithField("namespace path", nsPath).Fatal("Failed to get netns from path")
		}
	} else if interfaceName != "" {
		// Create a new network namespace for the workload.
		attempts := 0
		for {
			namespace, err = nsutils.NewNS()
			if err == nil {
				break
			}
			log.WithError(err).Error("Failed to create namespace")
			attempts++
			time.Sleep(1 * time.Second)
			if attempts > 30 {
				log.WithError(err).Panic("Giving up after multiple retries")
			}
		}
		log.WithField("namespace", namespace.Path()).Debug("Created namespace")

		hostVethName := interfaceName
		var addrs []*cniv1.IPConfig
		if ipv4Addr != "" {
			addrs = append(addrs, &cniv1.IPConfig{
				Address: net.IPNet{
					IP:   net.ParseIP(ipv4Addr),
					Mask: net.CIDRMask(32, 32),
				},
			})
		}
		if ipv6Addr != "" {
			addrs = append(addrs, &cniv1.IPConfig{
				Address: net.IPNet{
					IP:   net.ParseIP(ipv6Addr),
					Mask: net.CIDRMask(128, 128),
				},
			})
		}
		_, v4Default, err := net.ParseCIDR("0.0.0.0/0")
		panicIfError(err)
		_, v6Default, err := net.ParseCIDR("::/0")
		panicIfError(err)
		routes := []*net.IPNet{
			v4Default,
			v6Default, // Only used if we end up adding a v6 address.
		}
		hostNlHandle, err := netlink.NewHandle(syscall.NETLINK_ROUTE)
		panicIfError(err)

		defer hostNlHandle.Close()

		if useNetkit {
			err = doNetkitSetUp(hostNlHandle, namespace, addrs, "eth0", hostVethName, routes, mtu)
		} else {
			conf := types.NetConf{
				MTU:       mtu,
				NumQueues: 1,
			}
			dp := linux.NewLinuxDataplane(conf, log.WithField("ns", namespace.Path()))
			_, err = dp.DoWorkloadNetnsSetUp(
				hostNlHandle,
				namespace.Path(),
				addrs,
				"eth0",
				hostVethName,
				routes,
				nil,
			)
		}
		panicIfError(err)
	} else {
		namespace, err = ns.GetCurrentNS()
		panicIfError(err)
	}

	// Now listen on the specified ports in the workload namespace.
	err = namespace.Do(func(_ ns.NetNS) error {
		if interfaceName != "" {
			lo, err := netlink.LinkByName("lo")
			if err != nil {
				return fmt.Errorf("failed to look up 'lo' inside netns: %w", err)
			}
			err = netlink.LinkSetUp(lo)
			if err != nil {
				return fmt.Errorf("failed bring 'lo' up inside netns: %w", err)
			}
		}

		if sidecarIptables {
			if err := doSidecarIptablesSetup(); err != nil {
				return fmt.Errorf("failed to setup sidecar-like iptables: %v", err)
			}
		}
		if ipv6Addr != "" {
			attempts := 0
			for {
				out, err := exec.Command("ip", "-6", "addr").CombinedOutput()
				panicIfError(err)
				if strings.Contains(string(out), "tentative") {
					attempts++
					if attempts > 30 {
						log.Panic("IPv6 address still tentative after 30s")
					}
					time.Sleep(1 * time.Second)
					continue
				}
				break
			}
		}

		// Print out the namespace path, so that test code can pick it up and execute subsequent
		// operations in the same namespace - which (in the context of this FV framework)
		// effectively means _as_ this workload.
		fmt.Println(namespace.Path())

		handleRequest := func(conn net.Conn) {
			log.WithFields(log.Fields{
				"localAddr":  conn.LocalAddr(),
				"remoteAddr": conn.RemoteAddr(),
			}).Info("Accepted new connection.")
			defer func() {
				err := conn.Close()
				log.WithError(err).Info("Closed connection.")
			}()

			if hasSyscallConn, ok := conn.(utils.HasSyscallConn); ok {
				mtu, err := utils.ConnMTU(hasSyscallConn)
				log.WithError(err).Infof("server start PMTU: %d", mtu)

				defer func() {
					mtu, err := utils.ConnMTU(hasSyscallConn)
					log.WithError(err).Infof("server end PMTU: %d", mtu)
				}()
			}

			decoder := json.NewDecoder(conn)
			w := bufio.NewWriter(conn)

			for {
				var request connectivity.Request

				err := decoder.Decode(&request)
				if err != nil {
					log.WithError(err).Error("failed to read request")
					return
				}

				if request.SendSize > 0 {
					rcv := request.SendSize
					buff := make([]byte, 4096)

					r := decoder.Buffered()

					for rcv > 0 {
						n, err := r.Read(buff)
						rcv -= n
						if err == io.EOF {
							break
						}
					}

					for rcv > 0 {
						var err error
						n := 0
						if rcv < 4096 {
							n, err = conn.Read(buff[:rcv])
						} else {
							n, err = conn.Read(buff)
						}
						rcv -= n
						if err != nil {
							log.Errorf("Reading from connection failed. %d bytes too short\n", rcv)
							return
						}
					}
				}

				seenSrc := "<unknown>"
				seenLocal := "<unknown>"
				if conn.RemoteAddr() != nil {
					seenSrc = conn.RemoteAddr().String()
				}
				if conn.LocalAddr() != nil {
					seenLocal = conn.LocalAddr().String()
				}

				response := connectivity.Response{
					Timestamp:  time.Now(),
					SourceAddr: seenSrc,
					ServerAddr: seenLocal,
					Request:    request,
				}

				respBytes, err := json.Marshal(&response)
				if err != nil {
					log.Error("failed to marshall response while handling connection")
					return
				}
				respBytes = append(respBytes, '\n')
				_, err = w.Write(respBytes)
				if err != nil {
					log.Error("failed to write response while handling connection")
					return
				}
				err = w.Flush()
				if err != nil {
					log.Error("failed to write response while handling connection")
					return
				}

				if request.ResponseSize > 0 {
					wrt := bufio.NewWriter(conn)
					respBytes = make([]byte, request.ResponseSize)
					respBytes[request.ResponseSize-1] = '\n'
					n, err := wrt.Write(respBytes)
					if err != nil {
						log.Errorf("Writing to connection failed. %d bytes too short", request.ResponseSize-n)
						break
					}
					err = wrt.Flush()
					if err != nil {
						log.Errorf("Writing to connection failed to flush out %d bytes", request.ResponseSize-n)
						break
					}
				}
			}
		}

		// Listen on each port.
		for _, port := range ports {
			for _, ipAddress := range ipAddrs {
				var myAddr string
				if listenAnyIP {
					myAddr = "0.0.0.0"
				} else if strings.Contains(ipAddress, ":") {
					myAddr = "[" + ipAddress + "]"
				} else {
					myAddr = ipAddress
				}
				if !strings.HasPrefix(protocol, "ip") {
					myAddr += ":" + port
				}
				logCxt := log.WithFields(log.Fields{
					"protocol": protocol,
					"myAddr":   myAddr,
				})
				if strings.HasPrefix(protocol, "ip") {
					logCxt.Info("About to listen for raw IP packets")
					p, err := net.ListenPacket(protocol, myAddr)
					panicIfError(err)
					logCxt.Info("Listening for raw IP packets")

					go loopRespondingToPackets(logCxt, p)
				} else if protocol == "udp" {
					// Since UDP is connectionless, we can't use Listen() as we do for TCP.  Instead,
					// we use ListenPacket so that we can directly send/receive individual packets.
					logCxt.Info("About to listen for UDP packets")
					p, err := net.ListenPacket("udp", myAddr)
					panicIfError(err)
					logCxt.Info("Listening for UDP connections")

					go loopRespondingToPackets(logCxt, p)
				} else if protocol == "sctp" {
					portInt, err := strconv.Atoi(port)
					panicIfError(err)
					netIP, err := net.ResolveIPAddr("ip", ipAddress)
					panicIfError(err)
					sAddrs := &sctp.SCTPAddr{
						IPAddrs: []net.IPAddr{*netIP},
						Port:    portInt,
					}
					logCxt.Info("About to listen for SCTP connections")
					l, err := sctp.ListenSCTP("sctp", sAddrs)
					panicIfError(err)
					logCxt.Info("Listening for SCTP connections")
					go func() {
						defer l.Close()
						for {
							conn, err := l.Accept()
							panicIfError(err)
							go handleRequest(conn)
						}
					}()
				} else {
					logCxt.Info("About to listen for TCP connections")
					l, err := net.Listen("tcp", myAddr)
					panicIfError(err)
					logCxt.Info("Listening for TCP connections")
					go func() {
						defer l.Close()
						for {
							conn, err := l.Accept()
							panicIfError(err)
							go handleRequest(conn)
						}
					}()
				}
			}
		}
		for {
			time.Sleep(10 * time.Second)
		}
	})
	panicIfError(err)
}

func loopRespondingToPackets(logCxt *log.Entry, p net.PacketConn) {
	defer p.Close()
	for {
		buffer := make([]byte, 1024)
		n, addr, err := p.ReadFrom(buffer)
		panicIfError(err)

		var request connectivity.Request
		err = json.Unmarshal(buffer[:n], &request)
		if err != nil {
			logCxt.WithError(err).WithField("remoteAddr", addr).Info("Failed to parse data")
			continue
		}

		response := connectivity.Response{
			Timestamp:  time.Now(),
			SourceAddr: addr.String(),
			ServerAddr: p.LocalAddr().String(),
			Request:    request,
		}

		data, err := json.Marshal(&response)
		if err != nil {
			logCxt.WithError(err).WithField("remoteAddr", addr).Info("Failed to respond")
			continue
		}
		data = append(data, '\n')

		_, err = p.WriteTo(data, addr)

		if !connectivity.IsMessagePartOfStream(request.Payload) {
			// Only print when packet is not part of stream.
			logCxt.WithError(err).WithField("remoteAddr", addr).Info("Responded")
		}
	}
}

// doNetkitSetUp creates a netkit L2 pair instead of a veth pair for the workload.
// The primary (host-side) end stays in the host namespace; the peer is moved into
// the workload namespace. IP addresses, routes and sysctls are configured to match
// what DoWorkloadNetnsSetUp does for veth pairs.
func doNetkitSetUp(
	hostNlHandle *netlink.Handle,
	workloadNS ns.NetNS,
	ipAddrs []*cniv1.IPConfig,
	contIfName string,
	hostIfName string,
	routes []*net.IPNet,
	mtu int,
) error {
	// Clean up if host-side interface already exists.
	if oldLink, err := hostNlHandle.LinkByName(hostIfName); err == nil {
		if err = hostNlHandle.LinkDel(oldLink); err != nil {
			return fmt.Errorf("failed to delete old host interface %v: %v", hostIfName, err)
		}
		log.Infof("Cleaned up old host interface: %v", hostIfName)
	}

	// Determine IP versions present.
	var hasIPv4, hasIPv6 bool
	for _, addr := range ipAddrs {
		if addr.Address.IP.To4() != nil {
			hasIPv4 = true
			addr.Address.Mask = net.CIDRMask(32, 32)
		} else if addr.Address.IP.To16() != nil {
			hasIPv6 = true
			addr.Address.Mask = net.CIDRMask(128, 128)
		}
	}

	// Create netkit in host namespace, with peer placed in workload namespace.
	la := netlink.NewLinkAttrs()
	la.Name = hostIfName
	la.MTU = mtu
	nk := &netlink.Netkit{
		LinkAttrs: la,
		Mode:      netlink.NETKIT_MODE_L2,
	}
	nk.SetPeerAttrs(&netlink.LinkAttrs{
		Name:      contIfName,
		Namespace: netlink.NsFd(int(workloadNS.Fd())),
	})
	if err := netlink.LinkAdd(nk); err != nil {
		return fmt.Errorf("failed to add netkit pair (%s, %s): %w", hostIfName, contIfName, err)
	}
	log.Infof("Created netkit pair: host=%s container=%s (in workload NS)", hostIfName, contIfName)

	// Configure host-side interface: MAC, proxy_arp, bring up.
	hostLink, err := hostNlHandle.LinkByName(hostIfName)
	if err != nil {
		return fmt.Errorf("failed to find host-side netkit %s: %w", hostIfName, err)
	}
	hostMAC, _ := net.ParseMAC("ee:ee:ee:ee:ee:ee")
	if err := hostNlHandle.LinkSetHardwareAddr(hostLink, hostMAC); err != nil {
		log.Warnf("Failed to set MAC on %s: %v (using kernel-assigned MAC)", hostIfName, err)
	}

	// Host-side sysctls (proxy_arp, forwarding, etc.)
	if hasIPv4 {
		writeProcSysOrLog("/proc/sys/net/ipv4/conf/%s/route_localnet", hostIfName, "1")
		writeProcSysOrLog("/proc/sys/net/ipv4/neigh/%s/proxy_delay", hostIfName, "0")
		writeProcSysOrLog("/proc/sys/net/ipv4/conf/%s/proxy_arp", hostIfName, "1")
		writeProcSysOrLog("/proc/sys/net/ipv4/conf/%s/forwarding", hostIfName, "1")
	}
	if hasIPv6 {
		writeProcSysOrLog("/proc/sys/net/ipv6/conf/%s/accept_dad", hostIfName, "0")
		writeProcSysOrLog("/proc/sys/net/ipv6/conf/%s/disable_ipv6", hostIfName, "0")
		writeProcSysOrLog("/proc/sys/net/ipv6/conf/%s/proxy_ndp", hostIfName, "1")
		writeProcSysOrLog("/proc/sys/net/ipv6/conf/%s/forwarding", hostIfName, "1")
	}

	if err := hostNlHandle.LinkSetUp(hostLink); err != nil {
		return fmt.Errorf("failed to set %s up: %w", hostIfName, err)
	}

	// Configure container-side interface inside the workload namespace.
	err = workloadNS.Do(func(_ ns.NetNS) error {
		contLink, err := netlink.LinkByName(contIfName)
		if err != nil {
			return fmt.Errorf("failed to find container netkit %s: %w", contIfName, err)
		}

		if hasIPv6 {
			// Disable DAD before bringing the interface up.
			if err := writeProcSys(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_dad", contIfName), "0"); err != nil {
				return err
			}
		}

		if err := netlink.LinkSetUp(contLink); err != nil {
			return fmt.Errorf("failed to set %s up: %w", contIfName, err)
		}

		// Add IP addresses.
		for _, addr := range ipAddrs {
			if err := netlink.AddrAdd(contLink, &netlink.Addr{IPNet: &addr.Address}); err != nil {
				return fmt.Errorf("failed to add IP %v to %s: %w", addr.Address, contIfName, err)
			}
		}

		// Add IPv4 routes.
		if hasIPv4 {
			gw := net.IPv4(169, 254, 1, 1)
			gwNet := &net.IPNet{IP: gw, Mask: net.CIDRMask(32, 32)}
			if err := netlink.RouteAdd(&netlink.Route{
				LinkIndex: contLink.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
				Dst:       gwNet,
			}); err != nil {
				return fmt.Errorf("failed to add gateway route: %w", err)
			}
			for _, r := range routes {
				if r.IP.To4() == nil {
					continue
				}
				if err := netlink.RouteAdd(&netlink.Route{
					LinkIndex: contLink.Attrs().Index,
					Dst:       r,
					Gw:        gw,
				}); err != nil {
					return fmt.Errorf("failed to add IPv4 route %v: %w", r, err)
				}
			}
		}

		// Add IPv6 routes.
		if hasIPv6 {
			// Enable IPv6 in the namespace.
			_ = writeProcSys("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0")
			_ = writeProcSys("/proc/sys/net/ipv6/conf/default/disable_ipv6", "0")
			_ = writeProcSys("/proc/sys/net/ipv6/conf/lo/disable_ipv6", "0")

			// Get the host-side link-local address for use as IPv6 gateway.
			var hostIPv6 net.IP
			for i := range 10 {
				if i > 0 {
					time.Sleep(50 * time.Millisecond)
				}
				addrs, err := hostNlHandle.AddrList(hostLink, netlink.FAMILY_V6)
				if err == nil && len(addrs) > 0 {
					hostIPv6 = addrs[0].IP
					break
				}
			}
			if hostIPv6 == nil {
				return fmt.Errorf("failed to get IPv6 link-local address for %s", hostIfName)
			}
			for _, r := range routes {
				if r.IP.To4() != nil {
					continue
				}
				if err := netlink.RouteAdd(&netlink.Route{
					LinkIndex: contLink.Attrs().Index,
					Dst:       r,
					Gw:        hostIPv6,
				}); err != nil {
					return fmt.Errorf("failed to add IPv6 route %v: %w", r, err)
				}
			}
		}

		// Container-side sysctls (rp_filter, etc.)
		if hasIPv4 {
			_ = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", contIfName), "1")
		}

		return nil
	})
	return err
}

func writeProcSysOrLog(pathFmt, ifName, value string) {
	path := fmt.Sprintf(pathFmt, ifName)
	if err := writeProcSys(path, value); err != nil {
		log.Warnf("Failed to write %s=%s: %v", path, value, err)
	}
}

func writeProcSys(path, value string) error {
	return os.WriteFile(path, []byte(value), 0644)
}

func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
}

// doSidecarIptablesSetup generates some iptables rules to redirect a
// traffic to localhost:15001. This is to simulate a sidecar.
//
// Commands are a very simplified version of commands from
// https://github.com/istio/cni/blob/f1a08bef3f235de1ecb67074b741b0d4c5fd8c44/tools/deb/istio-iptables.sh
func doSidecarIptablesSetup() error {
	cmds := [][]string{
		{"iptables", "-t", "nat", "-N", "FV_WL_REDIRECT"},
		{"iptables", "-t", "nat", "-A", "FV_WL_REDIRECT", "-p", "tcp", "-j", "REDIRECT", "--to-port", "15001"},
		{"iptables", "-t", "nat", "-N", "FV_WL_OUTPUT"},
		{"iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "FV_WL_OUTPUT"},
		{"iptables", "-t", "nat", "-A", "FV_WL_OUTPUT", "!", "-d", "127.0.0.1/32", "-j", "FV_WL_REDIRECT"},
	}
	for _, cmd := range cmds {
		if err := utils.RunCommand(cmd[0], cmd[1:]...); err != nil {
			return err
		}
	}
	return nil
}
