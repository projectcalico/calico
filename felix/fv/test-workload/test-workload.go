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
	"time"

	"github.com/projectcalico/calico/felix/fv/cgroup"
	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/utils"

	"github.com/containernetworking/plugins/pkg/ns"
	nsutils "github.com/containernetworking/plugins/pkg/testutils"
	"github.com/docopt/docopt-go"
	"github.com/ishidawataru/sctp"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const usage = `test-workload, test workload for Felix FV testing.

If <interface-name> is "", the workload will start in the current namespace.

Usage:
  test-workload [--protocol=<protocol>] [--namespace-path=<path>] [--sidecar-iptables] [--up-lo] [--mtu=<mtu>] <interface-name> <ip-address> <ports>
`

func main() {
	log.SetLevel(log.DebugLevel)

	// If we've been told to, move into this felix's cgroup.
	cgroup.MaybeMoveToFelixCgroupv2()

	arguments, err := docopt.ParseArgs(usage, nil, "v0.1")
	if err != nil {
		println(usage)
		log.WithError(err).Fatal("Failed to parse usage")
	}
	interfaceName := arguments["<interface-name>"].(string)
	ipAddress := arguments["<ip-address>"].(string)
	portsStr := arguments["<ports>"].(string)
	protocol := arguments["--protocol"].(string)
	nsPath := ""
	if arg, ok := arguments["--namespace-path"]; ok && arg != nil {
		nsPath = arg.(string)
	}
	sidecarIptables := arguments["--sidecar-iptables"].(bool)
	upLo := arguments["--up-lo"].(bool)
	mtu := 1450
	if arg, ok := arguments["--mtu"]; ok && arg != nil {
		mtu, err = strconv.Atoi(arg.(string))
		panicIfError(err)
	}
	panicIfError(err)

	ports := strings.Split(portsStr, ",")

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
		log.WithField("namespace", namespace).Debug("Created namespace")

		peerName := "w" + interfaceName
		if len(peerName) > 11 {
			peerName = peerName[:11]
		}
		// Create a veth pair.
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name: interfaceName,
				MTU:  mtu,
			},
			PeerName: peerName,
		}
		err = netlink.LinkAdd(veth)
		panicIfError(err)
		log.WithField("veth", veth).Debug("Created veth pair")

		err := netlink.LinkSetUp(veth)
		panicIfError(err)

		peerVeth, err := netlink.LinkByName(veth.PeerName)
		panicIfError(err)

		// Need to set the peer up in order to get an IPv6 address.
		err = netlink.LinkSetUp(peerVeth)
		panicIfError(err)

		var hostIPv6Addr net.IP
		if strings.Contains(ipAddress, ":") {
			attempts := 0
			for {
				// No need to add a dummy next hop route as the host veth device will already have an IPv6
				// link local address that can be used as a next hop.
				// Just fetch the address of the host end of the veth and use it as the next hop.
				addresses, err := netlink.AddrList(veth, netlink.FAMILY_V6)
				if err != nil {
					log.WithError(err).Panic("Error listing IPv6 addresses for the host side of the veth pair")
				}

				if len(addresses) < 1 {
					attempts++
					if attempts > 30 {
						log.WithError(err).Panic("Giving up waiting for IPv6 addresses after multiple retries")
					}

					time.Sleep(100 * time.Millisecond)
					continue
				}

				hostIPv6Addr = addresses[0].IP
				break
			}
		}

		// Move the workload end of the pair into the namespace, and set it up.
		workloadIf, err := netlink.LinkByName(veth.PeerName)
		log.WithField("workloadIf", workloadIf).Debug("Workload end")
		panicIfError(err)
		err = netlink.LinkSetNsFd(workloadIf, int(namespace.Fd()))
		panicIfError(err)
		err = namespace.Do(func(_ ns.NetNS) (err error) {
			err = utils.RunCommand("ip", "link", "set", veth.PeerName, "name", "eth0")
			if err != nil {
				return
			}
			err = utils.RunCommand("ip", "link", "set", "eth0", "up")
			if err != nil {
				return
			}

			err = utils.RunCommand("ip", "link", "set", "dev", "lo", "up")
			if err != nil {
				log.WithError(err).Info("Failed to set dev lo up")
			}

			if strings.Contains(ipAddress, ":") {
				// Make sure ipv6 is enabled in the container/pod network namespace.
				// Without these sysctls enabled, interfaces will come up but they won't get a link local IPv6 address,
				// which is required to add the default IPv6 route.
				if err = writeProcSys("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0"); err != nil {
					log.WithError(err).Error("Failed to enable IPv6.")
					return
				}

				if err = writeProcSys("/proc/sys/net/ipv6/conf/default/disable_ipv6", "0"); err != nil {
					log.WithError(err).Error("Failed to enable IPv6 by default.")
					return
				}

				if err = writeProcSys("/proc/sys/net/ipv6/conf/lo/disable_ipv6", "0"); err != nil {
					log.WithError(err).Error("Failed to enable IPv6 on the loopback interface.")
					return
				}

				err = utils.RunCommand("ip", "-6", "addr", "add", ipAddress+"/128", "dev", "eth0")
				if err != nil {
					log.WithField("ipAddress", ipAddress+"/128").WithError(err).Error("Failed to add IPv6 addr to eth0.")
					return
				}
				err = utils.RunCommand("ip", "-6", "route", "add", "default", "via", hostIPv6Addr.String(), "dev", "eth0")
				if err != nil {
					log.WithField("hostIP", hostIPv6Addr.String()).WithError(err).Info("Failed to add IPv6 route to eth0.")
					return
				}

				// Output the routing table to the log for diagnostic purposes.
				err = utils.RunCommand("ip", "-6", "route")
				if err != nil {
					log.WithError(err).Info("Failed to output IPv6 routes.")
				}
				err = utils.RunCommand("ip", "-6", "addr")
				if err != nil {
					log.WithError(err).Info("Failed to output IPv6 addresses.")
				}
			} else {
				err = utils.RunCommand("ip", "addr", "add", ipAddress+"/32", "dev", "eth0")
				if err != nil {
					log.WithField("ipAddress", ipAddress+"/32").WithError(err).Error("Failed to add IPv4 addr to eth0.")
					return
				}
				err = utils.RunCommand("ip", "route", "add", "169.254.169.254/32", "dev", "eth0")
				if err != nil {
					log.WithField("hostIP", hostIPv6Addr.String()).WithError(err).Info("Failed to add IPv4 route to eth0.")
					return
				}
				err = utils.RunCommand("ip", "route", "add", "default", "via", "169.254.169.254", "dev", "eth0")
				if err != nil {
					log.WithField("hostIP", hostIPv6Addr.String()).WithError(err).Info("Failed to add default route to eth0.")
					return
				}

				// Output the routing table to the log for diagnostic purposes.
				err = utils.RunCommand("ip", "route")
				if err != nil {
					log.WithError(err).Info("Failed to output IPv4 routes.")
					return
				}
				err = utils.RunCommand("ip", "addr")
				if err != nil {
					log.WithError(err).Info("Failed to output IPv4 addresses.")
					return
				}
			}
			return
		})
		panicIfError(err)

		// Set the host end up too.
		hostIf, err := netlink.LinkByName(veth.LinkAttrs.Name)
		log.WithField("hostIf", hostIf).Debug("Host end")
		panicIfError(err)
		err = netlink.LinkSetUp(hostIf)
		panicIfError(err)
	} else {
		namespace, err = ns.GetCurrentNS()
		panicIfError(err)
	}

	// Print out the namespace path, so that test code can pick it up and execute subsequent
	// operations in the same namespace - which (in the context of this FV framework)
	// effectively means _as_ this workload.
	fmt.Println(namespace.Path())

	// Now listen on the specified ports in the workload namespace.
	err = namespace.Do(func(_ ns.NetNS) error {
		if upLo {
			if err := utils.RunCommand("ip", "link", "set", "lo", "up"); err != nil {
				return fmt.Errorf("failed to bring loopback up: %v", err)
			}
		}
		if sidecarIptables {
			if err := doSidecarIptablesSetup(); err != nil {
				return fmt.Errorf("failed to setup sidecar-like iptables: %v", err)
			}
		}
		if strings.Contains(ipAddress, ":") {
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

				response := connectivity.Response{
					Timestamp:  time.Now(),
					SourceAddr: conn.RemoteAddr().String(),
					ServerAddr: conn.LocalAddr().String(),
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
			var myAddr string
			if strings.Contains(ipAddress, ":") {
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

func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
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
