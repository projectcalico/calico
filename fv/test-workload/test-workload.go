// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/ns"
	"github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/felix/fv/utils"
)

const usage = `test-workload, test workload for Felix FV testing.

Usage:
  test-workload <interface-name> <ip-address> <ports>
`

func main() {
	log.SetLevel(log.DebugLevel)

	arguments, err := docopt.Parse(usage, nil, true, "v0.1", false)
	if err != nil {
		println(usage)
		log.WithError(err).Fatal("Failed to parse usage")
	}
	interfaceName := arguments["<interface-name>"].(string)
	ipAddress := arguments["<ip-address>"].(string)
	portsStr := arguments["<ports>"].(string)
	panicIfError(err)

	ports := strings.Split(portsStr, ",")

	// Create a new network namespace for the workload.
	namespace, err := ns.NewNS()
	panicIfError(err)
	log.WithField("namespace", namespace).Debug("Created namespace")

	// Create a veth pair.
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: interfaceName},
		PeerName:  "w" + interfaceName,
	}
	err = netlink.LinkAdd(veth)
	panicIfError(err)
	log.WithField("veth", veth).Debug("Created veth pair")

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
		err = utils.RunCommand("ip", "addr", "add", ipAddress+"/32", "dev", "eth0")
		if err != nil {
			return
		}
		err = utils.RunCommand("ip", "route", "add", "169.254.169.254/32", "dev", "eth0")
		if err != nil {
			return
		}
		err = utils.RunCommand("ip", "route", "add", "default", "via", "169.254.169.254", "dev", "eth0")
		return
	})
	panicIfError(err)

	// Set the host end up too.
	hostIf, err := netlink.LinkByName(veth.LinkAttrs.Name)
	log.WithField("hostIf", hostIf).Debug("Host end")
	panicIfError(err)
	err = netlink.LinkSetUp(hostIf)
	panicIfError(err)

	// Print out the namespace path, so that test code can pick it up and execute subsequent
	// operations in the same namespace - which (in the context of this FV framework)
	// effectively means _as_ this workload.
	fmt.Println(namespace.Path())

	// Now listen on the specified ports in the workload namespace.
	err = namespace.Do(func(_ ns.NetNS) error {

		handleRequest := func(conn net.Conn) {
			log.WithFields(log.Fields{
				"localAddr":  conn.LocalAddr(),
				"remoteAddr": conn.RemoteAddr(),
			}).Info("Accepted new connection.")
			defer func() {
				conn.Close()
				log.Info("Closed connection.")
			}()

			for {
				buf := make([]byte, 1024)
				size, err := conn.Read(buf)
				if err != nil {
					return
				}
				data := buf[:size]
				log.WithField("data", data).Info("Read data from connection")
				conn.Write(data)
			}
		}

		// Listen on each port.
		for _, port := range ports {
			log.WithField("port", port).Info("About to listen for connections")
			l, err := net.Listen("tcp", ipAddress+":"+port)
			panicIfError(err)
			log.WithField("port", port).Info("Listening for connections")

			go func() {
				defer l.Close()
				for {
					conn, err := l.Accept()
					panicIfError(err)
					go handleRequest(conn)
				}
			}()
		}

		for {
			time.Sleep(10 * time.Second)
		}

		return nil
	})
	panicIfError(err)
}

func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
	return
}
