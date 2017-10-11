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
	"bufio"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/ns"
	"github.com/docopt/docopt-go"
	reuse "github.com/jbenet/go-reuseport"
	log "github.com/sirupsen/logrus"

	"github.com/satori/go.uuid"

	"github.com/projectcalico/felix/fv/utils"
)

const usage = `test-connection: test connection to some target, for Felix FV testing.

Usage:
  test-connection <namespace-path> <ip-address> <port> [--source-port=<source>] [--protocol=<protocol>]

Options:
  --source-port=<source>  Source port to use for the connection [default: 0].
  --protocol=<protocol>  Protocol to test [default: tcp].

If connection is successful, test-connection exits successfully.

If connection is unsuccessful, test-connection panics and so exits with a failure status.`

func main() {
	log.SetLevel(log.DebugLevel)

	arguments, err := docopt.Parse(usage, nil, true, "v0.1", false)
	if err != nil {
		println(usage)
		log.WithError(err).Fatal("Failed to parse usage")
	}
	log.WithField("args", arguments).Info("Parsed arguments")
	namespacePath := arguments["<namespace-path>"].(string)
	ipAddress := arguments["<ip-address>"].(string)
	port := arguments["<port>"].(string)
	sourcePort := arguments["--source-port"].(string)
	log.Infof("Test connection from %v:%v to IP %v port %v", namespacePath, sourcePort, ipAddress, port)
	protocol := arguments["--protocol"].(string)

	// I found that configuring the timeouts on all the network calls was a bit fiddly.  Since
	// it leaves the process hung if one of them is missed, use a global timeout instead.
	go func() {
		time.Sleep(2 * time.Second)
		panic("Timed out")
	}()

	if namespacePath == "-" {
		// Test connection from wherever we are already running.
		err = tryConnect(ipAddress, port, sourcePort, protocol)
	} else {
		// Get the specified network namespace (representing a workload).
		var namespace ns.NetNS
		namespace, err = ns.GetNS(namespacePath)
		if err != nil {
			panic(err)
		}
		log.WithField("namespace", namespace).Debug("Got namespace")

		// Now, in that namespace, try connecting to the target.
		err = namespace.Do(func(_ ns.NetNS) error {
			return tryConnect(ipAddress, port, sourcePort, protocol)
		})
	}

	if err != nil {
		panic(err)
	}
}

func tryConnect(ipAddress, port string, sourcePort string, protocol string) error {

	err := utils.RunCommand("ip", "r")
	if err != nil {
		return err
	}

	uid := uuid.NewV4().String()
	testMessage := "hello," + uid

	// The reuse library implements a version of net.Dialer that can reuse UDP/TCP ports, which we
	// need in order to make connection retries work.
	var d reuse.Dialer
	localAddr := "0.0.0.0:" + sourcePort
	if protocol == "udp" {
		remoteAddr := ipAddress + ":" + port
		log.Infof("Connecting from %v to %v", localAddr, remoteAddr)
		d.D.LocalAddr, err = net.ResolveUDPAddr("udp", localAddr)
		conn, err := d.Dial("udp", remoteAddr)
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		fmt.Fprintf(conn, testMessage+"\n")
		reply, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			panic(err)
		}
		reply = strings.TrimSpace(reply)
		if reply != testMessage {
			panic(errors.New("Unexpected reply: " + reply))
		}
	} else {
		d.D.LocalAddr, err = net.ResolveTCPAddr("tcp", localAddr)
		if err != nil {
			return err
		}
		conn, err := d.Dial("tcp", ipAddress+":"+port)
		if err != nil {
			return err
		}
		defer conn.Close()

		fmt.Fprintf(conn, testMessage+"\n")
		reply, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return err
		}
		reply = strings.TrimSpace(reply)
		if reply != testMessage {
			return errors.New("Unexpected reply: " + reply)
		}
	}

	return nil
}
