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

	"github.com/projectcalico/felix/fv/utils"
)

const usage = `test-connection: test connection to some target, for Felix FV testing.

Usage:
  test-connection <namespace-path> <ip-address> <port> [--source-port=<source>]

Options:
  --source-port=<source>  Source port to use for the connection [default: 0].

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

	if namespacePath == "-" {
		// Test connection from wherever we are already running.
		err = tryConnect(ipAddress, port, sourcePort)
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
			return tryConnect(ipAddress, port, sourcePort)
		})
	}

	if err != nil {
		panic(err)
	}
}

func tryConnect(ipAddress, port string, sourcePort string) error {

	err := utils.RunCommand("ip", "r")
	if err != nil {
		return err
	}

	const testMessage = "hello"

	// The reuse library implements a version of net.Dialer that can reuse TCP ports, which we
	// need in order to make connection retries work.  (Without that, the TCP port gets stuck in
	// one of the wait states and we're not allowed to reuse the same port.)
	var d reuse.Dialer
	d.D.Timeout = 5 * time.Second
	d.D.LocalAddr, err = net.ResolveTCPAddr("tcp", "0.0.0.0:"+sourcePort)
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

	return nil
}
