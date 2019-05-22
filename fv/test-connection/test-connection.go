// Copyright (c) 2017-2019 Tigera, Inc. All rights reserved.
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
	"os"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/ns"
	docopt "github.com/docopt/docopt-go"
	reuse "github.com/libp2p/go-reuseport"
	log "github.com/sirupsen/logrus"

	uuid "github.com/satori/go.uuid"

	"github.com/projectcalico/felix/fv/utils"
)

const usage = `test-connection: test connection to some target, for Felix FV testing.

Usage:
  test-connection <namespace-path> <ip-address> <port> [--source-port=<source>] [--protocol=<protocol>] [--loop-with-file=<file>]

Options:
  --source-port=<source>  Source port to use for the connection [default: 0].
  --protocol=<protocol>   Protocol to test [default: tcp].
  --loop-with-file=<file>  Whether to send messages repeatedly, file is used for synchronization

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
	loopFile := ""
	if arg, ok := arguments["--loop-with-file"]; ok && arg != nil {
		loopFile = arg.(string)
	}

	if loopFile == "" {
		// I found that configuring the timeouts on all the
		// network calls was a bit fiddly.  Since it leaves
		// the process hung if one of them is missed, use a
		// global timeout instead.
		go func() {
			time.Sleep(2 * time.Second)
			panic("Timed out")
		}()
	}

	if namespacePath == "-" {
		// Test connection from wherever we are already running.
		err = tryConnect(ipAddress, port, sourcePort, protocol, loopFile)
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
			return tryConnect(ipAddress, port, sourcePort, protocol, loopFile)
		})
	}

	if err != nil {
		panic(err)
	}
}

func tryConnect(ipAddress, port, sourcePort, protocol, loopFile string) error {

	err := utils.RunCommand("ip", "r")
	if err != nil {
		return err
	}

	uid := uuid.NewV4().String()
	testMessage := "hello," + uid

	// The reuse library implements a version of net.Dialer that can reuse UDP/TCP ports, which we
	// need in order to make connection retries work.
	var d reuse.Dialer
	var localAddr string
	var remoteAddr string
	if strings.Contains(ipAddress, ":") {
		localAddr = "[::]:" + sourcePort
		remoteAddr = "[" + ipAddress + "]:" + port
	} else {
		localAddr = "0.0.0.0:" + sourcePort
		remoteAddr = ipAddress + ":" + port
	}
	ls := newLoopState(loopFile)
	log.Infof("Connecting from %v to %v over %s", localAddr, remoteAddr, protocol)
	if protocol == "udp" {
		d.D.LocalAddr, _ = net.ResolveUDPAddr("udp", localAddr)
		log.WithFields(log.Fields{
			"addr":     localAddr,
			"resolved": d.D.LocalAddr,
		}).Infof("Resolved udp addr")
		conn, err := d.Dial("udp", remoteAddr)
		log.Infof(`UDP "connection" established`)
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		for {
			fmt.Fprintf(conn, testMessage+"\n")
			log.WithField("message", testMessage).Info("Sent message over udp")
			reply, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				panic(err)
			}
			reply = strings.TrimSpace(reply)
			log.WithField("reply", reply).Info("Got reply")
			if reply != testMessage {
				panic(errors.New("Unexpected reply: " + reply))
			}
			if !ls.Next() {
				break
			}
		}
	} else {
		d.D.LocalAddr, err = net.ResolveTCPAddr("tcp", localAddr)
		if err != nil {
			return err
		}
		log.WithFields(log.Fields{
			"addr":     localAddr,
			"resolved": d.D.LocalAddr,
		}).Infof("Resolved tcp addr")
		conn, err := d.Dial("tcp", remoteAddr)
		if err != nil {
			return err
		}
		defer conn.Close()
		log.Infof("TCP connection established")

		for {
			fmt.Fprintf(conn, testMessage+"\n")
			log.WithField("message", testMessage).Info("Sent message over tcp")
			reply, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				return err
			}
			reply = strings.TrimSpace(reply)
			log.WithField("reply", reply).Info("Got reply")
			if reply != testMessage {
				return errors.New("Unexpected reply: " + reply)
			}
			if !ls.Next() {
				break
			}
		}
	}

	return nil
}

type loopState struct {
	sentInitial bool
	loopFile    string
}

func newLoopState(loopFile string) *loopState {
	return &loopState{
		sentInitial: false,
		loopFile:    loopFile,
	}
}

func (l *loopState) Next() bool {
	if l.loopFile == "" {
		return false
	}

	if l.sentInitial {
		// This is after the connection was established in
		// previous iteration, so we wait for the loop file to
		// appear (it should be created by other process). If
		// the file exists, it means that the other process
		// wants us to delete the file, drop the connection
		// and quit.
		if _, err := os.Stat(l.loopFile); err != nil {
			if !os.IsNotExist(err) {
				panic(fmt.Errorf("Failed to stat loop file %s: %v", l.loopFile, err))
			}
		} else {
			if err := os.Remove(l.loopFile); err != nil {
				panic(fmt.Errorf("Could not remove loop file %s: %v", l.loopFile, err))
			}
			return false
		}
	} else {
		// A connection was just established and the initial
		// message was sent so we set the flag to true and
		// delete the loop file, so other process can continue
		// with the appropriate checks
		if err := os.Remove(l.loopFile); err != nil {
			panic(fmt.Errorf("Could not remove loop file %s: %v", l.loopFile, err))
		}
		l.sentInitial = true
	}
	time.Sleep(500 * time.Millisecond)
	return true
}
