// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.
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
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/ns"
	"github.com/docopt/docopt-go"
	"github.com/ishidawataru/sctp"
	reuse "github.com/libp2p/go-reuseport"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/fv/utils"
)

const usage = `test-connection: test connection to some target, for Felix FV testing.

Usage:
  test-connection <namespace-path> <ip-address> <port> [--source-ip=<source_ip>] [--source-port=<source>] [--protocol=<protocol>] [--loop-with-file=<file>]

Options:
  --source-ip=<source_ip>  Source IP to use for the connection [default: 0.0.0.0].
  --source-port=<source_port>  Source port to use for the connection [default: 0].
  --protocol=<protocol>   Protocol to test [default: tcp].
  --loop-with-file=<file>  Whether to send messages repeatedly, file is used for synchronization

If connection is successful, test-connection exits successfully.

If connection is unsuccessful, test-connection panics and so exits with a failure status.`

// Note about the --loop-with-file=<FILE> flag:
//
// This flag takes a path to a file as a value. The file existence is
// used as a means of synchronization.
//
// Before this program is started, the file should exist. When the
// program establishes a long-running connection and sends the first
// message, it will remove the file. That way other process can assume
// that the connection is here when the file disappears and can
// perform some checks.
//
// If the other process creates the file again, it will tell this
// program to close the connection, remove the file and quit.

const defaultIPv4SourceIP = "0.0.0.0"
const defaultIPv6SourceIP = "::"

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
	sourceIpAddress := arguments["--source-ip"].(string)

	// Set default for source IP. If we're using IPv6 as indicated by ipAddress
	// and no --source-ip option was provided, set the source IP to the default
	// IPv6 address.
	if strings.Contains(ipAddress, ":") && sourceIpAddress == defaultIPv4SourceIP {
		sourceIpAddress = defaultIPv6SourceIP
	}

	log.Infof("Test connection from namespace %v IP %v port%v to IP %v port %v", namespacePath, sourceIpAddress, sourcePort, ipAddress, port)
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
		// Add the source IP (if set) to eth0.
		err = maybeAddAddr(sourceIpAddress)
		// Test connection from wherever we are already running.
		if err == nil {
			err = tryConnect(ipAddress, port, sourceIpAddress, sourcePort, protocol, loopFile)
		}
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
			// Add an interface for the source IP if any.
			e := maybeAddAddr(sourceIpAddress)
			if e != nil {
				return e
			}
			return tryConnect(ipAddress, port, sourceIpAddress, sourcePort, protocol, loopFile)
		})
	}

	if err != nil {
		panic(err)
	}
}

func maybeAddAddr(sourceIP string) error {
	if sourceIP != defaultIPv4SourceIP && sourceIP != defaultIPv6SourceIP {
		if !strings.Contains(sourceIP, ":") {
			sourceIP += "/32"
		} else {
			sourceIP += "/128"
		}

		// Check if the IP is already set on eth0.
		out, err := exec.Command("ip", "a", "show", "dev", "eth0").Output()
		if err != nil {
			return err
		}
		if strings.Contains(string(out), sourceIP) {
			log.Infof("IP addr %s already exists on eth0, skip adding IP", sourceIP)
			return nil
		}
		cmd := exec.Command("ip", "addr", "add", sourceIP, "dev", "eth0")
		return cmd.Run()
	}
	return nil
}

func tryConnect(remoteIpAddr, remotePort, sourceIpAddr, sourcePort, protocol, loopFile string) error {

	err := utils.RunCommand("ip", "r")
	if err != nil {
		return err
	}

	uid := uuid.NewV4().String()
	testMessage := "hello," + uid

	var localAddr string
	var remoteAddr string
	if strings.Contains(remoteIpAddr, ":") {
		localAddr = "[" + sourceIpAddr + "]:" + sourcePort
		remoteAddr = "[" + remoteIpAddr + "]:" + remotePort
	} else {
		localAddr = sourceIpAddr + ":" + sourcePort
		remoteAddr = remoteIpAddr + ":" + remotePort
	}
	ls := newLoopState(loopFile)
	log.Infof("Connecting from %v to %v over %s", localAddr, remoteAddr, protocol)
	if protocol == "udp" {
		// Since we specify the source port rather than use an ephemeral port, if
		// the SO_REUSEADDR and SO_REUSEPORT options are not set, when we make
		// another call to this program, the original port is in post-close wait
		// state and bind fails.  The reuse library implements a Dial() that sets
		// these options.
		conn, err := reuse.Dial("udp", localAddr, remoteAddr)
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
	} else if protocol == "sctp" {
		lip, err := net.ResolveIPAddr("ip", "::")
		if err != nil {
			return err
		}
		lport, err := strconv.Atoi(sourcePort)
		if err != nil {
			return err
		}
		laddr := &sctp.SCTPAddr{IPAddrs: []net.IPAddr{*lip}, Port: lport}
		rip, err := net.ResolveIPAddr("ip", remoteIpAddr)
		if err != nil {
			return err
		}
		rport, err := strconv.Atoi(remotePort)
		if err != nil {
			return err
		}
		raddr := &sctp.SCTPAddr{IPAddrs: []net.IPAddr{*rip}, Port: rport}
		// Since we specify the source port rather than use an ephemeral port, if
		// the SO_REUSEADDR and SO_REUSEPORT options are not set, when we make
		// another call to this program, the original port is in post-close wait
		// state and bind fails. The reuse.Dial() does not support SCTP, but the
		// SCTP library has a SocketConfig that accepts a Control function
		// (provided by reuse) that sets these options.
		sCfg := sctp.SocketConfig{Control: reuse.Control}
		conn, err := sCfg.Dial("sctp", laddr, raddr)
		if err != nil {
			panic(err)
		}
		defer conn.Close()
		log.Infof("SCTP connection established")

		for {
			fmt.Fprintf(conn, testMessage+"\n")
			log.WithField("message", testMessage).Info("Sent message over sctp")
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
	} else {
		if err != nil {
			return err
		}
		// Since we specify the source port rather than use an ephemeral port, if
		// the SO_REUSEADDR and SO_REUSEPORT options are not set, when we make
		// another call to this program, the original port is in post-close wait
		// state and bind fails.  The reuse library implements a Dial() that sets
		// these options.
		conn, err := reuse.Dial("tcp", localAddr, remoteAddr)
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
