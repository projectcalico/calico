// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/docopt/docopt-go"
	"github.com/google/uuid"
	"github.com/ishidawataru/sctp"
	reuse "github.com/libp2p/go-reuseport"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/fv/cgroup"
	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/utils"
)

const usage = `test-connection: test connection to some target, for Felix FV testing.

Usage:
  test-connection <namespace-path> <ip-address> <port> [--source-ip=<source_ip>] [--source-port=<source>] [--protocol=<protocol>] [--duration=<seconds>] [--loop-with-file=<file>] [--sendlen=<bytes>] [--recvlen=<bytes>] [--log-pongs] [--stdin] [--timeout=<seconds>] [--sleep=<seconds>]

Options:
  --source-ip=<source_ip>  Source IP to use for the connection [default: 0.0.0.0].
  --source-port=<source>   Source port to use for the connection [default: 0].
  --protocol=<protocol>    Protocol to test tcp (default), udp (connected) udp-noconn (unconnected).
  --duration=<seconds>     Total seconds test should run. 0 means run a one off connectivity check. Non-Zero means packets loss test.[default: 0]
  --loop-with-file=<file>  Whether to send messages repeatedly, file is used for synchronization
  --log-pongs              Whether to log every response
  --debug                  Enable debug logging
  --sendlen=<bytes>        How many additional bytes to send
  --recvlen=<bytes>        Tell the other side to send this many additional bytes
  --stdin                  Read and send data from stdin
  --timeout=<seconds>      Exit after timeout if pong not received
  --sleep=<seconds>        How long to sleep before seding another ping

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
	log.SetLevel(log.InfoLevel)

	// If we've been told to, move into this felix's cgroup.
	cgroup.MaybeMoveToFelixCgroupv2()

	arguments, err := docopt.ParseArgs(usage, nil, "v0.1")
	if err != nil {
		println(usage)
		log.WithError(err).Fatal("Failed to parse usage")
	}
	log.WithField("args", arguments).Info("Parsed arguments")
	namespacePath := arguments["<namespace-path>"].(string)
	ipAddress := arguments["<ip-address>"].(string)
	protocol := arguments["--protocol"].(string)
	port := ""
	sourcePort := ""
	// No such thing as a port for raw IP.
	if !strings.HasPrefix(protocol, "ip") {
		port = arguments["<port>"].(string)
		sourcePort = arguments["--source-port"].(string)
	}
	sourceIpAddress := arguments["--source-ip"].(string)
	if debug, err := arguments.Bool("--debug"); err == nil && debug {
		log.SetLevel(log.DebugLevel)
		log.Debug("Debug logging enabled")
	}

	sendLenStr, _ := arguments["--sendlen"].(string)
	recvLenStr, _ := arguments["--recvlen"].(string)

	sendLen := 0
	if sendLenStr != "" {
		sendLen, _ = strconv.Atoi(sendLenStr)
	}
	recvLen := 0
	if recvLenStr != "" {
		recvLen, _ = strconv.Atoi(recvLenStr)
	}

	// Set default for source IP. If we're using IPv6 as indicated by ipAddress
	// and no --source-ip option was provided, set the source IP to the default
	// IPv6 address.
	if strings.Contains(ipAddress, ":") && sourceIpAddress == defaultIPv4SourceIP {
		sourceIpAddress = defaultIPv6SourceIP
	}

	duration := arguments["--duration"].(string)
	seconds, err := strconv.Atoi(duration)
	if err != nil {
		// panic on error
		log.WithField("duration", duration).Fatal("Invalid duration argument")
	}
	loopFile := ""
	if arg, ok := arguments["--loop-with-file"]; ok && arg != nil {
		loopFile = arg.(string)
	}

	logPongs, err := arguments.Bool("--log-pongs")
	if err != nil {
		log.WithError(err).Fatal("Invalid --log-pongs")
	}

	stdin, err := arguments.Bool("--stdin")
	if err != nil {
		log.WithError(err).Fatal("Invalid --stdin")
	}

	var timeout, sleep time.Duration

	if toval := arguments["--timeout"]; toval != nil {
		timeoutSecs, err := strconv.ParseFloat(toval.(string), 64)
		if err != nil {
			// panic on error
			log.WithField("timeout", timeout).Fatal("Invalid --timeout argument")
		}
		timeout = time.Duration(timeoutSecs * float64(time.Second))
	}

	if toval := arguments["--sleep"]; toval != nil {
		secs, err := strconv.ParseFloat(toval.(string), 64)
		if err != nil {
			// panic on error
			log.WithField("sleep", sleep).Fatal("Invalid --sleep argument")
		}
		sleep = time.Duration(secs * float64(time.Second))
	}

	log.Infof("Test connection from namespace %v IP %v port %v to IP %v port %v proto %v "+
		"max duration %d seconds, timeout %v logging pongs (%v), stdin %v",
		namespacePath, sourceIpAddress, sourcePort, ipAddress, port, protocol, seconds, timeout, logPongs, stdin)

	if loopFile == "" {
		// I found that configuring the timeouts on all the network calls was a bit fiddly.  Since
		// it leaves the process hung if one of them is missed, use a global timeout instead.
		go func() {
			timeout := time.Duration(seconds + 2)
			time.Sleep(timeout * time.Second)
			log.Fatal("Timed out")
		}()
	}

	if namespacePath == "-" {
		// Add the source IP (if set) to eth0.
		err = maybeAddAddr(sourceIpAddress)
		// Test connection from wherever we are already running.
		if err == nil {
			err = tryConnect(ipAddress, port, sourceIpAddress, sourcePort, protocol,
				seconds, loopFile, sendLen, recvLen, logPongs, stdin, timeout, sleep)
		}
	} else {
		// Get the specified network namespace (representing a workload).
		var namespace ns.NetNS
		namespace, err = ns.GetNS(namespacePath)
		if err != nil {
			log.WithError(err).Fatal("Failed to get netns")
		}
		log.WithField("namespace", namespace).Debug("Got namespace")

		// Now, in that namespace, try connecting to the target.
		err = namespace.Do(func(_ ns.NetNS) error {
			// Add an interface for the source IP if any.
			e := maybeAddAddr(sourceIpAddress)
			if e != nil {
				return e
			}
			return tryConnect(ipAddress, port, sourceIpAddress, sourcePort, protocol,
				seconds, loopFile, sendLen, recvLen, logPongs, stdin, timeout, sleep)
		})
	}

	if err != nil {
		log.WithError(err).Fatal("Failed to connect")
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

type statistics struct {
	totalReq   int
	totalReply int
}

type testConn struct {
	stat statistics

	config   connectivity.ConnConfig
	protocol protocolDriver
	duration time.Duration

	sendLen int
	recvLen int
	stdin   bool
}

type protocolDriver interface {
	Connect() error
	Send(msg []byte) error
	Receive() ([]byte, error)
	Close() error
	SetReadDeadline(t time.Time) error

	MTU() (int, error)
}

func NewTestConn(remoteIpAddr, remotePort, sourceIpAddr, sourcePort, protocol string,
	duration time.Duration, sendLen, recvLen int, stdin bool) (*testConn, error) {
	err := utils.RunCommand("ip", "r")
	if err != nil {
		return nil, err
	}

	var localAddr string
	var remoteAddr string
	if strings.Contains(remoteIpAddr, ":") {
		localAddr = "[" + sourceIpAddr + "]"
		remoteAddr = "[" + remoteIpAddr + "]"
	} else {
		localAddr = sourceIpAddr
		remoteAddr = remoteIpAddr
	}

	if !strings.HasPrefix(protocol, "ip") {
		// All the protocols apart from our raw IP protocol have ports.
		localAddr += ":" + sourcePort
		remoteAddr += ":" + remotePort
	}

	log.Infof("Connecting from %v to %v over %s", localAddr, remoteAddr, protocol)

	var driver protocolDriver

	if strings.HasPrefix(protocol, "ip") {
		driver = &rawIP{
			localAddr:  localAddr,
			remoteAddr: remoteAddr,
			protocol:   protocol,
		}
	} else {
		switch protocol {
		case "udp":
			driver = &connectedUDP{
				localAddr:  localAddr,
				remoteAddr: remoteAddr,
			}
		case "udp-recvmsg":
			driver = &connectedUDP{
				localAddr:   localAddr,
				remoteAddr:  remoteAddr,
				useReadFrom: true,
			}
		case "udp-noconn":
			driver = &unconnectedUDP{
				localAddr:  localAddr,
				remoteAddr: remoteAddr,
			}
		case "sctp":
			driver = &connectedSCTP{
				sourcePort:   sourcePort,
				remoteIpAddr: remoteIpAddr,
				remotePort:   remotePort,
			}
		default:
			driver = &connectedTCP{
				localAddr:  localAddr,
				remoteAddr: remoteAddr,
			}
		}
	}

	err = driver.Connect()
	if err != nil {
		return nil, err
	}

	var connType string
	if duration == time.Duration(0) {
		connType = connectivity.ConnectionTypePing
	} else {
		connType = connectivity.ConnectionTypeStream
		if protocol != "udp" {
			log.Fatal("Wrong protocol for packets loss test")
		}
	}

	log.Infof("%s connection established from %v to %v", connType, localAddr, remoteAddr)
	return &testConn{
		config:   connectivity.ConnConfig{ConnType: connType, ConnID: uuid.NewString()},
		protocol: driver,
		duration: duration,
		sendLen:  sendLen,
		recvLen:  recvLen,
		stdin:    stdin,
	}, nil

}

func tryConnect(remoteIPAddr, remotePort, sourceIPAddr, sourcePort, protocol string,
	seconds int, loopFile string, sendLen, recvLen int, logPongs, stdin bool, timeout, sleep time.Duration) error {

	tc, err := NewTestConn(remoteIPAddr, remotePort, sourceIPAddr, sourcePort, protocol,
		time.Duration(seconds)*time.Second, sendLen, recvLen, stdin)
	if err != nil {
		tc.sendErrorResp(err)
		log.WithError(err).Fatal("Failed to create TestConn")
	}
	defer func() {
		_ = tc.Close()
	}()

	if remotePort == "6443" {
		// Testing for connectivity to the Kubernetes API server.  If we reach here, we're
		// good.  Skip sending and receiving any data, as that would need TLS.
		connectivity.Result{
			LastResponse: connectivity.Response{
				Timestamp:  time.Now(),
				SourceAddr: sourceIPAddr,
				ServerAddr: remoteIPAddr,
				Request: connectivity.Request{
					Payload: "Dummy request: TCP handshake only for API server connection testing",
				},
			},
			Stats: connectivity.Stats{
				RequestsSent:      1,
				ResponsesReceived: 1,
			},
			ClientMTU: connectivity.MTUPair{},
		}.PrintToStdout()
		return nil
	}

	if remotePort == "5473" {
		// Testing for connectivity to Typha. If we reach here, we're good.
		// Skip sending and receiving any data.
		connectivity.Result{
			LastResponse: connectivity.Response{
				Timestamp:  time.Now(),
				SourceAddr: sourceIPAddr,
				ServerAddr: remoteIPAddr,
				Request: connectivity.Request{
					Payload: "Dummy request: TCP handshake only for Typha connection testing",
				},
			},
			Stats: connectivity.Stats{
				RequestsSent:      1,
				ResponsesReceived: 1,
			},
			ClientMTU: connectivity.MTUPair{},
		}.PrintToStdout()
		return nil
	}

	if loopFile != "" {
		return tc.tryLoopFile(loopFile, logPongs, timeout, sleep)
	}

	if tc.config.ConnType == connectivity.ConnectionTypePing {
		return tc.tryConnectOnceOff(timeout)
	}

	return tc.tryConnectWithPacketLoss()
}

func (tc *testConn) GetTestMessage(sequence int) connectivity.Request {
	req := tc.config.GetTestMessage(sequence)
	req.SendSize = tc.sendLen
	req.ResponseSize = tc.recvLen

	return req
}

func (tc *testConn) tryLoopFile(loopFile string, logPongs bool, timeout, sleep time.Duration) error {
	req := tc.GetTestMessage(0)
	msg, err := json.Marshal(req)
	if err != nil {
		log.WithError(err).Panic("Failed to marshall request")
	}

	ls := newLoopState(loopFile)
	ls.sleep = sleep
	var lastResponse connectivity.Response

	var retryStart time.Time

	for {
		err = tc.protocol.Send(msg)
		if err != nil {
			log.WithError(err).Fatal("Failed to send")
		}
		tc.stat.totalReq++

		var respRaw []byte

		if timeout > 0 {
			if err := tc.protocol.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
				return err
			}
			if retryStart.IsZero() {
				retryStart = time.Now()
			}
		}
		var err error
		respRaw, err = tc.protocol.Receive()
		if err == nil {
			if logPongs {
				fmt.Println("PONG")
			}
			retryStart = time.Time{}
		} else if os.IsTimeout(err) {
			fmt.Printf("receive timeout\n")
			if timeout > 0 {
				if time.Since(retryStart) > timeout {
					log.WithError(err).Fatalf("Failed to receive after %+v", timeout)
				} else {
					continue
				}
			}
			if !ls.Next() {
				break
			}
			continue
		} else {
			fmt.Printf("err = %+v\n", err)
			// If the initial exchange has completed and the loop file exists,
			// we were asked to stop. The connection error is expected during
			// shutdown, so exit cleanly. We only check after sentInitial so
			// that startup failures still fail loudly (the loop file is
			// expected to exist before the first successful exchange).
			if ls.sentInitial && ls.loopFile != "" {
				if _, statErr := os.Stat(ls.loopFile); statErr == nil {
					log.WithError(err).Info("Connection error during shutdown, exiting cleanly")
					if rmErr := os.Remove(ls.loopFile); rmErr != nil {
						log.WithError(rmErr).Info("Failed to remove loop file during shutdown")
					}
					break
				}
			}
			log.WithError(err).Fatal("Failed to receive")
		}

		var resp connectivity.Response
		err = json.Unmarshal(respRaw, &resp)
		if err != nil {
			log.WithError(err).Panic("Failed to unmarshall response")
		}

		if !resp.Request.Equal(req) {
			log.WithField("reply", resp).Fatal("Unexpected response")
		}
		tc.stat.totalReply++

		lastResponse = resp
		if !ls.Next() {
			break
		}
	}
	res := connectivity.Result{
		LastResponse: lastResponse,
		Stats: connectivity.Stats{
			RequestsSent:      tc.stat.totalReq,
			ResponsesReceived: tc.stat.totalReply,
		},
	}
	res.PrintToStdout()
	return nil
}

func (tc *testConn) sendErrorResp(err error) {
	var resp connectivity.Response
	resp.ErrorStr = err.Error()
	res := connectivity.Result{
		LastResponse: resp,
		Stats: connectivity.Stats{
			RequestsSent:      1,
			ResponsesReceived: 0,
		},
	}
	res.PrintToStdout()
}

func (tc *testConn) tryConnectOnceOff(timeout time.Duration) error {
	log.Info("Doing single-shot test...")
	if timeout != 0 {
		done := make(chan struct{})
		defer func() {
			close(done)
		}()
		go func() {
			select {
			case <-done:
				return
			case <-time.After(timeout):
				log.Fatalf("Timed out after %.1fs", timeout.Seconds())
			}
		}()
	}

	if tc.stdin {
		var buf bytes.Buffer
		count, err := io.Copy(&buf, os.Stdin)
		log.WithError(err).WithField("count", count).Info("Read message bytes from stdin")
		err = tc.protocol.Send(buf.Bytes())
		if err != nil {
			log.WithError(err).Panic("Failed to send stdin request")
		}
		return nil
	}

	req := tc.GetTestMessage(0)
	msg, err := json.Marshal(req)
	if err != nil {
		log.WithError(err).Panic("Failed to marshall request")
	}

	mtuPair := connectivity.MTUPair{}
	mtuPair.Start, err = tc.protocol.MTU()
	if err != nil {
		log.WithError(err).Error("Failed to read connection MTU")
		return err
	}

	err = tc.protocol.Send(msg)
	if err != nil {
		log.WithError(err).Fatal("Failed to send")
	}

	if tc.sendLen > 0 {
		if err := tc.protocol.Send(make([]byte, tc.sendLen)); err != nil {
			log.WithError(err).Fatal("Failed send extra bytes")
		}
	}

	respRaw, err := tc.protocol.Receive()
	if err != nil {
		tc.sendErrorResp(err)
		log.WithError(err).Fatal("Failed to receive")
	}

	var resp connectivity.Response
	err = json.Unmarshal(respRaw, &resp)
	if err != nil {
		log.WithError(err).Panic("Failed to unmarshall response")
	}

	if !resp.Request.Equal(req) {
		log.WithField("reply", resp).Fatal("Unexpected response")
	}

	if tc.recvLen > 0 {
		bytes, err := tc.protocol.Receive()
		if len(bytes) < tc.recvLen {
			log.WithError(err).WithField("received extra bytes", len(bytes)).Fatal("Receive too short")
		}
		if err != nil {
			log.WithError(err).Fatal("Failed to receive extra bytes")
		}
	}

	mtuPair.End, err = tc.protocol.MTU()
	if err != nil {
		log.WithError(err).Fatal("Failed to get MTU")
	}

	res := connectivity.Result{
		LastResponse: resp,
		Stats: connectivity.Stats{
			RequestsSent:      1,
			ResponsesReceived: 1,
		},
		ClientMTU: mtuPair,
	}
	res.PrintToStdout()

	return nil
}

func (tc *testConn) tryConnectWithPacketLoss() error {
	ctx, cancel := context.WithTimeout(context.Background(), tc.duration)
	defer cancel()
	reqDone := make(chan int)

	log.Info("Start packet loss testing.")

	var wg sync.WaitGroup

	var lastResponse connectivity.Response

	// Start a reader
	wg.Go(func() {

		lastSequence := 0
		count := 0
		outOfOrder := 0
		maxGap := 0
		for {
			select {
			case reqTotal := <-reqDone:
				log.Infof("Reader completed.total req %d, total reply %d, last reply %d, outOfOrder %d, maxGap %d",
					reqTotal, count, lastSequence, outOfOrder, maxGap)

				if count > reqTotal {
					log.Fatal("Got more packets than we sent")
				}

				tc.stat.totalReq = reqTotal
				tc.stat.totalReply = count
				return
			default:
				// Deadline is point of time. Have to set it in the loop for each read.
				if err := tc.protocol.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
					log.WithError(err).Warn("Failed to set read deadline.")
					continue
				}
				respRaw, err := tc.protocol.Receive()

				if e, ok := err.(net.Error); ok && e.Timeout() {
					// This was a timeout. Nothing to read.
					log.Debugf("Read timeout. Total reply so far %d", count)
					continue
				} else if err != nil {
					// This is an error, not a timeout
					log.WithError(err).Fatal("Got non-timeout error while reading.")
				}

				var resp connectivity.Response
				err = json.Unmarshal(respRaw, &resp)
				if err != nil {
					log.WithError(err).Warning("Failed to unmarshall response")
					continue
				}
				lastResponse = resp

				lastSequence, err = tc.config.GetTestMessageSequence(resp.Request.Payload)
				if err != nil {
					log.WithError(err).Fatal("Failed to get test message sequence from payload")
				}

				if lastSequence != count {
					outOfOrder++
					if gap := int(math.Abs(float64(lastSequence - count))); gap > maxGap {
						maxGap = gap
					}
				}

				count++
			}
		}
	})

	// start a writer
	wg.Go(func() {

		count := 0
		for {
			select {
			case <-ctx.Done():
				log.Info("Timeout for writer.")

				// Grace period for reader to finish.
				time.Sleep(200 * time.Millisecond)
				reqDone <- count
				log.Info("Asked reader to complete.")

				return
			default:
				req := tc.GetTestMessage(count)
				msg, err := json.Marshal(req)
				if err != nil {
					log.WithError(err).Panic("Failed to marshall request")
				}

				err = tc.protocol.Send(msg)
				if err != nil {
					log.WithError(err).Fatal("Failed to send")
				}

				count++

				// Slow down sending request, otherwise we may get udp buffer overflow and loss packet,
				// which is not the right kind of packet loss we want to trace.
				// watch -n 1 'cat  /proc/net/udp' to monitor udp buffer overflow.

				// Max 200 packets per second.
				time.Sleep(5 * time.Millisecond)
			}
		}

	})

	// Wait for writer and reader to complete.
	wg.Wait()

	res := connectivity.Result{
		LastResponse: lastResponse,
		Stats: connectivity.Stats{
			RequestsSent:      tc.stat.totalReq,
			ResponsesReceived: tc.stat.totalReply,
		},
	}
	res.PrintToStdout()

	return nil
}

func (tc *testConn) Close() error {
	return tc.protocol.Close()
}

type loopState struct {
	sentInitial bool
	loopFile    string
	sleep       time.Duration
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
				log.Panicf("Failed to stat loop file %s: %v", l.loopFile, err)
			}
		} else {
			if err := os.Remove(l.loopFile); err != nil {
				log.Panicf("Could not remove loop file %s: %v", l.loopFile, err)
			}
			return false
		}
	} else {
		// A connection was just established and the initial
		// message was sent so we set the flag to true and
		// delete the loop file, so other process can continue
		// with the appropriate checks
		if err := os.Remove(l.loopFile); err != nil {
			log.Panicf("Could not remove loop file %s: %v", l.loopFile, err)
		}
		l.sentInitial = true
	}
	if l.sleep != 0 {
		time.Sleep(l.sleep)
	} else {
		time.Sleep(500 * time.Millisecond)
	}
	return true
}

// connectedUDP abstracts a connected UDP stream.  I.e. it calls connect() to bind the local end of
// the socket.  It can optionally use RecvFrom() when reading form the other side.
type connectedUDP struct {
	conn        *net.UDPConn
	r           *bufio.Reader
	localAddr   string
	remoteAddr  string
	useReadFrom bool
}

func (d *connectedUDP) SetReadDeadline(t time.Time) error {
	return d.conn.SetReadDeadline(t)
}

func (d *connectedUDP) Close() error {
	if d.conn == nil {
		return nil
	}
	log.Info("Closing UDP connection.")
	return d.conn.Close()
}

func (d *connectedUDP) Connect() error {
	// Since we specify the source port rather than use an ephemeral port, if
	// the SO_REUSEADDR and SO_REUSEPORT options are not set, when we make
	// another call to this program, the original port is in post-close wait
	// state and bind fails.  The reuse library implements a Dial() that sets
	// these options.
	conn, err := reuse.Dial("udp", d.localAddr, d.remoteAddr)
	if err != nil {
		return err
	}
	d.conn = conn.(*net.UDPConn)
	d.r = bufio.NewReader(d.conn)
	return nil
}

func (d *connectedUDP) Send(msg []byte) error {
	msg = append(msg, '\n')
	_, err := d.conn.Write(msg)
	return err
}

func (d *connectedUDP) Receive() ([]byte, error) {
	if d.useReadFrom {
		bufIn := make([]byte, 8<<10)
		n, from, err := d.conn.ReadFrom(bufIn)
		if err != nil {
			log.WithError(err).Error("Failed to read from")
		} else {
			log.Infof("Received %d bytes from %s", n, from)
		}
		return bytes.TrimRight(bufIn[:n], "\n"), err
	} else {
		log.Debug("Connected UDP buffered read")
		d.r.Reset(d.conn)
		return d.r.ReadBytes('\n')
	}
}

func (d *connectedUDP) MTU() (int, error) {
	return utils.ConnMTU(d.conn)
}

// unconnectedUDP abstracts an unconnected UDP stream.  I.e. it calls ListenPacket() to open the local side
// of the connection than then it uses SendTo and RecvFrom.
type unconnectedUDP struct {
	conn               net.PacketConn
	localAddr          string
	remoteAddr         string
	remoteAddrResolved *net.UDPAddr
}

func (d *unconnectedUDP) Close() error {
	if d.conn == nil {
		return nil
	}
	return d.conn.Close()
}

func (d *unconnectedUDP) Connect() error {
	log.Info("'Connecting' unconnected UDP")
	conn, err := net.ListenPacket("udp", d.localAddr)
	if err != nil {
		log.WithError(err).Fatal("Failed to listen UDP")
	}
	d.conn = conn
	remoteAddrResolved, err := net.ResolveUDPAddr("udp", d.remoteAddr)
	if err != nil {
		log.WithError(err).Fatal("Failed to resolve UDP")
	}
	log.WithFields(log.Fields{
		"addr":               conn.LocalAddr(),
		"remoteAddrResolved": remoteAddrResolved,
	}).Infof("Resolved udp addr")
	d.remoteAddrResolved = remoteAddrResolved
	return nil
}

func (d *unconnectedUDP) Send(msg []byte) error {
	_, err := d.conn.WriteTo(msg, d.remoteAddrResolved)
	if err != nil {
		return err
	}
	log.WithField("message", string(msg)).Infof("Sent message over unconnected UDP to %v", d.remoteAddr)
	return nil
}

func (d *unconnectedUDP) Receive() ([]byte, error) {
	bufIn := make([]byte, 8<<10)
	n, from, err := d.conn.ReadFrom(bufIn)
	if err != nil {
		log.WithError(err).Error("Failed to read from")
	} else {
		log.Infof("Received %d bytes from %s", n, from)
	}
	return bufIn[:n], err
}

func (d *unconnectedUDP) MTU() (int, error) {
	return 0, nil
}

func (d *unconnectedUDP) SetReadDeadline(t time.Time) error {
	return d.conn.SetReadDeadline(t)
}

// connectedSCTP abstracts an SCTP stream.
type connectedSCTP struct {
	sourcePort   string
	remoteIpAddr string
	remotePort   string

	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
}

// rawIP implements a raw IP connection on the given protocol number.  I.e. is sends the message as the body of the
// IP packet with no additional header.
type rawIP struct {
	localAddr          string
	remoteAddr         string
	protocol           string
	remoteAddrResolved net.Addr

	conn net.PacketConn
}

func (d *rawIP) Close() error {
	if d.conn == nil {
		return nil
	}
	return d.conn.Close()
}

func (d *rawIP) Connect() error {
	log.Info("'Connecting' raw IP, proto=", d.protocol)

	var err error
	d.remoteAddrResolved, err = net.ResolveIPAddr(d.protocol, d.remoteAddr)
	if err != nil {
		return err
	}

	d.conn, err = net.ListenPacket(d.protocol, d.localAddr)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	return nil
}

func (d *rawIP) Send(msg []byte) error {
	_, err := d.conn.WriteTo(msg, d.remoteAddrResolved)
	if err != nil {
		return err
	}
	log.WithField("message", string(msg)).Infof("Sent message over raw IP to %v", d.remoteAddr)
	return nil
}

func (d *rawIP) Receive() ([]byte, error) {
	bufIn := make([]byte, 8<<10)
	n, from, err := d.conn.ReadFrom(bufIn)
	if err != nil {
		log.WithError(err).Error("Failed to read from")
	} else {
		log.Infof("Received %d bytes from %s", n, from)
	}
	return bufIn[:n], err
}

func (d *rawIP) MTU() (int, error) {
	return 0, nil
}

func (d *rawIP) SetReadDeadline(t time.Time) error {
	return d.conn.SetReadDeadline(t)
}

func (d *connectedSCTP) Connect() error {
	lip, err := net.ResolveIPAddr("ip", "::")
	if err != nil {
		return err
	}
	lport, err := strconv.Atoi(d.sourcePort)
	if err != nil {
		return err
	}
	laddr := &sctp.SCTPAddr{IPAddrs: []net.IPAddr{*lip}, Port: lport}
	rip, err := net.ResolveIPAddr("ip", d.remoteIpAddr)
	if err != nil {
		return err
	}
	rport, err := strconv.Atoi(d.remotePort)
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
	d.conn, err = sCfg.Dial("sctp", laddr, raddr)
	if err != nil {
		return err
	}

	d.r = bufio.NewReader(d.conn)
	d.w = bufio.NewWriter(d.conn)

	return nil
}

func (d *connectedSCTP) Send(msg []byte) error {
	_, err := d.w.Write(msg)
	if err != nil {
		return err
	}
	return d.w.Flush()
}

func (d *connectedSCTP) Receive() ([]byte, error) {
	return d.r.ReadSlice('\n')
}

func (d *connectedSCTP) Close() error {
	if d.conn == nil {
		return nil
	}
	return d.conn.Close()
}

func (d *connectedSCTP) MTU() (int, error) {
	return 0, nil
}

func (d *connectedSCTP) SetReadDeadline(t time.Time) error {
	return d.conn.SetReadDeadline(t)
}

type tcpConn6 struct {
	s int
}

func (c *tcpConn6) Read(b []byte) (n int, err error) {
	return unix.Read(c.s, b)
}

func (c *tcpConn6) Write(b []byte) (n int, err error) {
	return unix.Write(c.s, b)
}

func (c *tcpConn6) Close() error {
	return unix.Close(c.s)
}

func (c *tcpConn6) LocalAddr() net.Addr {
	return nil
}

func (c *tcpConn6) RemoteAddr() net.Addr {
	return nil
}

func (c *tcpConn6) SetDeadline(t time.Time) error {
	return nil
}

func (c *tcpConn6) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *tcpConn6) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *tcpConn6) SyscallConn() (syscall.RawConn, error) {
	return &tcpConn6Raw{s: c.s}, nil
}

type tcpConn6Raw struct {
	s int
}

func (c *tcpConn6Raw) Control(f func(fd uintptr)) error {
	f(uintptr(c.s))
	return nil
}

func (c *tcpConn6Raw) Read(f func(fd uintptr) (done bool)) error {
	panic("not implemented")
}

func (c *tcpConn6Raw) Write(f func(fd uintptr) (done bool)) error {
	panic("not implemented")
}

func tcpForceV6(ip net.IP, port int) (net.Conn, error) {
	s, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}

	err = unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if err != nil {
		return nil, err
	}

	err = unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	if err != nil {
		return nil, err
	}

	saddr := unix.SockaddrInet6{
		Port: port,
	}

	copy(saddr.Addr[:], ip.To16())

	saddr.Addr[10] = 0xff
	saddr.Addr[11] = 0xff

	err = unix.Connect(s, &saddr)
	if err != nil {
		return nil, err
	}

	return &tcpConn6{s: s}, nil
}

// connectedTCP abstracts an SCTP stream.
type connectedTCP struct {
	localAddr  string
	remoteAddr string

	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
}

func (d *connectedTCP) Connect() error {
	// Since we specify the source port rather than use an ephemeral port, if
	// the SO_REUSEADDR and SO_REUSEPORT options are not set, when we make
	// another call to this program, the original port is in post-close wait
	// state and bind fails.  The reuse library implements a Dial() that sets
	// these options.

	var conn net.Conn

	if strings.Contains(d.remoteAddr, "[") {
		addr, port, _ := net.SplitHostPort(d.remoteAddr)
		ip := net.ParseIP(addr)
		if ip == nil {
			return fmt.Errorf("ip %s is invalid", addr)
		}
		if ip.To4() != nil {
			// We want to force ipv6 on ipv4 address
			var err error

			p, _ := strconv.Atoi(port)
			if conn, err = tcpForceV6(ip, p); err != nil {
				return fmt.Errorf("failed creating v6 connection for ip %s", d.remoteAddr)
			}
		}
	}

	if conn == nil {
		var err error
		conn, err = reuse.Dial("tcp", d.localAddr, d.remoteAddr)
		if err != nil {
			return err
		}
	}

	d.conn = conn

	d.r = bufio.NewReader(d.conn)
	d.w = bufio.NewWriter(d.conn)
	return nil
}

func (d *connectedTCP) Send(msg []byte) error {
	_, err := d.w.Write(msg)
	if err != nil {
		return err
	}
	return d.w.Flush()
}

func (d *connectedTCP) Receive() ([]byte, error) {
	err := d.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		return nil, err
	}
	return d.r.ReadSlice('\n')
}

func (d *connectedTCP) Close() error {
	if d.conn == nil {
		return nil
	}
	return d.conn.Close()
}

func (d *connectedTCP) MTU() (int, error) {
	return utils.ConnMTU(d.conn.(utils.HasSyscallConn))
}

func (d *connectedTCP) SetReadDeadline(t time.Time) error {
	return d.conn.SetReadDeadline(t)
}
