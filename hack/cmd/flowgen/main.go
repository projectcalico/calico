// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

// flowgen opens new flows from the pod it runs in at a configured rate, for the node-level (K3)
// benchmark of the flow-log collector's pending-policy evaluation, see
// felix/design/flow-logs-policy-evaluation.md.
//
// Destinations and ports are drawn from the app-policy/policyscale preset applied to the cluster
// (same preset, same seed: same flows as `policyscale -flows` prints, so the expected verdict of
// every flow is known). Each flow is one datagram (UDP) or one connection attempt (TCP) from a
// fresh ephemeral port; the destinations need not exist, since the collector sees a flow as soon
// as conntrack does. The generator reports the achieved rate every second and a summary at the
// end, so a run that fell short of its target is visible in its own output.
//
//	kubectl label pod flowgen policyscale.projectcalico.org/target=true
//	kubectl exec flowgen -- flowgen -preset composite -rate 10000 -duration 30m
//
// -override-dst sends every flow to one address, keeping the generated ports, for a lab run
// against a single sink; -targets spreads them round-robin over several, for an ingress run
// against many target pods; -dry-run draws the flows without sending anything.
//
// -mode hold opens -connections TCP connections instead, at -rate per second, and keeps them
// open for the run, writing a few bytes on each every -hold-interval; -mode listen accepts and
// holds connections for it (see hold.go).
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"github.com/projectcalico/calico/app-policy/policyscale"
)

func main() {
	var (
		mode        = flag.String("mode", "flows", "flows: open short flows at -rate. hold: open -connections long-lived TCP connections at -rate and keep them open for the run. listen: accept TCP connections on -listen-ports and hold them, reading and discarding data")
		preset      = flag.String("preset", "composite", "policy set the cluster has applied: baseline, egress or composite")
		seed        = flag.Int64("seed", policyscale.DefaultSeed, "generator seed; must match the applied policy set")
		rate        = flag.Int("rate", 1000, "new flows per second to open")
		duration    = flag.Duration("duration", 30*time.Second, "how long to run; with -mode hold or listen, 0 runs until interrupted")
		protocol    = flag.String("protocol", "udp", "udp (one datagram per flow) or tcp (one connection attempt per flow)")
		concurrency = flag.Int("concurrency", 64, "sender goroutines")
		miss        = flag.Float64("miss-fraction", 0.1, "fraction of flows that match no rule")
		repeat      = flag.Float64("repeat-fraction", 0.5, "fraction of flows that repeat an earlier flow's destination on a new source port")
		overrideDst = flag.String("override-dst", "", "send every flow to this address instead of the generated one (lab use)")
		targetList  = flag.String("targets", "", "send flows round-robin to these addresses instead of the generated ones: a comma-separated list, or @file with addresses separated by commas, spaces or newlines (# starts a comment). With -direction ingress, the pods the policies select")
		dryRun      = flag.Bool("dry-run", false, "draw the flows without sending")
		tcpTimeout  = flag.Duration("tcp-timeout", 5*time.Millisecond, "how long a TCP connection attempt waits before it is abandoned")
		spread      = flag.Bool("spread-source", true, "with -direction ingress: send flows whose generated source is the shared TEST-NET address from across its /24 instead, as many clients would; verdicts are unchanged because no rule names those addresses")
		direction   = flag.String("direction", "egress", "egress: flows leave this pod for the generated destinations. ingress: flows go to -override-dst or -targets (pods the policies select) from the generated source addresses, which needs workload source spoofing allowed for this pod")

		connections  = flag.Int("connections", 1000, "-mode hold: connections to open and hold")
		holdPort     = flag.Int("hold-port", 0, "-mode hold: connect to this port instead of the generated one, e.g. the port a -mode listen sink accepts on")
		holdInterval = flag.Duration("hold-interval", 10*time.Second, "-mode hold: how often to write on each held connection")
		holdBytes    = flag.Int("hold-bytes", 8, "-mode hold: bytes written on each held connection every -hold-interval")
		dialTimeout  = flag.Duration("dial-timeout", 3*time.Second, "-mode hold: how long a connection attempt waits before it counts as failed")
		listenAddr   = flag.String("listen-addr", "0.0.0.0", "-mode listen: address to listen on")
		listenPorts  = flag.String("listen-ports", "9000", "-mode listen: ports to listen on: a comma-separated list of ports and ranges, e.g. 9000 or 80,443,8000-8010")
	)
	flag.Parse()

	switch *mode {
	case "flows", "hold":
	case "listen":
		// Needs no policy set: it only accepts.
		ports, err := parsePorts(*listenPorts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "-listen-ports: %v\n", err)
			os.Exit(2)
		}
		if _, _, err := runListen(*listenAddr, ports, *duration); err != nil {
			fmt.Fprintf(os.Stderr, "flowgen: listen: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", *mode)
		os.Exit(2)
	}

	var spec policyscale.Spec
	switch *preset {
	case "baseline":
		spec = policyscale.Baseline()
	case "egress":
		spec = policyscale.EgressAllowList()
	case "composite":
		spec = policyscale.Composite()
	default:
		fmt.Fprintf(os.Stderr, "unknown preset %q\n", *preset)
		os.Exit(2)
	}
	spec.Seed = *seed
	fx := policyscale.Build(spec)
	targets, err := parseTargets(*overrideDst, *targetList)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	dir := policyscale.Egress
	switch *direction {
	case "egress":
	case "ingress":
		dir = policyscale.Ingress
		if len(targets) == 0 {
			fmt.Fprintln(os.Stderr, "-direction ingress needs -override-dst or -targets: the addresses of pods the policies select")
			os.Exit(2)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown direction %q\n", *direction)
		os.Exit(2)
	}
	if fx.Rules(dir) == 0 {
		fmt.Fprintf(os.Stderr, "the preset has no %s rules\n", *direction)
		os.Exit(2)
	}
	if *protocol != "udp" && *protocol != "tcp" {
		fmt.Fprintf(os.Stderr, "unknown protocol %q\n", *protocol)
		os.Exit(2)
	}
	sampler := fx.NewSampler(*seed, policyscale.FlowModel{Direction: dir, MissFraction: *miss, RepeatFraction: *repeat})
	if *mode == "hold" {
		// A held connection needs the replies, so it always comes from this pod's own address:
		// with -direction ingress it goes to the targets without the generated source.
		if *connections < 1 || *holdBytes < 1 || *holdInterval <= 0 || *rate < 1 || *holdPort < 0 || *holdPort > 65535 {
			fmt.Fprintln(os.Stderr, "-mode hold needs -connections, -rate, -hold-bytes and -hold-interval above zero, and -hold-port in 0-65535")
			os.Exit(2)
		}
		res := runHold(sampler, holdConfig{
			connections: *connections,
			rate:        *rate,
			duration:    *duration,
			dialTimeout: *dialTimeout,
			interval:    *holdInterval,
			payload:     []byte(strings.Repeat("h", *holdBytes)),
			port:        *holdPort,
			shards:      max(*concurrency, 1),
			targets:     targets,
		})
		if res.failed > 0 {
			os.Exit(1)
		}
		os.Exit(0)
	}
	send := sender(*protocol, targets, *tcpTimeout, *dryRun, dir == policyscale.Ingress, *spread)

	var (
		opened, failed atomic.Uint64
		work           = make(chan *policyscale.Flow, *concurrency*4)
		wg             sync.WaitGroup
	)
	for i := 0; i < *concurrency; i++ {
		wg.Go(func() {
			for f := range work {
				if err := send(f); err != nil {
					if failed.Add(1) == 1 {
						fmt.Fprintf(os.Stderr, "flowgen: first failure: %v\n", err)
					}
				} else {
					opened.Add(1)
				}
			}
		})
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	deadline := time.Now().Add(*duration)
	report := time.NewTicker(time.Second)
	defer report.Stop()

	// Pace with a fixed-interval ticker and a per-tick quota, so a stall is not followed by a
	// burst that the collector would see as a spike.
	const ticksPerSecond = 100
	pace := time.NewTicker(time.Second / ticksPerSecond)
	defer pace.Stop()
	perTick := *rate / ticksPerSecond
	remainder := *rate % ticksPerSecond
	var lastOpened uint64
	start := time.Now()
	fmt.Fprintf(os.Stderr, "flowgen: %s, %d flows/s for %s over %s, %d senders", *preset, *rate, *duration, *protocol, *concurrency)
	if len(targets) > 0 {
		fmt.Fprintf(os.Stderr, ", %d destination addresses", len(targets))
	}
	fmt.Fprintln(os.Stderr)
	tick := 0
run:
	for time.Now().Before(deadline) {
		select {
		case <-pace.C:
			n := perTick
			if tick%ticksPerSecond < remainder {
				n++
			}
			tick++
			for i := 0; i < n; i++ {
				work <- sampler.Next()
			}
		case <-report.C:
			o := opened.Load()
			fmt.Fprintf(os.Stderr, "%6.0fs  %6.0f flows/s  opened=%d failed=%d queued=%d\n",
				time.Since(start).Seconds(), float64(o-lastOpened), o, failed.Load(), len(work))
			lastOpened = o
		case <-stop:
			break run
		}
	}
	close(work)
	wg.Wait()
	elapsed := time.Since(start)
	fmt.Fprintf(os.Stderr, "flowgen: done in %s: opened %d (%.0f flows/s of %d requested), failed %d\n",
		elapsed.Round(time.Millisecond), opened.Load(), float64(opened.Load())/elapsed.Seconds(), *rate, failed.Load())
	if failed.Load() > 0 {
		os.Exit(1)
	}
}

// parseTargets returns the addresses flows are sent to instead of the generated destinations:
// -override-dst's one, or -targets' list. None means the generated destinations.
func parseTargets(overrideDst, targetList string) ([]net.IP, error) {
	if overrideDst != "" && targetList != "" {
		return nil, errors.New("-override-dst and -targets are alternatives; give one")
	}
	if overrideDst != "" {
		ip := net.ParseIP(overrideDst)
		if ip == nil {
			return nil, fmt.Errorf("bad -override-dst %q", overrideDst)
		}
		return []net.IP{ip}, nil
	}
	if targetList == "" {
		return nil, nil
	}
	text := targetList
	if file, ok := strings.CutPrefix(targetList, "@"); ok {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("-targets: %w", err)
		}
		var lines []string
		for _, l := range strings.Split(string(b), "\n") {
			l, _, _ = strings.Cut(l, "#")
			lines = append(lines, l)
		}
		text = strings.Join(lines, ",")
	}
	var ips []net.IP
	for _, f := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
		ip := net.ParseIP(f)
		if ip == nil {
			return nil, fmt.Errorf("-targets: bad address %q", f)
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return nil, errors.New("-targets: no addresses")
	}
	return ips, nil
}

// sender returns the function that opens one flow.
func sender(protocol string, targets []net.IP, tcpTimeout time.Duration, dryRun, spoofSource, spread bool) func(*policyscale.Flow) error {
	if dryRun {
		return func(*policyscale.Flow) error { return nil }
	}
	dst := destination(targets)
	if protocol == "udp" {
		payload := []byte("policyscale")
		return func(f *policyscale.Flow) error {
			// A fresh socket per flow gives each its own ephemeral source port, which is what
			// makes it a new flow to conntrack.
			c, err := net.Dial("udp", dst(f))
			if err != nil {
				return err
			}
			_, err = c.Write(payload)
			_ = c.Close()
			return err
		}
	}
	if spoofSource {
		// Ingress: the connection comes from the flow's generated source address, which is not
		// this pod's. IP_FREEBIND and IP_TRANSPARENT let the socket bind and route it; the reply goes to that address, not
		// back here, so the attempt times out locally while the node still sees the whole
		// exchange.
		shared := net.ParseIP(policyscale.SourceIP).To4()
		var next atomic.Uint32
		return func(f *policyscale.Flow) error {
			src := f.SrcIP
			if spread && src.Equal(shared) {
				// 192.0.2.1-254, skipping the shared address itself.
				n := next.Add(1)%253 + 1
				if n >= uint32(shared[3]) {
					n++
				}
				src = net.IPv4(shared[0], shared[1], shared[2], byte(n))
			}
			d := net.Dialer{
				Timeout:   tcpTimeout,
				LocalAddr: &net.TCPAddr{IP: src},
				Control: func(_, _ string, c syscall.RawConn) error {
					var serr error
					if err := c.Control(func(fd uintptr) {
						// IP_FREEBIND allows the bind; IP_TRANSPARENT lets the route lookup accept a
						// source that isn't local (it needs CAP_NET_ADMIN).
						if serr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_FREEBIND, 1); serr == nil {
							serr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
						}
					}); err != nil {
						return err
					}
					return serr
				},
			}
			c, err := d.Dial("tcp", dst(f))
			if err == nil {
				_ = c.Close()
				return nil
			}
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() || errors.Is(err, syscall.ECONNREFUSED) {
				return nil
			}
			return err
		}
	}
	return func(f *policyscale.Flow) error {
		// The SYN alone creates the conntrack entry; a destination that does not answer leaves the
		// attempt to time out, which is fine. A refusal is a flow too.
		c, err := net.DialTimeout("tcp", dst(f), tcpTimeout)
		if err == nil {
			_ = c.Close()
			return nil
		}
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() || errors.Is(err, syscall.ECONNREFUSED) {
			return nil
		}
		return err
	}
}

// destination returns the function that gives a flow's "address:port": the generated address,
// or the targets in turn, with the generated port.
func destination(targets []net.IP) func(*policyscale.Flow) string {
	var next atomic.Uint64
	return func(f *policyscale.Flow) string {
		ip := f.DstIP
		if len(targets) > 0 {
			ip = targets[(next.Add(1)-1)%uint64(len(targets))]
		}
		return net.JoinHostPort(ip.String(), strconv.Itoa(f.DstPort))
	}
}
