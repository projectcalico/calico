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
// against a single sink; -dry-run draws the flows without sending anything.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/projectcalico/calico/app-policy/policyscale"
)

func main() {
	var (
		preset      = flag.String("preset", "composite", "policy set the cluster has applied: baseline, egress or composite")
		seed        = flag.Int64("seed", policyscale.DefaultSeed, "generator seed; must match the applied policy set")
		rate        = flag.Int("rate", 1000, "new flows per second to open")
		duration    = flag.Duration("duration", 30*time.Second, "how long to run")
		protocol    = flag.String("protocol", "udp", "udp (one datagram per flow) or tcp (one connection attempt per flow)")
		concurrency = flag.Int("concurrency", 64, "sender goroutines")
		miss        = flag.Float64("miss-fraction", 0.1, "fraction of flows that match no rule")
		repeat      = flag.Float64("repeat-fraction", 0.5, "fraction of flows that repeat an earlier flow's destination on a new source port")
		overrideDst = flag.String("override-dst", "", "send every flow to this address instead of the generated one (lab use)")
		dryRun      = flag.Bool("dry-run", false, "draw the flows without sending")
		tcpTimeout  = flag.Duration("tcp-timeout", 5*time.Millisecond, "how long a TCP connection attempt waits before it is abandoned")
	)
	flag.Parse()

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
	if fx.Rules(policyscale.Egress) == 0 {
		fmt.Fprintln(os.Stderr, "the preset has no egress rules; flowgen drives egress flows from the pod it runs in")
		os.Exit(2)
	}
	if *protocol != "udp" && *protocol != "tcp" {
		fmt.Fprintf(os.Stderr, "unknown protocol %q\n", *protocol)
		os.Exit(2)
	}
	var override net.IP
	if *overrideDst != "" {
		if override = net.ParseIP(*overrideDst); override == nil {
			fmt.Fprintf(os.Stderr, "bad -override-dst %q\n", *overrideDst)
			os.Exit(2)
		}
	}

	sampler := fx.NewSampler(*seed, policyscale.FlowModel{Direction: policyscale.Egress, MissFraction: *miss, RepeatFraction: *repeat})
	send := sender(*protocol, override, *tcpTimeout, *dryRun)

	var (
		opened, failed atomic.Uint64
		work           = make(chan *policyscale.Flow, *concurrency*4)
		wg             sync.WaitGroup
	)
	for i := 0; i < *concurrency; i++ {
		wg.Go(func() {
			for f := range work {
				if err := send(f); err != nil {
					failed.Add(1)
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
	fmt.Fprintf(os.Stderr, "flowgen: %s, %d flows/s for %s over %s, %d senders\n", *preset, *rate, *duration, *protocol, *concurrency)
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
			fmt.Fprintf(os.Stderr, "%6.0fs  %6d flows/s  opened=%d failed=%d queued=%d\n",
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

// sender returns the function that opens one flow.
func sender(protocol string, override net.IP, tcpTimeout time.Duration, dryRun bool) func(*policyscale.Flow) error {
	if dryRun {
		return func(*policyscale.Flow) error { return nil }
	}
	dst := func(f *policyscale.Flow) string {
		ip := f.DstIP
		if override != nil {
			ip = override
		}
		return net.JoinHostPort(ip.String(), strconv.Itoa(f.DstPort))
	}
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
