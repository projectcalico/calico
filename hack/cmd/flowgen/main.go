// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

// flowgen opens new flows from the pod it runs in at a configured rate, against a policy set the
// cluster has applied from app-policy/policyscale, for node-level measurements of the flow-log
// collector's pending-policy evaluation.
//
// Flows are drawn from the same fixture as the applied set (the same flows `policyscale -flows`
// prints), so the expected trace of every flow is known. Each flow is one UDP datagram, or one TCP
// connection attempt that ends in a reset; the destinations need not exist, since the collector
// sees a flow as soon as conntrack does. Progress goes to stderr every second, and one JSON
// summary line to stdout at the end.
//
// Exit codes: 0 when every flow was sent at the requested rate; 1 when a flow failed; 2 for a bad
// flag; 3 when -fixture doesn't match; 4 when the achieved rate fell short by more than
// -max-shortfall.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"github.com/projectcalico/calico/app-policy/policyscale"
)

const (
	exitFailures  = 1
	exitUsage     = 2
	exitFixture   = 3
	exitShortfall = 4
)

const usageHeader = `Usage: flowgen [flags]

Sends flows drawn from an app-policy/policyscale fixture at a cluster that has applied it. Two
mistakes make a run measure nothing while it looks fine:

  - The flows must come from the fixture the cluster applied: the same -preset, -seed and
    POLICYSCALE_POLICIES, POLICYSCALE_RULES_PER_POLICY and POLICYSCALE_IPSETS environment as
    the policyscale run that rendered it. Pass the fixture label of the applied objects as
    -fixture, and flowgen refuses to run against another:
      kubectl get tiers.projectcalico.org -l policyscale.projectcalico.org/fixture \
        -o custom-columns=NAME:.metadata.name,FIXTURE:.metadata.labels.policyscale\.projectcalico\.org/fixture,OBJECTS:.metadata.annotations.policyscale\.projectcalico\.org/objects
    Objects with another fixture label are left over from an earlier set; fewer objects with
    this one than the tier's objects count means the set is only partly applied.
  - Each flow must use the protocol the fixture gave it, which is what -protocol fixture does.

Ingress runs (-direction ingress) send from the generated source addresses, so flowgen must run
as root with NET_RAW or NET_ADMIN, the pod needs a cni.projectcalico.org/allowedSourcePrefixes
annotation covering 'policyscale -prefixes', and the node rp_filter=0. A flow the node drops on
its source still counts as opened here; the collector's own counts are the check.

`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("flowgen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		logf(stderr, "%s", usageHeader)
		fs.PrintDefaults()
	}
	var (
		mode         = fs.String("mode", "flows", "flows: open short flows at -rate. hold: open -connections long-lived TCP connections at -rate and keep them open for the run. listen: accept TCP connections on -listen-ports and hold them, reading and discarding data")
		preset       = fs.String("preset", "composite", "policy set the cluster has applied: baseline, egress, composite or shapes")
		seed         = fs.Int64("seed", policyscale.DefaultSeed, "generator seed; must match the applied policy set")
		flowSeed     = fs.Int64("flow-seed", 0, "seed of the flow sequence, so that pods or steps of one run send different flows from one fixture; default -seed")
		fixture      = fs.String("fixture", "", "fingerprint of the applied policy set, from its objects' "+policyscale.FixtureLabel+" label; flowgen refuses to run if its own fixture differs")
		rate         = fs.Int("rate", 1000, "new flows per second to open")
		duration     = fs.Duration("duration", 30*time.Second, "how long to run; with -mode hold or listen, 0 runs until interrupted")
		protocol     = fs.String("protocol", "fixture", "fixture: send each flow with the protocol the fixture gave it. tcp or udp: send every flow with that protocol, which changes the trace of flows generated with another")
		concurrency  = fs.Int("concurrency", 0, "sender goroutines; 0 sizes the pool from -rate and -tcp-timeout, since a TCP attempt nobody answers holds a sender for the whole timeout")
		maxShortfall = fs.Float64("max-shortfall", 0.05, "fraction of the requested rate of sendable flows a run may fall short by before it exits 4")
		miss         = fs.Float64("miss-fraction", 0.1, "fraction of flows that match no rule")
		repeat       = fs.Float64("repeat-fraction", 0.5, "fraction of flows that repeat an earlier flow's destination on a new source port")
		overrideDst  = fs.String("override-dst", "", "send every flow to this address instead of the generated one, for a lab sink; this changes the flows' traces, see the warning flowgen prints")
		targetList   = fs.String("targets", "", "send flows round-robin to these addresses instead of the generated ones: a comma-separated list, or @file with addresses separated by commas, spaces or newlines (# starts a comment). With -direction ingress, the pods the policies select")
		dryRun       = fs.Bool("dry-run", false, "draw the flows without sending, and report how many of each protocol and expected action were drawn, how many match a rule and how many -protocol or -targets changed; working out each trace makes it slower than -rate")
		tcpTimeout   = fs.Duration("tcp-timeout", 5*time.Millisecond, "how long a TCP connection attempt waits before it is abandoned")
		spread       = fs.Bool("spread-source", true, "with -direction ingress: send flows whose generated source is the shared TEST-NET-1 address from across its /24 instead. Conntrack takes a new SYN that reuses a source port of a SYN it still holds (for 120 s) as the old flow, so one source and destination carry only a few hundred new flows/s; without spreading most ingress flows are such repeats. No rule names those addresses, so traces are unchanged")
		spreadDst    = fs.Bool("spread-denied", true, "with -direction egress: send the flows that match no rule to addresses across TEST-NET-2's /24 instead of one, for the same conntrack reason as -spread-source; no rule names those addresses either")
		direction    = fs.String("direction", "egress", "egress: flows leave this pod for the generated destinations. ingress: flows go to -override-dst or -targets (pods the policies select) from the generated source addresses; see the ingress requirements above")

		connections  = fs.Int("connections", 1000, "-mode hold: connections to open and hold; one destination address and port takes about 28,000, so spread larger counts over -targets or ports")
		holdPort     = fs.Int("hold-port", 0, "-mode hold: connect to this port instead of the generated one, e.g. the port a -mode listen sink accepts on")
		holdInterval = fs.Duration("hold-interval", 10*time.Second, "-mode hold: how often to write on each held connection")
		holdBytes    = fs.Int("hold-bytes", 8, "-mode hold: bytes written on each held connection every -hold-interval")
		dialTimeout  = fs.Duration("dial-timeout", 3*time.Second, "-mode hold: how long a connection attempt waits before it counts as failed")
		listenAddr   = fs.String("listen-addr", "0.0.0.0", "-mode listen: address to listen on")
		listenPorts  = fs.String("listen-ports", "9000", "-mode listen: ports to listen on: a comma-separated list of ports and ranges, e.g. 9000 or 80,443,8000-8010")
	)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return exitUsage
	}
	usageErr := func(format string, args ...any) int {
		logf(stderr, "flowgen: "+format+"\n", args...)
		return exitUsage
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)

	switch *mode {
	case "flows", "hold":
	case "listen":
		if *dryRun {
			return usageErr("-dry-run doesn't apply to -mode listen")
		}
		// Needs no policy set: it only accepts.
		ports, err := parsePorts(*listenPorts)
		if err != nil {
			return usageErr("-listen-ports: %v", err)
		}
		listeners, err := listen(*listenAddr, ports)
		if err != nil {
			logf(stderr, "flowgen: listen: %v\n", err)
			return exitFailures
		}
		res := serveListeners(listeners, *duration, stop, stderr)
		writeSummary(stdout, summary{Mode: "listen", Seconds: res.elapsed.Seconds(), Accepted: res.accepted, OpenAtEnd: res.openAtEnd, BytesRead: res.bytes})
		return 0
	default:
		return usageErr("unknown mode %q", *mode)
	}

	if *rate < 1 {
		return usageErr("-rate must be at least 1")
	}
	if *concurrency < 0 {
		return usageErr("-concurrency must be 0 (sized from -rate) or more")
	}
	if *maxShortfall < 0 || *maxShortfall > 1 {
		return usageErr("-max-shortfall must be between 0 and 1")
	}
	spec, err := policyscale.Preset(*preset, *seed)
	if err != nil {
		return usageErr("%v", err)
	}
	fx := policyscale.Build(spec)
	fingerprint := fx.Fingerprint()
	if err := checkFixture(*fixture, fingerprint); err != nil {
		logf(stderr, "flowgen: %v\n", err)
		writeSummary(stdout, summary{Mode: *mode, Preset: *preset, Fingerprint: fingerprint, Exit: exitFixture, Reason: err.Error()})
		return exitFixture
	}
	targets, err := parseTargets(*overrideDst, *targetList)
	if err != nil {
		return usageErr("%v", err)
	}
	dir := policyscale.Egress
	switch *direction {
	case "egress":
	case "ingress":
		dir = policyscale.Ingress
		if len(targets) == 0 {
			return usageErr("-direction ingress needs -override-dst or -targets: the addresses of pods the policies select")
		}
	default:
		return usageErr("unknown direction %q", *direction)
	}
	if fx.Rules(dir) == 0 {
		return usageErr("the preset has no %s rules", *direction)
	}
	forced, err := parseProtocol(*protocol)
	if err != nil {
		return usageErr("%v", err)
	}
	if *flowSeed == 0 {
		*flowSeed = *seed
	}
	model := policyscale.FlowModel{Direction: dir, MissFraction: *miss, RepeatFraction: *repeat}
	sampler := fx.NewSampler(*flowSeed, model)

	if *mode == "hold" {
		// A held connection needs the replies, so it always comes from this pod's own address:
		// with -direction ingress it goes to the targets without the generated source.
		switch {
		case *dryRun:
			return usageErr("-dry-run doesn't apply to -mode hold, which opens real connections")
		case *connections < 1 || *holdBytes < 1 || *holdInterval <= 0 || *holdPort < 0 || *holdPort > 65535:
			return usageErr("-mode hold needs -connections, -hold-bytes and -hold-interval above zero, and -hold-port in 0-65535")
		case forced == policyscale.ProtocolUDP:
			return usageErr("-mode hold holds TCP connections; -protocol udp doesn't apply")
		}
		next := sampler.Next
		if forced == 0 {
			next = tcpFlows(sampler.Next)
		}
		res := runHold(next, holdConfig{
			connections: *connections,
			rate:        *rate,
			duration:    *duration,
			dialTimeout: *dialTimeout,
			interval:    *holdInterval,
			payload:     []byte(strings.Repeat("h", *holdBytes)),
			port:        *holdPort,
			shards:      max(*concurrency, 64),
			targets:     targets,
		}, stop, stderr)
		s := summary{Mode: "hold", Preset: *preset, Fingerprint: fingerprint, Direction: dir.String(), RequestedRate: *rate,
			Seconds: res.elapsed.Seconds(), Opened: res.opened, OpenAtEnd: res.openAtEnd, Failed: res.failed, ClosedByPeer: res.closed}
		if res.failed > 0 {
			s.Exit = exitFailures
		}
		writeSummary(stdout, s)
		return s.Exit
	}

	prepare := preparer(prepareConfig{
		forcedProtocol: forced,
		targets:        targets,
		spreadSource:   dir == policyscale.Ingress && *spread,
		spreadDenied:   dir == policyscale.Egress && *spreadDst,
	})
	var changed *verdictChange
	if forced != 0 || len(targets) > 0 {
		c := sampleVerdictChanges(fx, dir, fx.NewSampler(*flowSeed, model), prepare, 200)
		changed = &c
		logf(stderr, "flowgen: -protocol %s, %d target(s): %d of %d sampled flows get a different trace from the one policyscale -flows prints for them\n",
			*protocol, len(targets), c.Changed, c.Sampled)
		for _, t := range targets {
			if a, ok := netip.AddrFromSlice(t); ok && inPrefixes(a.Unmap(), fx.Prefixes()) {
				logf(stderr, "flowgen: target %s is inside the fixture's address ranges, so flows to it can match rules they weren't aimed at\n", t)
			}
		}
	}

	senders := *concurrency
	if senders == 0 {
		senders = sendersFor(*rate, *tcpTimeout)
	}
	var (
		send  sendFunc
		tally *dryRunTally
	)
	if *dryRun {
		tally = newDryRunTally(fx, dir)
		send = func(f *policyscale.Flow) (outcome, error) { return tally.record(f, prepare(f)), nil }
	} else {
		send = sender(prepare, *tcpTimeout, dir == policyscale.Ingress)
	}
	describe := fmt.Sprintf("%s (fingerprint %s), %s, %d flows/s for %s, protocol %s, %d senders", *preset, fingerprint, dir, *rate, *duration, *protocol, senders)
	if len(targets) > 0 {
		describe += fmt.Sprintf(", %d destination addresses", len(targets))
	}
	res := runFlows(sampler.Next, flowsConfig{rate: *rate, duration: *duration, concurrency: senders, describe: describe}, send, stderr, stop)

	s := summary{Mode: "flows", Preset: *preset, Fingerprint: fingerprint, Direction: dir.String(), RequestedRate: *rate,
		Seconds: res.elapsed.Seconds(), Opened: res.opened, Failed: res.failed, Skipped: res.skipped, Unroutable: res.unroutable,
		AchievedRate: float64(res.opened) / res.elapsed.Seconds(), Changed: changed}
	if tally != nil {
		s.DryRun = tally.summary()
		logf(stderr, "flowgen: dry run: %s\n", tally)
	}
	s.Exit, s.Reason = verdict(res, *rate, *maxShortfall, *dryRun)
	if s.Reason != "" {
		logf(stderr, "flowgen: %s\n", s.Reason)
	}
	writeSummary(stdout, s)
	return s.Exit
}

// logf writes progress for a person to read: a lost line doesn't change the run's result.
func logf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// checkFixture compares the fingerprint the cluster's policy set was rendered with, when given,
// with the one this run's fixture has.
func checkFixture(want, got string) error {
	want = strings.ToLower(strings.TrimSpace(want))
	if want == "" || want == got {
		return nil
	}
	return fmt.Errorf("the applied policy set has fixture %s but this run's is %s: "+
		"use the -preset, -seed and POLICYSCALE_* environment the set was rendered with, or every flow misses every rule", want, got)
}

// parseProtocol returns the protocol -protocol forces on every flow, or 0 to use each flow's own.
func parseProtocol(s string) (int, error) {
	switch s {
	case "fixture":
		return 0, nil
	case "tcp":
		return policyscale.ProtocolTCP, nil
	case "udp":
		return policyscale.ProtocolUDP, nil
	}
	return 0, fmt.Errorf("unknown protocol %q: want fixture, tcp or udp", s)
}

// sendersFor sizes the sender pool so that TCP attempts nobody answers, each of which holds a
// sender for the whole timeout, still leave half the pool free at the requested rate.
func sendersFor(rate int, tcpTimeout time.Duration) int {
	return max(64, int(math.Ceil(2*float64(rate)*tcpTimeout.Seconds()))+16)
}

// verdict gives the run's exit code and, unless it succeeded, why. The requested rate is scaled
// down by the share of flows flowgen can't send, so a preset with ICMP flows isn't a shortfall.
func verdict(res flowsResult, rate int, maxShortfall float64, dryRun bool) (int, string) {
	if res.failed > 0 {
		return exitFailures, fmt.Sprintf("%d flows failed", res.failed)
	}
	drawn := res.opened + res.failed + res.skipped + res.unroutable
	if dryRun || drawn == 0 || res.elapsed <= 0 {
		return 0, ""
	}
	sendable := float64(rate) * float64(res.opened) / float64(drawn)
	achieved := float64(res.opened) / res.elapsed.Seconds()
	if achieved < (1-maxShortfall)*sendable {
		return exitShortfall, fmt.Sprintf("achieved %.0f flows/s of the %.0f/s the sendable flows were requested at", achieved, sendable)
	}
	return 0, ""
}

// tcpFlows draws only the fixture's TCP flows, for hold mode.
func tcpFlows(next func() *policyscale.Flow) func() *policyscale.Flow {
	return func() *policyscale.Flow {
		for range 1 << 16 {
			if f := next(); f.Protocol == policyscale.ProtocolTCP {
				return f
			}
		}
		panic("the fixture produced no TCP flow in 65,536 draws")
	}
}

// outcome is what became of one flow.
type outcome int

const (
	sent outcome = iota
	// skipped flows have a protocol flowgen can't send.
	skipped
	// unroutable flows have no route from this pod, such as IPv6 flows on an IPv4-only node.
	unroutable
	failed
)

type sendFunc func(*policyscale.Flow) (outcome, error)

type flowsConfig struct {
	rate        int
	duration    time.Duration
	concurrency int
	describe    string
}

type flowsResult struct {
	opened, skipped, unroutable, failed uint64
	elapsed                             time.Duration
}

// runFlows draws flows at cfg.rate per second for cfg.duration and hands each to send on one of
// cfg.concurrency goroutines, reporting progress to out every second.
func runFlows(next func() *policyscale.Flow, cfg flowsConfig, send sendFunc, out io.Writer, stop <-chan os.Signal) flowsResult {
	var (
		opened, skippedN, unroutableN, failedN atomic.Uint64
		work                                   = make(chan *policyscale.Flow, cfg.concurrency*4)
		wg                                     sync.WaitGroup
	)
	for range cfg.concurrency {
		wg.Go(func() {
			for f := range work {
				switch o, err := send(f); o {
				case sent:
					opened.Add(1)
				case skipped:
					skippedN.Add(1)
				case unroutable:
					unroutableN.Add(1)
				default:
					if failedN.Add(1) == 1 {
						logf(out, "flowgen: first failure: %v\n", err)
					}
				}
			}
		})
	}

	deadline := time.Now().Add(cfg.duration)
	report := time.NewTicker(time.Second)
	defer report.Stop()

	// Pace with a fixed-interval ticker and a per-tick quota, so a stall is not followed by a
	// burst that the collector would see as a spike: a ticker drops the ticks it couldn't deliver.
	const ticksPerSecond = 100
	pace := time.NewTicker(time.Second / ticksPerSecond)
	defer pace.Stop()
	var lastOpened uint64
	start := time.Now()
	logf(out, "flowgen: %s\n", cfg.describe)
	tick := 0
run:
	for time.Now().Before(deadline) {
		select {
		case <-pace.C:
			n := flowsForTick(cfg.rate, ticksPerSecond, tick)
			tick++
			for range n {
				work <- next()
			}
		case <-report.C:
			o := opened.Load()
			logf(out, "%6.0fs  %6.0f flows/s  opened=%d skipped=%d unroutable=%d failed=%d queued=%d\n",
				time.Since(start).Seconds(), float64(o-lastOpened), o, skippedN.Load(), unroutableN.Load(), failedN.Load(), len(work))
			lastOpened = o
		case <-stop:
			break run
		}
	}
	close(work)
	wg.Wait()
	res := flowsResult{opened: opened.Load(), skipped: skippedN.Load(), unroutable: unroutableN.Load(), failed: failedN.Load(), elapsed: time.Since(start)}
	logf(out, "flowgen: done in %s: opened %d (%.0f flows/s of %d requested), skipped %d, unroutable %d, failed %d\n",
		res.elapsed.Round(time.Millisecond), res.opened, float64(res.opened)/res.elapsed.Seconds(), cfg.rate, res.skipped, res.unroutable, res.failed)
	return res
}

// flowsForTick spreads rate flows a second over the ticks, so that each tick's share differs by
// at most one from any other's.
func flowsForTick(rate, ticksPerSecond, tick int) int {
	t := tick % ticksPerSecond
	return (t+1)*rate/ticksPerSecond - t*rate/ticksPerSecond
}

type prepareConfig struct {
	forcedProtocol int
	targets        []net.IP
	spreadSource   bool
	spreadDenied   bool
}

// preparer returns the function that turns a generated flow into the flow put on the wire: with
// the forced protocol, sent to the targets in turn, and with the shared source or the denied
// destination spread across its /24. The result is a copy; the expected trace of the flow as sent
// is Expect of that copy.
func preparer(cfg prepareConfig) func(*policyscale.Flow) *policyscale.Flow {
	source := spreader(policyscale.SourceIP)
	denied := spreader(policyscale.DeniedDestIP)
	var nextTarget atomic.Uint64
	return func(f *policyscale.Flow) *policyscale.Flow {
		c := *f
		if cfg.forcedProtocol != 0 {
			c.Protocol = cfg.forcedProtocol
		}
		if len(cfg.targets) > 0 {
			c.DstIP = cfg.targets[(nextTarget.Add(1)-1)%uint64(len(cfg.targets))]
		}
		if cfg.spreadSource {
			c.SrcIP = source(c.SrcIP)
		}
		if cfg.spreadDenied {
			c.DstIP = denied(c.DstIP)
		}
		return &c
	}
}

// spreader returns the function that replaces the given IPv4 address with the addresses of its
// /24 in turn, skipping the network, broadcast and given addresses, and leaves any other address
// alone.
func spreader(addr string) func(net.IP) net.IP {
	shared := net.ParseIP(addr).To4()
	var next atomic.Uint32
	return func(ip net.IP) net.IP {
		if !ip.Equal(shared) {
			return ip
		}
		n := byte(next.Add(1)%253 + 1)
		if n >= shared[3] {
			n++
		}
		return net.IPv4(shared[0], shared[1], shared[2], n)
	}
}

// sender returns the function that opens one flow. With spoofSource, the flow comes from its own
// source address rather than this pod's, as an ingress run's flows must.
func sender(prepare func(*policyscale.Flow) *policyscale.Flow, tcpTimeout time.Duration, spoofSource bool) sendFunc {
	payload := []byte("policyscale")
	return func(generated *policyscale.Flow) (outcome, error) {
		f := prepare(generated)
		var d net.Dialer
		var network string
		switch f.Protocol {
		case policyscale.ProtocolTCP:
			network = "tcp"
			d.Timeout = tcpTimeout
			if spoofSource {
				d.LocalAddr = &net.TCPAddr{IP: f.SrcIP}
			}
		case policyscale.ProtocolUDP:
			// A UDP dial waits on nothing, and a timeout would only fail a flow whose sender
			// started late.
			network = "udp"
			if spoofSource {
				d.LocalAddr = &net.UDPAddr{IP: f.SrcIP}
			}
		default:
			return skipped, nil
		}
		if spoofSource {
			d.Control = freebind
		}
		c, err := d.Dial(network, net.JoinHostPort(f.DstIP.String(), strconv.Itoa(f.DstPort)))
		if errors.Is(err, syscall.ENETUNREACH) {
			return unroutable, nil
		}
		if network == "udp" {
			if err != nil {
				return failed, err
			}
			_, err = c.Write(payload)
			_ = c.Close()
			if err != nil {
				return failed, err
			}
			return sent, nil
		}
		if err == nil {
			// Reset rather than close, so the connection leaves no TIME_WAIT behind: against
			// one sink, those use up the source ports within seconds.
			_ = c.(*net.TCPConn).SetLinger(0)
			_ = c.Close()
			return sent, nil
		}
		// The SYN alone creates the conntrack entry, so a destination that doesn't answer in time,
		// or refuses, still made a flow. A spoofed source never sees the reply at all.
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() || errors.Is(err, syscall.ECONNREFUSED) {
			return sent, nil
		}
		return failed, err
	}
}

// freebind lets a socket bind to, and send from, an address that isn't this pod's: IP_FREEBIND
// allows the bind, and IP_TRANSPARENT lets the route lookup accept the source. The process needs
// to run as root with NET_RAW or NET_ADMIN.
func freebind(_, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		if serr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_FREEBIND, 1); serr == nil {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
		}
	}); err != nil {
		return err
	}
	return serr
}

// verdictChange counts sampled flows whose expected trace differs once prepared for the wire.
type verdictChange struct {
	Sampled int `json:"sampled"`
	Changed int `json:"changed"`
}

func sampleVerdictChanges(fx *policyscale.Fixture, dir policyscale.Direction, s *policyscale.Sampler, prepare func(*policyscale.Flow) *policyscale.Flow, n int) verdictChange {
	c := verdictChange{Sampled: n}
	for range n {
		f := s.Next()
		if !sameTrace(fx.Expect(dir, f), fx.Expect(dir, prepare(f))) {
			c.Changed++
		}
	}
	return c
}

func sameTrace(a, b []policyscale.Verdict) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func inPrefixes(a netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// dryRunTally counts the flows a dry run draws by protocol, by the final action the fixture expects
// for them as they would be sent, by whether any rule matches them, and by whether preparing them
// for the wire changed their trace. A run whose flows match no rule measures nothing, whatever the
// final actions look like.
type dryRunTally struct {
	fx  *policyscale.Fixture
	dir policyscale.Direction

	mu sync.Mutex
	s  dryRunSummary
}

type dryRunSummary struct {
	ByProtocol    map[string]int `json:"byProtocol"`
	ByFinalAction map[string]int `json:"byFinalAction"`
	Matching      int            `json:"matching"`
	MatchingNone  int            `json:"matchingNone"`
	Changed       int            `json:"changed"`
	Skipped       int            `json:"skipped"`
}

func newDryRunTally(fx *policyscale.Fixture, dir policyscale.Direction) *dryRunTally {
	return &dryRunTally{fx: fx, dir: dir, s: dryRunSummary{ByProtocol: map[string]int{}, ByFinalAction: map[string]int{}}}
}

func (t *dryRunTally) record(generated, f *policyscale.Flow) outcome {
	if f.Protocol != policyscale.ProtocolTCP && f.Protocol != policyscale.ProtocolUDP {
		t.mu.Lock()
		t.s.Skipped++
		t.mu.Unlock()
		return skipped
	}
	action, matched := "none", false
	trace := t.fx.Expect(t.dir, f)
	if len(trace) > 0 {
		action = trace[len(trace)-1].Action
	}
	for _, v := range trace {
		if v.Index != policyscale.TierDefaultIndex {
			matched = true
		}
	}
	changed := !sameTrace(trace, t.fx.Expect(t.dir, generated))
	t.mu.Lock()
	defer t.mu.Unlock()
	t.s.ByProtocol[protocolName(f.Protocol)]++
	t.s.ByFinalAction[action]++
	if matched {
		t.s.Matching++
	} else {
		t.s.MatchingNone++
	}
	if changed {
		t.s.Changed++
	}
	return sent
}

func (t *dryRunTally) summary() *dryRunSummary {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.s
	return &s
}

func (t *dryRunTally) String() string {
	s := t.summary()
	return fmt.Sprintf("%s flows by protocol: %s; by expected final action: %s; matching a rule: %d, matching none: %d; trace changed for the wire: %d; skipped (protocol flowgen can't send): %d",
		t.dir, counts(s.ByProtocol), counts(s.ByFinalAction), s.Matching, s.MatchingNone, s.Changed, s.Skipped)
}

func counts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%d", k, m[k])
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " ")
}

func protocolName(p int) string {
	switch p {
	case policyscale.ProtocolTCP:
		return "tcp"
	case policyscale.ProtocolUDP:
		return "udp"
	}
	return strconv.Itoa(p)
}

// summary is the one JSON line a run writes to stdout, for a harness to read.
type summary struct {
	Mode          string         `json:"mode"`
	Preset        string         `json:"preset,omitempty"`
	Fingerprint   string         `json:"fingerprint,omitempty"`
	Direction     string         `json:"direction,omitempty"`
	RequestedRate int            `json:"requestedRate,omitempty"`
	AchievedRate  float64        `json:"achievedRate"`
	Seconds       float64        `json:"seconds"`
	Opened        uint64         `json:"opened"`
	Failed        uint64         `json:"failed"`
	Skipped       uint64         `json:"skipped"`
	Unroutable    uint64         `json:"unroutable"`
	OpenAtEnd     uint64         `json:"openAtEnd,omitempty"`
	ClosedByPeer  uint64         `json:"closedByPeer,omitempty"`
	Accepted      uint64         `json:"accepted,omitempty"`
	BytesRead     uint64         `json:"bytesRead,omitempty"`
	Changed       *verdictChange `json:"changed,omitempty"`
	DryRun        *dryRunSummary `json:"dryRun,omitempty"`
	Exit          int            `json:"exit"`
	Reason        string         `json:"reason,omitempty"`
}

func writeSummary(w io.Writer, s summary) {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	logf(w, "%s\n", b)
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
