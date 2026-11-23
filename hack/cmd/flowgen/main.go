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
// prints), so the expected verdict of every flow is known. Each flow is one datagram (UDP) or one
// connection attempt (TCP) from a fresh ephemeral port; the destinations need not exist, since the
// collector sees a flow as soon as conntrack does. flowgen reports the achieved rate every second
// and a summary at the end, so a run that fell short of its target shows it in its own output.
//
//	policyscale -preset composite -staged > set.yaml && kubectl apply --server-side -f set.yaml
//	kubectl label pod flowgen policyscale.projectcalico.org/target=true
//	kubectl exec flowgen -- flowgen -preset composite -fixture "$(policyscale -preset composite -fingerprint)" -rate 10000 -duration 30m
//
// Two mistakes make a run measure nothing while looking like a working one:
//
//   - The flows must come from the fixture the cluster applied: the same -preset, -seed and
//     POLICYSCALE_* environment as the policyscale run that rendered it. Otherwise every flow aims
//     at a destination no applied rule carries, and every evaluation misses everything. The
//     rendered tiers carry the fixture's fingerprint in their policyscale.projectcalico.org/fixture
//     annotation; pass it as -fixture and flowgen refuses to run against a different one.
//   - Each flow must use the protocol the fixture gave it. A rule that names a protocol rejects
//     flows of any other on its cheapest check, so TCP rules sent UDP flows cost almost nothing to
//     evaluate. flowgen sends each flow with its own protocol unless -protocol forces one, and
//     -dry-run shows the verdicts a forced protocol would get.
//
// -override-dst sends every flow to one address, keeping the generated ports, for a lab run against
// a single sink; -targets spreads them round-robin over several, for an ingress run against many
// target pods; -dry-run draws the flows without sending anything and prints how many match a rule.
// flowgen can send TCP and UDP; flows the fixture gives another protocol (the shapes preset's
// ICMP, SCTP and UDPLite rules) are counted as skipped.
//
// -mode hold opens -connections TCP connections instead, at -rate per second, and keeps them
// open for the run, writing a few bytes on each every -hold-interval; -mode listen accepts and
// holds connections for it (see hold.go).
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
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

func main() {
	var (
		mode        = flag.String("mode", "flows", "flows: open short flows at -rate. hold: open -connections long-lived TCP connections at -rate and keep them open for the run. listen: accept TCP connections on -listen-ports and hold them, reading and discarding data")
		preset      = flag.String("preset", "composite", "policy set the cluster has applied: baseline, egress, composite or shapes")
		seed        = flag.Int64("seed", policyscale.DefaultSeed, "generator seed; must match the applied policy set")
		fixture     = flag.String("fixture", "", "fingerprint of the applied policy set, from its tiers' "+policyscale.FingerprintAnnotation+" annotation or `policyscale -fingerprint`; flowgen refuses to run if its own fixture differs")
		rate        = flag.Int("rate", 1000, "new flows per second to open")
		duration    = flag.Duration("duration", 30*time.Second, "how long to run; with -mode hold or listen, 0 runs until interrupted")
		protocol    = flag.String("protocol", "fixture", "fixture: send each flow with the protocol the fixture gave it. tcp or udp: send every flow with that protocol, which changes the verdict of flows generated with another")
		concurrency = flag.Int("concurrency", 64, "sender goroutines")
		miss        = flag.Float64("miss-fraction", 0.1, "fraction of flows that match no rule")
		repeat      = flag.Float64("repeat-fraction", 0.5, "fraction of flows that repeat an earlier flow's destination on a new source port")
		overrideDst = flag.String("override-dst", "", "send every flow to this address instead of the generated one (lab use)")
		targetList  = flag.String("targets", "", "send flows round-robin to these addresses instead of the generated ones: a comma-separated list, or @file with addresses separated by commas, spaces or newlines (# starts a comment). With -direction ingress, the pods the policies select")
		dryRun      = flag.Bool("dry-run", false, "draw the flows without sending, and print how many of each protocol and expected action were drawn and how many match a rule; working out each verdict makes it slower than -rate")
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

	spec, err := policyscale.Preset(*preset, *seed)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fx := policyscale.Build(spec)
	fingerprint := policyscale.Fingerprint(fx.Spec)
	if err := checkFixture(*fixture, fingerprint); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
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
	forced, err := parseProtocol(*protocol)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if forced != 0 {
		fmt.Fprintf(os.Stderr, "flowgen: -protocol %s sends every flow as %s; flows the fixture generated with another protocol no longer get the verdicts policyscale -flows prints\n", *protocol, *protocol)
	}
	sampler := fx.NewSampler(*seed, policyscale.FlowModel{Direction: dir, MissFraction: *miss, RepeatFraction: *repeat})
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	if *mode == "hold" {
		// A held connection needs the replies, so it always comes from this pod's own address:
		// with -direction ingress it goes to the targets without the generated source.
		if *connections < 1 || *holdBytes < 1 || *holdInterval <= 0 || *rate < 1 || *holdPort < 0 || *holdPort > 65535 {
			fmt.Fprintln(os.Stderr, "-mode hold needs -connections, -rate, -hold-bytes and -hold-interval above zero, and -hold-port in 0-65535")
			os.Exit(2)
		}
		if forced == policyscale.ProtocolUDP {
			fmt.Fprintln(os.Stderr, "-mode hold holds TCP connections; -protocol udp doesn't apply")
			os.Exit(2)
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
			shards:      max(*concurrency, 1),
			targets:     targets,
		})
		if res.failed > 0 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	prepare := preparer(forced, targets, dir == policyscale.Ingress && *spread)
	var (
		send  sendFunc
		tally *dryRunTally
	)
	if *dryRun {
		tally = newDryRunTally(fx, dir)
		send = func(f *policyscale.Flow) (outcome, error) { return tally.record(prepare(f)), nil }
	} else {
		send = sender(prepare, *tcpTimeout, dir == policyscale.Ingress)
	}
	describe := fmt.Sprintf("%s (fingerprint %s), %d flows/s for %s, protocol %s, %d senders", *preset, fingerprint, *rate, *duration, *protocol, *concurrency)
	if len(targets) > 0 {
		describe += fmt.Sprintf(", %d destination addresses", len(targets))
	}
	res := runFlows(sampler.Next, flowsConfig{rate: *rate, duration: *duration, concurrency: *concurrency, describe: describe}, send, os.Stderr, stop)
	if tally != nil {
		tally.print(os.Stdout)
	}
	if res.failed > 0 {
		os.Exit(1)
	}
}

// checkFixture compares the fingerprint the cluster's policy set was rendered with, when given,
// with the one this run's fixture has.
func checkFixture(want, got string) error {
	if want == "" || want == got {
		return nil
	}
	return fmt.Errorf("the applied policy set has fingerprint %s but this run's fixture has %s: "+
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
	opened, skipped, failed uint64
	elapsed                 time.Duration
}

// runFlows draws flows at cfg.rate per second for cfg.duration and hands each to send on one of
// cfg.concurrency goroutines, reporting progress to out every second.
func runFlows(next func() *policyscale.Flow, cfg flowsConfig, send sendFunc, out io.Writer, stop <-chan os.Signal) flowsResult {
	var (
		opened, skippedN, failedN atomic.Uint64
		work                      = make(chan *policyscale.Flow, cfg.concurrency*4)
		wg                        sync.WaitGroup
	)
	for range cfg.concurrency {
		wg.Go(func() {
			for f := range work {
				switch o, err := send(f); o {
				case sent:
					opened.Add(1)
				case skipped:
					skippedN.Add(1)
				default:
					if failedN.Add(1) == 1 {
						fmt.Fprintf(out, "flowgen: first failure: %v\n", err)
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
	perTick := cfg.rate / ticksPerSecond
	remainder := cfg.rate % ticksPerSecond
	var lastOpened uint64
	start := time.Now()
	fmt.Fprintf(out, "flowgen: %s\n", cfg.describe)
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
			for range n {
				work <- next()
			}
		case <-report.C:
			o := opened.Load()
			fmt.Fprintf(out, "%6.0fs  %6.0f flows/s  opened=%d skipped=%d failed=%d queued=%d\n",
				time.Since(start).Seconds(), float64(o-lastOpened), o, skippedN.Load(), failedN.Load(), len(work))
			lastOpened = o
		case <-stop:
			break run
		}
	}
	close(work)
	wg.Wait()
	res := flowsResult{opened: opened.Load(), skipped: skippedN.Load(), failed: failedN.Load(), elapsed: time.Since(start)}
	fmt.Fprintf(out, "flowgen: done in %s: opened %d (%.0f flows/s of %d requested), skipped %d, failed %d\n",
		res.elapsed.Round(time.Millisecond), res.opened, float64(res.opened)/res.elapsed.Seconds(), cfg.rate, res.skipped, res.failed)
	return res
}

// preparer returns the function that turns a generated flow into the flow put on the wire: with
// the forced protocol, sent to the targets in turn, and, for ingress runs that spread the shared
// source, from an address across its /24. The result is a copy; the expected verdict of the flow
// as sent is Expect of that copy.
func preparer(forcedProtocol int, targets []net.IP, spreadSource bool) func(*policyscale.Flow) *policyscale.Flow {
	shared := net.ParseIP(policyscale.SourceIP).To4()
	var nextTarget, nextSource atomic.Uint64
	return func(f *policyscale.Flow) *policyscale.Flow {
		c := *f
		if forcedProtocol != 0 {
			c.Protocol = forcedProtocol
		}
		if len(targets) > 0 {
			c.DstIP = targets[(nextTarget.Add(1)-1)%uint64(len(targets))]
		}
		if spreadSource && c.SrcIP.Equal(shared) {
			// 192.0.2.1-254, skipping the shared address itself.
			n := byte(nextSource.Add(1)%253 + 1)
			if n >= shared[3] {
				n++
			}
			c.SrcIP = net.IPv4(shared[0], shared[1], shared[2], n)
		}
		return &c
	}
}

// sender returns the function that opens one flow. With spoofSource, the flow comes from its own
// source address rather than this pod's, as an ingress run's flows must.
func sender(prepare func(*policyscale.Flow) *policyscale.Flow, tcpTimeout time.Duration, spoofSource bool) sendFunc {
	payload := []byte("policyscale")
	return func(generated *policyscale.Flow) (outcome, error) {
		f := prepare(generated)
		d := net.Dialer{Timeout: tcpTimeout}
		var network string
		switch f.Protocol {
		case policyscale.ProtocolTCP:
			network = "tcp"
			if spoofSource {
				d.LocalAddr = &net.TCPAddr{IP: f.SrcIP}
			}
		case policyscale.ProtocolUDP:
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
		// A fresh socket per flow gives each its own ephemeral source port, which is what makes
		// it a new flow to conntrack.
		c, err := d.Dial(network, net.JoinHostPort(f.DstIP.String(), strconv.Itoa(f.DstPort)))
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
// allows the bind, and IP_TRANSPARENT (which needs CAP_NET_ADMIN) lets the route lookup accept the
// source.
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

// dryRunTally counts the flows a dry run draws by protocol, by the final action the fixture expects
// for them as they would be sent, and by whether any rule matches them. A run whose flows match no
// rule measures nothing, whatever the final actions look like.
type dryRunTally struct {
	fx  *policyscale.Fixture
	dir policyscale.Direction

	mu              sync.Mutex
	byProtocol      map[string]int
	byAction        map[string]int
	matched, missed int
	skipped         int
}

func newDryRunTally(fx *policyscale.Fixture, dir policyscale.Direction) *dryRunTally {
	return &dryRunTally{fx: fx, dir: dir, byProtocol: map[string]int{}, byAction: map[string]int{}}
}

func (t *dryRunTally) record(f *policyscale.Flow) outcome {
	if f.Protocol != policyscale.ProtocolTCP && f.Protocol != policyscale.ProtocolUDP {
		t.mu.Lock()
		t.skipped++
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
	t.mu.Lock()
	t.byProtocol[protocolName(f.Protocol)]++
	t.byAction[action]++
	if matched {
		t.matched++
	} else {
		t.missed++
	}
	t.mu.Unlock()
	return sent
}

func (t *dryRunTally) print(w io.Writer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fmt.Fprintf(w, "dry run: %s flows by protocol: %s; by expected final action: %s; matching a rule: %d, matching none: %d; skipped (protocol flowgen can't send): %d\n",
		t.dir, counts(t.byProtocol), counts(t.byAction), t.matched, t.missed, t.skipped)
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
