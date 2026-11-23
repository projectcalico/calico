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

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/projectcalico/calico/app-policy/policyscale"
)

var (
	egressFixture = sync.OnceValue(func() *policyscale.Fixture { return policyscale.Build(policyscale.EgressAllowList()) })
	shapesFixture = sync.OnceValue(func() *policyscale.Fixture { return policyscale.Build(policyscale.RuleShapes()) })
)

// The run sends close to the requested rate, and spreads it over the second rather than sending
// a second's worth at once: no 100 ms window carries much more than a tenth of the rate. Below
// 100 flows/s only the per-tick remainder sends anything.
func TestRunFlowsPacesEvenly(t *testing.T) {
	for _, rate := range []int{500, 50} {
		var (
			mu    sync.Mutex
			times []time.Time
		)
		send := func(*policyscale.Flow) (outcome, error) {
			mu.Lock()
			times = append(times, time.Now())
			mu.Unlock()
			return sent, nil
		}
		sampler := egressFixture().NewSampler(1, policyscale.FlowModel{Direction: policyscale.Egress})
		start := time.Now()
		res := runFlows(sampler.Next, flowsConfig{rate: rate, duration: time.Second, concurrency: 4, describe: "test"}, send, io.Discard, nil)

		// Ticks the scheduler couldn't deliver are dropped rather than made up, so a loaded machine
		// sends fewer; it must never send many more.
		if res.opened > uint64(rate+rate/100+1) || res.opened < uint64(rate/2) {
			t.Fatalf("opened %d flows in a 1 s run at %d/s", res.opened, rate)
		}
		windows := map[int]int{}
		for _, ts := range times {
			windows[int(ts.Sub(start)/(100*time.Millisecond))]++
		}
		for w, n := range windows {
			if n > max(rate/10*3/2, 2) {
				t.Errorf("rate %d: window %d carried %d flows, more than 1.5 times its share of %d", rate, w, n, rate/10)
			}
		}
	}
}

// The flows sent are the fixture's, in the fixture's order, so each has the trace policyscale
// -flows prints for it.
func TestRunFlowsDrawsTheFixturesFlows(t *testing.T) {
	fx := egressFixture()
	model := policyscale.FlowModel{Direction: policyscale.Egress, MissFraction: 0.1, RepeatFraction: 0.5}

	var got []*policyscale.Flow
	send := func(f *policyscale.Flow) (outcome, error) {
		got = append(got, f)
		return sent, nil
	}
	runFlows(fx.NewSampler(policyscale.DefaultSeed, model).Next,
		flowsConfig{rate: 300, duration: 300 * time.Millisecond, concurrency: 1, describe: "test"}, send, io.Discard, nil)
	if len(got) == 0 {
		t.Fatal("no flows sent")
	}
	want := fx.NewSampler(policyscale.DefaultSeed, model)
	for i, f := range got {
		if w := want.Next(); f.String() != w.String() {
			t.Fatalf("flow %d is %s, want the fixture's %s", i, f, w)
		}
	}
}

func TestCheckFixture(t *testing.T) {
	for _, ok := range []string{"", "abc", " ABC\n"} {
		if err := checkFixture(ok, "abc"); err != nil {
			t.Errorf("-fixture %q: %v", ok, err)
		}
	}
	if err := checkFixture("abd", "abc"); err == nil || !strings.Contains(err.Error(), "POLICYSCALE_") {
		t.Errorf("different fixture: %v", err)
	}
}

// A policy set scaled through the environment is a different fixture, so a flowgen run without the
// same environment is caught by the fingerprint.
func TestScaledFixtureHasAnotherFingerprint(t *testing.T) {
	unscaled := egressFixture().Fingerprint()
	t.Setenv("POLICYSCALE_POLICIES", "50")
	spec, err := policyscale.Preset("egress", policyscale.DefaultSeed)
	if err != nil {
		t.Fatal(err)
	}
	if scaled := policyscale.Build(spec).Fingerprint(); checkFixture(scaled, unscaled) == nil {
		t.Fatalf("scaling the preset kept fingerprint %s", scaled)
	}
}

// Each flow keeps the protocol the fixture gave it unless one is forced, and the targets and the
// spread addresses apply to the copy that is sent, never to the fixture's flow.
func TestPreparer(t *testing.T) {
	fx := shapesFixture()
	var flows []*policyscale.Flow
	protocols := map[int]bool{}
	for _, sf := range fx.ShapeFlows(policyscale.Egress) {
		flows = append(flows, sf.Flow)
		protocols[sf.Flow.Protocol] = true
	}
	if len(protocols) < 3 {
		t.Fatalf("the shapes preset should give flows of several protocols, got %v", protocols)
	}
	keep := preparer(prepareConfig{})
	for _, f := range flows {
		if c := keep(f); c.Protocol != f.Protocol || c == f {
			t.Fatalf("%s: sent as protocol %d", f, c.Protocol)
		}
	}
	udp := preparer(prepareConfig{forcedProtocol: policyscale.ProtocolUDP})
	for _, f := range flows {
		if c := udp(f); c.Protocol != policyscale.ProtocolUDP {
			t.Fatalf("%s: -protocol udp sent protocol %d", f, c.Protocol)
		}
	}

	to := preparer(prepareConfig{targets: []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")}})
	f := policyscale.NewFlow(policyscale.SourceIP, 40000, policyscale.DeniedDestIP, 443)
	var dsts []string
	for range 3 {
		dsts = append(dsts, to(f).DstIP.String())
	}
	if strings.Join(dsts, ",") != "10.0.0.1,10.0.0.2,10.0.0.1" {
		t.Errorf("targets not taken in turn: %v", dsts)
	}

	spread := preparer(prepareConfig{spreadSource: true, spreadDenied: true})
	srcs, denied := map[string]bool{}, map[string]bool{}
	for range 2 * 253 {
		c := spread(f)
		srcs[c.SrcIP.String()] = true
		denied[c.DstIP.String()] = true
	}
	for name, seen := range map[string]map[string]bool{policyscale.SourceIP: srcs, policyscale.DeniedDestIP: denied} {
		prefix := name[:strings.LastIndex(name, ".")+1]
		if len(seen) != 253 || seen[name] || seen[prefix+"0"] || seen[prefix+"255"] {
			t.Errorf("%s spread over %d addresses of its /24, including itself or the ends: %v", name, len(seen), seen[name])
		}
	}
	if f.DstIP.String() != policyscale.DeniedDestIP || f.SrcIP.String() != policyscale.SourceIP {
		t.Errorf("the fixture's flow was changed: %s", f)
	}
}

// Spreading the shared source and the denied destination over their /24s changes no trace: no rule
// names those addresses.
func TestSpreadKeepsTraces(t *testing.T) {
	for name, fx := range map[string]*policyscale.Fixture{
		"egress":    egressFixture(),
		"composite": policyscale.Build(policyscale.Composite()),
		"shapes":    shapesFixture(),
	} {
		prepare := preparer(prepareConfig{spreadSource: true, spreadDenied: true})
		for _, dir := range []policyscale.Direction{policyscale.Ingress, policyscale.Egress} {
			if fx.Rules(dir) == 0 {
				continue
			}
			s := fx.NewSampler(1, policyscale.FlowModel{Direction: dir, MissFraction: 0.5})
			if c := sampleVerdictChanges(fx, dir, s, prepare, 300); c.Changed != 0 {
				t.Errorf("%s %s: spreading changed %d of %d traces", name, dir, c.Changed, c.Sampled)
			}
		}
	}
}

// Sending to a target in place of the generated destination changes the traces, and flowgen says
// how many; with neither -targets nor a forced protocol nothing changes.
func TestSampleVerdictChanges(t *testing.T) {
	fx := egressFixture()
	model := policyscale.FlowModel{Direction: policyscale.Egress, MissFraction: 0.1}
	override := preparer(prepareConfig{targets: []net.IP{net.ParseIP("127.0.0.1")}})
	if c := sampleVerdictChanges(fx, policyscale.Egress, fx.NewSampler(1, model), override, 200); c.Changed < 150 {
		t.Errorf("-override-dst 127.0.0.1 changed only %d of %d egress traces", c.Changed, c.Sampled)
	}
	if c := sampleVerdictChanges(fx, policyscale.Egress, fx.NewSampler(1, model), preparer(prepareConfig{}), 200); c.Changed != 0 {
		t.Errorf("an unchanged flow got another trace %d times", c.Changed)
	}
}

// A dry run counts the flows that match a rule as they would be sent, which is how it shows a
// forced protocol at work: every flow misses rules that name TCP.
func TestDryRunTally(t *testing.T) {
	fx := egressFixture()
	model := policyscale.FlowModel{Direction: policyscale.Egress, MissFraction: 0.1}

	run := func(forced int) *dryRunSummary {
		tally := newDryRunTally(fx, policyscale.Egress)
		prepare := preparer(prepareConfig{forcedProtocol: forced})
		s := fx.NewSampler(1, model)
		for range 200 {
			f := s.Next()
			tally.record(f, prepare(f))
		}
		return tally.summary()
	}

	if s := run(0); s.ByProtocol["tcp"] != 200 || s.Matching == 0 || s.Changed != 0 || s.Skipped != 0 {
		t.Errorf("fixture protocols: %+v", s)
	}
	if s := run(policyscale.ProtocolUDP); s.ByProtocol["udp"] != 200 || s.Matching != 0 || s.Changed == 0 {
		t.Errorf("-protocol udp against TCP rules should match no rule, and change the matching flows' traces: %+v", s)
	}

	tally := newDryRunTally(shapesFixture(), policyscale.Egress)
	var unsendable int
	for _, sf := range shapesFixture().ShapeFlows(policyscale.Egress) {
		if p := sf.Flow.Protocol; p != policyscale.ProtocolTCP && p != policyscale.ProtocolUDP {
			unsendable++
		}
		tally.record(sf.Flow, sf.Flow)
	}
	if s := tally.summary(); unsendable == 0 || s.Skipped != unsendable {
		t.Errorf("shapes preset, %d flows flowgen can't send: %+v", unsendable, s)
	}
}

// The sender puts a UDP flow on the wire as a datagram and a TCP flow as a connection that ends in
// a reset, to the target in place of the generated destination. A refused attempt made a flow
// too; a flow of another protocol is skipped.
func TestSenderSendsToASink(t *testing.T) {
	udpSink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udpSink.Close() }()
	tcpSink, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcpSink.Close() }()
	readErr := make(chan error, 1)
	go func() {
		c, err := tcpSink.Accept()
		if err != nil {
			readErr <- err
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = c.Read(make([]byte, 1))
		_ = c.Close()
		readErr <- err
	}()

	send := sender(preparer(prepareConfig{targets: []net.IP{net.ParseIP("127.0.0.1")}}), time.Second, false)
	udpFlow := policyscale.NewFlow(policyscale.SourceIP, 40000, "198.51.100.7", udpSink.LocalAddr().(*net.UDPAddr).Port)
	udpFlow.Protocol = policyscale.ProtocolUDP
	if o, err := send(udpFlow); o != sent {
		t.Fatalf("UDP flow: %v %v", o, err)
	}
	buf := make([]byte, 64)
	_ = udpSink.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, _, err := udpSink.ReadFrom(buf); err != nil || string(buf[:n]) != "policyscale" {
		t.Fatalf("UDP sink got %q, %v", buf[:n], err)
	}

	tcpFlow := policyscale.NewFlow(policyscale.SourceIP, 40000, "198.51.100.7", tcpSink.Addr().(*net.TCPAddr).Port)
	if o, err := send(tcpFlow); o != sent {
		t.Fatalf("TCP flow: %v %v", o, err)
	}
	// A reset, not a close, so the sender's side leaves no TIME_WAIT.
	if err := <-readErr; !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("the TCP sink read %v, want a reset", err)
	}

	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refusedPort := closed.Addr().(*net.TCPAddr).Port
	_ = closed.Close()
	if o, err := send(policyscale.NewFlow(policyscale.SourceIP, 40000, "198.51.100.7", refusedPort)); o != sent {
		t.Fatalf("refused TCP flow: %v %v, want it counted as sent", o, err)
	}

	icmp := policyscale.NewFlow(policyscale.SourceIP, 0, "198.51.100.7", 8<<8)
	icmp.Protocol = policyscale.ProtocolICMP
	if o, _ := send(icmp); o != skipped {
		t.Fatalf("ICMP flow: %v, want skipped", o)
	}
}

func TestTCPFlowsOnly(t *testing.T) {
	var all []*policyscale.Flow
	for _, sf := range shapesFixture().ShapeFlows(policyscale.Egress) {
		all = append(all, sf.Flow)
	}
	i := 0
	next := tcpFlows(func() *policyscale.Flow {
		f := all[i%len(all)]
		i++
		return f
	})
	for range 50 {
		if f := next(); f.Protocol != policyscale.ProtocolTCP {
			t.Fatalf("hold mode drew a protocol %d flow", f.Protocol)
		}
	}
}

// Attempts nobody answers hold a sender for the whole TCP timeout, so the pool grows with the rate.
func TestSendersFor(t *testing.T) {
	if n := sendersFor(1000, 5*time.Millisecond); n != 64 {
		t.Errorf("1,000/s: %d senders, want the floor of 64", n)
	}
	if n := sendersFor(20000, 5*time.Millisecond); n < 200 {
		t.Errorf("20,000/s at 5 ms: %d senders hold only %d attempts a second", n, n*200)
	}
}

func TestVerdict(t *testing.T) {
	second := time.Second
	for _, tc := range []struct {
		name   string
		res    flowsResult
		dryRun bool
		want   int
	}{
		{"on rate", flowsResult{opened: 990, elapsed: second}, false, 0},
		{"short", flowsResult{opened: 500, elapsed: second}, false, exitShortfall},
		{"failures first", flowsResult{opened: 500, failed: 1, elapsed: second}, false, exitFailures},
		{"skipped flows aren't a shortfall", flowsResult{opened: 600, skipped: 400, elapsed: second}, false, 0},
		{"unroutable flows aren't either", flowsResult{opened: 600, unroutable: 400, elapsed: second}, false, 0},
		{"a dry run has no rate", flowsResult{opened: 100, elapsed: second}, true, 0},
	} {
		if got, reason := verdict(tc.res, 1000, 0.05, tc.dryRun); got != tc.want {
			t.Errorf("%s: exit %d (%s), want %d", tc.name, got, reason, tc.want)
		}
	}
}

// The flags a harness gets wrong exit 2 before any flow is sent; a fixture mismatch exits 3 with
// its summary; a dry run ends with one JSON line on stdout.
func TestRunExitCodes(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want int
	}{
		{[]string{"-rate", "0"}, exitUsage},
		{[]string{"-concurrency", "-1"}, exitUsage},
		{[]string{"-mode", "hold", "-dry-run"}, exitUsage},
		{[]string{"-preset", "nope"}, exitUsage},
		{[]string{"-no-such-flag"}, exitUsage},
		{[]string{"-preset", "egress", "-fixture", "000000000000", "-duration", "1ms"}, exitFixture},
		{[]string{"-preset", "egress", "-dry-run", "-rate", "200", "-duration", "300ms"}, 0},
	} {
		var stdout bytes.Buffer
		if got := run(tc.args, &stdout, io.Discard); got != tc.want {
			t.Errorf("%v: exit %d, want %d", tc.args, got, tc.want)
			continue
		}
		if tc.want == exitUsage {
			continue
		}
		var s summary
		if err := json.Unmarshal(stdout.Bytes(), &s); err != nil {
			t.Errorf("%v: summary %q: %v", tc.args, stdout.String(), err)
			continue
		}
		if s.Exit != tc.want || s.Fingerprint == "" {
			t.Errorf("%v: summary %+v", tc.args, s)
		}
		if tc.want == 0 && (s.DryRun == nil || s.DryRun.Matching == 0) {
			t.Errorf("%v: dry-run summary %+v", tc.args, s.DryRun)
		}
	}
}
