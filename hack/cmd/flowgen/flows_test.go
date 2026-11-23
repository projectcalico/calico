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
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectcalico/calico/app-policy/policyscale"
)

// The run sends close to the requested rate, and spreads it over the second rather than sending
// a second's worth at once: no 100 ms window carries much more than a tenth of the rate.
func TestRunFlowsPacesEvenly(t *testing.T) {
	const rate = 500
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
	fx := policyscale.Build(policyscale.EgressAllowList())
	sampler := fx.NewSampler(1, policyscale.FlowModel{Direction: policyscale.Egress})
	start := time.Now()
	res := runFlows(sampler.Next, flowsConfig{rate: rate, duration: time.Second, concurrency: 4, describe: "test"}, send, io.Discard, nil)

	// Ticks the scheduler couldn't deliver are dropped rather than made up, so a loaded machine
	// sends fewer; it must never send more.
	if res.opened > rate+rate/100 || res.opened < rate/2 {
		t.Fatalf("opened %d flows in a 1 s run at %d/s", res.opened, rate)
	}
	windows := map[int]int{}
	for _, ts := range times {
		windows[int(ts.Sub(start)/(100*time.Millisecond))]++
	}
	for w, n := range windows {
		if n > rate/10*3/2 {
			t.Errorf("window %d carried %d flows, more than 1.5 times its share of %d", w, n, rate/10)
		}
	}
}

// The flows sent are the fixture's, in the fixture's order, so each has the verdict policyscale
// -flows prints for it.
func TestRunFlowsDrawsTheFixturesFlows(t *testing.T) {
	spec, err := policyscale.Preset("egress", policyscale.DefaultSeed)
	if err != nil {
		t.Fatal(err)
	}
	fx := policyscale.Build(spec)
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
	if err := checkFixture("", "abc"); err != nil {
		t.Errorf("no -fixture given: %v", err)
	}
	if err := checkFixture("abc", "abc"); err != nil {
		t.Errorf("same fixture: %v", err)
	}
	if err := checkFixture("abd", "abc"); err == nil || !strings.Contains(err.Error(), "POLICYSCALE_") {
		t.Errorf("different fixture: %v", err)
	}
}

// A policy set scaled through the environment is a different fixture, so a flowgen run without the
// same environment is caught by the fingerprint.
func TestScaledFixtureHasAnotherFingerprint(t *testing.T) {
	spec, err := policyscale.Preset("egress", policyscale.DefaultSeed)
	if err != nil {
		t.Fatal(err)
	}
	unscaled := policyscale.Fingerprint(policyscale.Build(spec).Spec)
	t.Setenv("POLICYSCALE_POLICIES", "500")
	spec, err = policyscale.Preset("egress", policyscale.DefaultSeed)
	if err != nil {
		t.Fatal(err)
	}
	scaled := policyscale.Fingerprint(policyscale.Build(spec).Spec)
	if checkFixture(scaled, unscaled) == nil {
		t.Fatalf("scaling the preset kept fingerprint %s", scaled)
	}
}

// Each flow keeps the protocol the fixture gave it unless one is forced, and the targets and the
// spread source apply to the copy that is sent, never to the fixture's flow.
func TestPreparer(t *testing.T) {
	fx := policyscale.Build(policyscale.RuleShapes())
	var flows []*policyscale.Flow
	protocols := map[int]bool{}
	for _, sf := range fx.ShapeFlows(policyscale.Egress) {
		flows = append(flows, sf.Flow)
		protocols[sf.Flow.Protocol] = true
	}
	if len(protocols) < 3 {
		t.Fatalf("the shapes preset should give flows of several protocols, got %v", protocols)
	}
	keep := preparer(0, nil, false)
	for _, f := range flows {
		if c := keep(f); c.Protocol != f.Protocol || c == f {
			t.Fatalf("%s: sent as protocol %d", f, c.Protocol)
		}
	}
	udp := preparer(policyscale.ProtocolUDP, nil, false)
	for _, f := range flows {
		if c := udp(f); c.Protocol != policyscale.ProtocolUDP {
			t.Fatalf("%s: -protocol udp sent protocol %d", f, c.Protocol)
		}
	}

	targets := []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")}
	to := preparer(0, targets, true)
	f := policyscale.NewFlow(policyscale.SourceIP, 40000, "198.51.100.7", 443)
	var dsts, srcs []string
	for range 3 {
		c := to(f)
		dsts = append(dsts, c.DstIP.String())
		srcs = append(srcs, c.SrcIP.String())
	}
	if strings.Join(dsts, ",") != "10.0.0.1,10.0.0.2,10.0.0.1" {
		t.Errorf("targets not taken in turn: %v", dsts)
	}
	for _, s := range srcs {
		if s == policyscale.SourceIP || !strings.HasPrefix(s, "192.0.2.") {
			t.Errorf("shared source not spread across its /24: %v", srcs)
		}
	}
	if f.DstIP.String() != "198.51.100.7" || f.SrcIP.String() != policyscale.SourceIP {
		t.Errorf("the fixture's flow was changed: %s", f)
	}
}

// A dry run counts the flows that match a rule as they would be sent, which is how it shows a
// forced protocol at work: every flow misses rules that name TCP.
func TestDryRunTally(t *testing.T) {
	fx := policyscale.Build(policyscale.EgressAllowList())
	model := policyscale.FlowModel{Direction: policyscale.Egress, MissFraction: 0.1}

	run := func(forced int) string {
		tally := newDryRunTally(fx, policyscale.Egress)
		prepare := preparer(forced, nil, false)
		s := fx.NewSampler(1, model)
		for range 200 {
			tally.record(prepare(s.Next()))
		}
		var b bytes.Buffer
		tally.print(&b)
		return b.String()
	}

	out := run(0)
	if !strings.Contains(out, "by protocol: tcp=200;") || strings.Contains(out, "matching a rule: 0,") || !strings.Contains(out, "skipped (protocol flowgen can't send): 0") {
		t.Errorf("fixture protocols: %s", out)
	}
	out = run(policyscale.ProtocolUDP)
	if !strings.Contains(out, "by protocol: udp=200;") || !strings.Contains(out, "matching a rule: 0, matching none: 200;") {
		t.Errorf("-protocol udp against TCP rules should match no rule: %s", out)
	}

	shapes := policyscale.Build(policyscale.RuleShapes())
	tally := newDryRunTally(shapes, policyscale.Egress)
	var unsendable int
	for _, sf := range shapes.ShapeFlows(policyscale.Egress) {
		if p := sf.Flow.Protocol; p != policyscale.ProtocolTCP && p != policyscale.ProtocolUDP {
			unsendable++
		}
		tally.record(sf.Flow)
	}
	var b bytes.Buffer
	tally.print(&b)
	if unsendable == 0 || !strings.Contains(b.String(), "skipped (protocol flowgen can't send): "+strconv.Itoa(unsendable)) {
		t.Errorf("shapes preset, %d flows flowgen can't send: %s", unsendable, b.String())
	}
}

// The sender puts a UDP flow on the wire as a datagram and a TCP flow as a connection, to the
// target in place of the generated destination; a flow of another protocol is skipped.
func TestSenderSendsToASink(t *testing.T) {
	udpSink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpSink.Close()
	tcpSink, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpSink.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := tcpSink.Accept(); err == nil {
			_ = c.Close()
			accepted <- struct{}{}
		}
	}()

	send := sender(preparer(0, []net.IP{net.ParseIP("127.0.0.1")}, false), time.Second, false)
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
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("TCP sink accepted no connection")
	}

	icmp := policyscale.NewFlow(policyscale.SourceIP, 0, "198.51.100.7", 8<<8)
	icmp.Protocol = policyscale.ProtocolICMP
	if o, _ := send(icmp); o != skipped {
		t.Fatalf("ICMP flow: %v, want skipped", o)
	}
}

func TestTCPFlowsOnly(t *testing.T) {
	fx := policyscale.Build(policyscale.RuleShapes())
	var all []*policyscale.Flow
	for _, sf := range fx.ShapeFlows(policyscale.Egress) {
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
