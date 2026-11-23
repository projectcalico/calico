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

package fv_test

import (
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calico/app-policy/policyscale"
	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/collector/local"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

// With no staged policies, the pending verdict Felix works out for a flow must name exactly the
// policies, rules and actions the dataplane enforced for it. The policies are the policyscale
// rule-shape preset, one rule for each kind of criterion, applied as enforced policy to one
// workload; every flow the preset aims at a rule is sent between that workload and a peer workload
// of its own, and every flow log must report the same pending and enforced policies, which must
// also be what the preset's oracle expects. Rule shapes with a known difference between the two,
// listed in policyscale.KnownDifferences for the dataplane under test, are left out.
var _ = infrastructure.DatastoreDescribe(
	"_BPF-SAFE_ pending policies equal enforced policies with no staged policies",
	[]apiconfig.DatastoreType{apiconfig.Kubernetes},
	func(getInfra infrastructure.InfraFactory) {
		const (
			localLabel   = "pending-equals-enforced"
			profileAllow = "__PROFILE__|pro:kns.default|allow|0"
		)
		var (
			infra infrastructure.DatastoreInfra
			tc    infrastructure.TopologyContainers
			fx    *policyscale.Fixture
			byIP  map[netip.Addr]*workload.Workload
		)

		dataplane := policyscale.Iptables
		switch {
		case BPFMode():
			dataplane = policyscale.BPF
		case infrastructure.NFTMode():
			dataplane = policyscale.Nftables
		}

		BeforeEach(func() {
			infra = getInfra()
			opts := infrastructure.DefaultTopologyOptions()
			opts.IPIPMode = api.IPIPModeNever
			opts.EnableIPv6 = true
			opts.FlowLogSource = infrastructure.FlowLogSourceLocalSocket
			opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "3"
			opts.ExtraEnvVars["FELIX_FLOWLOGSPOLICYEVALUATIONMODE"] = "Continuous"
			opts.ExtraEnvVars["FELIX_FLOWLOGSGOLDMANESERVER"] = local.SocketAddress

			var c client.Interface
			tc, c = infrastructure.StartNNodeTopology(2, opts, infra)
			infra.AddDefaultAllow()

			// The policies select a workload on the first node; every peer address the preset
			// uses is a workload of its own on the second node.
			shapes := policyscale.DefaultShapes()
			shapes.LocalIPv4 = netip.MustParseAddr("10.65.0.10")
			shapes.LocalIPv6 = netip.MustParseAddr("dead:beef::10")
			shapes.PeerIPv4 = netip.MustParsePrefix("10.65.1.0/24")
			shapes.PeerIPv6 = netip.MustParsePrefix("dead:beef::1:0/120")
			shapes.LeaveOut = policyscale.LeaveOutAt(dataplane)
			fx = policyscale.Build(policyscale.Spec{Seed: policyscale.DefaultSeed, Shapes: &shapes})

			resourceOpts := policyscale.ResourceOptions{Selector: fmt.Sprintf("%s == 'true'", localLabel)}

			byIP = map[netip.Addr]*workload.Workload{}
			addWorkload := func(felix *infrastructure.Felix, name string, v4, v6 netip.Addr, labels map[string]string) *workload.Workload {
				infrastructure.AssignIP(name, v4.String(), felix.Hostname, c)
				infrastructure.AssignIP(name, v6.String(), felix.Hostname, c)
				w := workload.New(felix, name, "default", v4.String(), "8055", "tcp",
					workload.WithIPv6Address(v6.String()))
				maps.Copy(labels, fx.EndpointLabels(resourceOpts, v4, v6))
				w.WorkloadEndpoint.Labels = labels
				for _, np := range fx.NamedPorts() {
					if slices.Contains(np.Addrs, v4) || slices.Contains(np.Addrs, v6) {
						w.WorkloadEndpoint.Spec.Ports = append(w.WorkloadEndpoint.Spec.Ports, internalapi.WorkloadEndpointPort{
							Name:     np.Name,
							Port:     uint16(np.Port),
							Protocol: numorstring.ProtocolFromString(np.Protocol),
						})
					}
				}
				Expect(w.Start(infra)).To(Succeed())
				w.ConfigureInInfra(infra)
				byIP[v4], byIP[v6] = w, w
				return w
			}
			addWorkload(tc.Felixes[0], "local", shapes.LocalIPv4, shapes.LocalIPv6,
				map[string]string{localLabel: "true"})
			for _, offset := range peerOffsets(fx, shapes) {
				addWorkload(tc.Felixes[1], fmt.Sprintf("peer-%d", offset),
					nthAddr(shapes.PeerIPv4, offset), nthAddr(shapes.PeerIPv6, offset),
					map[string]string{"peer": strconv.Itoa(offset)})
			}

			ensureRoutesProgrammed(tc.Felixes)
			if BPFMode() {
				ensureAllNodesBPFProgramsAttached(tc.Felixes)
			}

			applyResources(c, fx.Resources(resourceOpts))
		})

		It("reports the enforced policies as the pending ones for every flow of the rule-shape preset", func() {
			excluded := policyscale.DifferencesAt(policyscale.Evaluator, dataplane)

			plan := newPendingPlan()
			for _, dir := range []policyscale.Direction{policyscale.Ingress, policyscale.Egress} {
				for _, sf := range fx.ShapeFlows(dir, excluded...) {
					if strings.HasPrefix(sf.Name, "destination service:") {
						// A service match needs a Kubernetes Service and its endpoint slices,
						// which the test doesn't create; with no service, the rule matches
						// nothing, enforced or pending.
						continue
					}
					plan.add(fx, dir, sf, byIP, profileAllow)
				}
			}
			Expect(plan.conflicts).To(BeEmpty(),
				"flows that would share a flow log record but expect different verdicts")
			log.Infof("Sending %d flows, expecting %d flow log records", len(plan.flows), len(plan.records))

			var mismatches []string
			for attempt := 1; ; attempt++ {
				for _, f := range tc.Felixes {
					f.FlowServerReset()
				}
				var records []flowlog.FlowLog
				for _, round := range plan.rounds() {
					for _, f := range tc.Felixes {
						flushConntrack(f)
					}
					sendPlannedFlows(round)

					// Records arrive with each flush; give every planned one time to.
					deadline := time.Now().Add(30 * time.Second)
					for {
						records = nil
						for _, f := range tc.Felixes {
							fls, err := f.FlowLogs()
							if err == nil {
								records = append(records, fls...)
							}
						}
						if len(plan.missingFor(records, round)) == 0 || time.Now().After(deadline) {
							break
						}
						time.Sleep(time.Second)
					}
				}

				var converged bool
				mismatches, converged = plan.compare(records)
				if converged || attempt == 5 {
					log.Infof("Compared %d flow log records on attempt %d", len(records), attempt)
					break
				}
				// The dataplane hasn't caught up with every policy yet: the enforced verdicts
				// still differ from the oracle's. Try again with fresh connections.
				log.Infof("Attempt %d: the dataplane doesn't enforce the oracle's verdicts yet:\n%s",
					attempt, strings.Join(mismatches, "\n"))
				time.Sleep(3 * time.Second)
			}
			Expect(mismatches).To(BeEmpty(), "%d flow log records with pending policies that differ from "+
				"the enforced ones, or with enforced policies that differ from the oracle's:\n%s",
				len(mismatches), strings.Join(mismatches, "\n"))
		})
	})

// peerOffsets returns the offset in the peer pools of every peer address the preset's flows use.
func peerOffsets(fx *policyscale.Fixture, p policyscale.ShapesParams) []int {
	seen := map[int]bool{}
	for _, dir := range []policyscale.Direction{policyscale.Ingress, policyscale.Egress} {
		for _, sf := range fx.ShapeFlows(dir) {
			for _, ip := range []net.IP{sf.Flow.SrcIP, sf.Flow.DstIP} {
				a, _ := netip.AddrFromSlice(ip)
				a = a.Unmap()
				for _, pool := range []netip.Prefix{p.PeerIPv4, p.PeerIPv6} {
					if pool.Contains(a) {
						b := a.AsSlice()
						seen[int(b[len(b)-1])] = true
					}
				}
			}
		}
	}
	var out []int
	for o := range seen {
		out = append(out, o)
	}
	sort.Ints(out)
	return out
}

func nthAddr(p netip.Prefix, n int) netip.Addr {
	a := p.Masked().Addr()
	for range n {
		a = a.Next()
	}
	return a
}

func applyResources(c client.Interface, objs []runtime.Object) {
	// Tiers first and policies last, so that every policy arrives with what it refers to.
	for _, pass := range []func(runtime.Object) bool{
		func(o runtime.Object) bool { _, ok := o.(*api.Tier); return ok },
		func(o runtime.Object) bool { _, ok := o.(*api.GlobalNetworkSet); return ok },
		func(o runtime.Object) bool { _, ok := o.(*api.GlobalNetworkPolicy); return ok },
	} {
		for _, o := range objs {
			if !pass(o) {
				continue
			}
			var err error
			switch r := o.(type) {
			case *api.Tier:
				_, err = c.Tiers().Create(utils.Ctx, r, utils.NoOptions)
			case *api.GlobalNetworkSet:
				_, err = c.GlobalNetworkSets().Create(utils.Ctx, r, utils.NoOptions)
			case *api.GlobalNetworkPolicy:
				_, err = c.GlobalNetworkPolicies().Create(utils.Ctx, r, utils.NoOptions)
			}
			Expect(err).NotTo(HaveOccurred())
		}
	}
	for _, o := range objs {
		switch o.(type) {
		case *api.Tier, *api.GlobalNetworkSet, *api.GlobalNetworkPolicy:
		default:
			Fail(fmt.Sprintf("the preset rendered a %T, which the test doesn't create", o))
		}
	}
}

func flushConntrack(f *infrastructure.Felix) {
	if BPFMode() {
		f.Exec("calico-bpf", "conntrack", "clean")
		f.Exec("calico-bpf", "-6", "conntrack", "clean")
		return
	}
	f.Exec("conntrack", "-F")
	f.Exec("conntrack", "-f", "ipv6", "-F")
}

// pendingRecordKey is what tells flow log records apart, once aggregated by workload: the
// collector keeps one pending verdict for all the flows that share it.
type pendingRecordKey struct {
	src, dst string
	proto    int
	// port is the destination port, or the ICMP type and code; -1 for protocols whose ports the
	// collector doesn't read.
	port     int
	reporter flowlog.ReporterType
	action   flowlog.Action
}

func (k pendingRecordKey) String() string {
	return fmt.Sprintf("%s -> %s proto %d port %d reporter=%s action=%s", k.src, k.dst, k.proto, k.port, k.reporter, k.action)
}

func recordPort(proto, port int) int {
	switch proto {
	case 1, 6, 17, 58:
		return port
	}
	return -1
}

type plannedFlow struct {
	name     string
	src, dst *workload.Workload
	flow     *policyscale.Flow
	keys     []pendingRecordKey
}

type plannedRecord struct {
	key      pendingRecordKey
	expected []string
	flows    []string
}

type pendingPlan struct {
	flows     []plannedFlow
	records   map[pendingRecordKey]*plannedRecord
	conflicts []string
}

func newPendingPlan() *pendingPlan {
	return &pendingPlan{records: map[pendingRecordKey]*plannedRecord{}}
}

// add plans a flow and the flow log records it should produce: one from its source workload
// always, and one from its destination when the source lets it out. When the flow would share a
// record with a flow that expects a different verdict, a TCP or UDP flow moves to another
// destination port that the oracle gives the same verdict, if there is one.
func (p *pendingPlan) add(fx *policyscale.Fixture, dir policyscale.Direction, sf policyscale.ShapeFlow,
	byIP map[netip.Addr]*workload.Workload, profileAllow string,
) {
	lookup := func(ip net.IP) *workload.Workload {
		a, _ := netip.AddrFromSlice(ip)
		w := byIP[a.Unmap()]
		Expect(w).NotTo(BeNil(), "no workload for %s in flow %q", ip, sf.Name)
		return w
	}
	src, dst := lookup(sf.Flow.SrcIP), lookup(sf.Flow.DstIP)

	recordsFor := func(f *policyscale.Flow) []*plannedRecord {
		local := verdictStrings(fx.Expect(dir, f))
		peer := []string{"0|" + profileAllow}
		srcExp, dstExp := peer, local
		if dir == policyscale.Egress {
			srcExp, dstExp = local, peer
		}
		port := recordPort(f.Protocol, f.DstPort)
		out := []*plannedRecord{{
			key:      pendingRecordKey{src.Name, dst.Name, f.Protocol, port, flowlog.ReporterSrc, finalAction(srcExp)},
			expected: srcExp,
		}}
		if finalAction(srcExp) == flowlog.ActionAllow {
			out = append(out, &plannedRecord{
				key:      pendingRecordKey{src.Name, dst.Name, f.Protocol, port, flowlog.ReporterDst, finalAction(dstExp)},
				expected: dstExp,
			})
		}
		return out
	}
	clashes := func(recs []*plannedRecord) bool {
		for _, r := range recs {
			if existing, ok := p.records[r.key]; ok && !slices.Equal(existing.expected, r.expected) {
				return true
			}
		}
		return false
	}

	f := sf.Flow
	recs := recordsFor(f)
	if clashes(recs) && (f.Protocol == 6 || f.Protocol == 17) {
		for k := 1; k <= 5; k++ {
			moved := *f
			moved.DstPort = f.DstPort + 1000*k
			movedRecs := recordsFor(&moved)
			if !clashes(movedRecs) && sameExpectations(recs, movedRecs) {
				f, recs = &moved, movedRecs
				break
			}
		}
	}
	if clashes(recs) {
		p.conflicts = append(p.conflicts, fmt.Sprintf("%s: %v", sf.Name, recs[len(recs)-1].key))
		return
	}
	pf := plannedFlow{name: sf.Name, src: src, dst: dst, flow: f}
	for _, r := range recs {
		pf.keys = append(pf.keys, r.key)
	}
	p.flows = append(p.flows, pf)
	for _, r := range recs {
		if existing, ok := p.records[r.key]; ok {
			existing.flows = append(existing.flows, sf.Name)
			continue
		}
		r.flows = []string{sf.Name}
		p.records[r.key] = r
	}
}

func sameExpectations(a, b []*plannedRecord) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !slices.Equal(a[i].expected, b[i].expected) {
			return false
		}
	}
	return true
}

// verdictStrings renders the oracle's trace as flow log policy strings.
func verdictStrings(trace []policyscale.Verdict) []string {
	var out []string
	for i, v := range trace {
		if v.Kind == api.KindProfile {
			out = append(out, fmt.Sprintf("%d|%s|pro:%s|%s|%d", i, v.Tier, v.Policy, v.Action, v.Index))
			continue
		}
		out = append(out, fmt.Sprintf("%d|%s|gnp:%s.%s|%s|%d", i, v.Tier, v.Tier, v.Policy, v.Action, v.Index))
	}
	return out
}

func finalAction(trace []string) flowlog.Action {
	if len(trace) > 0 {
		if parts := strings.Split(trace[len(trace)-1], "|"); len(parts) == 5 && parts[3] == "allow" {
			return flowlog.ActionAllow
		}
	}
	return flowlog.ActionDeny
}

// rounds splits the planned flows into rounds to send one after another, with conntrack cleared in
// between. BPF conntrack tracks all ICMP between two addresses as one connection, whatever the type
// and code, so a second ICMP flow between them would join the first and never meet policy; each
// round holds at most one ICMP flow between a pair of addresses. Elsewhere one round holds them all.
func (p *pendingPlan) rounds() [][]plannedFlow {
	if !BPFMode() {
		return [][]plannedFlow{p.flows}
	}
	var rounds [][]plannedFlow
	icmpSeen := map[string]int{}
	for _, pf := range p.flows {
		r := 0
		if pf.flow.Protocol == 1 || pf.flow.Protocol == 58 {
			a, b := pf.flow.SrcIP.String(), pf.flow.DstIP.String()
			if b < a {
				a, b = b, a
			}
			pair := a + "/" + b
			r = icmpSeen[pair]
			icmpSeen[pair]++
		}
		for len(rounds) <= r {
			rounds = append(rounds, nil)
		}
		rounds[r] = append(rounds[r], pf)
	}
	return rounds
}

// sendPlannedFlows sends one packet that opens each flow, from inside its source workload.
func sendPlannedFlows(flows []plannedFlow) {
	bySrc := map[*workload.Workload][]string{}
	for _, pf := range flows {
		bySrc[pf.src] = append(bySrc[pf.src], pktgenCommand(pf.flow))
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for w, cmds := range bySrc {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer GinkgoRecover()
			sem <- struct{}{}
			defer func() { <-sem }()
			out, err := w.ExecCombinedOutput("sh", "-c", strings.Join(cmds, " && "))
			Expect(err).NotTo(HaveOccurred(), "sending flows from %s: %s", w.Name, out)
		}()
	}
	wg.Wait()
}

func pktgenCommand(f *policyscale.Flow) string {
	args := []string{"pktgen", f.SrcIP.String(), f.DstIP.String()}
	switch f.Protocol {
	case 1, 58:
		typ, code := policyscale.ICMPTypeCode(f)
		proto := "icmp"
		if f.Protocol == 58 {
			proto = "icmp6"
		}
		args = append(args, proto, fmt.Sprintf("--icmp-type=%d", typ), fmt.Sprintf("--icmp-code=%d", code),
			"--payload-size=8")
	case 6:
		args = append(args, "tcp", "--tcp-syn", "--payload-size=0")
	case 17:
		args = append(args, "udp", "--payload-size=8")
	case 132:
		args = append(args, "sctp")
	case 136:
		args = append(args, "udplite", "--payload-size=8")
	default:
		Fail(fmt.Sprintf("no way to send protocol %d", f.Protocol))
	}
	if f.Protocol != 1 && f.Protocol != 58 {
		args = append(args, fmt.Sprintf("--port-src=%d", f.SrcPort), fmt.Sprintf("--port-dst=%d", f.DstPort))
	}
	return strings.Join(args, " ")
}

// missing returns the planned records that none of the flow log records match yet.
func (p *pendingPlan) missing(records []flowlog.FlowLog) []string {
	return p.missingFor(records, p.flows)
}

// missingFor returns the records the given flows should produce that none of the flow log records
// match yet.
func (p *pendingPlan) missingFor(records []flowlog.FlowLog, flows []plannedFlow) []string {
	seen := map[pendingRecordKey]bool{}
	for _, r := range records {
		seen[keyOfRecord(r)] = true
	}
	var out []string
	for _, pf := range flows {
		for _, k := range pf.keys {
			if !seen[k] {
				out = append(out, fmt.Sprintf("%v (flows %q)", k, p.records[k].flows))
			}
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

func keyOfRecord(r flowlog.FlowLog) pendingRecordKey {
	return pendingRecordKey{
		src:      r.SrcMeta.AggregatedName,
		dst:      r.DstMeta.AggregatedName,
		proto:    r.Tuple.Proto,
		port:     recordPort(r.Tuple.Proto, r.Tuple.L4Dst),
		reporter: r.Reporter,
		action:   r.Action,
	}
}

// compare checks every flow log record that belongs to a planned flow. A record's enforced
// policies differing from the oracle's means the dataplane hasn't caught up with the policies yet,
// so the result is only final, converged, once none does; a record whose pending policies differ
// from its enforced ones, or are empty, is a mismatch either way.
func (p *pendingPlan) compare(records []flowlog.FlowLog) (mismatches []string, converged bool) {
	converged = true
	var unplanned []string
	for _, r := range records {
		key := keyOfRecord(r)
		planned, ok := p.records[key]
		if !ok {
			unplanned = append(unplanned, fmt.Sprintf("%v enforced=%v pending=%v",
				key, sortedPolicies(r.FlowEnforcedPolicySet), sortedPolicies(r.FlowPendingPolicySet)))
			continue
		}
		enforced, pending := sortedPolicies(r.FlowEnforcedPolicySet), sortedPolicies(r.FlowPendingPolicySet)
		var problems []string
		if !slices.Equal(enforced, planned.expected) {
			problems = append(problems, "enforced policies differ from the oracle's")
			converged = false
		}
		if len(pending) == 0 {
			problems = append(problems, "no pending policies")
		} else if !slices.Equal(pending, enforced) {
			problems = append(problems, "pending policies differ from the enforced ones")
		}
		if len(problems) == 0 {
			continue
		}
		mismatches = append(mismatches, fmt.Sprintf("- %v: %s\n    flows:    %q\n    enforced: %v\n    pending:  %v\n    oracle:   %v",
			key, strings.Join(problems, "; "), planned.flows, enforced, pending, planned.expected))
	}
	// A missing record means the dataplane dropped the flow before it reached policy, or hasn't
	// logged it yet.
	for _, m := range p.missing(records) {
		mismatches = append(mismatches, "- no flow log record: "+m)
		converged = false
	}
	if len(unplanned) > 0 {
		sort.Strings(unplanned)
		log.Infof("Flow log records for flows the test didn't plan:\n%s", strings.Join(slices.Compact(unplanned), "\n"))
		if !converged {
			mismatches = append(mismatches, "Flow log records for flows the test didn't plan:\n"+strings.Join(slices.Compact(unplanned), "\n"))
		}
	}
	sort.Strings(mismatches)
	return slices.Compact(mismatches), converged
}

func sortedPolicies(s flowlog.FlowPolicySet) []string {
	var out []string
	for p := range s {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
