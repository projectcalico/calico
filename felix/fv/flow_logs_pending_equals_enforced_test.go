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
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calico/app-policy/policyscale"
	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/collector/local"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

// With no staged policies, the pending verdict Felix works out for a flow must name exactly the
// policies, rules and actions the dataplane enforced for it. The policies are the policyscale
// rule-shape preset, one rule for each kind of criterion, applied as enforced policy to a local
// workload; every flow the preset aims at a rule is sent between a local workload and a peer
// workload of its own, and every flow log record must report the same pending and enforced
// policies, which must also be what the preset's oracle expects. Rule shapes with a known
// difference between the two on the dataplane under test, listed in policyscale's known
// differences, are left out.
var _ = infrastructure.DatastoreDescribe(
	"_BPF-SAFE_ pending policies equal enforced policies with no staged policies",
	[]apiconfig.DatastoreType{apiconfig.Kubernetes},
	func(getInfra infrastructure.InfraFactory) {
		const (
			localLabel   = "pending-equals-enforced"
			profileAllow = "__PROFILE__|pro:" + policyscale.DefaultProfile + "|allow|0"
		)
		var (
			infra    infrastructure.DatastoreInfra
			tc       infrastructure.TopologyContainers
			fx       *policyscale.Fixture
			policies []*api.GlobalNetworkPolicy
			byIP     map[netip.Addr]*workload.Workload
			locals   []*workload.Workload
		)

		dataplane := policyscale.Iptables
		switch {
		case BPFMode():
			dataplane = policyscale.BPF
		case infrastructure.NFTMode():
			dataplane = policyscale.Nftables
		}
		// The size of the plan on each dataplane today, less a margin: a plan much smaller than
		// this has lost rule shapes.
		minRules, minFlows := map[policyscale.Where]int{policyscale.Iptables: 70, policyscale.Nftables: 62, policyscale.BPF: 70},
			map[policyscale.Where]int{policyscale.Iptables: 250, policyscale.Nftables: 220, policyscale.BPF: 235}

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

			// The policies select the local workloads on the first node; every peer address the
			// preset uses is a workload of its own on the second node.
			shapes := policyscale.DefaultShapes()
			shapes.LocalIPv4 = netip.MustParseAddr("10.65.0.10")
			shapes.LocalIPv6 = netip.MustParseAddr("dead:beef::10")
			shapes.PeerIPv4 = netip.MustParsePrefix("10.65.1.0/24")
			shapes.PeerIPv6 = netip.MustParsePrefix("dead:beef::1:0/120")
			shapes.LeaveOut = policyscale.LeaveOutAt(dataplane)
			fx = policyscale.Build(policyscale.Spec{
				Seed:    policyscale.DefaultSeed,
				Shapes:  &shapes,
				Profile: policyscale.DefaultProfile,
			})

			byIP = map[netip.Addr]*workload.Workload{}
			addWorkload := func(felix *infrastructure.Felix, name string, labels map[string]string, addrs ...netip.Addr) *workload.Workload {
				var wopts []workload.Opt
				for _, a := range addrs {
					infrastructure.AssignIP(name, a.String(), felix.Hostname, c)
				}
				if len(addrs) > 1 {
					wopts = append(wopts, workload.WithIPv6Address(addrs[1].String()))
				}
				w := workload.New(felix, name, "default", addrs[0].String(), "8055", "tcp", wopts...)
				w.WorkloadEndpoint.Labels = labels
				for _, np := range fx.NamedPorts() {
					if slices.ContainsFunc(addrs, func(a netip.Addr) bool { return slices.Contains(np.Addrs, a) }) {
						w.WorkloadEndpoint.Spec.Ports = append(w.WorkloadEndpoint.Spec.Ports, internalapi.WorkloadEndpointPort{
							Name:     np.Name,
							Port:     uint16(np.Port),
							Protocol: numorstring.ProtocolFromString(np.Protocol),
						})
					}
				}
				Expect(w.Start(infra)).To(Succeed())
				w.ConfigureInInfra(infra)
				for _, a := range addrs {
					byIP[a] = w
				}
				return w
			}
			// A flow log record doesn't tell the IP families apart, and holds one pending verdict,
			// so each family's flows go to a local workload of their own.
			locals = []*workload.Workload{
				addWorkload(tc.Felixes[0], "local-v4", map[string]string{localLabel: "true"}, shapes.LocalIPv4),
				addWorkload(tc.Felixes[0], "local-v6", map[string]string{localLabel: "true"}, shapes.LocalIPv6),
			}
			for _, offset := range peerOffsets(fx, shapes) {
				addWorkload(tc.Felixes[1], fmt.Sprintf("peer-%d", offset), map[string]string{"peer": strconv.Itoa(offset)},
					nthAddr(shapes.PeerIPv4, offset), nthAddr(shapes.PeerIPv6, offset))
			}

			ensureRoutesProgrammed(tc.Felixes)
			if BPFMode() {
				ensureAllNodesBPFProgramsAttached(tc.Felixes)
			}

			createServiceEndpointSlices(infra, fx.Services())
			objs := fx.Resources(policyscale.ResourceOptions{
				Selector: fmt.Sprintf("%s == 'true'", localLabel),
				Enforced: true,
			})
			applyResources(c, objs)
			policies = nil
			for _, o := range objs {
				if gnp, ok := o.(*api.GlobalNetworkPolicy); ok {
					policies = append(policies, gnp)
				}
			}
			waitForPolicies(tc.Felixes[0], locals, policies)
		})

		It("reports the enforced policies as the pending ones for every flow of the rule-shape preset", func() {
			// The builds this runs against know every protocol name on BPF, so rules that name
			// ICMPv6 and UDPLite are checked there too.
			excluded := slices.DeleteFunc(policyscale.DifferencesAt(policyscale.Evaluator, dataplane),
				func(d policyscale.Difference) bool { return d == policyscale.ProtocolNamesOnBPF })

			plan := newPendingPlan()
			rules := 0
			for _, dir := range []policyscale.Direction{policyscale.Ingress, policyscale.Egress} {
				rules += len(fx.ShapeRules(dir))
				for _, sf := range fx.ShapeFlows(dir, excluded...) {
					plan.add(fx, dir, sf, byIP, profileAllow)
				}
			}
			Expect(plan.conflicts).To(BeEmpty(),
				"flows that would share a flow log record but expect different verdicts")
			Expect(rules).To(BeNumerically(">=", minRules[dataplane]), "rules in the preset")
			Expect(len(plan.flows)).To(BeNumerically(">=", minFlows[dataplane]), "flows planned")
			log.Infof("Sending %d flows for %d rules, expecting %d flow log records", len(plan.flows), rules, len(plan.records))

			var mismatches, earlyPending []string
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
				var pendingOnly []string
				mismatches, pendingOnly, converged = plan.compare(records)
				if converged || attempt == 5 {
					log.Infof("Compared %d flow log records on attempt %d", len(records), attempt)
					break
				}
				// The dataplane hasn't caught up with every policy yet: some enforced verdicts still
				// differ from the oracle's. Pending verdicts that differed even where the enforced
				// one was right are kept, since a retry could hide them.
				earlyPending = append(earlyPending, pendingOnly...)
				log.Infof("Attempt %d: the dataplane doesn't enforce the oracle's verdicts yet:\n%s",
					attempt, strings.Join(mismatches, "\n"))
				time.Sleep(3 * time.Second)
			}
			if len(earlyPending) > 0 {
				log.Warnf("Pending policies that differed from correct enforced ones before the dataplane caught up:\n%s",
					strings.Join(earlyPending, "\n"))
				AddReportEntry("pending policies that differed before the dataplane caught up", earlyPending)
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

// createServiceEndpointSlices makes the endpoint slices Felix builds a service match from. Felix
// needs no Service object for that.
func createServiceEndpointSlices(infra infrastructure.DatastoreInfra, services []policyscale.Service) {
	kc := infra.(*infrastructure.K8sDatastoreInfra).K8sClient
	for _, svc := range services {
		ns := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: svc.Namespace}}
		if _, err := kc.CoreV1().Namespaces().Create(utils.Ctx, ns, metav1.CreateOptions{}); !apierrors.IsAlreadyExists(err) {
			Expect(err).NotTo(HaveOccurred())
		}
		port := int32(svc.Port)
		protocol := v1.Protocol(strings.ToUpper(svc.Protocol))
		byFamily := map[discovery.AddressType][]string{}
		for _, a := range svc.Addrs {
			family := discovery.AddressTypeIPv4
			if a.Is6() {
				family = discovery.AddressTypeIPv6
			}
			byFamily[family] = append(byFamily[family], a.String())
		}
		for family, addrs := range byFamily {
			eps := &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      strings.ToLower(fmt.Sprintf("%s-%s", svc.Name, family)),
					Namespace: svc.Namespace,
					Labels:    map[string]string{discovery.LabelServiceName: svc.Name},
				},
				AddressType: family,
				Endpoints:   []discovery.Endpoint{{Addresses: addrs}},
				Ports:       []discovery.EndpointPort{{Port: &port, Protocol: &protocol}},
			}
			_, err := kc.DiscoveryV1().EndpointSlices(svc.Namespace).Create(utils.Ctx, eps, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		}
	}
}

// waitForPolicies waits until the first node's dataplane has every policy for the local
// workloads, in both IP families, so that the first flows sent meet all of them.
func waitForPolicies(f *infrastructure.Felix, locals []*workload.Workload, policies []*api.GlobalNetworkPolicy) {
	hook := func(p *api.GlobalNetworkPolicy) string {
		if slices.Contains(p.Spec.Types, api.PolicyTypeEgress) {
			return "egress"
		}
		return "ingress"
	}
	missing := func() []string {
		var out []string
		if BPFMode() {
			for _, w := range locals {
				args := []string{"calico-bpf", "policy", "dump", w.InterfaceName}
				if strings.Contains(w.IP, ":") {
					args = []string{"calico-bpf", "-6", "policy", "dump", w.InterfaceName}
				}
				for _, h := range []string{"ingress", "egress"} {
					dump, _ := f.ExecOutput(append(args, h)...)
					for _, p := range policies {
						if hook(p) == h && !strings.Contains(dump, "Policy: GlobalNetworkPolicy "+p.Name) {
							out = append(out, fmt.Sprintf("%s %s %s", w.Name, h, p.Name))
						}
					}
				}
			}
			return out
		}
		var dumps []string
		if infrastructure.NFTMode() {
			for _, table := range []string{"ip", "ip6"} {
				d, _ := f.ExecOutput("nft", "list", "chains", table, "calico")
				dumps = append(dumps, d)
			}
		} else {
			for _, save := range []string{"iptables-save", "ip6tables-save"} {
				d, _ := f.ExecOutput(save, "-t", "filter")
				dumps = append(dumps, d)
			}
		}
		for _, p := range policies {
			prefix := rules.PolicyInboundPfx
			if hook(p) == "egress" {
				prefix = rules.PolicyOutboundPfx
			}
			chain := rules.PolicyChainName(prefix, &types.PolicyID{Name: p.Name, Kind: api.KindGlobalNetworkPolicy}, infrastructure.NFTMode())
			for i, d := range dumps {
				if !strings.Contains(d, chain) {
					out = append(out, fmt.Sprintf("%s (table %d)", chain, i))
				}
			}
		}
		return out
	}
	Eventually(missing, "60s", "1s").Should(BeEmpty(), "policies the dataplane doesn't have yet")
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
	kinds := map[string]string{
		api.KindGlobalNetworkPolicy:       "gnp",
		api.KindStagedGlobalNetworkPolicy: "sgnp",
		api.KindProfile:                   "pro",
	}
	var out []string
	for i, v := range trace {
		kind, ok := kinds[v.Kind]
		Expect(ok).To(BeTrue(), "no flow log name for a %s", v.Kind)
		out = append(out, fmt.Sprintf("%d|%s|%s:%s|%s|%d", i, v.Tier, kind, v.Policy, v.Action, v.Index))
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

// compare checks every flow log record from the test's workloads against the plan. A record's
// enforced policies differing from the oracle's, a planned record missing, or a record the plan
// didn't expect (as when the dataplane took another action) means the dataplane hasn't caught up
// with the policies yet, so the result is only final, converged, once there are none. A record
// whose pending policies are empty or differ from its enforced ones is a mismatch either way;
// pendingOnly lists those whose enforced policies were right.
func (p *pendingPlan) compare(records []flowlog.FlowLog) (mismatches, pendingOnly []string, converged bool) {
	converged = true
	for _, r := range records {
		key := keyOfRecord(r)
		enforced, pending := sortedPolicies(r.FlowEnforcedPolicySet), sortedPolicies(r.FlowPendingPolicySet)
		planned, ok := p.records[key]
		if !ok {
			mismatches = append(mismatches, fmt.Sprintf("- %v: no flow sent should produce this record\n    enforced: %v\n    pending:  %v",
				key, enforced, pending))
			converged = false
			continue
		}
		var problems []string
		enforcedRight := slices.Equal(enforced, planned.expected)
		if !enforcedRight {
			problems = append(problems, "enforced policies differ from the oracle's")
			converged = false
		}
		pendingWrong := len(pending) == 0 || !slices.Equal(pending, enforced)
		if len(pending) == 0 {
			problems = append(problems, "no pending policies")
		} else if !slices.Equal(pending, enforced) {
			problems = append(problems, "pending policies differ from the enforced ones")
		}
		if len(problems) == 0 {
			continue
		}
		m := fmt.Sprintf("- %v: %s\n    flows:    %q\n    enforced: %v\n    pending:  %v\n    oracle:   %v",
			key, strings.Join(problems, "; "), planned.flows, enforced, pending, planned.expected)
		mismatches = append(mismatches, m)
		if enforcedRight && pendingWrong {
			pendingOnly = append(pendingOnly, m)
		}
	}
	// A missing record means the dataplane dropped the flow before it reached policy, or hasn't
	// logged it yet.
	for _, m := range p.missing(records) {
		mismatches = append(mismatches, "- no flow log record: "+m)
		converged = false
	}
	sort.Strings(mismatches)
	sort.Strings(pendingOnly)
	return slices.Compact(mismatches), slices.Compact(pendingOnly), converged
}

func sortedPolicies(s flowlog.FlowPolicySet) []string {
	var out []string
	for p := range s {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
