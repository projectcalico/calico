// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// calico-bpf-policy-check builds a workload's BPF policy program offline from
// exported YAML and reports unreachable code.
//
// Example, with resources exported from a diags bundle:
//
//	CGO_ENABLED=0 go run ./felix/cmd/calico-bpf-policy-check \
//	  -resources ./bundle/ -pod my-ns/my-pod
//
// Host endpoint policy is not modelled.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	kapiv1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/projectcalico/calico/felix/bpf/asm"
	"github.com/projectcalico/calico/felix/bpf/jump"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

const hostname = "policy-check"

var (
	resources      = flag.String("resources", "", "Comma-separated YAML files or directories with Tiers, policies, Namespaces and Pods.")
	pod            = flag.String("pod", "", "Workload to check, as namespace/name of a Pod in -resources.")
	namespace      = flag.String("namespace", "", "Workload namespace, when not using -pod.")
	labels         = flag.String("labels", "", "Workload labels as k=v,k=v, when not using -pod.")
	serviceAccount = flag.String("service-account", "default", "Workload service account, when not using -pod.")
	direction      = flag.String("direction", "ingress", "Policy direction: ingress (to the workload) or egress.")
	ipv6           = flag.Bool("ipv6", false, "Build the IPv6 program.")
	flowLogs       = flag.Bool("flow-logs", true, "Felix has flow logs enabled.")
	policyDebug    = flag.Bool("policy-debug", true, "Felix has BPFPolicyDebugEnabled (the default).")
	jumpLimit      = flag.Int("jump-limit", 0, "Override the jumps per sub-program limit.")
	sweep          = flag.String("sweep-jump-limit", "", "Check every jump limit in the range from:to.")
	dump           = flag.Bool("dump", false, "Print the instructions.")
	logLevel       = flag.String("log-level", "warn", "Log level.")
)

func main() {
	flag.Parse()
	lvl, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		fatalf("bad -log-level: %v", err)
	}
	logrus.SetLevel(lvl)
	if *resources == "" {
		fatalf("-resources is required")
	}

	objs, err := loadResources(strings.Split(*resources, ","))
	if err != nil {
		fatalf("%v", err)
	}
	wl, err := pickWorkload(objs)
	if err != nil {
		fatalf("%v", err)
	}
	rules, idAlloc, err := buildRules(objs, wl)
	if err != nil {
		fatalf("%v", err)
	}

	if *sweep == "" {
		if !check(rules, idAlloc, *jumpLimit, true) {
			os.Exit(1)
		}
		return
	}
	from, to, ok := strings.Cut(*sweep, ":")
	lo, err1 := strconv.Atoi(from)
	hi, err2 := strconv.Atoi(to)
	if !ok || err1 != nil || err2 != nil || lo > hi {
		fatalf("bad -sweep-jump-limit %q, want from:to", *sweep)
	}
	var bad []int
	for limit := lo; limit <= hi; limit++ {
		if !check(rules, idAlloc, limit, false) {
			bad = append(bad, limit)
		}
	}
	fmt.Printf("jump limits %d..%d with unreachable code: %v\n", lo, hi, bad)
	if len(bad) > 0 {
		os.Exit(1)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}

// objects holds the resources that affect a workload's policy program.
type objects struct {
	tiers     []apiv3.Tier
	gnps      []apiv3.GlobalNetworkPolicy
	nps       []apiv3.NetworkPolicy
	knps      []networkingv1.NetworkPolicy
	nss       []kapiv1.Namespace
	pods      []kapiv1.Pod
	numIgnore int
}

func loadResources(paths []string) (*objects, error) {
	objs := &objects{}
	for _, path := range paths {
		err := filepath.WalkDir(path, func(f string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !(strings.HasSuffix(f, ".yaml") || strings.HasSuffix(f, ".yml") || strings.HasSuffix(f, ".json")) {
				return nil
			}
			if strings.HasPrefix(d.Name(), "._") {
				return nil // macOS metadata
			}
			return objs.loadFile(f)
		})
		if err != nil {
			return nil, err
		}
	}
	return objs, nil
}

func (o *objects) loadFile(f string) error {
	data, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	dec := k8syaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	for {
		doc, err := dec.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		if err := o.add(doc); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
	}
}

func (o *objects) add(doc []byte) error {
	var tm struct {
		metav1.TypeMeta `json:",inline"`
		Items           []any `json:"items"`
	}
	if err := yaml.Unmarshal(doc, &tm); err != nil {
		return err
	}
	if strings.HasSuffix(tm.Kind, "List") {
		for _, item := range tm.Items {
			b, err := yaml.Marshal(item)
			if err != nil {
				return err
			}
			if err := o.add(b); err != nil {
				return err
			}
		}
		return nil
	}
	group, _, _ := strings.Cut(tm.APIVersion, "/")
	var err error
	switch {
	case group == "projectcalico.org" && tm.Kind == "Tier":
		err = appendDecoded(doc, &o.tiers)
	case group == "projectcalico.org" && tm.Kind == "GlobalNetworkPolicy":
		err = appendDecoded(doc, &o.gnps)
	case group == "projectcalico.org" && tm.Kind == "NetworkPolicy":
		err = appendDecoded(doc, &o.nps)
	case group == "networking.k8s.io" && tm.Kind == "NetworkPolicy":
		err = appendDecoded(doc, &o.knps)
	case tm.APIVersion == "v1" && tm.Kind == "Namespace":
		err = appendDecoded(doc, &o.nss)
	case tm.APIVersion == "v1" && tm.Kind == "Pod":
		err = appendDecoded(doc, &o.pods)
	default:
		o.numIgnore++
	}
	return err
}

func appendDecoded[T any](doc []byte, out *[]T) error {
	var v T
	if err := yaml.Unmarshal(doc, &v); err != nil {
		return err
	}
	*out = append(*out, v)
	return nil
}

type workload struct {
	namespace      string
	labels         map[string]string
	serviceAccount string
}

func pickWorkload(objs *objects) (*workload, error) {
	if *pod != "" {
		ns, name, ok := strings.Cut(*pod, "/")
		if !ok {
			return nil, fmt.Errorf("-pod must be namespace/name")
		}
		for _, p := range objs.pods {
			if p.Namespace == ns && p.Name == name {
				sa := p.Spec.ServiceAccountName
				if sa == "" {
					sa = "default"
				}
				return &workload{namespace: ns, labels: p.Labels, serviceAccount: sa}, nil
			}
		}
		return nil, fmt.Errorf("pod %s not found in -resources", *pod)
	}
	if *namespace == "" {
		return nil, fmt.Errorf("give -pod, or -namespace and -labels")
	}
	wl := &workload{namespace: *namespace, labels: map[string]string{}, serviceAccount: *serviceAccount}
	for kv := range strings.SplitSeq(*labels, ",") {
		if kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, fmt.Errorf("bad label %q, want k=v", kv)
		}
		wl.labels[k] = v
	}
	return wl, nil
}

// buildRules returns the rules Felix's calculation graph selects for the
// workload.
func buildRules(objs *objects, wl *workload) (polprog.Rules, *idalloc.IDAllocator, error) {
	var ups []api.Update
	add := func(up watchersyncer.SyncerUpdateProcessor, kvp *model.KVPair) error {
		out, err := up.Process(kvp)
		if err != nil {
			return fmt.Errorf("%v: %w", kvp.Key, err)
		}
		for _, o := range out {
			ups = append(ups, api.Update{KVPair: *o, UpdateType: api.UpdateTypeKVNew})
		}
		return nil
	}
	c := conversion.NewConverter()
	for i := range objs.tiers {
		t := &objs.tiers[i]
		if err := add(updateprocessors.NewTierUpdateProcessor(), &model.KVPair{
			Key: model.ResourceKey{Name: t.Name, Kind: apiv3.KindTier}, Value: t,
		}); err != nil {
			return polprog.Rules{}, nil, err
		}
	}
	for i := range objs.gnps {
		p := &objs.gnps[i]
		if err := add(updateprocessors.NewGlobalNetworkPolicyUpdateProcessor(apiv3.KindGlobalNetworkPolicy), &model.KVPair{
			Key: model.ResourceKey{Name: p.Name, Kind: apiv3.KindGlobalNetworkPolicy}, Value: p,
		}); err != nil {
			return polprog.Rules{}, nil, err
		}
	}
	for i := range objs.nps {
		p := &objs.nps[i]
		if err := add(updateprocessors.NewNetworkPolicyUpdateProcessor(apiv3.KindNetworkPolicy), &model.KVPair{
			Key: model.ResourceKey{Name: p.Name, Namespace: p.Namespace, Kind: apiv3.KindNetworkPolicy}, Value: p,
		}); err != nil {
			return polprog.Rules{}, nil, err
		}
	}
	for i := range objs.knps {
		kvp, err := c.K8sNetworkPolicyToCalico(&objs.knps[i])
		if err != nil {
			logrus.WithError(err).Warnf("Partial conversion of NetworkPolicy %s/%s", objs.knps[i].Namespace, objs.knps[i].Name)
		}
		if err := add(updateprocessors.NewNetworkPolicyUpdateProcessor(model.KindKubernetesNetworkPolicy), kvp); err != nil {
			return polprog.Rules{}, nil, err
		}
	}

	ns := kapiv1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: wl.namespace}}
	for _, n := range objs.nss {
		if n.Name == wl.namespace {
			ns = n
		}
	}
	if ns.Labels == nil {
		logrus.Warnf("Namespace %s not in -resources; namespace selectors only see its name", wl.namespace)
	}
	ns.UID = "00000000-0000-0000-0000-000000000001"
	kvp, err := c.NamespaceToProfile(&ns)
	if err != nil {
		return polprog.Rules{}, nil, err
	}
	if err := add(updateprocessors.NewProfileUpdateProcessor(), kvp); err != nil {
		return polprog.Rules{}, nil, err
	}
	sa := &kapiv1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
		Name: wl.serviceAccount, Namespace: wl.namespace, UID: "00000000-0000-0000-0000-000000000002",
	}}
	if kvp, err = c.ServiceAccountToProfile(sa); err != nil {
		return polprog.Rules{}, nil, err
	}
	if err := add(updateprocessors.NewProfileUpdateProcessor(), kvp); err != nil {
		return polprog.Rules{}, nil, err
	}

	wepLabels := map[string]string{}
	for k, v := range wl.labels {
		wepLabels[k] = v
	}
	wepLabels[apiv3.LabelNamespace] = wl.namespace
	wepLabels[apiv3.LabelOrchestrator] = apiv3.OrchestratorKubernetes
	wepLabels[apiv3.LabelServiceAccount] = wl.serviceAccount
	ups = append(ups, api.Update{UpdateType: api.UpdateTypeKVNew, KVPair: model.KVPair{
		Key: model.WorkloadEndpointKey{Hostname: hostname, OrchestratorID: "k8s", WorkloadID: wl.namespace + "/wl", EndpointID: "eth0"},
		Value: &model.WorkloadEndpoint{
			State:  "active",
			Name:   "cali0000000000",
			Labels: uniquelabels.Make(wepLabels),
			ProfileIDs: []string{
				conversion.NamespaceProfileNamePrefix + wl.namespace,
				conversion.ServiceAccountProfileNamePrefix + wl.namespace + "." + wl.serviceAccount,
			},
			IPv4Nets: []cnet.IPNet{cnet.MustParseCIDR("10.0.0.1/32")},
			IPv6Nets: []cnet.IPNet{cnet.MustParseCIDR("fd00::1/128")},
		},
	}})

	conf := config.New()
	conf.FelixHostname = hostname
	conf.BPFEnabled = true
	eventBuf := calc.NewEventSequencer(conf)
	policies := map[string]*proto.Policy{}
	profiles := map[string]*proto.Profile{}
	var wep *proto.WorkloadEndpoint
	eventBuf.Callback = func(msg any) {
		switch m := msg.(type) {
		case *proto.ActivePolicyUpdate:
			policies[m.Id.String()] = m.Policy
		case *proto.ActiveProfileUpdate:
			profiles[m.Id.Name] = m.Profile
		case *proto.WorkloadEndpointUpdate:
			wep = m.Endpoint
		}
	}
	cg := calc.NewCalculationGraph(eventBuf, calc.NewLookupsCache(), conf, func() {})
	vf := calc.NewValidationFilter(cg, conf)
	vf.OnUpdates(ups)
	vf.OnStatusUpdated(api.InSync)
	cg.Flush()
	eventBuf.Flush()
	if wep == nil {
		return polprog.Rules{}, nil, fmt.Errorf("calculation graph produced no endpoint")
	}

	ingress := *direction == "ingress"
	if !ingress && *direction != "egress" {
		return polprog.Rules{}, nil, fmt.Errorf("bad -direction %q", *direction)
	}
	idAlloc := idalloc.New()
	var matchID uint64
	convert := func(prs []*proto.Rule) []polprog.Rule {
		var out []polprog.Rule
		for _, pr := range prs {
			for _, ids := range [][]string{
				pr.SrcIpSetIds, pr.NotSrcIpSetIds, pr.DstIpSetIds, pr.NotDstIpSetIds,
				pr.DstIpPortSetIds, pr.SrcNamedPortIpSetIds,
				pr.NotSrcNamedPortIpSetIds, pr.DstNamedPortIpSetIds, pr.NotDstNamedPortIpSetIds,
			} {
				for _, id := range ids {
					idAlloc.GetOrAlloc(id)
				}
			}
			matchID++
			out = append(out, polprog.Rule{Rule: pr, MatchID: matchID})
		}
		return out
	}

	// Mirrors bpfEndpointManager.extractRules.
	var rules polprog.Rules
	fmt.Printf("Policies for the workload (%s):\n", *direction)
	for _, tier := range wep.Tiers {
		pols := tier.IngressPolicies
		if !ingress {
			pols = tier.EgressPolicies
		}
		if len(pols) == 0 {
			continue
		}
		pt := polprog.Tier{Name: tier.Name}
		for _, pid := range pols {
			if model.KindIsStaged(pid.Kind) {
				continue
			}
			pol := policies[pid.String()]
			if pol == nil {
				return polprog.Rules{}, nil, fmt.Errorf("unknown policy %v", pid)
			}
			prs := pol.InboundRules
			if !ingress {
				prs = pol.OutboundRules
			}
			fmt.Printf("  tier %-30s %-24s %s: %d rules\n", tier.Name, pid.Kind, policyName(pid), len(prs))
			pt.Policies = append(pt.Policies, polprog.Policy{
				Name: pid.Name, Namespace: pid.Namespace, Kind: pid.Kind, Rules: convert(prs),
			})
		}
		matchID++
		pt.EndRuleID = matchID
		pt.EndAction = polprog.TierEndDeny
		if tier.DefaultAction == string(apiv3.Pass) {
			pt.EndAction = polprog.TierEndPass
		}
		rules.Tiers = append(rules.Tiers, pt)
	}
	for _, name := range wep.ProfileIds {
		prof := profiles[name]
		if prof == nil {
			continue
		}
		prs := prof.InboundRules
		if !ingress {
			prs = prof.OutboundRules
		}
		rules.Profiles = append(rules.Profiles, polprog.Profile{Name: name, Rules: convert(prs)})
	}
	matchID++
	rules.NoProfileMatchID = matchID
	return rules, idAlloc, nil
}

func policyName(pid *proto.PolicyID) string {
	if pid.Namespace == "" {
		return pid.Name
	}
	return pid.Namespace + "/" + pid.Name
}

// check builds the program and returns false if any sub-program has
// unreachable code or a sub-program is not tail-called.
func check(rules polprog.Rules, idAlloc *idalloc.IDAllocator, limit int, verbose bool) bool {
	const polMapIdx = 5
	opts := []polprog.Option{
		polprog.WithAllowDenyJumps(10, 11),
		polprog.WithPolicyMapIndexAndStride(polMapIdx, jump.TCMaxEntryPoints),
	}
	if *ipv6 {
		opts = append(opts, polprog.WithIPv6())
	}
	if *flowLogs {
		opts = append(opts, polprog.WithFlowLogs())
	}
	if *policyDebug || *dump {
		opts = append(opts, polprog.WithPolicyDebugEnabled())
	}
	if limit > 0 {
		opts = append(opts, polprog.WithMaxJumpsPerProgram(limit))
	}
	progs, err := polprog.NewBuilder(idAlloc, 1, 2, 3, 4, opts...).Instructions(rules)
	if err != nil {
		fmt.Printf("jump limit %d: build failed: %v\n", limit, err)
		return false
	}
	ok := true
	for i, p := range progs {
		unreachable := asm.UnreachableInsns(p)
		jumps := 0
		for _, in := range p {
			// Counted like the builder's split limit, which includes calls and exits.
			if cls := in.OpClass(); cls == asm.OpClassJump64 || cls == asm.OpClassJump32 {
				jumps++
			}
		}
		if verbose {
			fmt.Printf("sub-program %d: %d instructions, %d jumps\n", i, len(p), jumps)
		}
		if len(unreachable) > 0 {
			ok = false
			fmt.Printf("jump limit %d: sub-program %d: unreachable instructions %v\n", limit, i, unreachable)
		}
		if *dump {
			for j, in := range p {
				for _, l := range in.Labels {
					fmt.Printf("        %s:\n", l)
				}
				for _, cm := range in.Comments {
					fmt.Printf("        // %s\n", cm)
				}
				fmt.Printf("%d/%5d: %s\n", i, j, in)
			}
		}
	}
	return ok
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: CGO_ENABLED=0 go run ./felix/cmd/calico-bpf-policy-check -resources DIR (-pod NS/NAME | -namespace NS -labels k=v,...)\n\n")
		flag.PrintDefaults()
	}
}
