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

// policyscale renders one of the app-policy/policyscale presets as Calico resources, for applying
// the benchmark policy sets to a cluster, or prints flows drawn from its flow model with the
// trace the endpoint's pending policies must report for each, for driving and checking a
// node-level run.
//
//	go run ./hack/cmd/policyscale -preset composite > composite.yaml
//	kubectl label pod <pod> policyscale.projectcalico.org/target=true
//	kubectl apply --server-side -f composite.yaml
//
// The policies are staged by default, so they are evaluated for the pending verdict without
// being enforced; -staged=false renders enforced policies, which will deny the selected
// endpoint's non-matching traffic.
//
//	go run ./hack/cmd/policyscale -preset composite -flows 1000 -direction egress
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/projectcalico/calico/app-policy/policyscale"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() (err error) {
	var (
		preset    = flag.String("preset", "composite", "policy set to render: baseline, egress, composite or shapes")
		seed      = flag.Int64("seed", policyscale.DefaultSeed, "generator seed; the shapes preset has no random choices")
		selector  = flag.String("selector", policyscale.TargetSelector, "endpoint selector the policies apply to")
		profile   = flag.String("profile", policyscale.DefaultProfile, "the endpoint's namespace profile, kns.<namespace>, which allows what gets past every tier; empty for an endpoint with none")
		staged    = flag.Bool("staged", true, "render StagedGlobalNetworkPolicy rather than GlobalNetworkPolicy; staged policies are evaluated for the pending verdict but program no enforcement rules, so the set is safe to apply to a live cluster")
		out       = flag.String("out", "-", "output file, - for stdout")
		flows     = flag.Int("flows", 0, "instead of resources, print this many flows with their expected traces; the shapes preset prints every flow aimed at its rules")
		direction = flag.String("direction", "egress", "direction of the printed flows: ingress or egress")
		miss      = flag.Float64("miss-fraction", 0.1, "fraction of printed flows that match no rule; not used by the shapes preset")
		repeat    = flag.Float64("repeat-fraction", 0.5, "fraction of printed flows that repeat an earlier one with a new source port; not used by the shapes preset")
		overDst   = flag.String("override-dst", "", "with -flows: give each flow this destination before working out its expected trace, as flowgen -override-dst sends it")
		printFP   = flag.Bool("fingerprint", false, "print the fingerprint of the policy set and exit; every rendered object carries it in the "+policyscale.FixtureLabel+" label")
		prefixes  = flag.Bool("prefixes", false, "print the address ranges the policy set's flows use, one per line, and exit: the routes a sink needs and the sources an ingress run spoofs")
	)
	flag.Usage = usage
	flag.Parse()

	spec, err := policyscale.Preset(*preset, *seed)
	if err != nil {
		return err
	}
	var dir policyscale.Direction
	switch *direction {
	case "ingress":
		dir = policyscale.Ingress
	case "egress":
		dir = policyscale.Egress
	default:
		return fmt.Errorf("unknown direction %q", *direction)
	}
	var dst net.IP
	if *overDst != "" {
		if dst = net.ParseIP(*overDst); dst == nil {
			return fmt.Errorf("bad -override-dst %q", *overDst)
		}
	}
	spec.Profile = *profile
	if err := spec.Validate(); err != nil {
		return err
	}
	fx := policyscale.Build(spec)
	switch {
	case *printFP:
		fmt.Println(fx.Fingerprint())
		return nil
	case *prefixes:
		for _, p := range fx.Prefixes() {
			fmt.Println(p)
		}
		return nil
	}

	var w io.Writer = os.Stdout
	if *out != "-" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, f.Close()) }()
		w = f
	}
	bw := bufio.NewWriter(w)
	defer func() { err = errors.Join(err, bw.Flush()) }()

	fmt.Fprintf(os.Stderr, "%s (fingerprint %s): %d ingress rules in %d policies, %d egress rules in %d policies, %d IP sets with %d members\n",
		*preset, fx.Fingerprint(), fx.Rules(policyscale.Ingress), fx.Policies(policyscale.Ingress),
		fx.Rules(policyscale.Egress), fx.Policies(policyscale.Egress), fx.IPSets(), fx.IPSetMembers())

	if *flows == 0 {
		return fx.WriteYAML(bw, policyscale.ResourceOptions{Selector: *selector, Enforced: !*staged})
	}
	// The traces are what the cluster's flow logs report, which name the kinds the policies are
	// rendered with.
	expect := func(f *policyscale.Flow) []policyscale.Verdict {
		if *staged {
			return policyscale.AsStaged(fx.Expect(dir, f))
		}
		return fx.Expect(dir, f)
	}
	pw := &printer{w: bw}
	if spec.Shapes != nil {
		pw.printf("protocol\tsrc\tsport\tdst\tdport\texpected\tflow\tdifferences\n")
		for _, sf := range fx.ShapeFlows(dir) {
			f := sf.Flow
			pw.printf("%d\t%s\t%d\t%s\t%d\t%v\t%s\t%v\n", f.Protocol, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, expect(f), sf.Name, sf.Differences)
		}
		return pw.err
	}
	pw.printf("protocol\tsrc\tsport\tdst\tdport\texpected\n")
	s := fx.NewSampler(*seed, policyscale.FlowModel{Direction: dir, MissFraction: *miss, RepeatFraction: *repeat})
	for i := 0; i < *flows; i++ {
		f := s.Next()
		if dst != nil {
			f.DstIP = dst
		}
		pw.printf("%d\t%s\t%d\t%s\t%d\t%v\n", f.Protocol, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, expect(f))
	}
	return pw.err
}

// printer keeps the first write error, so a long run of prints is checked once at the end.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) printf(format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, args...)
	}
}

func usage() {
	out := flag.CommandLine.Output()
	_, _ = fmt.Fprintf(out, `Usage: policyscale [flags]

Renders a generated policy set as Calico resources, or prints flows with the traces a cluster with
that set reports for them. The preset, -seed and the POLICYSCALE_POLICIES,
POLICYSCALE_RULES_PER_POLICY and POLICYSCALE_IPSETS environment variables (which scale the egress
allow-list) decide the set; flowgen must run with the same ones.

`)
	flag.PrintDefaults()
}
