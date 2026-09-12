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

// policyscale renders one of the app-policy/policyscale presets as Calico resources, for applying
// the benchmark policy sets to a cluster, or prints flows drawn from its flow model with the
// verdict the engine must reach for each, for driving and checking a node-level run.
//
//	go run ./hack/cmd/policyscale -preset composite > composite.yaml
//	kubectl label pod flowgen-target policyscale.projectcalico.org/target=true
//	kubectl apply -f composite.yaml
//
//	go run ./hack/cmd/policyscale -preset composite -flows 1000 -direction egress
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	"github.com/projectcalico/calico/app-policy/policyscale"
)

func main() {
	var (
		preset    = flag.String("preset", "composite", "policy set to render: baseline, egress or composite")
		seed      = flag.Int64("seed", policyscale.DefaultSeed, "generator seed")
		selector  = flag.String("selector", "policyscale.projectcalico.org/target == 'true'", "endpoint selector the policies apply to")
		out       = flag.String("out", "-", "output file, - for stdout")
		flows     = flag.Int("flows", 0, "instead of resources, print this many flows with their expected verdicts")
		direction = flag.String("direction", "egress", "direction of the printed flows: ingress or egress")
		miss      = flag.Float64("miss-fraction", 0.1, "fraction of printed flows that match no rule")
		repeat    = flag.Float64("repeat-fraction", 0.5, "fraction of printed flows that repeat an earlier one with a new source port")
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

	w := os.Stdout
	if *out != "-" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}
	bw := bufio.NewWriter(w)
	defer bw.Flush()

	fmt.Fprintf(os.Stderr, "%s: %d ingress rules in %d policies, %d egress rules in %d policies, %d IP sets with %d members\n",
		*preset, fx.Rules(policyscale.Ingress), fx.Policies(policyscale.Ingress),
		fx.Rules(policyscale.Egress), fx.Policies(policyscale.Egress), fx.IPSets(), fx.IPSetMembers())

	if *flows > 0 {
		dir := policyscale.Egress
		if *direction == "ingress" {
			dir = policyscale.Ingress
		}
		s := fx.NewSampler(*seed, policyscale.FlowModel{Direction: dir, MissFraction: *miss, RepeatFraction: *repeat})
		fmt.Fprintln(bw, "protocol\tsrc\tsport\tdst\tdport\texpected")
		for i := 0; i < *flows; i++ {
			f := s.Next()
			fmt.Fprintf(bw, "%d\t%s\t%d\t%s\t%d\t%v\n", f.Protocol, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, fx.Expect(dir, f))
		}
		return
	}

	if err := fx.WriteYAML(bw, policyscale.ResourceOptions{Selector: *selector}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
