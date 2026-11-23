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

package checker

import (
	"flag"
	"maps"
	"os"
	"testing"

	"github.com/projectcalico/calico/app-policy/policyscale"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/hack/perf/perfdoc"
)

// benchEngine is one way of evaluating flows against a policy set. The benchmarks run each case
// once per engine, against what each engine loads from the same fixture, so that the engines'
// numbers compare within one run rather than across machines and days.
type benchEngine struct {
	name string
	// load sets the fixture up for this engine: its store, and the endpoint it evaluates for.
	load func(fx *policyscale.Fixture) (*policystore.PolicyStore, *proto.WorkloadEndpoint)
	// evaluate is the engine's own way in, so that each engine is timed on its own path.
	evaluate evaluator
}

var benchEngines = []benchEngine{{
	name: "Interpreted",
	load: func(fx *policyscale.Fixture) (*policystore.PolicyStore, *proto.WorkloadEndpoint) {
		return fx.NewStore(), fx.Endpoint()
	},
	evaluate: Evaluate,
}}

// engineCase is what one timed loop of Evaluate covered: a walk of rulesPerOp rules, or
// flowsPerOp separate flows.
type engineCase struct {
	engine     string
	dir        policyscale.Direction
	rulesPerOp int
	flowsPerOp int
	// fields holds scenario fields of the case's own, for its perf document.
	fields map[string]any
}

// reportEngineCase reports the per-rule or per-flow cost of the timed loop just stopped and, when
// CI asks for perf documents, writes one for the case.
func reportEngineCase(b *testing.B, rec *perfdoc.Recorder, fx *policyscale.Fixture, c engineCase) {
	nsPerOp := float64(b.Elapsed().Nanoseconds()) / float64(b.N)
	fields := map[string]any{
		"test_name":      "policy_eval_engine",
		"case":           b.Name(),
		"engine":         c.engine,
		"direction":      c.dir.String(),
		"scale_policies": fx.Policies(c.dir),
		"scale_rules":    fx.Rules(c.dir),
		"scale_ipsets":   fx.IPSets(),
	}
	if c.rulesPerOp > 0 {
		b.ReportMetric(float64(c.rulesPerOp), "rules/op")
		b.ReportMetric(nsPerOp/float64(c.rulesPerOp), "ns/rule")
		fields["rules_per_op"] = c.rulesPerOp
		fields["ns_per_rule"] = nsPerOp / float64(c.rulesPerOp)
	}
	if c.flowsPerOp > 0 {
		b.ReportMetric(nsPerOp/float64(c.flowsPerOp), "ns/flow")
		fields["flows_per_op"] = c.flowsPerOp
		fields["ns_per_flow"] = nsPerOp / float64(c.flowsPerOp)
	}
	maps.Copy(fields, c.fields)
	rec.Finish(os.Getenv(policyscale.PerfArtifactsEnvVar), policyscale.PerfFamily, b.Name(), fields)
}

// Each engine is timed through its own evaluate, never a fixed one, or a faster engine added to
// the table would be timed on the interpreted walk.
func TestBenchmarksEvaluateThroughTheEngine(t *testing.T) {
	restore := flagValue(t, "test.benchtime", "3x")
	defer restore()
	fx := policyscale.Build(policyscale.RuleShapes())
	calls := 0
	counting := benchEngine{
		name: "Counting",
		load: benchEngines[0].load,
		evaluate: func(scope PolicyScope, dir rules.RuleDir, store *policystore.PolicyStore, ep *proto.WorkloadEndpoint, f Flow) ([]*calc.RuleID, error) {
			calls++
			return Evaluate(scope, dir, store, ep, f)
		},
	}
	flow := fx.DeniedFlow(policyscale.Ingress)
	testing.Benchmark(func(b *testing.B) {
		benchEvaluateFlows(b, fx, counting, policyscale.Ingress, []*policyscale.Flow{flow}, 0, nil)
	})
	// Go runs the function with b.N = 1 and then 3, each with a pre-flight evaluation.
	if want := (1 + 1) + (1 + 3); calls != want {
		t.Errorf("the engine's evaluate ran %d times, want %d", calls, want)
	}
}

func flagValue(t *testing.T, name, value string) (restore func()) {
	f := flag.Lookup(name)
	old := f.Value.String()
	if err := f.Value.Set(value); err != nil {
		t.Fatal(err)
	}
	return func() { _ = f.Value.Set(old) }
}
