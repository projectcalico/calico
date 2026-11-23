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
	"maps"
	"os"
	"testing"

	"github.com/projectcalico/calico/app-policy/policyscale"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/hack/perf/perfdoc"
)

// benchEngine is one way of evaluating flows against a policy set. The benchmarks run each case
// once per engine, against stores loaded from the same fixture, so that the engines' numbers
// compare within one run rather than across machines and days.
type benchEngine struct {
	name string
	// newStore loads the fixture into a store set up for this engine.
	newStore func(fx *policyscale.Fixture) *policystore.PolicyStore
}

var benchEngines = []benchEngine{
	{name: "Interpreted", newStore: (*policyscale.Fixture).NewStore},
}

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
