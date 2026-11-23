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

// BenchmarkEvaluateRuleShapes evaluates every flow of policyscale's rule-shape preset: a rule for
// each kind of criterion the engine checks, in both directions, with flows of both IP families
// aimed at each. The set is small, so what it shows is the cost of the criteria the large sets
// hardly use (ICMP type and code, IP version, named ports, services, negations) rather than of
// the walk.
//
//	go test ./app-policy/checker/ -run '^$' -bench BenchmarkEvaluateRuleShapes \
//	    -benchmem -benchtime 1000x -cpu 1

import (
	"testing"

	"github.com/projectcalico/calico/app-policy/policyscale"
)

func BenchmarkEvaluateRuleShapes(b *testing.B) {
	fx := policyscale.Build(policyscale.RuleShapes())
	// The pre-flight compares every trace with the oracle, which can't hold for flows that expose
	// a known difference between the evaluator and the dataplanes.
	excluded := policyscale.DifferencesAt(policyscale.Evaluator)

	for _, dir := range []policyscale.Direction{policyscale.Ingress, policyscale.Egress} {
		var flows []*policyscale.Flow
		for _, sf := range fx.ShapeFlows(dir, excluded...) {
			flows = append(flows, sf.Flow)
		}
		b.Run(dir.String(), func(b *testing.B) {
			for _, engine := range benchEngines {
				b.Run(engine.name, func(b *testing.B) {
					benchEvaluateFlows(b, fx, engine, dir, flows, 0, nil)
				})
			}
		})
	}
}
