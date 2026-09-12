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

// Package policyscale generates the large synthetic policy sets used to benchmark and test the
// user-mode policy engine in app-policy/checker and its caller in Felix's flow-log collector.
//
// One generator, two outputs. A Fixture built from a Spec can be materialised as a
// policystore.PolicyStore plus a proto.WorkloadEndpoint (what the engine and the collector
// evaluate against, in unit tests and Go benchmarks) or as Calico resources (Tier,
// GlobalNetworkPolicy, GlobalNetworkSet) that apply the same policy set to a real cluster. Both
// come from the same model, so a number measured at the engine level, at the collector level and
// on a node all describe the same policy set.
//
// The presets are the two rule-set shapes measured in production diagnostics from a large
// deployment, anonymised:
//
//   - Baseline: hundreds of "baseline" policies that apply to every endpoint, almost every rule a
//     Pass, about a quarter referencing one of thousands of IP sets whose sizes follow the
//     measured histogram. See DefaultBaseline.
//   - EgressAllowList: a single-tier destination allow-list of ~300 policies and ~18.6k egress
//     rules, each matching a destination address (a CIDR for ~75%, a selector-derived IP set for
//     ~25%) and a handful of destination ports drawn from the measured port distribution. See
//     DefaultEgress.
//   - Composite: both applied to one endpoint, the reference set the PMREQ-954 targets are quoted
//     against.
//
// The fixture also knows the answer. Fixture.Expect computes the verdict the engine must reach
// for a flow from the generator's own model of each rule, independently of the engine's matching
// code, so it serves as the oracle for differential tests; MatchingFlow, DeniedFlow and Sampler
// produce flows that exercise the walk at chosen depths or following a configurable flow model.
package policyscale
