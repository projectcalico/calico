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

package policyscale

const (
	// PerfArtifactsEnvVar names the directory the policy evaluation benchmarks write their
	// hack/perf documents to, for the Lens trend store. It is unset outside CI, so ordinary
	// benchmark runs keep their numbers out of the trend data.
	PerfArtifactsEnvVar = "POLICY_EVAL_PERF_ARTIFACTS_DIR"

	// PerfFamily is the hack/perf family, and so the Lens index, that both the engine and the
	// collector benchmarks publish to. Their documents differ in test_name.
	PerfFamily = "benchmark_data_policy_eval"
)
