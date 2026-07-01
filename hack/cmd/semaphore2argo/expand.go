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

package main

// This file expands a parsed Pipeline into the flat list of test jobs that
// Semaphore would actually run. Each ResolvedJob carries its fully-merged
// environment. The merge precedence mirrors Semaphore exactly (and the
// existing .semaphore/end-to-end/report/generate_e2e_report.py):
//
//	global_job_config.env_vars ⊕ block task.env_vars ⊕ job env_vars ⊕ matrix item
//
// with later layers overriding earlier ones. A job matrix fans out into the
// cartesian product of its axes (source order; last axis varies fastest).

// ResolvedJob is a single concrete test run: one Semaphore job after matrix
// expansion, with its environment fully resolved.
type ResolvedJob struct {
	Block string
	Job   string
	Env   map[string]string
}

// Expand walks the pipeline and returns every ResolvedJob it would run, in
// deterministic (block, job, matrix) source order.
func Expand(p *Pipeline) []ResolvedJob {
	global := envMap(p.GlobalJobConfig.EnvVars)

	var jobs []ResolvedJob
	for _, b := range p.Blocks {
		blockEnv := mergeEnv(global, envMap(b.Task.EnvVars))
		for _, j := range b.Task.Jobs {
			jobEnv := mergeEnv(blockEnv, envMap(j.EnvVars))
			if len(j.Matrix) == 0 {
				jobs = append(jobs, ResolvedJob{Block: b.Name, Job: j.Name, Env: jobEnv})
				continue
			}
			for _, combo := range cartesian(j.Matrix) {
				jobs = append(jobs, ResolvedJob{
					Block: b.Name,
					Job:   j.Name,
					Env:   mergeEnv(jobEnv, combo),
				})
			}
		}
	}
	return jobs
}

// envMap converts a Semaphore env_vars list into a map, preserving the
// original (upper-case) names.
func envMap(vars []EnvVar) map[string]string {
	m := make(map[string]string, len(vars))
	for _, v := range vars {
		m[v.Name] = v.Value
	}
	return m
}

// mergeEnv returns a new map containing base overlaid with over (over wins).
func mergeEnv(base, over map[string]string) map[string]string {
	m := make(map[string]string, len(base)+len(over))
	for k, v := range base {
		m[k] = v
	}
	for k, v := range over {
		m[k] = v
	}
	return m
}

// cartesian returns the cartesian product of the matrix axes as a slice of
// env maps, one per combination. Axes are combined in source order with the
// last axis varying fastest, giving stable, golden-testable output.
func cartesian(axes []Axis) []map[string]string {
	result := []map[string]string{{}}
	for _, axis := range axes {
		var next []map[string]string
		for _, partial := range result {
			for _, value := range axis.Values {
				combo := mergeEnv(partial, map[string]string{axis.EnvVar: value})
				next = append(next, combo)
			}
		}
		result = next
	}
	return result
}
