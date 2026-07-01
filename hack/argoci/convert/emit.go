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

package convert

// This file turns a parsed Pipeline into an Argo CronWorkflow (see
// .argoci/DESIGN.md). Each Semaphore job becomes one DAG task that
// templateRefs the shared e2e-test WorkflowTemplate; a job matrix becomes a
// withItems fan-out on that single task. Test selection (E2E_TEST_CONFIG or
// K8S_E2E_FLAGS) is passed through verbatim in the test-vars blob — the
// emitter is mechanism-agnostic.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// baseImage is the ArgoCI runner image (bz + cloud CLIs + kubectl + docker
// client). Pinned here; revisit when the image is versioned for calico.
const baseImage = "gcr.io/tigera-cc-dev/ci-base/ubuntu-cloud-providers:v0.104"

// defaultNamespace is the dedicated namespace for OSS Calico e2e workflows,
// isolated from the shared/private `argoci` namespace (see .argoci/DESIGN.md).
const defaultNamespace = "argoci-oss-e2es"

// EmitOptions parameterise a single generated CronWorkflow.
type EmitOptions struct {
	Name      string // cron metadata.name
	Namespace string // target namespace (defaults to defaultNamespace)
	Branch    string // git branch the cron checks out (RELEASE_STREAM derives from it)
	Schedule  string // cron schedule expression
}

// kv is an ordered key/value pair (used for withItems, where axis order is
// preserved for readability).
type kv struct {
	K, V string
}

// taskView is the render model for one DAG task.
type taskView struct {
	block       string // originating block name (for dependency wiring; not rendered)
	Name        string
	Depends     string
	CPURequests string
	MemRequests string
	VarLines    []string // export K='v' lines for the test-vars blob
	Items       [][]kv   // withItems entries; nil when the job has no matrix
	Todos       []string // CONVERTER-TODO reasons, if any
}

// Emit renders the CronWorkflow YAML for p and returns it along with the flat
// list of CONVERTER-TODO reasons across all tasks (empty when the conversion
// is fully mechanical).
func Emit(p *Pipeline, opts EmitOptions) (string, []string) {
	if opts.Namespace == "" {
		opts.Namespace = defaultNamespace
	}
	tasks := buildTasks(p)

	var todos []string
	for _, t := range tasks {
		for _, r := range t.Todos {
			todos = append(todos, fmt.Sprintf("%s: %s", t.Name, r))
		}
	}

	return render(opts, tasks), todos
}

// buildTasks walks the pipeline and produces the DAG tasks, including unique
// naming, dependency wiring, resource profiles and the test-vars blob.
func buildTasks(p *Pipeline) []taskView {
	global := envMap(p.GlobalJobConfig.EnvVars)

	// Dependencies reference block names; map each block to the task names it
	// produced so we can wire depends after naming.
	blockDeps := map[string][]string{}
	for _, b := range p.Blocks {
		blockDeps[b.Name] = b.Dependencies
	}
	blockTaskNames := map[string][]string{}

	seen := map[string]int{}
	uniq := func(name string) string {
		seen[name]++
		if seen[name] == 1 {
			return name
		}
		return fmt.Sprintf("%s-%d", name, seen[name])
	}

	var tasks []taskView
	for _, b := range p.Blocks {
		blockEnv := mergeEnv(global, envMap(b.Task.EnvVars))
		multi := len(b.Task.Jobs) > 1
		for _, j := range b.Task.Jobs {
			raw := slug(b.Name)
			if multi {
				raw = slug(b.Name) + "-" + slug(j.Name)
			}
			t := buildTask(uniq(raw), b.Name, blockEnv, j)
			blockTaskNames[b.Name] = append(blockTaskNames[b.Name], t.Name)
			tasks = append(tasks, t)
		}
	}

	// Wire dependencies: a task depends on every task produced by the blocks
	// its block depends on ("&&"-joined).
	for i := range tasks {
		var deps []string
		for _, depBlock := range blockDeps[tasks[i].block] {
			deps = append(deps, blockTaskNames[depBlock]...)
		}
		tasks[i].Depends = strings.Join(deps, " && ")
	}
	return tasks
}

// buildTask builds a single task view from a job and its (pre-matrix) block
// environment.
func buildTask(name, block string, blockEnv map[string]string, j Job) taskView {
	jobEnv := mergeEnv(blockEnv, envMap(j.EnvVars))

	matrixKeys := map[string]bool{}
	for _, a := range j.Matrix {
		matrixKeys[a.EnvVar] = true
	}

	// Static (non-matrix) env, sorted for stable output.
	keys := make([]string, 0, len(jobEnv))
	for k := range jobEnv {
		if !matrixKeys[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var lines []string
	for _, k := range keys {
		lines = append(lines, fmt.Sprintf("export %s=%s", k, shellQuote(jobEnv[k])))
	}
	// Matrix axes last so their {{item.X}} values override any static default.
	for _, a := range j.Matrix {
		lines = append(lines, fmt.Sprintf("export %s='{{item.%s}}'", a.EnvVar, a.EnvVar))
	}

	var items [][]kv
	if len(j.Matrix) > 0 {
		items = cartesianItems(j.Matrix)
	}

	// Resource profile keys off the (runtime-effective) provisioner: local-kind
	// runs the cluster in-pod and needs a large pod; everything else runs the
	// cluster on remote cloud VMs and stays small.
	cpu, mem := "1000m", "2Gi"
	if jobEnv["PROVISIONER"] == "local-kind" {
		cpu, mem = "3500m", "12Gi"
	}

	var todos []string
	_, hasCfg := jobEnv["E2E_TEST_CONFIG"]
	_, hasFlags := jobEnv["K8S_E2E_FLAGS"]
	if !hasCfg && !hasFlags {
		todos = append(todos, "no test selection (neither E2E_TEST_CONFIG nor K8S_E2E_FLAGS set)")
	}

	return taskView{
		block:       block,
		Name:        name,
		CPURequests: cpu,
		MemRequests: mem,
		VarLines:    lines,
		Items:       items,
		Todos:       todos,
	}
}

// cartesianItems returns the cartesian product of the matrix axes as ordered
// key/value lists (source axis order preserved, last axis varying fastest).
func cartesianItems(axes []Axis) [][]kv {
	items := [][]kv{{}}
	for _, a := range axes {
		var next [][]kv
		for _, partial := range items {
			for _, val := range a.Values {
				combo := append(append([]kv{}, partial...), kv{a.EnvVar, val})
				next = append(next, combo)
			}
		}
		items = next
	}
	return items
}

var nonSlugChars = regexp.MustCompile(`[^a-z0-9]+`)

// slug converts an arbitrary name into a lower-case, DNS-safe token.
func slug(s string) string {
	return strings.Trim(nonSlugChars.ReplaceAllString(strings.ToLower(s), "-"), "-")
}

// shellQuote single-quotes a value so the shell treats it literally (regex
// backslashes, pipes, brackets survive untouched). A literal single quote is
// emitted as the standard '\” escape.
func shellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}
