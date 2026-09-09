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

// Package cilanes resolves the test selection of every e2e lane under
// .argoci/cron, .semaphore/end-to-end/pipelines and
// .semaphore/semaphore.yml.d/blocks.
package cilanes

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	argoDir      = ".argoci/cron"
	semaphoreDir = ".semaphore/end-to-end/pipelines"
	blocksDir    = ".semaphore/semaphore.yml.d/blocks"

	// The end-to-end body scripts drive a provisioned cluster and take their
	// selection from the environment.
	provisionedSuiteScript = "body_"

	// The flannel migration script runs the suite once before migrating with a
	// hardcoded config, then again with the job's own.
	flannelMigrationScript    = "body_flannel-migration.sh"
	flannelMigrationPreConfig = "e2e/config/pre-migration-smoke.yaml"
	flannelMigrationPreName   = " [pre-migration]"
)

// kindTargets maps each make target that runs the calico e2e binary to where
// its selection comes from. The provisioned lanes get a config from
// run_tests.sh; the kind lanes call make directly, so the target decides.
var kindTargets = map[string]struct {
	// fixed is the config the target hardcodes, ignoring the environment.
	fixed string
	// fallback is the config the Makefile's ?= supplies when the environment
	// names none.
	fallback string
}{
	"e2e-test":     {fallback: "e2e/config/kind/conformance.yaml"},
	"e2e-test-bpf": {fixed: "e2e/config/kind/bpf.yaml"},
	"e2e-run":      {},
}

// Selection variables. run_tests.sh runs the e2e binary against the config
// named here and refuses to run at all without one.
const (
	envConfig   = "E2E_TEST_CONFIG"
	envTestType = "TEST_TYPE"
	envArea     = "FUNCTIONAL_AREA"
	envProvider = "PROVISIONER"
)

// Lane is one CI lane and the test selection it resolves to.
type Lane struct {
	// Source is the repo-relative CI file declaring the lane.
	Source string

	// Name identifies the lane within its file. A matrix entry is suffixed
	// only when it changes the selection.
	Name string

	// Config is the repo-relative E2E_TEST_CONFIG path.
	Config string

	// Area is the FUNCTIONAL_AREA both CI systems declare, naming the pipeline
	// a cron lane mirrors.
	Area string

	// TestType is the resolved TEST_TYPE. Only "k8s-e2e" lanes run the e2e
	// binary; the rest defer to `bz tests`.
	TestType string
}

// RunsE2EBinary reports whether the lane runs the e2e test binary, and so has a
// spec list worth generating.
func (l Lane) RunsE2EBinary() bool {
	return l.TestType == "k8s-e2e" && l.Config != ""
}

// SelectionArgs returns the spec-selecting arguments run_tests.sh would pass
// to the binary. repoRoot absolutizes the config path, as the binary requires.
func (l Lane) SelectionArgs(repoRoot string) ([]string, error) {
	if l.Config == "" {
		return nil, fmt.Errorf("lane %q selects nothing", l.Name)
	}
	abs, err := filepath.Abs(filepath.Join(repoRoot, l.Config))
	if err != nil {
		return nil, err
	}
	return []string{"--calico.test-config=" + abs}, nil
}

// Load resolves every lane declared under .argoci/cron,
// .semaphore/end-to-end/pipelines and .semaphore/semaphore.yml.d/blocks, sorted
// by source then name.
func Load(repoRoot string) ([]Lane, error) {
	var lanes []Lane
	for dir, parse := range map[string]func(string, []byte) ([]Lane, error){
		argoDir:      parseArgo,
		semaphoreDir: parseSemaphore,
		blocksDir:    parseSemaphoreBlocks,
	} {
		entries, err := os.ReadDir(filepath.Join(repoRoot, dir))
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			ext := filepath.Ext(e.Name())
			if e.IsDir() || (ext != ".yaml" && ext != ".yml") {
				continue
			}
			rel := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(filepath.Join(repoRoot, rel))
			if err != nil {
				return nil, err
			}
			found, err := parse(rel, data)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", rel, err)
			}
			lanes = append(lanes, found...)
		}
	}
	if len(lanes) == 0 {
		return nil, fmt.Errorf("no CI lanes found under %s: wrong repo root?", repoRoot)
	}
	sort.Slice(lanes, func(i, j int) bool {
		if lanes[i].Source != lanes[j].Source {
			return lanes[i].Source < lanes[j].Source
		}
		return lanes[i].Name < lanes[j].Name
	})
	return lanes, nil
}

type envVar struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

// env is a resolved environment, built up from least to most specific scope.
type env map[string]string

func (e env) clone() env {
	out := make(env, len(e))
	for k, v := range e {
		out[k] = v
	}
	return out
}

func (e env) apply(vars []envVar) env {
	out := e.clone()
	for _, v := range vars {
		out[v.Name] = v.Value
	}
	return out
}

// lanes builds every Lane one CI job resolves to, which is more than one when
// the job runs the suite several times.
func (e env) lanes(source, name, commands string) []Lane {
	l := e.lane(source, name)
	if !strings.Contains(commands, flannelMigrationScript) {
		return []Lane{l}
	}
	pre := Lane{
		Source:   source,
		Name:     name + flannelMigrationPreName,
		Area:     l.Area,
		Config:   flannelMigrationPreConfig,
		TestType: l.TestType,
	}
	return []Lane{l, pre}
}

// lane builds a Lane from a resolved environment, applying the same defaulting
// that .argoci/scripts/global_prologue.sh does for TEST_TYPE.
func (e env) lane(source, name string) Lane {
	testType, ok := e[envTestType]
	if !ok {
		testType = "k8s-e2e"
		if e[envProvider] == "gcp-openstack" {
			testType = "openstack-e2e"
		}
	}
	return Lane{
		Source:   source,
		Name:     name,
		Area:     e[envArea],
		Config:   e[envConfig],
		TestType: testType,
	}
}

type argoWorkflow struct {
	GlobalPrologue string     `yaml:"globalPrologue"`
	Steps          []argoStep `yaml:"steps"`
}

type argoStep struct {
	Name     string       `yaml:"name"`
	Env      []envVar     `yaml:"env"`
	Matrix   []argoMatrix `yaml:"matrix"`
	Commands string       `yaml:"commands"`
}

type argoMatrix struct {
	Name string   `yaml:"name"`
	Env  []envVar `yaml:"env"`
}

func parseArgo(source string, data []byte) ([]Lane, error) {
	var wf argoWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, err
	}
	global := prologueDefaults(wf.GlobalPrologue)

	var lanes []Lane
	for _, step := range wf.Steps {
		base := global.apply(step.Env)
		if len(step.Matrix) == 0 {
			lanes = append(lanes, base.lanes(source, step.Name, step.Commands)...)
			continue
		}
		for _, m := range step.Matrix {
			e := base.apply(m.Env)
			lanes = append(lanes, e.lanes(source, matrixName(step.Name, m.Name, base, e), step.Commands)...)
		}
	}
	return dedupe(lanes), nil
}

// matrixName suffixes the step name only when the entry changes the selection.
// CNI and manifest axes share one spec list.
func matrixName(step, entry string, base, resolved env) string {
	if base[envConfig] == resolved[envConfig] {
		return step
	}
	return step + " [" + entry + "]"
}

// dedupe collapses lanes that a matrix expanded into identical entries.
func dedupe(lanes []Lane) []Lane {
	seen := map[Lane]bool{}
	out := lanes[:0]
	for _, l := range lanes {
		if seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	return out
}

// exportDefault matches the `export NAME="${NAME:-value}"` idiom the ArgoCI
// prologues use to declare a workflow-wide default.
var exportDefault = regexp.MustCompile(`(?m)^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)="?\$\{([A-Za-z_][A-Za-z0-9_]*):-(.*)\}"?\s*$`)

func prologueDefaults(prologue string) env {
	e := env{}
	for _, m := range exportDefault.FindAllStringSubmatch(prologue, -1) {
		// Self-defaulting only. Anything else aliases another variable, which
		// this resolver does not model.
		if m[1] != m[2] {
			continue
		}
		e[m[1]] = strings.Trim(m[3], `"`)
	}
	return e
}

type semBlock struct {
	Name string `yaml:"name"`
	Task struct {
		EnvVars []envVar `yaml:"env_vars"`
		Jobs    []struct {
			Name     string   `yaml:"name"`
			EnvVars  []envVar `yaml:"env_vars"`
			Commands []string `yaml:"commands"`
			Matrix   []struct {
				EnvVar string   `yaml:"env_var"`
				Values []string `yaml:"values"`
			} `yaml:"matrix"`
		} `yaml:"jobs"`
	} `yaml:"task"`
}

type semPipeline struct {
	GlobalJobConfig struct {
		EnvVars []envVar `yaml:"env_vars"`
	} `yaml:"global_job_config"`
	Blocks []semBlock `yaml:"blocks"`
}

func parseSemaphore(source string, data []byte) ([]Lane, error) {
	var p semPipeline
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return blockLanes(source, p.Blocks, env{}.apply(p.GlobalJobConfig.EnvVars), false)
}

// parseSemaphoreBlocks reads the per-component block files, which are a bare
// sequence of blocks rather than a pipeline and carry no global_job_config.
// Most declare no e2e lane at all, so unlike a pipeline they are filtered.
func parseSemaphoreBlocks(source string, data []byte) ([]Lane, error) {
	var blocks []semBlock
	if err := yaml.Unmarshal(data, &blocks); err != nil {
		return nil, err
	}
	return blockLanes(source, blocks, env{}, true)
}

// blockLanes resolves the lanes in a sequence of Semaphore blocks. A kind job
// invokes make itself, so its target names the config; a provisioned job gets
// one from run_tests.sh in the environment.
func blockLanes(source string, blocks []semBlock, global env, filter bool) ([]Lane, error) {
	var lanes []Lane
	for _, block := range blocks {
		blockEnv := global.apply(block.Task.EnvVars)
		for _, job := range block.Task.Jobs {
			base := blockEnv.apply(job.EnvVars)
			name := block.Name + " / " + job.Name
			commands := strings.Join(job.Commands, "\n")

			for _, axis := range job.Matrix {
				if axis.EnvVar == envConfig {
					return nil, fmt.Errorf("job %q: matrix on %s is not modelled", name, axis.EnvVar)
				}
			}
			if target, ok := e2eMakeTarget(commands); ok {
				base = base.clone()
				base[envConfig] = kindConfig(target, base[envConfig])
			} else if filter && !strings.Contains(commands, provisionedSuiteScript) {
				continue
			}
			lanes = append(lanes, base.lanes(source, name, commands)...)
		}
	}
	return dedupe(lanes), nil
}

// makeTarget matches the `make <target>` a kind job runs, including through the
// run-and-monitor wrapper.
var makeTarget = regexp.MustCompile(`\bmake\s+([a-z0-9-]+)`)

// e2eMakeTarget returns the first target in commands that runs the e2e binary.
// Jobs that run something else, the ClusterNetworkPolicy binary among them, are
// not lanes even when they set E2E_TEST_CONFIG.
func e2eMakeTarget(commands string) (string, bool) {
	for _, m := range makeTarget.FindAllStringSubmatch(commands, -1) {
		if _, ok := kindTargets[m[1]]; ok {
			return m[1], true
		}
	}
	return "", false
}

// kindConfig resolves the config a kind target selects with, given whatever the
// job put in the environment.
func kindConfig(target, fromEnv string) string {
	t := kindTargets[target]
	if t.fixed != "" {
		return t.fixed
	}
	if fromEnv != "" {
		return fromEnv
	}
	return t.fallback
}
