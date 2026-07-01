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

// Package convert converts a Calico Semaphore end-to-end pipeline
// (.semaphore/end-to-end/pipelines/*.yml) into an Argo CronWorkflow for
// ArgoCI. See .argoci/DESIGN.md for the full design. It is used by the
// semaphore2argo command and by the job-parity tooling.
//
// This file defines the subset of the Semaphore pipeline schema that the
// converter reads. Only the fields that affect which jobs run and with what
// environment are modelled; presentation-only fields (commands, epilogue,
// execution_time_limit, promotions, after_pipeline) are ignored.
package convert

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Pipeline is a Semaphore end-to-end pipeline definition.
type Pipeline struct {
	Name            string          `yaml:"name"`
	Agent           Agent           `yaml:"agent"`
	GlobalJobConfig GlobalJobConfig `yaml:"global_job_config"`
	Blocks          []Block         `yaml:"blocks"`
}

// Agent selects the Semaphore runner machine. Blocks may override it.
type Agent struct {
	Machine Machine `yaml:"machine"`
}

// Machine is the runner machine type (e.g. c1-standard-1, f1-standard-2).
type Machine struct {
	Type    string `yaml:"type"`
	OSImage string `yaml:"os_image"`
}

// GlobalJobConfig holds pipeline-wide secrets and env vars. Its env_vars are
// the base (lowest-precedence) layer of every job's environment.
type GlobalJobConfig struct {
	Secrets []Secret `yaml:"secrets"`
	EnvVars []EnvVar `yaml:"env_vars"`
}

// Secret is a Semaphore secret reference by name.
type Secret struct {
	Name string `yaml:"name"`
}

// EnvVar is a name/value environment entry. All Semaphore env values are
// strings (quoted in YAML where needed).
type EnvVar struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

// Block is a Semaphore block: a group of jobs that may depend on other blocks.
type Block struct {
	Name         string   `yaml:"name"`
	Dependencies []string `yaml:"dependencies"`
	Task         Task     `yaml:"task"`
}

// Task holds a block's jobs plus block-level agent/env overrides. Note that
// block-level env vars live under task.env_vars (not block.env_vars).
type Task struct {
	Agent   *Agent   `yaml:"agent"`
	EnvVars []EnvVar `yaml:"env_vars"`
	Jobs    []Job    `yaml:"jobs"`
}

// Job is a single Semaphore job. A matrix, if present, fans the job out into
// the cartesian product of its axes.
type Job struct {
	Name    string   `yaml:"name"`
	EnvVars []EnvVar `yaml:"env_vars"`
	Matrix  []Axis   `yaml:"matrix"`
}

// Axis is one dimension of a job matrix: an env var and the values it ranges
// over.
type Axis struct {
	EnvVar string   `yaml:"env_var"`
	Values []string `yaml:"values"`
}

// LoadPipeline reads and parses a Semaphore pipeline YAML file.
func LoadPipeline(path string) (*Pipeline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading pipeline %q: %w", path, err)
	}
	var p Pipeline
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing pipeline %q: %w", path, err)
	}
	return &p, nil
}
