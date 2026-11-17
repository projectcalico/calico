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

package cronreadback

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const (
	envConfig = "E2E_TEST_CONFIG"

	// sourceURLAnnotation is the annotation the ArgoCI cron expansion puts on a
	// CronWorkflow, holding the blob URL of the cron file it came from.
	sourceURLAnnotation = "argoci-viewer/source-url"

	prologueBegin = "# BEGIN argoci:prologue\n"
	prologueEnd   = "# END argoci:prologue"
	inputPrefix   = "{{inputs.parameters."
)

// LiveCron is a CronWorkflow read back from ArgoCI, reduced to what the check
// compares.
type LiveCron struct {
	// Name is the CronWorkflow's name.
	Name string

	// Cells maps each expanded step to the E2E_TEST_CONFIG it runs with.
	Cells map[string]string
}

// nameValue is one entry of an env or parameter list.
type nameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// cronObject is the part of a CronWorkflow the check reads, as the ArgoCI cron
// expansion lays it out.
type cronObject struct {
	Metadata cronMetadata `json:"metadata"`
	Spec     cronSpec     `json:"spec"`
}

type cronMetadata struct {
	Name        string            `json:"name"`
	Annotations map[string]string `json:"annotations"`
}

type cronSpec struct {
	WorkflowMetadata runMetadata  `json:"workflowMetadata"`
	WorkflowSpec     workflowSpec `json:"workflowSpec"`
}

type runMetadata struct {
	Labels map[string]string `json:"labels"`
}

type workflowSpec struct {
	Entrypoint       string           `json:"entrypoint"`
	TemplateDefaults templateDefaults `json:"templateDefaults"`
	Templates        []templateSpec   `json:"templates"`
}

type templateDefaults struct {
	Script scriptSpec `json:"script"`
}

type templateSpec struct {
	Name      string      `json:"name"`
	DAG       *dagSpec    `json:"dag"`
	Script    *scriptSpec `json:"script"`
	Container *scriptSpec `json:"container"`
}

// scriptSpec is a script or container block. Only a script has source.
type scriptSpec struct {
	Env    []nameValue `json:"env"`
	Source string      `json:"source"`
}

type dagSpec struct {
	Tasks []dagTask `json:"tasks"`
}

type dagTask struct {
	Name      string        `json:"name"`
	Template  string        `json:"template"`
	Arguments taskArguments `json:"arguments"`
}

type taskArguments struct {
	Parameters []nameValue `json:"parameters"`
}

// prologueDefault matches a `export E2E_TEST_CONFIG="${E2E_TEST_CONFIG:-value}"`
// line, which is how a file's globalPrologue sets the default config.
var prologueDefault = regexp.MustCompile(`(?m)^\s*export\s+E2E_TEST_CONFIG="?\$\{E2E_TEST_CONFIG:-(.*?)\}"?\s*$`)

// parseLive reduces the JSON of one CronWorkflow to its cells. Each task of
// the entrypoint DAG is a cell, named after the task. Its config is, in order,
// the template's E2E_TEST_CONFIG env (filled from the task's arguments when a
// matrix shares the template), the workflow's template defaults, then the
// default the globalPrologue exports in the template's script. A task with none
// of these is no cell. A CronWorkflow with no entrypoint DAG is an error.
func parseLive(data []byte) (LiveCron, error) {
	var obj cronObject
	if err := json.Unmarshal(data, &obj); err != nil {
		return LiveCron{}, fmt.Errorf("decoding CronWorkflow: %w", err)
	}
	live := LiveCron{Name: obj.Metadata.Name, Cells: map[string]string{}}

	spec := obj.Spec.WorkflowSpec

	// Tasks name their template, so index the templates first.
	byName := map[string]templateSpec{}
	for _, t := range spec.Templates {
		byName[t.Name] = t
	}
	entry, ok := byName[spec.Entrypoint]
	if !ok || entry.DAG == nil {
		return LiveCron{}, fmt.Errorf("%s: no entrypoint DAG %q in spec.workflowSpec.templates", obj.Metadata.Name, spec.Entrypoint)
	}
	for _, task := range entry.DAG.Tasks {
		tmpl, ok := byName[task.Template]
		if !ok {
			continue
		}
		if config, ok := taskConfig(task, tmpl, spec.TemplateDefaults.Script); ok {
			live.Cells[normalizeName(task.Name)] = config
		}
	}
	return live, nil
}

// taskConfig returns the E2E_TEST_CONFIG a task's pod runs with.
func taskConfig(task dagTask, tmpl templateSpec, defaults scriptSpec) (string, bool) {
	body := tmpl.Script
	if body == nil {
		body = tmpl.Container
	}
	if body == nil {
		return "", false
	}
	value, ok := envValue(body.Env, envConfig)
	if !ok {
		value, ok = envValue(defaults.Env, envConfig)
	}
	if ok {
		return resolveInput(value, task.Arguments.Parameters)
	}
	return prologueConfig(body.Source)
}

// resolveInput fills a value that a matrix template takes from its task's
// arguments, as in {{inputs.parameters.E2E_TEST_CONFIG}}.
func resolveInput(value string, args []nameValue) (string, bool) {
	if !strings.HasPrefix(value, inputPrefix) || !strings.HasSuffix(value, "}}") {
		return value, true
	}
	name := strings.TrimSuffix(strings.TrimPrefix(value, inputPrefix), "}}")
	return envValue(args, name)
}

// envValue returns the value of the named entry.
func envValue(list []nameValue, name string) (string, bool) {
	for _, nv := range list {
		if nv.Name == name {
			return nv.Value, true
		}
	}
	return "", false
}

// prologueConfig returns the E2E_TEST_CONFIG default exported by the prologue
// section of a script. A script without that section, which the expansion
// writes only when the file has an epilogue, is searched whole.
func prologueConfig(source string) (string, bool) {
	if begin := strings.Index(source, prologueBegin); begin >= 0 {
		source = source[begin+len(prologueBegin):]
		if end := strings.Index(source, prologueEnd); end >= 0 {
			source = source[:end]
		}
	}
	m := prologueDefault.FindStringSubmatch(source)
	if m == nil {
		return "", false
	}
	return strings.Trim(m[1], `"`), true
}
