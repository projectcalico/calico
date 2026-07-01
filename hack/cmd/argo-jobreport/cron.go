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

// This file enumerates the concrete e2e jobs described by a generated Argo
// CronWorkflow, purely by parsing the emitted YAML — it deliberately shares
// no code with the converter's emitter, so comparing its output against the
// Semaphore-side expansion is a genuine cross-check rather than the converter
// grading its own homework.

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// cronDoc is the subset of a CronWorkflow this tool reads.
type cronDoc struct {
	Spec struct {
		WorkflowSpec struct {
			Templates []struct {
				Name string `yaml:"name"`
				DAG  struct {
					Tasks []struct {
						Name      string              `yaml:"name"`
						WithItems []map[string]string `yaml:"withItems"`
						Arguments struct {
							Parameters []struct {
								Name  string `yaml:"name"`
								Value string `yaml:"value"`
							} `yaml:"parameters"`
						} `yaml:"arguments"`
					} `yaml:"tasks"`
				} `yaml:"dag"`
			} `yaml:"templates"`
		} `yaml:"workflowSpec"`
	} `yaml:"spec"`
}

// EnumerateCron returns one environment map per concrete run described by the
// cron's `pipeline` DAG (expanding withItems and the test-vars blob).
func EnumerateCron(path string) ([]map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc cronDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing %q: %w", path, err)
	}

	var jobs []map[string]string
	for _, tmpl := range doc.Spec.WorkflowSpec.Templates {
		if tmpl.Name != "pipeline" {
			continue
		}
		for _, task := range tmpl.DAG.Tasks {
			var vars string
			for _, p := range task.Arguments.Parameters {
				if p.Name == "test-vars" {
					vars = p.Value
				}
			}
			base := parseTestVars(vars)
			items := task.WithItems
			if len(items) == 0 {
				items = []map[string]string{{}} // one run, no matrix
			}
			for _, item := range items {
				jobs = append(jobs, substitute(base, item))
			}
		}
	}
	return jobs, nil
}

// parseTestVars turns a test-vars blob of `export NAME='value'` lines into an
// environment map, reversing the emitter's single-quote escaping. A value may
// span multiple physical lines (e.g. an embedded kind config or JSON blob), so
// accumulate continuation lines until the single quote closes.
func parseTestVars(blob string) map[string]string {
	env := map[string]string{}
	lines := strings.Split(blob, "\n")
	for i := 0; i < len(lines); i++ {
		rest, ok := strings.CutPrefix(strings.TrimSpace(lines[i]), "export ")
		if !ok {
			continue
		}
		name, val, ok := strings.Cut(rest, "=")
		if !ok {
			continue
		}
		for strings.HasPrefix(val, "'") && !singleQuoteClosed(val) && i+1 < len(lines) {
			i++
			val += "\n" + lines[i] // raw: preserve the value's own indentation
		}
		env[name] = unquote(val)
	}
	return env
}

// singleQuoteClosed reports whether s (which begins with a single quote) has a
// matching closing quote, treating the '\” escape as content, not a closer.
func singleQuoteClosed(s string) bool {
	return strings.Count(strings.ReplaceAll(s, `'\''`, ""), "'") >= 2
}

// unquote reverses shellQuote: strips surrounding single quotes and unescapes
// the '\” sequence.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		s = strings.ReplaceAll(s[1:len(s)-1], `'\''`, `'`)
	}
	return s
}

// substitute replaces {{item.KEY}} references in base's values with the
// matching withItems value, returning a new map.
func substitute(base, item map[string]string) map[string]string {
	out := make(map[string]string, len(base))
	for k, v := range base {
		for ik, iv := range item {
			v = strings.ReplaceAll(v, "{{item."+ik+"}}", iv)
		}
		out[k] = v
	}
	return out
}
