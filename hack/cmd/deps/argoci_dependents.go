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

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// A step gated more narrowly than the steps depending on it drops them when they
// need it, and the check passes having run nothing.
const dependentsPrefix = "dependents-of-"

const argoWorkflowFile = ".argoci/ciworkflow.yaml"

type gateSpec struct {
	In        []string `yaml:"in"`
	Exclude   []string `yaml:"exclude"`
	DependsOn []string `yaml:"dependsOn"`
}

type argoInclude struct {
	Path    string    `yaml:"path"`
	Changes *gateSpec `yaml:"changes"`
}

// UnmarshalYAML accepts the bare-path form an ungated include is written in.
func (i *argoInclude) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		i.Path = value.Value
		return nil
	}
	type raw argoInclude
	var r raw
	if err := value.Decode(&r); err != nil {
		return err
	}
	*i = argoInclude(r)
	return nil
}

type argoWorkflow struct {
	Includes []argoInclude `yaml:"includes"`
}

type argoStep struct {
	Name    string    `yaml:"name"`
	Depends yaml.Node `yaml:"depends"`
	Changes *gateSpec `yaml:"changes"`
}

type argoModule struct {
	Steps []argoStep `yaml:"steps"`
}

var dependsIdent = regexp.MustCompile(`[A-Za-z0-9_-]+`)

// dependsNames reads either form the field takes: a list, or an expression.
func dependsNames(n yaml.Node) []string {
	switch n.Kind {
	case yaml.SequenceNode:
		var out []string
		for _, c := range n.Content {
			out = append(out, strings.SplitN(c.Value, ".", 2)[0])
		}
		return out
	case yaml.ScalarNode:
		var out []string
		for _, m := range dependsIdent.FindAllString(n.Value, -1) {
			out = append(out, strings.SplitN(m, ".", 2)[0])
		}
		return out
	}
	return nil
}

type step struct {
	name string
	gate gateSpec
	deps []string
}

// loadArgoSteps resolves each step to the gate governing it, which is the
// include's unless the step overrides it.
func loadArgoSteps(repoRoot string) ([]step, []argoInclude, error) {
	data, err := os.ReadFile(filepath.Join(repoRoot, argoWorkflowFile))
	if err != nil {
		return nil, nil, err
	}
	var wf argoWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", argoWorkflowFile, err)
	}

	var steps []step
	for _, inc := range wf.Includes {
		modData, err := os.ReadFile(filepath.Join(repoRoot, inc.Path))
		if err != nil {
			return nil, nil, err
		}
		var mod argoModule
		if err := yaml.Unmarshal(modData, &mod); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", inc.Path, err)
		}
		for _, s := range mod.Steps {
			gate := gateSpec{}
			switch {
			case s.Changes != nil:
				gate = *s.Changes
			case inc.Changes != nil:
				gate = *inc.Changes
			}
			steps = append(steps, step{name: s.Name, gate: gate, deps: dependsNames(s.Depends)})
		}
	}
	return steps, wf.Includes, nil
}

// referencedDependentGates collects the derived entries the workflow actually
// names. A step can be a dependency for ordering alone, and deriving a gate for
// one of those would union the whole repo into an entry nothing reads.
func referencedDependentGates(steps []step, includes []argoInclude) map[string]bool {
	referenced := map[string]bool{}
	note := func(g *gateSpec) {
		if g == nil {
			return
		}
		for _, name := range g.DependsOn {
			if strings.HasPrefix(name, dependentsPrefix) {
				referenced[strings.TrimPrefix(name, dependentsPrefix)] = true
			}
		}
	}
	for _, inc := range includes {
		note(inc.Changes)
	}
	for _, s := range steps {
		g := s.gate
		note(&g)
	}
	return referenced
}

// dependentGates unions what a step's dependents are gated on, transitively.
// Exclusions are dropped: one dependent's must not suppress another's
// inclusions, and firing too often only costs time.
func dependentGates(steps []step, components map[string]argoCIComponent, wanted map[string]bool) map[string]argoCIComponent {
	byName := map[string]step{}
	for _, s := range steps {
		byName[s.name] = s
	}
	dependents := map[string][]string{}
	for _, s := range steps {
		for _, d := range s.deps {
			dependents[d] = append(dependents[d], s.name)
		}
	}

	out := map[string]argoCIComponent{}
	for producer := range dependents {
		if !wanted[producer] {
			continue
		}
		seen := map[string]bool{}
		var patterns []string
		var walk func(string)
		walk = func(name string) {
			for _, dep := range dependents[name] {
				if seen[dep] {
					continue
				}
				seen[dep] = true
				g := byName[dep].gate
				patterns = append(patterns, g.In...)
				for _, c := range g.DependsOn {
					patterns = append(patterns, components[c].In...)
				}
				walk(dep)
			}
		}
		walk(producer)
		if len(patterns) == 0 {
			continue
		}
		out[dependentsPrefix+producer] = argoCIComponent{In: dedupeSorted(patterns)}
	}
	return out
}

func dedupeSorted(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
