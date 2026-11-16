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

// Package cronreadback reads the live ArgoCI CronWorkflows back and checks that
// each cell's E2E_TEST_CONFIG matches the cron file that was merged.
package cronreadback

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/projectcalico/calico/e2e/pkg/cilanes"
)

const (
	cronDir = ".argoci/cron"

	// The flannel migration lane's pre-migration run hardcodes its config in a
	// script, so it is no cell of its own.
	preMigrationSuffix = " [pre-migration]"
)

// ExpectedCron is one cron file and the cells it declares an E2E_TEST_CONFIG for.
type ExpectedCron struct {
	// Name is the live CronWorkflow name: the file's generateName base, then
	// the branch.
	Name string

	// File is the repo-relative cron file.
	File string

	// Cells maps each cell's live name to its E2E_TEST_CONFIG.
	Cells map[string]string
}

// cronHeader holds the top-level fields of a cron file that cilanes does not
// resolve.
type cronHeader struct {
	GenerateName string        `yaml:"generateName"`
	Includes     []cronInclude `yaml:"includes"`
}

// cronInclude is a module file a cron pulls its steps from.
type cronInclude struct {
	Path string `yaml:"path"`
}

// moduleFile is the part of a module file that sets a step's environment.
type moduleFile struct {
	Steps []moduleStep `yaml:"steps"`
}

type moduleStep struct {
	Name   string         `yaml:"name"`
	Env    []moduleEnvVar `yaml:"env"`
	Matrix []moduleMatrix `yaml:"matrix"`
}

type moduleMatrix struct {
	Name string         `yaml:"name"`
	Env  []moduleEnvVar `yaml:"env"`
}

type moduleEnvVar struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

// LoadExpected resolves every cron file under repoRoot to the live cron it
// deploys as on branch. The cells come from cilanes, so a file's
// globalPrologue default and its matrix entries resolve as they do for the
// lane test sets.
func LoadExpected(repoRoot, branch string) ([]ExpectedCron, error) {
	lanes, err := cilanes.Load(repoRoot)
	if err != nil {
		return nil, err
	}

	bySource := map[string][]cilanes.Lane{}
	for _, l := range lanes {
		bySource[l.Source] = append(bySource[l.Source], l)
	}

	entries, err := os.ReadDir(filepath.Join(repoRoot, cronDir))
	if err != nil {
		return nil, err
	}

	// A file's live name comes from its own generateName, which cilanes does not carry.
	var crons []ExpectedCron
	for _, e := range entries {
		ext := filepath.Ext(e.Name())
		if e.IsDir() || (ext != ".yaml" && ext != ".yml") {
			continue
		}
		rel := filepath.Join(cronDir, e.Name())
		data, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			return nil, err
		}
		var header cronHeader
		if err := yaml.Unmarshal(data, &header); err != nil {
			return nil, fmt.Errorf("%s: %w", rel, err)
		}
		if header.GenerateName == "" {
			return nil, fmt.Errorf("%s: no generateName, so no live cron name", rel)
		}
		cells := expectedCells(bySource[rel])
		for _, inc := range header.Includes {
			if err := addModuleCells(cells, repoRoot, inc.Path); err != nil {
				return nil, fmt.Errorf("%s: %w", rel, err)
			}
		}
		crons = append(crons, ExpectedCron{
			Name:  liveName(header.GenerateName, branch),
			File:  rel,
			Cells: cells,
		})
	}
	sort.Slice(crons, func(i, j int) bool { return crons[i].Name < crons[j].Name })
	return crons, nil
}

// expectedCells keys each lane that selects a config by the name its live cell
// has, which is how the live side is looked up.
func expectedCells(lanes []cilanes.Lane) map[string]string {
	cells := map[string]string{}
	for _, l := range lanes {
		if l.Config == "" || strings.HasSuffix(l.Name, preMigrationSuffix) {
			continue
		}
		cells[cellKey(l.Name)] = l.Config
	}
	return cells
}

// addModuleCells adds the cells of an included module whose step or matrix
// entry sets E2E_TEST_CONFIG. A kind step that leaves it to the make target
// carries no value in the live cron, so it is not expected to. A config set in
// a defaults.env block, or a cron's globalPrologue default reaching module
// steps, is not modeled and would show up as an extra live cell.
func addModuleCells(cells map[string]string, repoRoot, path string) error {
	data, err := os.ReadFile(filepath.Join(repoRoot, path))
	if err != nil {
		return fmt.Errorf("include %s: %w", path, err)
	}
	var mod moduleFile
	if err := yaml.Unmarshal(data, &mod); err != nil {
		return fmt.Errorf("include %s: %w", path, err)
	}
	for _, step := range mod.Steps {
		stepConfig := configIn(step.Env)
		if len(step.Matrix) == 0 {
			if stepConfig != "" {
				cells[normalizeName(step.Name)] = stepConfig
			}
			continue
		}
		for _, m := range step.Matrix {
			config := stepConfig
			if c := configIn(m.Env); c != "" {
				config = c
			}
			if config != "" {
				cells[cellKey(step.Name+" ["+m.Name+"]")] = config
			}
		}
	}
	return nil
}

// configIn returns the E2E_TEST_CONFIG value an env list sets, or "".
func configIn(vars []moduleEnvVar) string {
	for _, v := range vars {
		if v.Name == "E2E_TEST_CONFIG" {
			return v.Value
		}
	}
	return ""
}

// cellKey converts a cilanes lane name, "step [entry]", to the name Argo gives
// the expanded step, "step-entry", in the form both sides are matched on.
func cellKey(laneName string) string {
	if i := strings.LastIndex(laneName, " ["); i >= 0 && strings.HasSuffix(laneName, "]") {
		laneName = laneName[:i] + "-" + strings.TrimSuffix(laneName[i+2:], "]")
	}
	return normalizeName(laneName)
}

var nonNameChars = regexp.MustCompile(`[^a-z0-9-]+`)

// normalizeName folds a step name the way Kubernetes names fold, so a matrix
// entry with a capital or a dot still meets its live step.
func normalizeName(s string) string {
	return nonNameChars.ReplaceAllString(strings.ToLower(s), "-")
}

// liveName returns the CronWorkflow name a file's generateName deploys as on
// branch. A base that already ends with the branch is not suffixed twice.
func liveName(generateName, branch string) string {
	base := strings.TrimSuffix(generateName, "-")
	suffix := sanitizeBranch(branch)
	if strings.HasSuffix(base, "-"+suffix) {
		return base
	}
	return base + "-" + suffix
}

// sanitizeBranch turns a branch name into the suffix the live cron name
// carries, as in release-v3.33 to release-v3-33. Unlike a step name it has no
// leading or trailing dash.
func sanitizeBranch(branch string) string {
	return strings.Trim(normalizeName(branch), "-")
}
