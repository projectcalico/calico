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

// Package binaries builds the standalone binaries a release ships, for the
// components that produce no image of their own.
package binaries

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/archives"
	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/steps"
	"github.com/projectcalico/calico/release/internal/utils"
)

// The name becomes the log directory, so it is qualified: a bare "build"
// would collide with another group's.
const (
	buildStep   = "binaries-build"
	archiveStep = "binaries-archive"
)

const binDirName = "bin"

const (
	CalicoctlComponent = "calicoctl"
	FelixComponent     = "felix"
	E2EComponent       = "e2e"

	FelixBinary = "calico-bpf"

	// e2eTarget builds every arch; e2eSubDir is where it leaves them.
	e2eTarget = "build-all"
	e2eSubDir = "k8s"
)

// The release binaries and the target that builds them.
var all = func() map[string]string {
	return map[string]string{
		CalicoctlComponent: "build-all",
		FelixComponent:     "release-build",
	}
}

// ppc64le and s390x have no e2e runners, so building them costs time and disk
// for nothing.
var e2eArches = func() []string {
	return []string{"amd64", "arm64"}
}

// e2eArchitectures narrows configured to the arches e2e runners consume. An
// empty set means "all arches", the tooling-wide convention.
func e2eArchitectures(configured []string) []string {
	supported := e2eArches()
	if len(configured) == 0 {
		return slices.Clone(supported)
	}
	var out []string
	for _, arch := range configured {
		if slices.Contains(supported, arch) {
			out = append(out, arch)
		}
	}
	return out
}

func e2eSourceDir(repoRoot string) string {
	return filepath.Join(repoRoot, E2EComponent, binDirName, e2eSubDir)
}

func E2EDir(outputDir string) string {
	return filepath.Join(outputDir, outputs.FilesDirName, E2EComponent)
}

func e2eShipped(_, _, relPath string) bool {
	return strings.HasPrefix(relPath, fmt.Sprintf("%s-linux", E2EComponent))
}

func includeAll(_, _, _ string) bool { return true }

// Builder is one kind of binary: the make target that builds it, and what
// happens to the output.
type Builder interface {
	Component() string
	Target() string
	Env() []string
	SourceDir(repoRoot string) string
	Output() (dir string, include utils.IncludeFunc)
}

var (
	_ Builder = releaseBinaries{}
	_ Builder = e2eBinaries{}
)

var outDir = func(name, outputDir string) string {
	if name == CalicoctlComponent {
		return outputDir
	}
	return ""
}

func Release(outputDir string) []Builder {
	targets := all()
	out := make([]Builder, 0, len(targets))
	for _, name := range slices.Sorted(maps.Keys(targets)) {
		dir := outDir(name, outputDir)
		out = append(out, releaseBinaries{name: name, target: targets[name], outputDir: dir})
	}
	return out
}

type releaseBinaries struct {
	name      string
	target    string
	outputDir string
}

func (c releaseBinaries) Component() string                { return c.name }
func (c releaseBinaries) Target() string                   { return c.target }
func (c releaseBinaries) Env() []string                    { return nil }
func (c releaseBinaries) SourceDir(repoRoot string) string { return sourceDir(repoRoot, c.name) }
func (c releaseBinaries) Output() (string, utils.IncludeFunc) {
	if c.outputDir == "" {
		return "", nil
	}
	return c.outputDir, includeAll
}

func E2E(arches []string, outputDir string) Builder {
	narrowed := e2eArchitectures(arches)
	if len(narrowed) == 0 {
		logrus.WithFields(logrus.Fields{
			"step":   E2EComponent,
			"arches": arches,
		}).Warn("No e2e-supported arch requested, skipping e2e binaries")
		return nil
	}
	arches = narrowed
	return e2eBinaries{arches: arches, outputDir: outputDir}
}

type e2eBinaries struct {
	arches    []string
	outputDir string
}

func (e e2eBinaries) Component() string { return E2EComponent }
func (e e2eBinaries) Target() string    { return e2eTarget }
func (e e2eBinaries) Env() []string {
	return []string{utils.Env(utils.EnvArches, strings.Join(e.arches, " "))}
}
func (e e2eBinaries) SourceDir(repoRoot string) string    { return e2eSourceDir(repoRoot) }
func (e e2eBinaries) Output() (string, utils.IncludeFunc) { return e.outputDir, e2eShipped }

// archived is what each component contributes to the release archive. A var so
// a product shipping a different set can replace it.
var archived = func(repoRoot string) []archives.DirSource {
	return []archives.DirSource{
		{
			Label: archiveLabel(CalicoctlComponent),
			To:    filepath.Join(binDirName, CalicoctlComponent),
			From:  sourceDir(repoRoot, CalicoctlComponent),
		},
		{
			Label: archiveLabel(FelixComponent, FelixBinary),
			To:    binDirName,
			From:  sourceDir(repoRoot, FelixComponent),
			// Felix's bin/ holds build output; only the BPF tool ships.
			Filter: func(_, _, relPath string) bool { return relPath == FelixBinary },
		},
	}
}

func archiveLabel(name string, qualifier ...string) string {
	prefix := name
	if len(qualifier) > 0 {
		prefix = fmt.Sprintf("%s %s", prefix, strings.Join(qualifier, " "))
	}
	return fmt.Sprintf("%s binary", prefix)
}

// Read through this rather than spelling the path, so a reader and the build
// cannot disagree about where the binaries are.
func sourceDir(repoRoot, component string) string {
	return filepath.Join(repoRoot, component, binDirName)
}

type settings struct {
	RepoRoot string
	Version  string

	extraEnv []string

	steps.Step
}

type (
	BuildOption interface{ applyBuild(*settings) error }

	Option interface {
		applyBuild(*settings) error
	}
)

var (
	_ Option      = setting(nil)
	_ BuildOption = setting(nil)
)

type setting func(*settings) error

func (f setting) applyBuild(s *settings) error { return f(s) }

func WithRunner(r command.CommandRunner) Option {
	return setting(func(s *settings) error {
		s.Apply([]steps.Option{steps.WithRunner(r)})
		return nil
	})
}

// Concurrent builds otherwise interleave into one stream.
func WithLogsDir(dir string) Option {
	return setting(func(s *settings) error {
		s.Apply([]steps.Option{steps.WithLogsDir(dir)})
		return nil
	})
}
