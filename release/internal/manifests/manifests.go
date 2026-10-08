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

// Package manifests builds the Kubernetes manifests a release ships.
package manifests

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/steps"
	"github.com/projectcalico/calico/release/internal/utils"
)

const (
	buildStep  = "manifests-build"
	assertStep = "manifests-assert-versions"
)

const (
	DirName = "manifests"

	generateTarget  = "gen-manifests"
	ocpBundleTarget = "bin/" + OCPBundleFileName

	OCPBundleFileName = "ocp.tgz"
)

var generatedTrees = []string{DirName, "test-tools/mocknode/mock-node.yaml"}

// RegistryFile carries the product image the registry is read back from.
var RegistryFile = "calicoctl.yaml"

const registryKey = "spec.containers.image"

// The image in RegistryFile whose reference carries the registry. Both
// products ship it under this name, so it is not a per-product value.
const registryImage = "calico"

// Files is a deliberate subset. Widening it is a behaviour change.
var Files = func() []string {
	return []string{"calico.yaml", filepath.Join("ocp", "02-tigera-operator.yaml")}
}

var excluded = []string{"generate.sh", "README.md", ".gitattributes"}

// Include reports whether a file in the manifests tree ships with a release.
func Include(_, _, relPath string) bool {
	for _, name := range excluded {
		if filepath.Base(relPath) == name {
			return false
		}
	}
	return true
}

func Dir(outputDir string) string {
	return filepath.Join(outputDir, DirName)
}

func BundlePath(outputDir string) string {
	return filepath.Join(outputDir, OCPBundleFileName)
}

type Manifests struct {
	RepoRoot string

	Version string

	Operator registry.Component

	// The registry the release publishes to.
	Registry string

	OutputDir string
}

func (m Manifests) validate() error {
	var errs []error
	if m.RepoRoot == "" {
		errs = append(errs, fmt.Errorf("no repository root specified"))
	}
	if m.Version == "" {
		errs = append(errs, fmt.Errorf("no version specified"))
	}
	return errors.Join(errs...)
}

func validateFor(generate bool) func(Manifests) error {
	return func(m Manifests) error {
		errs := []error{m.validate()}
		if m.OutputDir == "" {
			errs = append(errs, fmt.Errorf("no output directory specified"))
		}
		if generate && m.Operator.Version == "" {
			errs = append(errs, fmt.Errorf("no operator version specified"))
		}
		return errors.Join(errs...)
	}
}

var validateAssert = func(m Manifests) error {
	errs := []error{m.validate()}
	if m.Operator.Version == "" {
		errs = append(errs, fmt.Errorf("no operator version specified"))
	}
	if m.Operator.Image == "" {
		errs = append(errs, fmt.Errorf("no operator image specified"))
	}
	return errors.Join(errs...)
}

func env(m Manifests) []string {
	e := []string{
		utils.Env(utils.EnvProductVersion, m.Version),
		utils.Env(utils.EnvOperatorVersion, m.Operator.Version),
		utils.Env(utils.EnvOperatorRegistryOverride, m.Operator.Registry),
		utils.Env(utils.EnvOperatorImageOverride, m.Operator.Image),
		utils.Env(utils.EnvRegistry, m.Registry),
	}
	return e
}

// A replacement, not an append hook: a product can drop or rewrite a variable.
var Env = env

type settings struct {
	Manifests

	// collect copies the generated tree into the output directory. Only a
	// hashrelease publishes the tree on its own; a release ships it in the
	// archive instead.
	collect bool

	steps.Step
}

type (
	BuildOption  interface{ applyBuild(*settings) error }
	AssertOption interface{ applyAssert(*settings) error }

	Option interface {
		applyBuild(*settings) error
		applyAssert(*settings) error
	}
)

var _ Option = setting(nil)

type setting func(*settings) error

func (f setting) applyBuild(s *settings) error  { return f(s) }
func (f setting) applyAssert(s *settings) error { return f(s) }

func WithRunner(r command.CommandRunner) Option {
	return setting(func(s *settings) error {
		s.Apply([]steps.Option{steps.WithRunner(r)})
		return nil
	})
}

// WithCollect copies the generated manifests into the output directory.
func WithCollect() BuildOption {
	return setting(func(s *settings) error {
		s.collect = true
		return nil
	})
}

func WithLogsDir(dir string) Option {
	return setting(func(s *settings) error {
		s.Apply([]steps.Option{steps.WithLogsDir(dir)})
		return nil
	})
}
