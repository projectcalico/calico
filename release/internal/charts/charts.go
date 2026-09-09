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

// Package charts packages the product's Helm charts, builds the repository
// index over them, and pushes the charts to their registries.
package charts

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/steps"
)

// The name becomes the log directory, so it is qualified: a bare "build"
// would collide with another group's.
const (
	buildStep   = "charts-build"
	publishStep = "charts-publish"
)

const (
	// chartsDirName holds a release's packaged charts.
	chartsDirName = "charts"

	// One invocation: a chart may be packaged into another as a sub-chart.
	chartTarget = "chart"

	indexFileName = "index.yaml"

	// The repository's own helm, so every run uses the same version.
	helmBinary = "./bin/helm"
)

// The charts a release ships, and where the product serves them from.
const (
	TigeraOperatorChart      = "tigera-operator"
	ProjectCalicoV1CRDsChart = "crd.projectcalico.org.v1"
	ProjectCalicoV3CRDsChart = "projectcalico.org.v3"
)

var RepoURL = func() string {
	return "https://docs.tigera.io/calico/charts"
}

// All is the set a release ships. It is a var so a product shipping a
// different set can replace it.
var All = func() []string {
	return []string{
		TigeraOperatorChart,
		ProjectCalicoV1CRDsChart,
		ProjectCalicoV3CRDsChart,
	}
}

// Version qualifies the product version when the charts rev separately from
// it. An empty suffix means the charts share the product version.
func Version(productVersion, suffix string) string {
	if suffix == "" {
		return productVersion
	}
	return productVersion + "-" + suffix
}

// Chart identifies the charts a release ships. One argument rather than
// several: the fields are same-typed strings a caller could silently swap.
type Chart struct {
	RepoRoot string

	ProductVersion string

	ChartVersion string

	Names []string

	BaseDir string
}

func (c Chart) validate() error {
	var errs []error
	if c.RepoRoot == "" {
		errs = append(errs, fmt.Errorf("no repository root specified"))
	}
	if c.ProductVersion == "" {
		errs = append(errs, fmt.Errorf("no version specified"))
	}
	if len(c.Names) == 0 {
		errs = append(errs, fmt.Errorf("no charts specified"))
	}
	if slices.Contains(c.Names, "") {
		errs = append(errs, fmt.Errorf("chart with no name"))
	}
	if c.BaseDir == "" {
		errs = append(errs, fmt.Errorf("no chart directory specified"))
	}
	return errors.Join(errs...)
}

func (c Chart) Version() string {
	return Version(c.ProductVersion, c.ChartVersion)
}

// FileName is the file one chart is packaged into.
func FileName(chart, chartVersion string) string {
	name := chart
	if chartVersion != "" {
		name = fmt.Sprintf("%s-%s", chart, chartVersion)
	}
	return fmt.Sprintf("%s.tgz", name)
}

// Dir is where a release's charts or their index sit under outputDir. The
// version keeps one release's charts apart from another's.
func Dir(outputDir, version string) string {
	name := chartsDirName
	if version != "" {
		name += "-" + version
	}
	return filepath.Join(outputDir, name)
}

// settings is what a verb runs with. A field belongs here only when a verb
// needs it.
type settings struct {
	Chart

	// env is extra environment for products whose charts need more than the
	// version and destination.
	env []string

	// modifyValues rewrites chart values to the versions being released. The
	// tree is restored afterwards.
	modifyValues func() error

	// index builds the repository index over the charts once they are packaged.
	index *index

	// repoURL is the Helm repository holding the index to merge with, and
	// chartURL is where that index tells clients to download charts from.
	repoURL  string
	chartURL string

	// indexDir is where the built index lands.
	indexDir string

	tmpDir string

	registries []string

	confirm bool

	refs steps.RefRecorder

	resolve steps.DigestResolver

	// resume is the record an earlier run left, and how to check it.
	resume *resume

	steps.Step
}

func (s *settings) Helm(args []string, env []string, logPath string) (string, error) {
	return s.Run(helmBinary, args, env, logPath)
}

// index is where a build writes its repository index.
type index struct {
	repoURL  string
	chartURL string
	dir      string
}

// resume is what an interrupted run left behind, and whether to override it.
type resume struct {
	published []string
	force     bool
}

// A step's options. Option reaches every step; the per-step interfaces let a
// setting that belongs to one verb be rejected at compile time by the others.
type (
	BuildOption   interface{ applyBuild(*settings) error }
	PublishOption interface{ applyPublish(*settings) error }

	Option interface {
		applyBuild(*settings) error
		applyPublish(*settings) error
	}
)

// Each adapter must satisfy the interfaces its options are returned as, so a
// missing apply method fails here rather than at a call site.
var (
	_ Option        = setting(nil)
	_ BuildOption   = buildSetting(nil)
	_ PublishOption = publishSetting(nil)
)

type setting func(*settings) error

func (f setting) applyBuild(s *settings) error   { return f(s) }
func (f setting) applyPublish(s *settings) error { return f(s) }

type buildSetting func(*settings) error

func (f buildSetting) applyBuild(s *settings) error { return f(s) }

type publishSetting func(*settings) error

func (f publishSetting) applyPublish(s *settings) error { return f(s) }

func WithRunner(r command.CommandRunner) Option {
	return setting(func(s *settings) error {
		s.Apply([]steps.Option{steps.WithRunner(r)})
		return nil
	})
}

// WithLogsDir gives each invocation its own log file. Concurrent pushes
// otherwise interleave into one stream.
func WithLogsDir(dir string) Option {
	return setting(func(s *settings) error {
		s.Apply([]steps.Option{steps.WithLogsDir(dir)})
		return nil
	})
}

// WithEnv adds environment to the chart target, for a product whose charts
// need more than the version and destination.
func WithEnv(env ...string) BuildOption {
	return buildSetting(func(s *settings) error {
		s.env = append(s.env, env...)
		return nil
	})
}

// WithIndex builds the repository index after packaging and leaves it in dir.
// repoURL holds the index to merge with; chartURL is where it sends clients.
//
// helm indexes a whole directory, so the charts are staged under tmpDir to
// index this release alone, and only the finished index reaches dir.
func WithIndex(repoURL, chartURL, dir, tmpDir string) BuildOption {
	return buildSetting(func(s *settings) error {
		if repoURL == "" || chartURL == "" || dir == "" || tmpDir == "" {
			return fmt.Errorf("an index needs a repository url, a chart url, a directory and a temp dir")
		}
		s.index = &index{repoURL: repoURL, chartURL: chartURL, dir: dir}
		s.tmpDir = tmpDir
		return nil
	})
}

// WithModifiedValues rewrites the chart values before packaging, restoring the
// tree afterwards.
func WithModifiedValues(edits []ValueEdit) BuildOption {
	return buildSetting(func(s *settings) error {
		if len(edits) == 0 {
			return fmt.Errorf("no chart values to modify")
		}
		s.modifyValues = func() error {
			return ModifyValues(Values{RepoRoot: s.RepoRoot, Edits: edits}, WithRunner(s.Runner()))
		}
		return nil
	})
}

func WithRecord(rec steps.RefRecorder) PublishOption {
	return publishSetting(func(s *settings) error {
		if rec == nil {
			return fmt.Errorf("no recorder to record published charts")
		}
		s.refs = rec
		return nil
	})
}

func WithResolver(resolve steps.DigestResolver) PublishOption {
	return publishSetting(func(s *settings) error {
		if resolve == nil {
			return fmt.Errorf("no resolver to read published digests")
		}
		s.resolve = resolve
		return nil
	})
}

// WithResume skips the charts an earlier run already published. Without force,
// a digest that disagrees with the record is an error: the tag moved under us.
func WithResume(published []string, force bool) PublishOption {
	return publishSetting(func(s *settings) error {
		s.resume = &resume{published: published, force: force}
		return nil
	})
}

// ValueEditsFor points the operator and product charts at the versions a
// release pins.
var ValueEditsFor = func(productVersion, operatorVersion string) []ValueEdit {
	return []ValueEdit{
		{Chart: operatorChartName, Key: "version", Value: operatorVersion},
		{Chart: operatorChartName, Key: "tag", Value: productVersion},
		{Chart: productChartName, Key: "version", Value: productVersion},
	}
}

// The charts whose values a release rewrites. productChartName renders the
// manifests rather than shipping, so it is not in the released set.
const (
	operatorChartName = "tigera-operator"
	productChartName  = "calico"
)
