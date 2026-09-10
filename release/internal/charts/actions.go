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

package charts

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/steps"
	"github.com/projectcalico/calico/release/internal/utils"
)

// Build packages every chart the release ships.
func Build(chart Chart, opts ...BuildOption) error {
	s, err := newSettings(buildStep, chart, opts)
	if err != nil {
		return err
	}

	// The edits land in the working tree, so restore it however the build ends.
	if s.modifyValues != nil {
		defer s.resetTree()
		if err := s.modifyValues(); err != nil {
			return s.Errorf("modifying chart values: %w", err)
		}
	}

	s.Logger().WithField("charts", len(s.Names)).Info("Building helm charts")
	if err := s.build(); err != nil {
		return err
	}
	if err := s.verify(); err != nil {
		return err
	}
	s.Logger().Info("Finished building helm charts")

	if s.index == nil {
		return nil
	}
	s.repoURL, s.chartURL, s.indexDir = s.index.repoURL, s.index.chartURL, s.index.dir
	s.Logger().Info("Building helm index")
	if err := s.buildIndex(); err != nil {
		return err
	}
	s.Logger().Info("Finished building helm index")

	return nil
}

// Publish pushes every built chart to every registry. confirm latches the push.
func Publish(chart Chart, registries []string, confirm bool, opts ...PublishOption) error {
	s, err := newSettings(publishStep, chart, opts)
	if err != nil {
		return err
	}
	if len(registries) == 0 {
		return s.Errorf("no registries to publish to")
	}
	s.registries, s.confirm = registries, confirm
	if !confirm {
		// A dry run pushes nothing, so a record would name unpublished charts.
		s.refs = nil
	}

	// Fail before pushing, rather than leaving a registry half updated.
	if err := s.present(); err != nil {
		return err
	}
	units, err := s.pending()
	if err != nil {
		return err
	}
	if len(units) == 0 {
		s.Logger().Info("Every chart is already published")
		return nil
	}
	if !confirm {
		s.Logger().WithField("charts", len(units)).Info("Dry run, not publishing helm charts")
		return nil
	}

	s.Logger().WithField("charts", len(units)).Info("Publishing helm charts")
	pushErr := s.push(units)

	// Record before reporting a failure: a partial publish is the run whose
	// record decides what a resume still owes.
	if err := s.record(units); err != nil {
		return errors.Join(pushErr, err)
	}
	if pushErr != nil {
		return pushErr
	}
	s.Logger().Info("Finished publishing helm charts")
	return nil
}

func newSettings[O any](step string, chart Chart, opts []O) (settings, error) {
	s := settings{Chart: chart}
	s.Apply([]steps.Option{steps.WithName(step), steps.WithDir(chart.RepoRoot)})
	if err := s.validate(); err != nil {
		return s, s.Errorf("%w", err)
	}
	for _, opt := range opts {
		if err := applyTo(opt, &s); err != nil {
			return s, s.Errorf("%w", err)
		}
	}
	if s.resolve == nil {
		s.resolve = registry.ResolveDigest
	}
	return s, nil
}

func applyTo(opt any, s *settings) error {
	switch o := opt.(type) {
	case BuildOption:
		return o.applyBuild(s)
	case PublishOption:
		return o.applyPublish(s)
	default:
		return fmt.Errorf("unknown option type %T", opt)
	}
}

func (s settings) build() error {
	if err := os.MkdirAll(s.BaseDir, utils.DirPerms); err != nil {
		return s.Errorf("creating chart dir: %w", err)
	}
	env := append(os.Environ(),
		utils.Env(utils.EnvGitVersion, s.Version()),
		utils.Env(utils.EnvChartDestination, s.BaseDir),
	)
	env = append(env, s.env...)

	out, err := s.Run("make", []string{"-C", s.RepoRoot, chartTarget}, env, s.LogPath("charts"))
	if err != nil {
		// Surface the captured output; the failure cause is usually only there.
		s.Logger().Error(out)
		return s.Errorf("building helm charts: %w", err)
	}
	return nil
}

// A chart missing here means the target and the list have drifted apart.
func (s settings) verify() error {
	var errs []error
	for _, chart := range s.Names {
		if _, err := os.Stat(s.path(chart)); err != nil {
			errs = append(errs, fmt.Errorf("chart %s was not built: %w", chart, err))
		}
	}
	return errors.Join(errs...)
}

func (s settings) resetTree() {
	if _, err := s.Runner().RunInDir(s.RepoRoot, "git", []string{"checkout", chartsTreePath}, nil); err != nil {
		s.Logger().WithError(err).Error("Failed to reset changes to charts")
	}
}

// chartsTreePath is the tree whose values a build rewrites and a reset restores.
const chartsTreePath = "charts/"

// The index directory holds only this release's charts, so the entries it adds
// are what was just built.
func (s settings) buildIndex() error {
	merged, err := s.downloadIndex()
	if err != nil {
		return err
	}
	// helm indexes a whole directory, so the staging dir must hold this
	// release's charts and nothing else.
	staging := Dir(s.tmpDir, s.Version())
	if err := os.RemoveAll(staging); err != nil {
		return s.Errorf("clearing helm index staging dir: %w", err)
	}
	if err := os.MkdirAll(staging, utils.DirPerms); err != nil {
		return s.Errorf("creating helm index staging dir: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(staging); err != nil {
			s.Logger().WithError(err).Warnf("failed to remove helm index staging dir %s", staging)
		}
	}()
	// The charts are linked in rather than copied.
	for _, chart := range s.Names {
		if err := os.Link(s.path(chart), filepath.Join(staging, s.fileName(chart))); err != nil {
			return s.Errorf("linking %s chart for building helm index: %w", chart, err)
		}
	}

	args := []string{
		"repo", "index", staging,
		"--url", s.chartURL,
		"--merge", merged,
	}
	// helm stamps entries with the current time; UTC keeps the index stable.
	env := append(os.Environ(), utils.Env(utils.EnvTZ, "UTC"))
	if out, err := s.Helm(args, env, s.LogPath("index")); err != nil {
		s.Logger().Error(out)
		return s.Errorf("building helm index: %w", err)
	}

	if err := os.MkdirAll(s.indexDir, utils.DirPerms); err != nil {
		return s.Errorf("creating helm index dir: %w", err)
	}
	if err := utils.CopyFile(filepath.Join(staging, indexFileName), filepath.Join(s.indexDir, indexFileName)); err != nil {
		return s.Errorf("writing the helm index: %w", err)
	}
	return nil
}

func (s settings) downloadIndex() (string, error) {
	indexURL, err := url.JoinPath(s.repoURL, indexFileName)
	if err != nil {
		return "", s.Errorf("constructing helm index url: %w", err)
	}
	dest := filepath.Join(s.tmpDir, indexFileName)
	if err := os.MkdirAll(filepath.Dir(dest), utils.DirPerms); err != nil {
		return "", s.Errorf("creating dir for downloaded helm index: %w", err)
	}
	if out, err := s.Runner().Run("curl", []string{"-fsSL", "--retry", "3", indexURL, "-o", dest}, nil); err != nil {
		s.Logger().Error(out)
		return "", s.Errorf("downloading previous helm index from %s: %w", indexURL, err)
	}
	return dest, nil
}

func (s settings) present() error {
	var errs []error
	for _, chart := range s.Names {
		if _, err := os.Stat(s.path(chart)); err != nil {
			errs = append(errs, fmt.Errorf("chart %s not built: %w", chart, err))
		}
	}
	return errors.Join(errs...)
}

// pending drops the charts an earlier run published, so an interrupted release
// resumes on what is left.
func (s settings) pending() ([]unit, error) {
	units := s.units()
	if s.resume == nil || len(s.resume.published) == 0 {
		return units, nil
	}

	recorded := steps.DigestsByRepo(s.resume.published)

	done, err := steps.Go(units, func(u unit) (bool, error) {
		return s.published(u, recorded)
	})
	if err != nil {
		return nil, err
	}
	var out []unit
	for i, u := range units {
		if done[i] {
			s.Logger().WithFields(map[string]any{"chart": u.chart, "registry": u.registry}).
				Info("Already published, skipping")
			continue
		}
		out = append(out, u)
	}
	return out, nil
}

func (s settings) published(u unit, recorded steps.RecordedDigests) (bool, error) {
	digests, ok := recorded[u.repo()]
	if !ok {
		return false, nil
	}
	ref := u.ref(s.Version())
	got, exists, err := s.resolve(ref)
	if err != nil {
		return false, s.Errorf("resolving %s: %w", ref, err)
	}
	if !exists {
		return false, nil
	}
	if _, known := digests[got]; known {
		return true, nil
	}
	if s.resume.force {
		return false, nil
	}
	return false, s.Errorf(
		"%s is published at %s; this release recorded %s. Pass --force to republish over it",
		ref, got, strings.Join(slices.Sorted(maps.Keys(digests)), ", "))
}

// Failures are collected, not stopped at: one chart failing must not hide the
// rest.
func (s settings) push(units []unit) error {
	_, err := steps.Go(units, func(u unit) (struct{}, error) {
		return struct{}{}, s.pushUnit(u)
	})
	return err
}

func (s settings) pushUnit(u unit) error {
	log := s.Logger().WithFields(map[string]any{"chart": u.chart, "registry": u.registry})
	args := []string{"push", s.path(u.chart), "oci://" + u.registry}
	if s.Logger().Logger.IsLevelEnabled(logrus.DebugLevel) {
		args = append(args, "--debug")
	}

	for attempt := 0; ; attempt++ {
		out, err := s.Run(helmBinary, args, nil, s.LogPath(u.slug()))
		if err == nil {
			log.Info("Published helm chart")
			return nil
		}
		if attempt < steps.MaxRetries {
			log.WithError(err).WithField("attempt", attempt).Warn("Publish failed, retrying")
			continue
		}
		log.Error(out)
		return s.Errorf("publishing %s to %s: %w", u.chart, u.registry, err)
	}
}

// record writes the digest refs the publish produced.
func (s settings) record(units []unit) error {
	if s.refs == nil {
		return nil
	}
	refs, lookupErr := steps.Go(units, func(u unit) (string, error) {
		ref := u.ref(s.Version())
		digest, exists, err := s.resolve(ref)
		if err != nil {
			return "", s.Errorf("recording published chart %s: %w", u.chart, err)
		}
		if !exists {
			s.Logger().WithField("chart", ref).Debug("Published chart absent, not recording")
			return "", nil
		}
		return fmt.Sprintf("%s@%s", u.repo(), digest), nil
	})

	errs := []error{lookupErr}
	for i, ref := range refs {
		if ref == "" {
			continue
		}
		if err := s.refs.Add(ref); err != nil {
			errs = append(errs, s.Errorf("recording published chart %s: %w", units[i].chart, err))
			break
		}
	}
	return errors.Join(errs...)
}

func (s settings) fileName(chart string) string {
	return FileName(chart, s.Version())
}

func (s settings) path(chart string) string {
	return filepath.Join(s.BaseDir, s.fileName(chart))
}

type unit struct {
	chart    string
	registry string
}

func (s settings) units() []unit {
	out := make([]unit, 0, len(s.Names)*len(s.registries))
	for _, chart := range s.Names {
		for _, reg := range s.registries {
			out = append(out, unit{chart: chart, registry: reg})
		}
	}
	return out
}

func (u unit) repo() string {
	return u.registry + "/" + u.chart
}

// ref names the chart at one version, the form a digest is resolved from.
func (u unit) ref(version string) string {
	return u.repo() + ":" + version
}

// A chart goes to several registries, so the registry is in the name.
func (u unit) slug() string {
	return u.chart + "-" + strings.NewReplacer("/", "-", ":", "-").Replace(u.registry)
}

type ValueEdit struct {
	Chart string
	Key   string
	Value string
}

// Edits are supplied by the caller: products stamp different charts.
type Values struct {
	RepoRoot string
	Edits    []ValueEdit
}

// ModifyValues points the charts at the versions being released. It edits the
// working tree, so a caller that is not committing calls ResetValues after.
func ModifyValues(v Values, opts ...Option) error {
	if v.RepoRoot == "" {
		return fmt.Errorf("no repository root specified")
	}
	if len(v.Edits) == 0 {
		return fmt.Errorf("no chart values to modify")
	}
	s, err := valuesStep(v.RepoRoot, opts)
	if err != nil {
		return err
	}
	for _, e := range v.Edits {
		if e.Chart == "" || e.Key == "" || e.Value == "" {
			return s.Errorf("incomplete chart value edit: %+v", e)
		}
		expr := fmt.Sprintf("s/%s: .*/%s: %s/g", e.Key, e.Key, e.Value)
		path := filepath.Join(v.RepoRoot, chartsTreePath, e.Chart, "values.yaml")
		if out, err := s.Runner().Run("sed", []string{"-i", expr, path}, nil); err != nil {
			s.Logger().Error(out)
			return s.Errorf("updating %s in %s: %w", e.Key, path, err)
		}
	}
	return nil
}

// Takes no chart set: rewriting the values predates packaging them.
func valuesStep(repoRoot string, opts []Option) (settings, error) {
	var s settings
	s.Apply([]steps.Option{steps.WithName(valuesStepName), steps.WithDir(repoRoot)})
	for _, opt := range opts {
		// Option reaches every step, so its build side is just one way in.
		if err := opt.applyBuild(&s); err != nil {
			return s, s.Errorf("%w", err)
		}
	}
	return s, nil
}

const valuesStepName = "charts-values"
