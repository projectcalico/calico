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

package images

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/archives"
	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/steps"
	"github.com/projectcalico/calico/release/internal/utils"
)

func Build(repoRoot, version string, variants []Variant, opts ...BuildOption) error {
	s, err := newSettings(buildStep, repoRoot, version, variants, opts)
	if err != nil {
		return err
	}

	units := s.units(s.env())
	s.Logger().WithField("images", len(units)).Info("Building container images")
	if err := s.runUnits(units); err != nil {
		return err
	}
	s.Logger().Info("Finished building container images")
	return nil
}

// Archive writes each image to its own tar under tarDir.
func Archive(repoRoot, version string, imageDirs []string, opts ...ArchiveOption) archives.Contributor {
	return archiver{
		RepoRoot: repoRoot,
		Version:  version,
		Variants: NarrowVariants(StandardVariants(PublishVariants), imageDirs),
		Options:  opts,
	}
}

var _ archives.Contributor = archiver{}

type archiver struct {
	RepoRoot string
	Version  string
	Variants []Variant
	Options  []ArchiveOption
}

func (a archiver) Name() string {
	return "images"
}

func (a archiver) Contribute(dir string) error {
	s, err := newSettings(archiveStep, a.RepoRoot, a.Version, a.Variants, a.Options)
	if err != nil {
		return err
	}
	if dir == "" {
		return s.Errorf("no directory to write images to")
	}
	dest := filepath.Join(dir, "images")
	if len(s.Registries) == 0 {
		return s.Errorf("no registry to archive images from")
	}
	units := s.units(s.env())
	s.Logger().WithField("images", len(units)).Info("Archiving container images")
	if err := os.MkdirAll(dest, os.ModePerm); err != nil {
		return fmt.Errorf("creating images dir %s: %w", dest, err)
	}

	// Images come from the first registry: an archive holds one copy, whichever
	// registry it is pulled from.
	reg := s.Registries[0]
	if _, err := steps.Go(units, func(u unit) (unitDone, error) {
		return unitDone{}, saveUnit(s, u, reg, dest)
	}); err != nil {
		return err
	}
	s.Logger().Info("Finished archiving container images")
	return nil
}

func saveUnit(s settings, u unit, reg, dest string) error {
	names, err := s.imageNames(u)
	if err != nil {
		return s.Errorf("%w", err)
	}
	for _, name := range names {
		image := fmt.Sprintf("%s/%s:%s", reg, name, s.Version)
		if err := save(s, image, filepath.Join(dest, name+".tar")); err != nil {
			return s.Errorf("%w", err)
		}
	}
	return nil
}

var publishEnv = func(s settings) []string {
	env := append(s.env(),
		utils.EnvTrue(utils.EnvRelease),
		utils.Env(utils.EnvReleaseTag, s.Version),
	)
	if s.confirm {
		env = append(env, utils.EnvTrue(utils.EnvConfirm))
	} else {
		env = append(env, utils.EnvTrue(utils.EnvDryRun))
	}
	if s.retag != nil {
		// Retagging inverts DEV_REGISTRIES: it becomes the source, so the
		// destination has to be named separately.
		env = append(env,
			utils.EnvTrue(utils.EnvImageOnly),
			utils.Env(utils.EnvDevTag, s.retag.tag),
			utils.Env(utils.EnvDevRegistries, s.retag.registry),
			utils.Env(utils.EnvReleaseRegistries, strings.Join(s.Registries, " ")),
		)
		if s.retag.skipDev {
			env = append(env, utils.EnvTrue(utils.EnvSkipDevImageRetag))
		}
	}
	return env
}

// confirm latches the push: without it the make targets run as a dry run, so it
// is an argument rather than an option a caller can forget.
func Publish(repoRoot, version string, variants []Variant, confirm bool, resolve steps.DigestResolver, opts ...PublishOption) error {
	s, err := newSettings(PublishStep, repoRoot, version, variants, opts)
	if err != nil {
		return err
	}
	if len(s.Registries) == 0 {
		return s.Errorf("no registries to publish to")
	}
	if resolve == nil {
		return s.Errorf("no digest resolver given")
	}
	s.resolve = resolve
	s.confirm = confirm
	if !confirm {
		// A dry run reaches no registry, so anything it recorded would claim
		// images exist when they do not.
		s.refs = nil
	}

	unscanned, depErr := s.runDependencies()
	units, err := pending(s, s.units(publishEnv(s)))
	if err != nil {
		return errors.Join(depErr, err)
	}
	if len(units) == 0 {
		s.Logger().Info("Every image is already published")
		if depErr != nil {
			return depErr
		}
		sendImagesToISS(s, unscanned)
		return nil
	}
	s.Logger().WithField("images", len(units)).Info("Publishing container images")
	publishErr := s.runUnits(units)

	// Record before reporting a failure: a partial publish is exactly the run
	// whose record decides what a resume still has to do.
	if err := record(s, units); err != nil {
		return errors.Join(depErr, publishErr, err)
	}
	if err := errors.Join(depErr, publishErr); err != nil {
		return err
	}
	s.Logger().Info("Finished publishing container images")

	sendImagesToISS(s, unscanned)
	return nil
}

// Resolve records already published images a release uses.
// A missing image fails only once the rest are recorded.
func Resolve(repoRoot, version string, variants []Variant, resolve steps.DigestResolver, opts ...ResolveOption) error {
	s, err := newSettings(ResolveStep, repoRoot, version, variants, opts)
	if err != nil {
		return err
	}
	if len(s.Registries) == 0 {
		return s.Errorf("no registries to resolve images in")
	}
	if resolve == nil {
		return s.Errorf("no digest resolver given")
	}

	s.resolve = resolve

	unscanned, depErr := s.runDependencies()
	units := s.units(s.env())
	s.Logger().WithField("images", len(units)).Info("Resolving container images")
	got, lookupErr := steps.GoLimit(units, lookupLimit, s.lookup)

	errs := []error{depErr}
	if lookupErr != nil {
		errs = append(errs, s.Errorf("%w", lookupErr))
	}
	if err := s.addRefs(got); err != nil {
		errs = append(errs, s.Errorf("%w", err))
	}
	var missing []string
	for _, r := range got {
		missing = append(missing, r.missing...)
	}
	if len(missing) > 0 {
		errs = append(errs, s.Errorf("%w", &MissingError{Images: missing}))
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	s.Logger().Info("Finished resolving container images")

	sendImagesToISS(s, unscanned)
	return nil
}

func (s settings) runDependencies() (unscanned []string, err error) {
	var errs []error
	for _, dep := range s.deps {
		refs, err := dep()
		unscanned = append(unscanned, refs...)
		errs = append(errs, err)
	}
	return unscanned, errors.Join(errs...)
}

// A scan failure must not fail the release: the images are already published.
func sendImagesToISS(s settings, unscanned []string) {
	if s.scan == nil {
		return
	}
	scan := *s.scan
	scan.Images = slices.DeleteFunc(slices.Clone(scan.Images), func(image string) bool {
		return slices.Contains(unscanned, image)
	})
	s.scan = &scan
	if s.scan.DryRun {
		s.Logger().WithFields(logrus.Fields{
			"images":  s.scan.Images,
			"stream":  s.scan.Stream,
			"release": s.scan.Release,
		}).Info("Dry run: would send images to ISS")
		return
	}
	s.Logger().Info("Sending images to ISS")
	scanner := imagescanner.New(s.scan.Config)
	if err := scanner.Scan(s.scan.ProductCode, s.scan.Images, s.scan.Stream, s.scan.Release, s.scan.OutputDir); err != nil {
		s.Logger().WithError(err).Error("Failed to scan images")
	}
}

// newSettings is generic so each step accepts only its own option type.
func newSettings[O any](step, repoRoot, version string, variants []Variant, opts []O) (settings, error) {
	s := settings{RepoRoot: repoRoot, Version: version, Variants: variants}
	s.Apply([]steps.Option{steps.WithName(step)})
	errs := []error{s.validate()}
	if step != ResolveStep {
		for _, v := range variants {
			if len(v.Images) > 0 {
				errs = append(errs, fmt.Errorf("variant %q declares its images, which only a resolve accepts", v.Name))
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return s, s.Errorf("%w", err)
	}
	for _, opt := range opts {
		if err := applyTo(opt, &s); err != nil {
			return s, s.Errorf("%w", err)
		}
	}
	return s.defaults(), nil
}

func applyTo(opt any, s *settings) error {
	switch o := opt.(type) {
	case BuildOption:
		return o.applyBuild(s)
	case ArchiveOption:
		return o.applyArchive(s)
	case PublishOption:
		return o.applyPublish(s)
	case ResolveOption:
		return o.applyResolve(s)
	default:
		return fmt.Errorf("unknown option type %T", opt)
	}
}

// unitStateAgainst binds one record, so every unit is judged against the same.
func (s settings) unitStateAgainst(recorded steps.RecordedDigests) func(unit) (bool, error) {
	return func(u unit) (bool, error) { return unitState(s, u, recorded) }
}

// pending drops the units an earlier run already published, so a release
// interrupted partway resumes on what is left.
func pending(s settings, units []unit) ([]unit, error) {
	if s.resume == nil {
		return units, nil
	}
	recorded := steps.DigestsByRepo(s.resume.published)
	done, err := steps.Go(units, s.unitStateAgainst(recorded))
	if err != nil {
		return nil, err
	}

	var out []unit
	for i, u := range units {
		if done[i] {
			s.Logger().WithFields(logrus.Fields{"variant": u.variant, "component": u.dir}).
				Info("Already published, skipping")
			continue
		}
		out = append(out, u)
	}
	return out, nil
}
