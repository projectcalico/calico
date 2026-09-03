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

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/imagescanner"
)

// Build builds every variant's images.
func Build(repoRoot, version string, variants []Variant, opts ...BuildOption) error {
	s, err := newSettings(repoRoot, version, variants, opts)
	if err != nil {
		return fmt.Errorf("build: %w", err)
	}

	units := s.units(s.env())
	logrus.WithField("images", len(units)).Info("Building container images")
	if err := s.runUnits(units, buildStep, s.logsDir); err != nil {
		return err
	}
	logrus.Info("Finished building container images")
	return nil
}

// Archive writes the images every variant ships into tarDir, one tar each, for
// a release archive to pick up.
func Archive(repoRoot, version string, variants []Variant, tarDir string, opts ...ArchiveOption) error {
	s, err := newSettings(repoRoot, version, variants, opts)
	if err != nil {
		return fmt.Errorf("archive: %w", err)
	}
	if tarDir == "" {
		return fmt.Errorf("archive: no directory to write images to")
	}
	if len(s.Registries) == 0 {
		return fmt.Errorf("archive: no registry to archive images from")
	}
	s.dir = tarDir

	units := s.units(s.env())
	logrus.WithField("images", len(units)).Info("Archiving container images")
	if err := os.MkdirAll(tarDir, os.ModePerm); err != nil {
		return fmt.Errorf("creating images dir: %w", err)
	}

	// Images come from the first registry: an archive holds one copy, whichever
	// registry it is pulled from.
	reg := s.Registries[0]
	for _, u := range units {
		names, err := s.imageNames(u)
		if err != nil {
			return fmt.Errorf()
		}
		for _, name := range names {
			image := fmt.Sprintf("%s/%s:%s", reg, name, s.Version)
			if err := s.save(image, filepath.Join(tarDir, name+".tar")); err != nil {
				return err
			}
		}
	}
	logrus.Info("Finished archiving container images")
	return nil
}

// Publish pushes every variant's images to their registries. confirm latches
// the push: without it the make targets run as a dry run, so it is an argument
// rather than an option a caller can forget.
func Publish(repoRoot, version string, variants []Variant, confirm bool, resolve DigestResolver, opts ...PublishOption) error {
	s, err := newSettings(repoRoot, version, variants, opts)
	if err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	if len(s.Registries) == 0 {
		return fmt.Errorf("publish: no registries to publish to")
	}
	if resolve == nil {
		return fmt.Errorf("publish: no digest resolver given")
	}
	s.resolve = resolve
	s.confirm = confirm
	if !confirm {
		// A dry run reaches no registry, so anything it recorded would claim
		// images exist when they do not.
		s.refs = nil
	}

	units, err := s.pending(s.units(s.publishEnv()))
	if err != nil {
		return err
	}
	if len(units) == 0 {
		logrus.Info("Every image is already published")
		return nil
	}
	logrus.WithField("images", len(units)).Info("Publishing container images")
	publishErr := s.runUnits(units, publishStep, s.logsDir)

	// Record before reporting a failure: a partial publish is exactly the run
	// whose record decides what a resume still has to do.
	if err := s.record(units); err != nil {
		return errors.Join(publishErr, err)
	}
	if publishErr != nil {
		return publishErr
	}
	logrus.Info("Finished publishing container images")

	if s.scan != nil {
		s.submitScan(*s.scan)
	}
	return nil
}

// newSettings validates what every step requires and layers the options over
// it. It is generic so each step passes only the option type it accepts.
func newSettings[O any](repoRoot, version string, variants []Variant, opts []O) (settings, error) {
	s := settings{Image: Image{RepoRoot: repoRoot, Version: version, Variants: variants}}
	if err := s.validate(); err != nil {
		return s, fmt.Errorf("settings: %w", err)
	}
	for _, opt := range opts {
		if err := applyTo(opt, &s); err != nil {
			return s, err
		}
	}
	return s.defaults(), nil
}

// applyTo layers one option over the settings.
func applyTo(opt any, s *settings) error {
	switch o := opt.(type) {
	case BuildOption:
		return o.applyBuild(s)
	case ArchiveOption:
		return o.applyArchive(s)
	case PublishOption:
		return o.applyPublish(s)
	default:
		return fmt.Errorf("unknown option type %T", opt)
	}
}

// pending drops the units an earlier run already published, so a release
// interrupted partway resumes on what is left.
func (s settings) pending(units []unit) ([]unit, error) {
	if s.resume == nil {
		return units, nil
	}
	var out []unit
	for _, u := range units {
		done, err := s.unitState(u)
		if err != nil {
			return nil, err
		}
		if done {
			logrus.WithFields(logrus.Fields{"variant": u.variant, "component": u.dir}).
				Info("Already published, skipping")
			continue
		}
		out = append(out, u)
	}
	return out, nil
}

// submitScan reports failures without returning them: the scanning service must
// not be able to fail a release.
func (s settings) submitScan(req ScanRequest) {
	logrus.Info("Sending images to ISS")
	scanner := imagescanner.New(req.Config)
	if err := scanner.Scan(req.ProductCode, req.Images, req.Stream, req.Release, req.OutputDir); err != nil {
		logrus.WithError(err).Error("Failed to scan images")
	}
}
