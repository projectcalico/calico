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

package distribution

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/steps"
	"github.com/projectcalico/calico/release/internal/utils"
)

const filePerms = 0o644

func BuildMetadata(a Attester, dir string, opts ...MetadataOption) error {
	s, err := newSettings(metadataStep, opts)
	if err != nil {
		return err
	}
	if a == nil {
		return s.Errorf("no release to describe")
	}
	if dir == "" {
		return s.Errorf("no directory to write metadata to")
	}

	bs, err := a.Attest()
	if err != nil {
		return s.Errorf("%w", err)
	}
	path := filepath.Join(dir, MetadataFileName)
	if err := os.WriteFile(path, bs, filePerms); err != nil {
		return s.Errorf("writing %s: %w", path, err)
	}
	s.Logger().WithField("path", path).Info("Wrote release metadata")
	return nil
}

// Must be the last write into dir: a later write lands unchecksummed.
func SHA256Sums(dir string, opts ...SumsOption) error {
	s, err := newSettings(sumsStep, opts)
	if err != nil {
		return err
	}
	if dir == "" {
		return s.Errorf("no directory to checksum")
	}

	names, err := sumCandidates(dir)
	if err != nil {
		return s.Errorf("%w", err)
	}
	if len(names) == 0 {
		return s.Errorf("no files to checksum in %s", dir)
	}

	out, err := s.Runner().RunInDir(dir, "sha256sum", names, nil)
	if err != nil {
		s.Logger().Error(out)
		return s.Errorf("checksumming %s: %w", dir, err)
	}
	path := filepath.Join(dir, SumsFileName)
	if err := os.WriteFile(path, []byte(out), filePerms); err != nil {
		return s.Errorf("writing %s: %w", path, err)
	}
	s.Logger().WithField("files", len(names)).Info("Wrote checksums")
	return nil
}

// Only the top level is attached anywhere, so a nested checksum could never
// be verified.
func sumCandidates(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || e.Name() == SumsFileName {
			continue
		}
		names = append(names, e.Name())
	}
	return names, nil
}

func Publish(pipeline []Upload, confirm bool, opts ...PublishOption) error {
	s, err := newSettings(artifactsStep, opts)
	if err != nil {
		return err
	}
	if len(pipeline) == 0 {
		return s.Errorf("no uploads to publish")
	}
	var errs []error
	for _, u := range pipeline {
		if u.Skip {
			continue
		}
		if err := u.validate(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return s.Errorf("%w", err)
	}
	s.pipeline, s.confirm = pipeline, confirm

	s.Logger().WithField("uploads", len(s.pipeline)).Info("Publishing artifacts")
	if _, err := s.push(s.pipeline); err != nil {
		return err
	}
	s.Logger().Info("Finished publishing artifacts")
	return nil
}

// Ordered, and stops at the first failure as a later upload may depend on an earlier one.
// Returns what published, so a record never names an upload that failed or
// was never reached.
func (s settings) push(uploads []Upload) ([]Upload, error) {
	var done []Upload
	for _, u := range uploads {
		if err := s.publishOne(u); err != nil {
			return done, err
		}
		done = append(done, u)
	}
	return done, nil
}

func (s settings) publishOne(u Upload) error {
	log := s.Logger().WithFields(logrus.Fields{
		"upload": u.label(), "source": u.Source, "destination": u.dest(),
	})

	if u.Skip {
		log.Info("Skipping upload")
		return nil
	}
	// Checked here rather than up front: an earlier upload in the list may
	// be what creates this source.
	if u.Source != "" {
		exists, err := utils.PathExists(u.Source)
		if err != nil {
			return s.Errorf("reading %s source (%s): %w", u.label(), u.Source, err)
		}
		if !exists {
			return s.Errorf("%s source (%s) does not exist", u.label(), u.Source)
		}
	}

	for attempt := 0; ; attempt++ {
		err := u.Handler.Publish(context.Background(), u.Source)
		if err == nil {
			log.Info("Published")
			return nil
		}
		if attempt < steps.MaxRetries {
			log.WithError(err).WithField("attempt", attempt).Warn("Publish failed, retrying")
			continue
		}
		return s.Errorf("publishing %s to %s: %w", u.label(), u.dest(), err)
	}
}

func newSettings[O any](step string, opts []O) (settings, error) {
	var s settings
	s.Apply([]steps.Option{steps.WithName(step)})
	for _, opt := range opts {
		if err := applyTo(opt, &s); err != nil {
			return s, s.Errorf("%w", err)
		}
	}
	return s, nil
}

func applyTo(opt any, s *settings) error {
	switch o := opt.(type) {
	case PublishOption:
		return o.applyPublish(s)
	case MetadataOption:
		return o.applyMetadata(s)
	case SumsOption:
		return o.applySums(s)
	default:
		return fmt.Errorf("unknown option type %T", opt)
	}
}
