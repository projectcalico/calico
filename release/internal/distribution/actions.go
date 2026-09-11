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

	"gopkg.in/yaml.v3"

	"github.com/projectcalico/calico/release/internal/steps"
)

const filePerms = 0o644

func BuildMetadata(m Metadata, dir string, opts ...MetadataOption) error {
	s, err := newSettings(metadataStep, opts)
	if err != nil {
		return err
	}
	if err := m.validate(); err != nil {
		return s.Errorf("%w", err)
	}
	if dir == "" {
		return s.Errorf("no directory to write metadata to")
	}

	bs, err := yaml.Marshal(m)
	if err != nil {
		return s.Errorf("marshalling metadata: %w", err)
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

func Publish(uploads []Upload, confirm bool, opts ...PublishOption) error {
	s, err := newSettings(artifactsStep, opts)
	if err != nil {
		return err
	}
	if len(uploads) == 0 {
		return s.Errorf("no uploads to publish")
	}
	var errs []error
	for _, u := range uploads {
		if err := u.validate(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return s.Errorf("%w", err)
	}
	s.uploads, s.confirm = uploads, confirm
	if !confirm {
		// A dry run sends nothing, so a record would name unpublished artifacts.
		s.refs = nil
	}

	pending, err := s.present()
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		s.Logger().Info("Nothing to publish")
		return nil
	}
	if !confirm {
		for _, u := range pending {
			s.Logger().WithFields(map[string]any{"source": u.Source, "destination": u.Handler.Name()}).
				Info("Dry run, not publishing")
		}
		return nil
	}

	s.Logger().WithField("uploads", len(pending)).Info("Publishing artifacts")
	pubErr := s.push(pending)

	// Record before reporting a failure: a partial publish is the run whose
	// record decides what is already done.
	if err := s.record(pending); err != nil {
		return errors.Join(pubErr, err)
	}
	if pubErr != nil {
		return pubErr
	}
	s.Logger().Info("Finished publishing artifacts")
	return nil
}

func (s settings) present() ([]Upload, error) {
	var (
		out  []Upload
		errs []error
	)
	for _, u := range s.uploads {
		switch _, err := os.Stat(u.Source); {
		case err == nil:
			out = append(out, u)
		case !errors.Is(err, os.ErrNotExist):
			errs = append(errs, s.Errorf("reading %s: %w", u.Source, err))
		case u.AllowMissing:
			s.Logger().WithFields(map[string]any{"source": u.Source, "destination": u.Handler.Name()}).
				Warn("Source does not exist, skipping")
		default:
			errs = append(errs, s.Errorf("%s is not built, and %s requires it", u.Source, u.Handler.Name()))
		}
	}
	return out, errors.Join(errs...)
}

// Collected, not stopped at: a rerun needs every outstanding failure.
func (s settings) push(uploads []Upload) error {
	_, err := steps.Go(uploads, func(u Upload) (struct{}, error) {
		return struct{}{}, s.publishOne(u)
	})
	return err
}

func (s settings) publishOne(u Upload) error {
	log := s.Logger().WithFields(map[string]any{"source": u.Source, "destination": u.Handler.Name()})
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
		return s.Errorf("publishing %s to %s: %w", u.Source, u.Handler.Name(), err)
	}
}

func (s settings) record(uploads []Upload) error {
	if s.refs == nil {
		return nil
	}
	refs := make([]string, 0, len(uploads))
	for _, u := range uploads {
		refs = append(refs, u.Handler.Name())
	}
	if err := s.refs.Add(refs...); err != nil {
		return s.Errorf("recording published artifacts: %w", err)
	}
	return nil
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
