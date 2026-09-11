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

// Package distribution sends a release's artifacts to where they are published.
package distribution

import (
	"context"
	"errors"
	"fmt"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/steps"
)

// The name becomes the log directory, so it is qualified: a bare "publish"
// would collide with another group's.
const (
	metadataStep     = "distribution-metadata"
	sumsStep         = "distribution-sha256sums"
	artifactsStep    = "distribution-publish-artifacts"
	hashreleaseStep  = "distribution-publish-hashrelease"
	MetadataFileName = "metadata.yaml"
	SumsFileName     = "SHA256SUMS"
)

type Destination interface {
	Name() string

	Publish(ctx context.Context, src string) error
}

type Upload struct {
	Source string

	Dest Destination

	AllowMissing bool
}

func (u Upload) validate() error {
	var errs []error
	if u.Source == "" {
		errs = append(errs, fmt.Errorf("upload with no source"))
	}
	if u.Dest == nil {
		errs = append(errs, fmt.Errorf("upload of %s has no destination", u.Source))
	}
	return errors.Join(errs...)
}

type Release struct {
	Version string

	OperatorVersion string

	// Images are supplied rather than derived: image identity has two sources,
	// the component Makefiles and the pinned-versions file, and only the
	// caller knows which applies.
	Images []string

	ChartVersion string

	Registry string
}

func (r Release) validate() error {
	var errs []error
	if r.Version == "" {
		errs = append(errs, fmt.Errorf("no version specified"))
	}
	if r.OperatorVersion == "" {
		errs = append(errs, fmt.Errorf("no operator version specified"))
	}
	return errors.Join(errs...)
}

type settings struct {
	Release

	uploads []Upload

	confirm bool

	steps.Step
}

// A step's options. Option reaches every step; the per-step interfaces let a
// setting that belongs to one verb be rejected at compile time by the others.
type (
	MetadataOption interface{ applyMetadata(*settings) error }
	SumsOption     interface{ applySums(*settings) error }
	PublishOption  interface{ applyPublish(*settings) error }

	Option interface {
		applyMetadata(*settings) error
		applySums(*settings) error
		applyPublish(*settings) error
	}
)

// Each adapter must satisfy the interfaces its options are returned as, so a
// missing apply method fails here rather than at a call site.
var (
	_ Option        = setting(nil)
	_ PublishOption = publishSetting(nil)
)

type setting func(*settings) error

func (f setting) applyMetadata(s *settings) error { return f(s) }
func (f setting) applySums(s *settings) error     { return f(s) }
func (f setting) applyPublish(s *settings) error  { return f(s) }

type publishSetting func(*settings) error

func (f publishSetting) applyPublish(s *settings) error { return f(s) }

func WithRunner(r command.CommandRunner) Option {
	return setting(func(s *settings) error {
		s.Apply([]steps.Option{steps.WithRunner(r)})
		return nil
	})
}

func WithLogsDir(dir string) Option {
	return setting(func(s *settings) error {
		s.Apply([]steps.Option{steps.WithLogsDir(dir)})
		return nil
	})
}

func WithDir(dir string) Option {
	return setting(func(s *settings) error {
		s.Apply([]steps.Option{steps.WithDir(dir)})
		return nil
	})
}
