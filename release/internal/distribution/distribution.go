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

type Handler interface {
	Name() string

	Publish(ctx context.Context, src string) error
}

type Upload struct {
	Source string

	Handler Handler

	AllowMissing bool
}

// validator is a handler that has its own rules about the upload it is given.
// A handler that finds its own content does not implement it.
type validator interface {
	Validate(u Upload) error
}

func (u Upload) validate() error {
	if u.Handler == nil {
		return fmt.Errorf("upload of %s has no destination", u.Source)
	}
	if v, ok := u.Handler.(validator); ok {
		return v.Validate(u)
	}
	return nil
}

// Metadata is what metadata.yaml records about a release.
type Metadata struct {
	Version string `json:"version"`

	OperatorVersion string `json:"operator_version" yaml:"operatorVersion"`

	// Supplied, not derived: a release and a hashrelease name images from
	// different sources.
	Images []string `json:"images"`

	ChartVersion string `json:"helm_chart_version" yaml:"helmChartVersion"`
}

func (m Metadata) validate() error {
	var errs []error
	if m.Version == "" {
		errs = append(errs, fmt.Errorf("no version specified"))
	}
	if m.OperatorVersion == "" {
		errs = append(errs, fmt.Errorf("no operator version specified"))
	}
	if len(m.Images) == 0 {
		errs = append(errs, fmt.Errorf("no images specified"))
	}
	return errors.Join(errs...)
}

type settings struct {
	pipeline []Upload

	confirm bool

	refs steps.RefRecorder

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

// WithRecord writes a ref per completed upload, so a later step reads what
// was published rather than what was planned.
func WithRecord(rec steps.RefRecorder) PublishOption {
	return publishSetting(func(s *settings) error {
		if rec == nil {
			return fmt.Errorf("no recorder to record published artifacts")
		}
		s.refs = rec
		return nil
	})
}
