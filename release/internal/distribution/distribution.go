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

	"gopkg.in/yaml.v3"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/registry"
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

	Name string

	//  when the step that produces Source did not run.
	Skip bool
}

// A handler that finds its own content does not implement this.
type validator interface {
	Validate(u Upload) error
}

// Falls back to the destination, so a log line reads without a Name.
func (u Upload) label() string {
	if u.Name != "" {
		return u.Name
	}
	return u.Handler.Name()
}

func (u Upload) dest() string {
	return u.Handler.Name()
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

// A product embeds Release and adds its own fields; the whole value is written.
type Attester interface {
	Attest() ([]byte, error)
}

// A product asserts the same in its own file.
var _ Attester = Metadata{}

type Component struct {
	registry.Component `json:",inline" yaml:",inline"`
}

// Rendered as the reference rather than its parts: consumers read this file
// for something to pull.
func (c Component) MarshalYAML() (any, error) {
	return c.String(), nil
}

type Metadata struct {
	Version string `json:"version"`

	OperatorVersion string `json:"operator_version" yaml:"operatorVersion"`

	Images []Component `json:"images"`

	ChartVersion string `json:"helm_chart_version" yaml:"helmChartVersion"`
}

func (r Metadata) Attest() ([]byte, error) {
	var errs []error
	if r.Version == "" {
		errs = append(errs, fmt.Errorf("no version specified"))
	}
	if r.OperatorVersion == "" {
		errs = append(errs, fmt.Errorf("no operator version specified"))
	}
	if len(r.Images) == 0 {
		errs = append(errs, fmt.Errorf("no images specified"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return yaml.Marshal(r)
}

type settings struct {
	pipeline []Upload

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
