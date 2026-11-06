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
	"fmt"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/steps"
)

// The name becomes the log directory, so it is qualified: a bare "publish"
// would collide with another group's.
const (
	sumsStep      = "distribution-sha256sums"
	artifactsStep = "distribution-publish-artifacts"
	sumsFileName  = "SHA256SUMS"
)

type Handler interface {
	Name() string

	Publish(ctx context.Context, src string) error
}

type Upload struct {
	Source string

	Handler Handler

	Name string

	// A skipped upload stays in the plan but does not run.
	Skip bool
}

// A handler that finds its own content does not implement this.
type validator interface {
	Validate(u Upload) error
}

// Only a handler that publishes files where users download them lists them.
type artifactLister interface {
	artifacts(src string) ([]outputs.ArtifactFile, error)
}

// Metadata is the artifacts' section of the release metadata.
func Metadata(pipeline []Upload) ([]outputs.Artifact, error) {
	files, err := artifactFiles(pipeline)
	if err != nil {
		return nil, err
	}
	return outputs.DescribeArtifacts(files)
}

// artifactFiles lists the files the pipeline publishes for download, with the
// URL each will be served at.
func artifactFiles(pipeline []Upload) ([]outputs.ArtifactFile, error) {
	var files []outputs.ArtifactFile
	for _, u := range pipeline {
		l, ok := u.Handler.(artifactLister)
		if u.Skip || !ok {
			continue
		}
		f, err := l.artifacts(u.Source)
		if err != nil {
			return nil, fmt.Errorf("artifacts of %s: %w", u.label(), err)
		}
		files = append(files, f...)
	}
	return files, nil
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

type settings struct {
	pipeline []Upload

	steps.Step
}

type Option func(*settings) error

func WithRunner(r command.CommandRunner) Option {
	return func(s *settings) error {
		s.Apply([]steps.Option{steps.WithRunner(r)})
		return nil
	}
}

func WithLogsDir(dir string) Option {
	return func(s *settings) error {
		s.Apply([]steps.Option{steps.WithLogsDir(dir)})
		return nil
	}
}

func WithDir(dir string) Option {
	return func(s *settings) error {
		s.Apply([]steps.Option{steps.WithDir(dir)})
		return nil
	}
}
