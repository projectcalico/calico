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

// Package archives builds the release archive: the tarball a user downloads.
package archives

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/steps"
	"github.com/projectcalico/calico/release/internal/utils"
)

const (
	buildStep   = "archives-build"
	windowsStep = "archives-build-windows"
)

const (
	filePrefix = "release"

	windowsComponent = "node"
	windowsDistDir   = "dist"
	windowsScript    = "install-calico-windows.ps1"

	// Make targets that produce the Windows archive and its install script.
	windowsArchiveTarget = "release-windows-archive"
	windowsScriptTarget  = windowsDistDir + "/" + windowsScript

	WindowsDirName = "windows"
)

var (
	WindowsFileName = func(version string) string {
		return fmt.Sprintf("calico-windows-%s.zip", version)
	}

	WindowsDir = func(outputDir string) string {
		return outputDir
	}

	WindowsScriptDir = func(outputDir string) string {
		return outputDir
	}

	WindowsHashreleaseDir = func(outputDir string) string {
		return filepath.Join(outputDir, outputs.FilesDirName, WindowsDirName)
	}

	FileName = func(a Archive) string {
		return fmt.Sprintf("%s-%s", filePrefix, a.Version)
	}
)

func withExtension(name string) string {
	return fmt.Sprintf("%s.tgz", name)
}

// ArchiveFileName is the archive as a release names it, without a directory.
func ArchiveFileName(a Archive) string {
	return withExtension(FileName(a))
}

func Path(a Archive) string {
	return filepath.Join(a.OutputDir, ArchiveFileName(a))
}

var validate = func(a Archive) error {
	var errs []error
	if a.Version == "" {
		errs = append(errs, fmt.Errorf("no version specified"))
	}
	if a.OutputDir == "" {
		errs = append(errs, fmt.Errorf("no output directory specified"))
	}
	return errors.Join(errs...)
}

var validateSources = func(a Archive) error {
	errs := []error{validate(a)}
	if len(a.Sources) == 0 {
		errs = append(errs, fmt.Errorf("no content specified"))
	}
	for i, c := range a.Sources {
		if c == nil {
			errs = append(errs, fmt.Errorf("content %d has nothing to contribute", i))
		}
	}
	return errors.Join(errs...)
}

var validateWindows = func(a Archive) error {
	errs := []error{validate(a)}
	if a.RepoRoot == "" {
		errs = append(errs, fmt.Errorf("no repository root specified"))
	}
	return errors.Join(errs...)
}

type Archive struct {
	Version string

	OperatorVersion string

	RepoRoot string

	OutputDir string

	Sources []Contributor
}

func (a Archive) stagingDir() string {
	return filepath.Join(filepath.Dir(a.OutputDir), FileName(a))
}

// Name is where the files land inside the archive; empty is the root.
type Contributor interface {
	Name() string
	Contribute(dir string) error
}

var _ Contributor = DirSource{}

// DirSource contributes a directory of files the release has already built.
type DirSource struct {
	Label string

	// To is the dir where the files land relative to the root of the archive.
	To string

	// From is the source directory containing the files to include in the archive.
	From string

	// Filter determines which files in the source directory are included in the archive.
	// If no filter is provided, all files are included.
	Filter utils.IncludeFunc
}

func (d DirSource) Name() string { return d.Label }

// Hard-linked to keep staging disk usage flat. Linking nothing is an error:
// the copy skips non-regular files, so empty means a missing component.
func (d DirSource) Contribute(dir string) error {
	include := d.Filter
	if include == nil {
		include = func(_, _, _ string) bool { return true }
	}
	found, err := utils.FindRecursiveFiles(d.From, include)
	if err != nil {
		return fmt.Errorf("reading %s: %w", d.From, err)
	}
	if len(found) == 0 {
		return fmt.Errorf("no files found in %s", d.From)
	}
	dest := filepath.Join(dir, d.To)
	if err := os.MkdirAll(dest, utils.DirPerms); err != nil {
		return fmt.Errorf("creating destination(%s) for %s: %w", dest, d.Name(), err)
	}
	return utils.LinkOrCopyDir(d.From, dest, include)
}

type settings struct {
	Archive

	steps.Step
}

type (
	BuildOption   interface{ applyBuild(*settings) error }
	WindowsOption interface{ applyWindows(*settings) error }

	Option interface {
		applyBuild(*settings) error
		applyWindows(*settings) error
	}
)

var (
	_ Option      = setting(nil)
	_ BuildOption = buildSetting(nil)
)

type setting func(*settings) error

func (f setting) applyBuild(s *settings) error   { return f(s) }
func (f setting) applyWindows(s *settings) error { return f(s) }

type buildSetting func(*settings) error

func (f buildSetting) applyBuild(s *settings) error { return f(s) }

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
