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

package archives

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/projectcalico/calico/release/internal/steps"
	"github.com/projectcalico/calico/release/internal/utils"
)

func beforeBuild(a Archive) (cleanupFn func() error, err error) {
	dir := a.stagingDir()
	cleanupFn = func() error {
		return os.RemoveAll(dir)
	}
	if err := cleanupFn(); err != nil {
		return nil, fmt.Errorf("clearing staging dir %s: %w", dir, err)
	}
	if err := os.Remove(Path(a)); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("clearing old archive %s: %w", Path(a), err)
	}
	return cleanupFn, nil
}

func Build(a Archive, opts ...BuildOption) error {
	s, err := newSettings(buildStep, a, validateSources, opts)
	if err != nil {
		return err
	}
	cleanup, err := beforeBuild(s.Archive)
	if err != nil {
		return err
	}
	defer func() {
		if err := cleanup(); err != nil {
			s.Logger().WithError(err).Warn("Cleanup failed")
		}
	}()

	s.Logger().WithField("sources", len(s.Sources)).Info("Staging release archive")
	staging := s.stagingDir()
	if err := s.stage(staging); err != nil {
		return err
	}
	if err := s.tar(staging); err != nil {
		return err
	}
	s.Logger().WithField("path", Path(s.Archive)).Info("Built release archive")
	return nil
}

func (s settings) stage(staging string) error {
	for _, c := range s.Sources {
		if err := c.Contribute(staging); err != nil {
			return s.Errorf("staging %s: %w", c.Name(), err)
		}
		s.Logger().WithField("source", c.Name()).Info("Staged")
	}
	return nil
}

func (s settings) tar(staging string) error {
	if err := os.MkdirAll(s.OutputDir, utils.DirPerms); err != nil {
		return s.Errorf("creating %s: %w", s.OutputDir, err)
	}
	args := []string{"-czvf", Path(s.Archive), "-C", filepath.Dir(staging), filepath.Base(staging)}
	out, err := s.Run("tar", args, nil, s.LogPath("tar"))
	if err != nil {
		s.Logger().Error(out)
		return s.Errorf("creating %s: %w", Path(s.Archive), err)
	}
	return nil
}

// BuildWindows builds the Windows archive and its install script into the
// output directory, beside the release tarball rather than inside it.
func BuildWindows(a Archive, opts ...WindowsOption) error {
	s, err := newSettings(windowsStep, a, validateWindows, opts)
	if err != nil {
		return err
	}

	env := append(os.Environ(), utils.Env(utils.EnvVersion, s.Version))
	dir := filepath.Join(s.RepoRoot, windowsComponent)
	// The install script is a file target with no prerequisites, so make skips
	// it when one is already there and the stale version's script survives.
	if err := os.Remove(filepath.Join(dir, windowsScriptTarget)); err != nil && !os.IsNotExist(err) {
		return s.Errorf("clearing stale %s: %w", windowsScriptTarget, err)
	}
	for _, target := range []string{windowsArchiveTarget, windowsScriptTarget} {
		args := append([]string{"-C", dir}, target)
		if out, err := s.Run("make", args, env, s.LogPath(target)); err != nil {
			s.Logger().Error(out)
			return s.Errorf("building %s: %w", target, err)
		}
	}

	collect := map[string]string{
		WindowsFileName(s.Version): WindowsDir(s.OutputDir),
		windowsScript:              WindowsScriptDir(s.OutputDir),
	}
	for name, dst := range collect {
		if err := os.MkdirAll(dst, utils.DirPerms); err != nil {
			return s.Errorf("creating %s: %w", dst, err)
		}
		if err := utils.LinkOrCopyFile(filepath.Join(dir, windowsDistDir, name), filepath.Join(dst, name)); err != nil {
			return s.Errorf("collecting %s: %w", name, err)
		}
	}
	s.Logger().WithField("dir", WindowsDir(s.OutputDir)).Info("Built Windows archive")
	return nil
}

func newSettings[O any](step string, a Archive, validate func(a Archive) error, opts []O) (settings, error) {
	s := settings{Archive: a}
	s.Apply([]steps.Option{steps.WithName(step)})
	if err := validate(a); err != nil {
		return s, s.Errorf("%w", err)
	}
	for _, opt := range opts {
		if err := applyTo(opt, &s); err != nil {
			return s, s.Errorf("%w", err)
		}
	}
	return s, nil
}

func applyTo(opt any, s *settings) error {
	switch o := opt.(type) {
	case BuildOption:
		return o.applyBuild(s)
	case WindowsOption:
		return o.applyWindows(s)
	default:
		return fmt.Errorf("unknown option type %T", opt)
	}
}
