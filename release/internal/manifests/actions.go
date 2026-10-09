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

package manifests

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/steps"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/yamledit"
)

func Build(m Manifests, generate, ocpBundle bool, opts ...BuildOption) error {
	s, err := newSettings(buildStep, m, validateFor(generate), opts)
	if err != nil {
		return err
	}
	if generate {
		cleanup, err := s.generate()
		if cleanup != nil {
			defer func() {
				if e := cleanup(); e != nil {
					s.Logger().WithError(e).Warn("Failed to clean up generated manifests")
				}
			}()
		}
		if err != nil {
			return err
		}
	}
	if !ocpBundle {
		return nil
	}
	return s.buildOCPBundle()
}

func (s settings) generate() (cleanup func() error, err error) {
	cleanup = s.reset

	s.Logger().WithField("version", s.Version).Info("Generating manifests")
	env := append(os.Environ(), Env(s.Manifests)...)
	if out, err := s.Run("make", []string{"-C", s.RepoRoot, generateTarget}, env, s.LogPath(generateTarget)); err != nil {
		s.Logger().Error(out)
		return cleanup, s.Errorf("generating manifests: %w", err)
	}
	if !s.collect {
		return cleanup, nil
	}
	return cleanup, s.collectInto(Dir(s.OutputDir))
}

// Logged rather than returned: the caller's own error is the one worth having.
func (s settings) reset() error {
	args := append([]string{"checkout"}, generatedTrees...)
	if out, err := s.Run("git", args, nil, ""); err != nil {
		s.Logger().Error(out)
		return fmt.Errorf("resetting manifests: %v", err)
	}
	return nil
}

func (s settings) collectInto(dest string) error {
	if err := os.MkdirAll(dest, utils.DirPerms); err != nil {
		return s.Errorf("creating %s: %w", dest, err)
	}
	// Trailing separators stop rsync nesting the directory inside itself.
	args := rsyncArgs()
	args = append(args, Dir(s.RepoRoot)+"/", dest+"/")
	if out, err := s.Run("rsync", args, nil, s.LogPath("rsync")); err != nil {
		s.Logger().Error(out)
		return s.Errorf("copying manifests to %s: %w", dest, err)
	}
	s.Logger().WithField("dir", dest).Info("Collected manifests")
	return nil
}

func rsyncArgs() []string {
	args := []string{"-av", "--delete"}
	for _, name := range excluded {
		args = append(args, "--exclude="+name)
	}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		args = append(args, "--verbose", "--progress")
	}
	return args
}

// The make target writes the bundle outside the manifests tree, so it needs
// collecting separately.
func (s settings) buildOCPBundle() error {
	s.Logger().Info("Building OCP bundle")
	env := append(os.Environ(), Env(s.Manifests)...)

	if out, err := s.Run("make", []string{"-C", s.RepoRoot, ocpBundleTarget}, env, s.LogPath(ocpBundleTarget)); err != nil {
		s.Logger().Error(out)
		return s.Errorf("building OCP bundle: %w", err)
	}
	if err := os.MkdirAll(s.OutputDir, utils.DirPerms); err != nil {
		return s.Errorf("creating %s: %w", s.OutputDir, err)
	}
	src := filepath.Join(s.RepoRoot, ocpBundleTarget)
	if err := utils.LinkOrCopyFile(src, BundlePath(s.OutputDir)); err != nil {
		return s.Errorf("collecting OCP bundle: %w", err)
	}
	return nil
}

// Registry reports the registry the manifests under root already carry.
func Registry(root string) (string, error) {
	path := filepath.Join(Dir(root), RegistryFile)
	imgs, err := yamledit.Read(path, registryKey)
	if err != nil {
		return "", err
	}
	for _, img := range imgs {
		if !strings.Contains(img, registryImage) {
			continue
		}
		// registry/image:tag, and a registry may carry a path of its own.
		if i := strings.LastIndex(img, "/"); i > 0 {
			return img[:i], nil
		}
		return "", nil
	}
	return "", fmt.Errorf("no registry found in %s using key(%s)", path, registryKey)
}

func AssertVersions(m Manifests, opts ...AssertOption) error {
	s, err := newSettings(assertStep, m, validateAssert, opts)
	if err != nil {
		return err
	}
	for _, name := range Files() {
		path := filepath.Join(Dir(s.RepoRoot), name)
		imgs, err := yamledit.Read(path, imageKey)
		if err != nil {
			return s.Errorf("reading images from %s: %w", name, err)
		}
		for _, img := range imgs {
			if err := s.assertImage(name, img); err != nil {
				return err
			}
		}
	}
	return nil
}

const imageKey = "image"

func isImage(ref, image string) bool {
	name, _, _ := strings.Cut(ref, ":")
	return name == image || strings.HasSuffix(name, "/"+image)
}

func (s settings) assertImage(file, img string) error {
	want := s.Version
	if s.Operator.Image != "" && isImage(img, s.Operator.Image) {
		want = s.Operator.Version
	}
	if !strings.HasSuffix(img, want) {
		return s.Errorf("incorrect image version (expected %s) in manifest %s: %s", want, file, img)
	}
	return nil
}

func newSettings[O any](step string, m Manifests, validate func(Manifests) error, opts []O) (settings, error) {
	s := settings{Manifests: m}
	s.Apply([]steps.Option{steps.WithName(step), steps.WithDir(m.RepoRoot)})
	if err := validate(m); err != nil {
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
	case AssertOption:
		return o.applyAssert(s)
	default:
		return fmt.Errorf("unknown option type %T", opt)
	}
}
