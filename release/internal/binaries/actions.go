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

package binaries

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/projectcalico/calico/release/internal/archives"
	"github.com/projectcalico/calico/release/internal/steps"
	"github.com/projectcalico/calico/release/internal/utils"
)

func Build(repoRoot, version string, builders []Builder, opts ...BuildOption) error {
	// A constructor returns nil when a product ships none of that kind, so
	// callers can append unconditionally.
	builders = slices.DeleteFunc(slices.Clone(builders), func(b Builder) bool { return b == nil })
	if len(builders) == 0 {
		return nil
	}
	s, err := newSettings(buildStep, repoRoot, version, opts)
	if err != nil {
		return err
	}

	s.Logger().WithField("builders", len(builders)).Info("Building binaries")
	if _, err := steps.Go(builders, func(b Builder) (unitDone, error) {
		return unitDone{}, s.build(b)
	}); err != nil {
		return err
	}
	for _, b := range builders {
		if err := s.collect(b); err != nil {
			return err
		}
	}
	s.Logger().Info("Finished building binaries")
	return nil
}

func (s settings) build(b Builder) error {
	log := s.Logger().WithFields(map[string]any{"component": b.Component(), "target": b.Target()})
	dir := filepath.Join(s.RepoRoot, b.Component())
	env := append(s.env(), b.Env()...)

	args := append([]string{"-C", dir}, strings.Fields(b.Target())...)
	for attempt := 0; ; attempt++ {
		out, err := s.Run("make", args, env, s.LogPath(b.Component()))
		if err == nil {
			log.Debug(out)
			return nil
		}
		if attempt < steps.MaxRetries {
			log.WithError(err).WithField("attempt", attempt).Warn("Binary build failed, retrying")
			continue
		}
		// Surface the captured output; the failure cause is usually only there.
		log.Error(out)
		return s.Errorf("building %s binaries: %w", b.Component(), err)
	}
}

func (s settings) collect(b Builder) error {
	dest, include := b.Output()
	if dest == "" {
		return nil
	}
	n, err := s.linkFrom(b.SourceDir(s.RepoRoot), dest, include)
	if err != nil {
		return s.Errorf("collecting %s binaries: %w", b.Component(), err)
	}
	s.Logger().WithFields(map[string]any{"component": b.Component(), "binaries": n}).
		Info("Collected binaries")
	return nil
}

func (s settings) linkFrom(src, dest string, include utils.IncludeFunc) (int, error) {
	found, err := utils.FindRecursiveFiles(src, include)
	if err != nil {
		return 0, fmt.Errorf("reading %s: %w", src, err)
	}
	if len(found) == 0 {
		return 0, fmt.Errorf("no binaries found in %s", src)
	}
	if err := os.MkdirAll(dest, utils.DirPerms); err != nil {
		return 0, fmt.Errorf("creating %s: %w", dest, err)
	}
	return len(found), utils.LinkOrCopyDir(src, dest, include)
}

func Archive(repoRoot string) []archives.Contributor {
	sources := archived(repoRoot)
	out := make([]archives.Contributor, 0, len(sources))
	for _, src := range sources {
		out = append(out, src)
	}
	return out
}

func newSettings[O any](step, repoRoot, version string, opts []O) (settings, error) {
	s := settings{RepoRoot: repoRoot, Version: version}
	s.Apply([]steps.Option{steps.WithName(step), steps.WithDir(repoRoot)})
	if repoRoot == "" {
		return s, s.Errorf("no repository root specified")
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
	default:
		return fmt.Errorf("unknown option type %T", opt)
	}
}

func (s settings) env() []string {
	env := append(os.Environ(), utils.Env(utils.EnvVersion, s.Version))
	return append(env, s.extraEnv...)
}

type unitDone struct{}
