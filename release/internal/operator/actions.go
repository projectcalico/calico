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

package operator

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/steps"
	"github.com/projectcalico/calico/release/internal/utils"
)

func Build(o Operator, variants []Variant, hashrelease bool, opts ...BuildOption) error {
	s, err := newSettings(buildStep, o, validateBuild(hashrelease), opts)
	if err != nil {
		return err
	}
	if err := s.preBuildValidation(); err != nil {
		return err
	}
	return eachVariant(variants, func(v Variant) error {
		return s.run(buildTarget, v, hashrelease, nil)
	})
}

func Publish(o Operator, variants []Variant, hashrelease bool, opts ...PublishOption) error {
	s, err := newSettings(PublishStep, o, validatePublish, opts)
	if err != nil {
		return err
	}
	if s.resolve == nil {
		s.resolve = registry.ResolveDigest
	}
	if s.dryRun {
		// A dry run pushes nothing, so there is nothing to record.
		s.refs = nil
	}
	env := []string{s.latch()}

	var recorded steps.RecordedDigests
	if s.resume != nil {
		recorded = steps.DigestsByRepo(s.resume.published)
	}
	return eachVariant(variants, func(v Variant) error {
		done, err := s.published(v, recorded)
		if err != nil {
			return err
		}
		if done {
			s.Logger().WithField("variant", v.Name).Info("Already published, skipping")
			return nil
		}
		// Recorded even when the push failed, so a resume knows what landed.
		return errors.Join(s.run(publishTarget, v, hashrelease, env), s.record(v))
	})
}

func PublishBranchTag(o Operator, variants []Variant, branch string, opts ...PublishOption) error {
	s, err := newSettings(branchStep, o, validateBranch, opts)
	if err != nil {
		return err
	}
	if branch == "" {
		return s.Errorf("no branch specified")
	}
	// A ref names the version it published at, and this retags at the branch.
	if s.refs != nil {
		return s.Errorf("a branch tag records nothing")
	}
	// No manifest refers to another variant under a branch tag.
	variants = Narrow(variants, []string{standardVariant})
	env := []string{s.latch(), utils.Env(utils.EnvImageTag, branch)}

	return eachVariant(variants, func(v Variant) error {
		return s.run(branchTagTarget, v, false, env)
	})
}

// Variants share the operator's tree, so they run one at a time. One failing
// does not stop the rest.
func eachVariant(variants []Variant, fn func(Variant) error) error {
	var errs []error
	for _, v := range variants {
		errs = append(errs, fn(v))
	}
	return errors.Join(errs...)
}

func (s settings) latch() string {
	if s.dryRun {
		return utils.EnvTrue(utils.EnvDryRun)
	}
	return utils.EnvTrue(utils.EnvConfirm)
}

// The variant's env goes last so an inherited value cannot pick the variant.
func (s settings) run(target string, v Variant, hashrelease bool, env []string) error {
	product, err := productEnv(s.Operator)
	if err != nil {
		return s.Errorf("%w", err)
	}
	full := append(os.Environ(), s.env(v, hashrelease)...)
	full = append(full, product...)
	full = append(full, env...)
	full = append(full, v.Env...)

	logFields := logrus.Fields{
		"variant":    v.Name,
		"image":      image(s.Operator, v),
		"registries": s.Registries,
		"version":    s.Version,
	}
	s.Logger().WithFields(logFields).Infof("Running %s", target)
	args := append([]string{"-C", Dir(s.Operator)}, strings.Fields(target)...)
	out, err := s.Run("make", args, full, s.LogPath(v.Name+"-"+logSlug(target)))
	if err != nil {
		s.Logger().Error(out)
		return s.Errorf("%s for %s: %w", target, v.Name, err)
	}
	return nil
}

func logSlug(target string) string {
	return strings.ReplaceAll(target, " ", "-")
}

// A replacement, not an append hook: a product can drop or rewrite a variable.
var productEnv = func(o Operator) ([]string, error) {
	var env []string
	if o.ProductRegistry != "" {
		reg, imagePath, err := registryParts(o.ProductRegistry)
		if err != nil {
			return nil, err
		}
		env = append(env,
			utils.Env("CALICO_REGISTRY", reg),
			utils.Env("CALICO_IMAGE_PATH", imagePath),
		)
	}
	if o.ProductVersion != "" {
		env = append(env, utils.Env("CALICO_VERSION", o.ProductVersion))
	}
	if opReg, opPath, err := registryParts(Registry(o)); err == nil {
		env = append(env,
			utils.Env("OPERATOR_IMAGE_REGISTRY", opReg),
			utils.Env("OPERATOR_IMAGE_PATH", opPath),
		)
	}
	return env, nil
}

func (s settings) env(v Variant, hashrelease bool) []string {
	env := []string{
		utils.Env(utils.EnvRegistry, Registry(s.Operator)),
		utils.Env(utils.EnvVersion, s.Version),
		utils.Env(utils.EnvDevRegistries, strings.Join(s.Registries, " ")),
	}
	if !hashrelease {
		env = append(env, utils.EnvTrue(utils.EnvRelease))
	}
	if len(s.arches) > 0 {
		env = append(env, utils.Env(utils.EnvArches, strings.Join(s.arches, " ")))
	}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		env = append(env, utils.EnvTrue(utils.EnvDebug))
	}
	return env
}

func (s settings) record(v Variant) error {
	if s.refs == nil {
		return nil
	}
	var refs []string
	var errs []error
	for _, t := range s.tags(v) {
		digest, exists, err := s.resolve(t.ref())
		if err != nil {
			errs = append(errs, s.Errorf("recording %s: %w", t.ref(), err))
			continue
		}
		if !exists {
			s.Logger().WithField("image", t.ref()).Debug("Published tag absent, not recording")
			continue
		}
		refs = append(refs, t.repo+"@"+digest)
	}
	if err := s.refs.Add(refs...); err != nil {
		errs = append(errs, s.Errorf("recording %s: %w", v.Name, err))
	}
	return errors.Join(errs...)
}

func (s settings) published(v Variant, recorded steps.RecordedDigests) (bool, error) {
	if len(recorded) == 0 {
		return false, nil
	}
	for _, t := range s.tags(v) {
		digests, ok := recorded[t.repo]
		if !ok {
			return false, nil
		}
		got, exists, err := s.resolve(t.ref())
		if err != nil {
			// A failed lookup says nothing about what is published.
			s.Logger().WithError(err).WithField("image", t.ref()).Warn("Could not resolve digest, will publish")
			return false, nil
		}
		if !exists {
			return false, nil
		}
		if _, known := digests[got]; known {
			continue
		}
		if s.resume.force {
			return false, nil
		}
		return false, s.Errorf(
			"%s is published at %s; this release recorded %s. Pass --force to publish anyway",
			t.ref(), got, strings.Join(slices.Sorted(maps.Keys(digests)), ", "))
	}
	return true, nil
}

type tag struct {
	repo string
	tag  string
}

func (t tag) ref() string {
	return t.repo + ":" + t.tag
}

func (s settings) tags(v Variant) []tag {
	var out []tag
	for _, reg := range s.Registries {
		repo := reg + "/" + image(s.Operator, v)
		out = append(out, tag{repo: repo, tag: s.Version})
		for _, arch := range s.arches {
			out = append(out, tag{repo: repo, tag: s.Version + "-" + arch})
		}
	}
	return out
}

func (s settings) preBuildValidation() error {
	if !s.validate {
		s.Logger().Warn("Skipping pre-build validation")
		return nil
	}
	dirty, err := utils.GitIsDirty(Dir(s.Operator))
	if err != nil {
		return s.Errorf("checking if git is dirty: %w", err)
	}
	if dirty {
		return s.Errorf("there are uncommitted changes in the repository, please commit or stash them")
	}
	return nil
}

func newSettings[O any](step string, o Operator, validate func(Operator) error, opts []O) (settings, error) {
	s := settings{Operator: o, validate: true}
	s.Apply([]steps.Option{steps.WithName(step), steps.WithDir(Dir(o))})
	if err := validate(o); err != nil {
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
	case PublishOption:
		return o.applyPublish(s)
	default:
		return fmt.Errorf("unknown option type %T", opt)
	}
}
