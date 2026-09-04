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

// Package images builds and publishes the product's container images.
package images

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/utils"
)

// Steps that drive images. The name becomes the log directory and the verb in
// a failure, so a new step adds one here rather than passing a literal.
const (
	buildStep   = "images-build"
	publishStep = "images-publish"
	archiveStep = "images-archive"
)

const (
	StandardVariant = "standard"

	// windowsVariant is named apart from the rest and published without
	// per-architecture tags.
	windowsVariant = "windows"
)

var (
	BuildVariants = []Variant{
		// felix ships an image that is built but never published on its own
		{
			Name:        StandardVariant,
			Target:      "release-build",
			ReleaseDirs: append(slices.Clone(utils.ImageReleaseDirs), "felix"),
		},
		{
			Name:        windowsVariant,
			Target:      "image-windows",
			ReleaseDirs: slices.Clone(utils.WindowsReleaseDirs),
		},
	}
	PublishVariants = []Variant{
		{
			Name:        StandardVariant,
			Target:      "release-publish",
			ReleaseDirs: slices.Clone(utils.ImageReleaseDirs),
		},
		{
			Name:        windowsVariant,
			Target:      "release-windows",
			ReleaseDirs: slices.Clone(utils.WindowsReleaseDirs),
		},
	}
)

// Variant is one kind of image and the directories that ship it. Target and Env
// cover the two ways a make target tells variants apart: its own target, or the
// shared one with extra environment.
type Variant struct {
	Name        string
	Target      string
	Env         []string
	ReleaseDirs []string
}

type ScanRequest struct {
	imagescanner.Config

	ProductCode string

	// Images are supplied, not derived: image identity has two sources here,
	// the component Makefiles and the pinned-versions file, and only the caller
	// knows which applies.
	Images []string

	Stream string

	Release bool

	OutputDir string
}

func VariantDirs(variants []Variant) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, v := range variants {
		for _, dir := range v.ReleaseDirs {
			if _, ok := seen[dir]; ok {
				continue
			}
			seen[dir] = struct{}{}
			out = append(out, dir)
		}
	}
	return out
}

// StandardVariants drops the Windows and any other kind.
func StandardVariants(variants []Variant) []Variant {
	var out []Variant
	for _, v := range variants {
		if v.Name == StandardVariant {
			out = append(out, v)
		}
	}
	return out
}

// NarrowVariants scopes variants to a subset of release directories. An empty
// subset leaves them untouched.
func NarrowVariants(variants []Variant, dirs []string) []Variant {
	if len(dirs) == 0 {
		return variants
	}
	out := make([]Variant, 0, len(variants))
	for _, v := range variants {
		v.ReleaseDirs = utils.FilterDirs(dirs, v.ReleaseDirs)
		if len(v.ReleaseDirs) == 0 {
			continue
		}
		out = append(out, v)
	}
	return out
}

type RefRecorder interface {
	Add(refs ...string) error
}

// DigestResolver reports the manifest digest of a tag. exists is false with a
// nil error when the tag is absent; auth and network failures return an error.
type DigestResolver func(image string) (digest string, exists bool, err error)

// Image is what every step needs to name the images a release ships.
type Image struct {
	RepoRoot   string
	Version    string
	Registries []string
	Arches     []string
	Variants   []Variant

	command.Step
}

// settings is what the options write into. Nothing outside the package builds
// one: a caller names the required values as arguments and adjusts the rest
// through options.
type settings struct {
	Image

	// confirm latches the push. Without it the make targets run as a dry run.
	confirm bool

	dir string

	// pull fetches an image that is not already local, which a release that
	// did not build its own images needs.
	pull bool

	retag *retag
	scan  *ScanRequest
	refs  RefRecorder

	// resolve reports a published tag's digest. Defaults to the registry.
	resolve DigestResolver

	// resume is the record an earlier run left, and how to check it.
	resume *resume
}

// A step's options. Option reaches every step; the per-step interfaces let a
// setting reach only the steps that use it, so passing a publish-only option to
// a build does not compile.
//
// An option validates its own input, so a setting that cannot be honoured is
// reported where it is set rather than being silently ignored.
type (
	BuildOption   interface{ applyBuild(*settings) error }
	ArchiveOption interface{ applyArchive(*settings) error }
	PublishOption interface{ applyPublish(*settings) error }

	Option interface {
		applyBuild(*settings) error
		applyArchive(*settings) error
		applyPublish(*settings) error
	}
)

// Each adapter must satisfy the interfaces its options are returned as, so a
// missing apply method fails here rather than at a call site.
var (
	_ Option        = setting(nil)
	_ ArchiveOption = archiveSetting(nil)
	_ PublishOption = publishSetting(nil)
)

type setting func(*settings) error

func (f setting) applyBuild(s *settings) error   { return f(s) }
func (f setting) applyArchive(s *settings) error { return f(s) }
func (f setting) applyPublish(s *settings) error { return f(s) }

type archiveSetting func(*settings) error

func (f archiveSetting) applyArchive(s *settings) error { return f(s) }

type publishSetting func(*settings) error

func (f publishSetting) applyPublish(s *settings) error { return f(s) }

func WithRunner(r command.CommandRunner) Option {
	return setting(func(s *settings) error {
		s.Apply([]command.Option{command.WithRunner(r)})
		return nil
	})
}

func WithRegistries(registries ...string) Option {
	return setting(func(s *settings) error {
		s.Registries = registries
		return nil
	})
}

// WithArches limits a step to these architectures. An empty list leaves the
// make targets to their own default, which is what a caller that named none
// means.
func WithArches(arches ...string) Option {
	return setting(func(s *settings) error {
		s.Arches = arches
		return nil
	})
}

// WithLogsDir gives each unit its own log file under dir. An empty dir leaves
// the output captured in memory.
func WithLogsDir(dir string) Option {
	return setting(func(s *settings) error {
		s.Apply([]command.Option{command.WithLogsDir(dir)})
		return nil
	})
}

// WithPull sets whether an archive may fetch an image that is not already
// local, which a release that did not build its own images needs.
func WithPull(pull bool) ArchiveOption {
	return archiveSetting(func(s *settings) error {
		s.pull = pull
		return nil
	})
}

// WithRetag publishes by moving the images already at registry/<component>:tag
// rather than pushing a locally built one. skipDev leaves the dev tag in place.
func WithRetag(registry, tag string, skipDev bool) PublishOption {
	return publishSetting(func(s *settings) error {
		if registry == "" || tag == "" {
			return fmt.Errorf("retag needs both a registry and a tag, got %q and %q", registry, tag)
		}
		s.retag = &retag{registry: registry, tag: tag, skipDev: skipDev}
		return nil
	})
}

func WithScan(req *ScanRequest) PublishOption {
	return publishSetting(func(s *settings) error {
		if req == nil {
			return fmt.Errorf("no scan request given")
		}
		s.scan = req
		return nil
	})
}

func WithRecord(rec RefRecorder) PublishOption {
	return publishSetting(func(s *settings) error {
		if rec == nil {
			return fmt.Errorf("no recorder given")
		}
		s.refs = rec
		return nil
	})
}

// WithResume skips the units an earlier run already published, judged against
// the refs it recorded. force republishes a unit whose published digest is not
// one of those refs; without it the difference is an error.
func WithResume(published []string, force bool) PublishOption {
	return publishSetting(func(s *settings) error {
		if len(published) == 0 {
			return fmt.Errorf("no recorded refs to resume from")
		}
		s.resume = &resume{published: published, force: force}
		return nil
	})
}

type retag struct {
	registry string
	tag      string
	skipDev  bool
}

// resume is what an earlier run recorded, and whether to override a mismatch.
type resume struct {
	published []string
	force     bool
}

func (s settings) defaults() settings {
	return s
}

func (c Image) validate() error {
	var errs []error
	if c.RepoRoot == "" {
		errs = append(errs, fmt.Errorf("no repository root specified"))
	}
	if c.Version == "" {
		errs = append(errs, fmt.Errorf("no version specified"))
	}
	if len(c.Variants) == 0 {
		errs = append(errs, fmt.Errorf("no image variants specified"))
	}
	for _, v := range c.Variants {
		if v.Name == "" {
			errs = append(errs, fmt.Errorf("variant with no name"))
		}
		if v.Target == "" {
			errs = append(errs, fmt.Errorf("variant %q has no make target", v.Name))
		}
		if len(v.ReleaseDirs) == 0 {
			errs = append(errs, fmt.Errorf("variant %q has no release directories", v.Name))
		}
	}
	if errs != nil {
		return fmt.Errorf("validate: %w", errors.Join(errs...))
	}
	return nil
}

func (c Image) env() []string {
	env := append(os.Environ(),
		utils.Env(utils.EnvVersion, c.Version),
		utils.Env(utils.EnvImageTag, c.Version),
	)
	if len(c.Registries) > 0 {
		env = append(env, utils.Env(utils.EnvDevRegistries, strings.Join(c.Registries, " ")))
	}
	if len(c.Arches) > 0 {
		env = append(env, utils.Env(utils.EnvArches, strings.Join(c.Arches, " ")))
	}
	return env
}

func (s settings) runUnits(units []unit) error {
	_, err := forEachUnit(units, s.runUnitOnly)
	return err
}

// runUnitOnly adapts runUnit to forEachUnit, which wants a result per unit.
func (s settings) runUnitOnly(u unit) (unitDone, error) {
	return unitDone{}, s.runUnit(u)
}

// forEachUnit runs fn over every unit at once: each shells out to make or
// reaches a registry, so the work is I/O the machine can overlap. Results keep
// the units' order. Every error is collected rather than only the first, which
// is why this is not errgroup: one component failing must not hide the rest.

// unitDone is the result of a unit that produces nothing to collect.
type unitDone struct{}

func forEachUnit[T any](units []unit, fn func(unit) (T, error)) ([]T, error) {
	var (
		wg   sync.WaitGroup
		out  = make([]T, len(units))
		errs = make([]error, len(units))
	)
	for i, u := range units {
		wg.Go(func() { out[i], errs[i] = fn(u) })
	}
	wg.Wait()
	return out, errors.Join(errs...)
}

func (s settings) runUnit(u unit) error {
	log := s.Logger().WithFields(logrus.Fields{"variant": u.variant, "component": u.dir, "target": u.target})
	dir := filepath.Join(s.RepoRoot, u.dir)

	args := append([]string{"-C", dir}, strings.Fields(u.target)...)
	for attempt := 0; ; attempt++ {
		out, err := s.Run("make", args, u.env, s.logPath(u))
		if err == nil {
			log.Debug(out)
			return nil
		}
		if attempt < command.MaxRetries {
			log.WithError(err).WithField("attempt", attempt).Warn("Image step failed, retrying")
			continue
		}
		// Surface the captured output; the failure cause is usually only in there.
		log.Error(out)
		return s.Errorf("%s images in %s: %w", u.variant, u.dir, err)
	}
}

// logPath namespaces the logs under the image step, with the variant in the
// file name so a component shipping several image kinds keeps a log per kind.
func (s settings) logPath(u unit) string {
	slug := strings.ReplaceAll(filepath.Clean(u.dir), string(filepath.Separator), "-")
	if u.variant != StandardVariant {
		slug += "-" + u.variant
	}
	return s.LogPath(slug)
}

// unit is one make invocation: a variant's target in one component directory.
type unit struct {
	variant string
	dir     string
	target  string
	env     []string
}

// A directory shipping more than one kind of image appears once per variant.
func (c Image) units(baseEnv []string) []unit {
	var out []unit
	for _, v := range c.Variants {
		for _, dir := range v.ReleaseDirs {
			env := make([]string, 0, len(baseEnv)+len(v.Env))
			env = append(env, baseEnv...)
			env = append(env, v.Env...)
			out = append(out, unit{variant: v.Name, dir: dir, target: v.Target, env: env})
		}
	}
	return out
}

// windowsImageSuffix separates the Windows images from the rest: build-images
// reports every image a directory ships, whatever the variant.
const windowsImageSuffix = "-windows"

func (c Image) imageNames(u unit) ([]string, error) {
	dir := filepath.Join(c.RepoRoot, u.dir)
	// RELEASE selects the released image names, set here so they cannot
	// depend on the caller's environment.
	env := append(slices.Clone(u.env), utils.EnvTrue(utils.EnvRelease))
	out, err := c.Runner().RunInDir("", "make", []string{"-C", dir, "-s", "build-images"}, env)
	if err != nil {
		return nil, fmt.Errorf("reading images in %s: %w", u.dir, err)
	}

	wantWindows := u.variant == windowsVariant
	var names []string
	for name := range strings.FieldsSeq(out) {
		if strings.HasSuffix(name, windowsImageSuffix) == wantWindows {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no %s images found in %s", u.variant, u.dir)
	}
	return names, nil
}

// tagPrefix returns the prefix a unit's published tags carry. The component
// Makefile derives it from the variant's own environment, so it is read rather
// than declared here.
func (c Image) tagPrefix(u unit) (string, error) {
	dir := filepath.Join(c.RepoRoot, u.dir)
	out, err := c.Runner().RunInDir("", "make", []string{"-C", dir, "-s", "image-tag-prefix"}, u.env)
	if err != nil {
		return "", fmt.Errorf("reading tag prefix in %s: %w", u.dir, err)
	}
	return strings.TrimSpace(out), nil
}

// unitState reads the record rather than the registry: the record already names
// what landed, and a local read costs nothing. done is true when every ref the
// unit publishes is recorded at the digest the registry currently serves.
func unitState(s settings, u unit, recorded recordedDigests) (done bool, err error) {
	if s.resume == nil {
		return false, nil
	}
	names, err := s.imageNames(u)
	if err != nil {
		return false, err
	}
	tags, err := s.unitTags(u)
	if err != nil {
		return false, err
	}

	for _, reg := range s.Registries {
		for _, name := range names {
			repo := fmt.Sprintf("%s/%s", reg, name)
			digests, ok := recorded[repo]
			if !ok {
				return false, nil
			}
			for _, tag := range tags {
				image := fmt.Sprintf("%s:%s", repo, tag)
				got, exists, err := s.resolve(image)
				if err != nil {
					return false, fmt.Errorf("resolving %s: %w", image, err)
				}
				if !exists {
					return false, nil
				}
				if _, known := digests[got]; !known {
					if !s.resume.force {
						return false, fmt.Errorf(
							"%s is published at %s; this release recorded %s. "+
								"Pass --force to republish over it",
							image, got, strings.Join(slices.Sorted(maps.Keys(digests)), ", "))
					}
					return false, nil
				}
			}
		}
	}
	return true, nil
}

type recordedDigests map[string]map[string]struct{}

// A repo publishes several tags, each at its own digest, so it maps to a SET of
// digests: a tag counts as published when its digest is in that set.
func digestsByRepo(refs []string) recordedDigests {
	out := make(recordedDigests, len(refs))
	for _, ref := range refs {
		repo, digest, ok := strings.Cut(ref, "@")
		if !ok {
			continue
		}
		if out[repo] == nil {
			out[repo] = map[string]struct{}{}
		}
		out[repo][digest] = struct{}{}
	}
	return out
}

func (c Image) publishedRefs(u unit, resolve DigestResolver) ([]string, error) {
	names, err := c.imageNames(u)
	if err != nil {
		return nil, err
	}
	tags, err := c.unitTags(u)
	if err != nil {
		return nil, err
	}

	var refs []string
	for _, reg := range c.Registries {
		for _, name := range names {
			for _, tag := range tags {
				image := fmt.Sprintf("%s/%s:%s", reg, name, tag)
				digest, exists, err := resolve(image)
				if err != nil {
					return nil, fmt.Errorf("resolving %s: %w", image, err)
				}
				if !exists {
					// The manifest and architecture tags are separately
					// skippable, so an absent tag is not an error.
					logrus.WithField("image", image).Debug("Published tag absent, not recording")
					continue
				}
				refs = append(refs, fmt.Sprintf("%s/%s@%s", reg, name, digest))
			}
		}
	}
	return refs, nil
}

// unitTags returns the tags a unit publishes. The Windows variant copies only
// its manifest list to the release tag, so it has no per-architecture tags.
func (c Image) unitTags(u unit) ([]string, error) {
	prefix, err := c.tagPrefix(u)
	if err != nil {
		return nil, err
	}
	if prefix != "" {
		prefix += "-"
	}
	if u.variant == windowsVariant {
		return []string{prefix + c.Version}, nil
	}
	tags := []string{prefix + c.Version}
	for _, arch := range c.Arches {
		tags = append(tags, fmt.Sprintf("%s%s-%s", prefix, c.Version, arch))
	}
	return tags, nil
}

// A dry run records nothing, so there is no recorder to write to.
func record(s settings, units []unit) error {
	if s.refs == nil {
		return nil
	}
	refs, lookupErr := forEachUnit(units, s.refsFor)
	// Written even when a lookup failed: a partial publish is exactly the run
	// whose record decides what a resume still owes. Writing after the lookups
	// keeps the record in the units' order.
	errs := []error{lookupErr}
	for _, got := range refs {
		if err := s.refs.Add(got...); err != nil {
			errs = append(errs, fmt.Errorf("recording published images: %w", err))
			break
		}
	}
	return errors.Join(errs...)
}

// refsFor names the unit in any failure: the lookups run together, so the error
// has to say which one it came from.
func (s settings) refsFor(u unit) ([]string, error) {
	refs, err := s.publishedRefs(u, s.resolve)
	if err != nil {
		return nil, fmt.Errorf("recording published images for %s: %w", u.dir, err)
	}
	return refs, nil
}

// save fetches the image first when it is not already local.
func save(s settings, image, out string) error {
	if s.pull {
		if _, err := s.Runner().Run("docker", []string{"image", "inspect", image}, nil); err != nil {
			s.Logger().WithField("image", image).Info("Image not found locally, pulling")
			if _, err := s.Runner().Run("docker", []string{"pull", image}, nil); err != nil {
				return fmt.Errorf("pulling %s: %w", image, err)
			}
		}
	}
	if _, err := s.Runner().Run("docker", []string{"save", "--output", out, image}, nil); err != nil {
		return s.Errorf("%w", err)
	}
	return nil
}
