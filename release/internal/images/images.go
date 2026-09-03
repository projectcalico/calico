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

// maxRetries is how many times a unit is retried. Image pushes fail on network
// flakes often enough that one retry saves a whole release run.
const maxRetries = 1

// Steps that drive images. The name becomes the log directory and the verb in
// a failure, so a new step adds one here rather than passing a literal.
const (
	buildStep   = "build"
	publishStep = "publish"
	archiveStep = "archive"
)

const (
	// StandardVariant is the product's main image, the one every component ships.
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

// ScanRequest is one submission to the image scanning service.
type ScanRequest struct {
	imagescanner.Config

	ProductCode string

	// Images are supplied, not derived: image identity has two sources here,
	// the component Makefiles and the pinned-versions file, and only the caller
	// knows which applies.
	Images []string

	Stream string

	// Release distinguishes a release scan from a hashrelease one.
	Release bool

	OutputDir string
}

// VariantDirs lists every release directory the variants cover, in order and
// without duplicates.
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

// StandardVariants keeps only the variant every component ships, dropping the
// Windows and any other kind.
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

// RefRecorder records the digest refs a publish put in a registry.
type RefRecorder interface {
	Add(refs ...string) error
}

// DigestResolver reports the manifest digest of a tag. exists is false with a
// nil error when the tag is absent; auth and network failures return an error.
type DigestResolver func(image string) (digest string, exists bool, err error)

// Image is what every step needs to name the images a release ships. The steps
// embed it and add only the settings their own verb uses, so a setting that
// belongs to one verb cannot be passed to another.
type Image struct {
	RepoRoot   string
	Version    string
	Registries []string
	Arches     []string
	Variants   []Variant

	// runner is unexported so it can only be set through WithRunner, which
	// keeps the zero-value config pointed at real commands.
	runner command.CommandRunner
}

// BuildOptions builds the images locally. It reaches no registry, so it carries
// none of the publish settings.
// settings is what the options write into. Nothing outside the package builds
// one: a caller names the required values as arguments and adjusts the rest
// through options.
type settings struct {
	Image

	step string

	// confirm latches the push. Without it the make targets run as a dry run.
	confirm bool

	// logsDir, when set, gives each unit its own log file. Concurrent units
	// otherwise interleave their output into one unreadable stream.
	logsDir string

	// dir is where an archive writes its tar files.
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

// setting is a change every step accepts.
type setting func(*settings) error

func (f setting) applyBuild(s *settings) error   { return f(s) }
func (f setting) applyArchive(s *settings) error { return f(s) }
func (f setting) applyPublish(s *settings) error { return f(s) }

// archiveSetting is a change only an archive accepts.
type archiveSetting func(*settings) error

func (f archiveSetting) applyArchive(s *settings) error { return f(s) }

// publishSetting is a change only a publish accepts.
type publishSetting func(*settings) error

func (f publishSetting) applyPublish(s *settings) error { return f(s) }

// WithRunner substitutes the runner the make targets are driven through.
func WithRunner(r command.CommandRunner) Option {
	return setting(func(s *settings) error {
		s.runner = r
		return nil
	})
}

// WithRegistries names the registries a step reads from or writes to.
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
		s.logsDir = dir
		return nil
	})
}

// WithPull lets an archive fetch an image that is not already local, which a
// release that did not build its own images needs.
func WithPull() ArchiveOption {
	return archiveSetting(func(s *settings) error {
		s.pull = true
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

// WithScan submits the published images to the scanning service.
func WithScan(req *ScanRequest) PublishOption {
	return publishSetting(func(s *settings) error {
		if req == nil {
			return fmt.Errorf("no scan request given")
		}
		s.scan = req
		return nil
	})
}

// WithRecord records the digest refs a publish produces.
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

// retag is the source a publish moves images from.
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

// defaults fills in anything the options left unset.
func (s settings) defaults() settings {
	if s.runner == nil {
		s.runner = &command.RealCommandRunner{}
	}
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

// env returns the environment every variant's target receives.
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

// runUnits runs every unit concurrently, collecting failures rather than
// stopping at the first: one component failing should not hide the rest.
func (s settings) runUnits(units []unit) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error

	for _, u := range units {
		wg.Add(1)
		go func(u unit) {
			defer wg.Done()
			if err := s.runUnit(u); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}(u)
	}
	wg.Wait()
	return errors.Join(errs...)
}

// runUnit runs one unit's make target, retrying on failure.
func (s settings) runUnit(u unit) error {
	log := s.logger().WithFields(logrus.Fields{"variant": u.variant, "component": u.dir, "target": u.target})
	dir := filepath.Join(s.RepoRoot, u.dir)

	args := append([]string{"-C", dir}, strings.Fields(u.target)...)
	for attempt := 0; ; attempt++ {
		out, err := s.run(args, u.env, s.logPath(u))
		if err == nil {
			log.Debug(out)
			return nil
		}
		if attempt < maxRetries {
			log.WithError(err).WithField("attempt", attempt).Warn("Image step failed, retrying")
			continue
		}
		// Surface the captured output; the failure cause is usually only in there.
		log.Error(out)
		return s.errorf("%s images in %s: %w", u.variant, u.dir, err)
	}
}

// run sends output to logPath when there is one, else captures it in memory.
func (c Image) run(args, env []string, logPath string) (string, error) {
	if logPath == "" {
		return c.runner.RunInDir("", "make", args, env)
	}
	return c.runner.RunInDirToFile("", "make", args, env, logPath)
}

// logPath namespaces the logs under the image step, with the variant in the
// file name so a component shipping several image kinds keeps a log per kind.
func (s settings) logPath(u unit) string {
	if s.logsDir == "" {
		return ""
	}
	slug := strings.ReplaceAll(filepath.Clean(u.dir), string(filepath.Separator), "-")
	if u.variant != StandardVariant {
		slug += "-" + u.variant
	}
	return filepath.Join(s.logsDir, "images-"+s.step, slug+".log")
}

// unit is one make invocation: a variant's target in one component directory.
type unit struct {
	variant string
	dir     string
	target  string
	env     []string
}

// units expands the variants into work. A directory shipping more than one kind
// of image appears once per variant.
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

// imageNames returns the image names a unit publishes.
func (c Image) imageNames(u unit) ([]string, error) {
	dir := filepath.Join(c.RepoRoot, u.dir)
	// RELEASE selects the released image names, set here so they cannot
	// depend on the caller's environment.
	env := append(slices.Clone(u.env), utils.EnvTrue(utils.EnvRelease))
	out, err := c.runner.RunInDir("", "make", []string{"-C", dir, "-s", "build-images"}, env)
	if err != nil {
		return nil, fmt.Errorf("reading images in %s: %w", u.dir, err)
	}

	wantWindows := u.variant == windowsVariant
	var names []string
	for _, name := range strings.Fields(out) {
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
	out, err := c.runner.RunInDir("", "make", []string{"-C", dir, "-s", "image-tag-prefix"}, u.env)
	if err != nil {
		return "", fmt.Errorf("reading tag prefix in %s: %w", u.dir, err)
	}
	return strings.TrimSpace(out), nil
}

// unitState reports whether a unit still needs publishing, judged against the
// refs an earlier run recorded. It reads the record rather than the registry:
// the record already names what landed, and a local read costs nothing.
//
// done is true when every ref the unit publishes is already recorded at the
// digest the registry currently serves.
// unitState reports whether a unit still needs publishing, judged against the
// refs an earlier run recorded. It reads the record rather than the registry:
// the record already names what landed, and a local read costs nothing.
func unitState(s settings, u unit) (done bool, err error) {
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

	// A repo publishes several tags, each at its own digest, and the record
	// keeps refs rather than tags. So a repo maps to the SET of digests it
	// recorded, and a tag counts as published when its digest is in that set.
	recorded := make(map[string]map[string]struct{}, len(s.resume.published))
	for _, ref := range s.resume.published {
		repo, digest, ok := strings.Cut(ref, "@")
		if !ok {
			continue
		}
		if recorded[repo] == nil {
			recorded[repo] = map[string]struct{}{}
		}
		recorded[repo][digest] = struct{}{}
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

// publishedRefs returns the digest refs a unit put in the registries.
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

// record writes the digest refs the publish produced. A dry run records
// nothing, so there is no recorder to write to.
func record(s settings, units []unit) error {
	if s.refs == nil {
		return nil
	}
	for _, u := range units {
		refs, err := s.publishedRefs(u, s.resolve)
		if err != nil {
			return fmt.Errorf("recording published images for %s: %w", u.dir, err)
		}
		if err := s.refs.Add(refs...); err != nil {
			return fmt.Errorf("recording published images for %s: %w", u.dir, err)
		}
	}
	return nil
}

// save writes one image to a tar file, fetching it first when it is not local.
func save(s settings, image, out string) error {
	if s.pull {
		if _, err := s.runner.Run("docker", []string{"image", "inspect", image}, nil); err != nil {
			s.logger().WithField("image", image).Info("Image not found locally, pulling")
			if _, err := s.runner.Run("docker", []string{"pull", image}, nil); err != nil {
				return fmt.Errorf("pulling %s: %w", image, err)
			}
		}
	}
	if _, err := s.runner.Run("docker", []string{"save", "--output", out, image}, nil); err != nil {
		return fmt.Errorf("%s: %w", s.step, err)
	}
	return nil
}

func (s settings) logger() *logrus.Entry {
	return logrus.WithField("step", s.step)
}
