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

package pinnedversion

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sirupsen/logrus"
	"go.yaml.in/yaml/v3"

	"github.com/projectcalico/calico/release/internal/charts"
	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
)

// Repo is a repo outside this one, pinned alongside the product.
type Repo struct {
	// Component is the pinned component name.
	Component string

	// Dir is the repository root.
	Dir string

	// Branch is recorded in the pin's note.
	Branch string
}

func (r Repo) Validate() error {
	var errs error
	if r.Component == "" {
		errs = errors.Join(errs, fmt.Errorf("component is required"))
	}
	if r.Dir == "" {
		errs = errors.Join(errs, fmt.Errorf("dir is required"))
	}
	if r.Branch == "" {
		errs = errors.Join(errs, fmt.Errorf("branch is required"))
	}
	if errs != nil {
		return fmt.Errorf("repo validation: %w", errs)
	}
	return nil
}

func (r Repo) GitVersion() (string, error) {
	return command.GitVersion(r.Dir, true)
}

// Config is the input to loading a pin.
type Config struct {
	RootDir string

	Dir string

	// HashreleaseDir is the base dir for hashreleases where pins can be written to <HashreleaseDir>/<hash>/.
	HashreleaseDir string

	// ReleaseBranchPrefix prefixes the release branch, e.g. "release".
	ReleaseBranchPrefix string

	// ProductRegistry is the regiostry for the product images.
	Registry string

	// Operator overrides the operator's image and registry.
	Operator registry.Component

	// Repos are repositories outside this one to pin alongside the product.
	Repos []Repo

	// ChartVersion qualifies the chart version when the charts rev separately
	// from the product. Empty means they share the product version.
	ChartVersion string
}

func (c Config) Valid() error {
	var errs error
	if c.RootDir == "" {
		errs = errors.Join(errs, fmt.Errorf("root dir is required"))
	}
	if c.Dir == "" {
		errs = errors.Join(errs, fmt.Errorf("dir is required"))
	}
	for i, r := range c.Repos {
		if err := r.Validate(); err != nil {
			errs = errors.Join(errs, fmt.Errorf("repo %d: %w", i, err))
		}
	}
	return errs
}

// Pin is the resolved entry for a hashrelease.
type Pin struct {
	// ReleaseName is the name of the hashrelease.
	ReleaseName string

	// Hash is the full hash of the hashrelease.
	// It is the hash of the product version and all versions of its Repos.
	Hash string

	// Note is the info about the hashrelease.
	Note string

	// ProductVersion is the product version in the hashrelease.
	ProductVersion string

	// ProductRegistry is the registry for the product images in the hashrelease.
	ProductRegistry string

	// ChartVersion qualifies the chart version when the charts rev with the product version.
	ChartVersion string

	// Operator is the operator for the hashrelease.
	Operator registry.Component

	// Components are the pinned components in the hashrelease.
	Components map[string]registry.Component

	// branch is the product branch the pin was generated from.
	branch string
}

// ComponentVersion returns a pinned component's version, empty if absent.
func (p *Pin) ComponentVersion(component string) string {
	return p.Components[component].Version
}

// HelmChartVersion returns the chart version: the product version, suffixed
// with ChartVersion when the charts rev separately from the product.
func (p *Pin) HelmChartVersion() string {
	return charts.Version(p.ProductVersion, p.ChartVersion)
}

// ReleaseBranch returns the release branch for the pinned product version.
func (p *Pin) ReleaseBranch(releaseBranchPrefix string) string {
	return releaseBranch(releaseBranchPrefix, p.ProductVersion)
}

// Images returns the pinned components that produce images, keyed by
// component name. The image name defaults to the component name.
func (p *Pin) Images() map[string]registry.Component {
	components := make(map[string]registry.Component)
	for name, c := range p.Components {
		if slices.Contains(noImageComponents, name) {
			continue
		}
		// A component that names its own image keeps it, e.g. coreos/flannel.
		if c.Image == "" {
			c.Image = componentImage(name)
		}
		components[name] = c
	}
	if p.Operator.Image != "" {
		components[p.Operator.Image] = p.Operator
	}
	return components
}

// ImageNames returns the image name of every component that produces one.
func (p *Pin) ImageNames() []string {
	imgs := p.Images()
	names := make([]string, 0, len(imgs))
	for _, c := range imgs {
		names = append(names, c.Image)
	}
	slices.Sort(names) // for deterministic output
	return names
}

// Hashrelease describes the pin as a hashrelease.
func (p *Pin) Hashrelease(srcBaseDir string, latest bool) *hashreleaseserver.Hashrelease {
	source := srcBaseDir
	if source != "" {
		source = filepath.Join(srcBaseDir, p.Hash)
	}
	return &hashreleaseserver.Hashrelease{
		Name:           p.ReleaseName,
		Hash:           p.Hash,
		Note:           p.Note,
		Stream:         version.DeterminePublishStream(p.branch, p.ProductVersion),
		ProductVersion: p.ProductVersion,
		ChartVersion:   p.ChartVersion,
		Operator:       p.Operator,
		Components:     maps.Clone(p.Components),
		Source:         source,
		Latest:         latest,
	}
}

// SetBranch records the product branch, which decides the publish stream.
func (p *Pin) SetBranch(branch string) {
	p.branch = branch
}

// FilePath returns the path of the pinned version file.
func FilePath(dir string) string {
	return filepath.Join(dir, pinnedVersionFileName)
}

// Reuseable decides whether a pin on disk belongs to this build.
type Reuseable interface {
	Reuse(p *Pin) bool
}

func reusable(r Reuseable, dirs ...string) (*Pin, error) {
	var found string
	for _, dir := range dirs {
		if _, err := os.Stat(FilePath(dir)); err == nil {
			found = dir
			break
		}
	}
	if found == "" {
		return nil, nil
	}
	p, err := read(found)
	if err != nil {
		// a missing or unreadable file just means there is nothing to reuse.
		return nil, nil
	}
	if r.Reuse(p) {
		logrus.WithField("dir", found).Info("Reusing the pinned version file")
		return p, nil
	}
	return nil, nil
}

// Load returns the pin for this build.
func Load(loader Loader) (*Pin, error) {
	if err := loader.Valid(); err != nil {
		return nil, err
	}
	return loader.Load()
}

// Loader supplies the pin. Implementations differ in where it comes from.
type Loader interface {
	Load() (*Pin, error)
	Valid() error
}

// FileLoader loads the pin from a pinned version file.
type FileLoader struct {
	Dir string

	// RootDir is set when the pin needs its branch resolved.
	RootDir string
}

func (l FileLoader) Valid() error {
	if l.Dir == "" {
		return fmt.Errorf("no dir provided to load pinned version file")
	}
	if l.RootDir == "" {
		logrus.Warn("no root dir provided to determine branch")
	}
	return nil
}

func (l FileLoader) Load() (*Pin, error) {
	p, err := read(l.Dir)
	if err != nil {
		return nil, err
	}
	if p.branch == "" && l.RootDir != "" {
		if err := setBranch(p, l.RootDir); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// setBranch resolves the branch a file-read pin lacks; it decides the publish stream.
var setBranch = func(p *Pin, repoDir string) error {
	branch, err := utils.GitBranch(repoDir)
	if err != nil {
		return fmt.Errorf("git branch: %w", err)
	}
	p.SetBranch(branch)
	return nil
}

// LocalLoader generates a pin from the product and any extra repos.
type LocalLoader struct {
	Config Config
}

func (l LocalLoader) Valid() error {
	return l.Config.Valid()
}

func (l LocalLoader) Load() (*Pin, error) {
	if p, err := reusable(l, l.Config.Dir); err != nil {
		return nil, err
	} else if p != nil {
		if err := setBranch(p, l.Config.RootDir); err != nil {
			return nil, err
		}
		return p, nil
	}
	pin, err := l.source()
	if err != nil {
		return nil, fmt.Errorf("source pin: %w", err)
	}
	dirs := []string{l.Config.Dir}
	if l.Config.HashreleaseDir != "" {
		dirs = append(dirs, filepath.Join(l.Config.HashreleaseDir, pin.Hash))
	}
	if err := writePin(l.Config, pin, dirs...); err != nil {
		return nil, fmt.Errorf("write pinned version file: %w", err)
	}
	return pin, nil
}

func (l LocalLoader) Reuse(p *Pin) bool {
	return localCheck(l, p)
}

// localCheck is the reuse rule for LocalLoader.
var localCheck = func(l LocalLoader, p *Pin) bool {
	productVer, err := productVersion(l.Config.RootDir)
	if err != nil {
		return false
	}
	if strings.HasSuffix(productVer, "-dirty") {
		return false
	}
	return p.ProductVersion == productVer
}

// source pins the versions of this repository and any extra repos.
func (l LocalLoader) source() (*Pin, error) {
	branch, err := utils.GitBranch(l.Config.RootDir)
	if err != nil {
		return nil, fmt.Errorf("git branch: %w", err)
	}
	productVer, err := productVersion(l.Config.RootDir)
	if err != nil {
		return nil, err
	}
	components, err := productComponents(l.Config, productVer)
	if err != nil {
		return nil, err
	}
	repos, err := repoComponents(l.Config.Repos)
	if err != nil {
		return nil, err
	}
	maps.Copy(components, repos)

	name := releaseName(branch, productVer)
	return &Pin{
		ReleaseName:     name,
		Hash:            hash(productVer, repos),
		Note:            hashreleaseNote(name, branch, l.Config.Repos),
		ProductVersion:  productVer,
		ChartVersion:    l.Config.ChartVersion,
		ProductRegistry: cmp.Or(l.Config.Registry, registry.DefaultProductRegistry),
		Operator:        operatorComponent(l.Config, productVer),
		Components:      components,
		branch:          branch,
	}, nil
}

// read loads a pin from the pinned version file.
func read(dir string) (*Pin, error) {
	data, err := os.ReadFile(FilePath(dir))
	if err != nil {
		return nil, err
	}
	var file []PinnedVersion
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	if len(file) == 0 {
		return nil, fmt.Errorf("no entries in %s", FilePath(dir))
	}
	return file[0].pin(), nil
}

// writePin persists a freshly generated pin. A product whose file carries
// fields Pin does not model replaces this.
var writePin = func(_ Config, p *Pin, dirs ...string) error {
	return write(p, dirs...)
}

// write persists the pin as the pinned version file.
func write(p *Pin, dirs ...string) error {
	if len(dirs) == 0 {
		return fmt.Errorf("no dir provided to write pinned version file")
	}
	if err := makeDirs(dirs); err != nil {
		return err
	}
	logrus.WithFields(logrus.Fields{
		"filename": pinnedVersionFileName,
		"dirs":     dirs,
	}).Info("Creating pinned version file")
	var fileErr error
	for _, dir := range dirs {
		if err := writeYAML(dir, []PinnedVersion{pinnedFrom(p)}); err != nil {
			fileErr = errors.Join(fileErr, err)
		}
	}
	if fileErr != nil {
		return fmt.Errorf("write pinned version file: %w", fileErr)
	}
	return nil
}

// makeDirs creates every dir, reporting all that could not be created.
func makeDirs(dirs []string) error {
	var errs error
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, utils.DirPerms); err != nil {
			errs = errors.Join(errs, fmt.Errorf("%s: %w", dir, err))
		}
	}
	if errs != nil {
		return fmt.Errorf("create pinned version dirs: %w", errs)
	}
	return nil
}

// writeYAML encodes v as YAML to path.
func writeYAML(dir string, v any) error {
	path := FilePath(dir)
	f, err := os.Create(path)
	defer func() { _ = f.Close() }()
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}

	enc := yaml.NewEncoder(f)
	enc.SetIndent(2)
	defer func() {
		if err := enc.Close(); err != nil {
			logrus.WithError(err).WithField("file", path).Warn("Failed to close YAML encoder")
		}
	}()
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("write to %s: %w", path, err)
	}
	return nil
}
