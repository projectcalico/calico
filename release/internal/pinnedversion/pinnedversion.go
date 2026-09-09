// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/operator"
)

const pinnedVersionFileName = "pinned_versions.yml"

const (
	apiComponentName              = "api"
	calicoComponentName           = "calico"
	flannelComponentName          = "flannel"
	networkingCalicoComponentName = "networking-calico"
)

var FlannelComponent = registry.Component{
	Registry: "quay.io",
	Image:    "coreos/flannel",
	Version:  "v0.12.0",
}

// noImageComponents are pinned components that do not produce an image.
var noImageComponents = []string{
	apiComponentName,
	calicoComponentName,
	networkingCalicoComponentName,
}

// PinnedVersion is an entry in the pinned version file.
type PinnedVersion struct {
	Title          string                        `yaml:"title"`
	HelmRelease    string                        `yaml:"helmRelease,omitempty"`
	ManifestURL    string                        `yaml:"manifest_url,omitempty"`
	ReleaseName    string                        `yaml:"release_name,omitempty"`
	Note           string                        `yaml:"note,omitempty"`
	Branch         string                        `yaml:"branch,omitempty"`
	Hash           string                        `yaml:"full_hash,omitempty"`
	TigeraOperator registry.Component            `yaml:"tigera-operator"`
	Components     map[string]registry.Component `yaml:"components"`
}

// pin converts a file entry to the in-memory pin.
func (p *PinnedVersion) pin() *Pin {
	branch := p.Branch
	if branch == "" {
		branch = branchFromNote(p.Note)
	}
	return &Pin{
		ReleaseName:    p.ReleaseName,
		Hash:           p.Hash,
		Note:           p.Note,
		ProductVersion: p.Title,
		ChartVersion:   p.HelmRelease,
		Operator:       p.TigeraOperator,
		Components:     p.Components,
		branch:         branch,
	}
}

// noteBranchRe recovers the branch from a note written before the branch had a
// field of its own.
var noteBranchRe = regexp.MustCompile(`using (\S+) release branch`)

// branchFromNote is the fallback for a pin file with no branch field. The
// branch decides the publish stream, so losing it sends a release to the wrong
// one.
func branchFromNote(note string) string {
	m := noteBranchRe.FindStringSubmatch(note)
	if m == nil {
		return ""
	}
	return m[1]
}

// pinnedFrom projects a pin onto its file entry.
func pinnedFrom(p *Pin) PinnedVersion {
	return PinnedVersion{
		Title:       p.ProductVersion,
		HelmRelease: p.ChartVersion,
		Branch:      p.branch,
		ManifestURL: hashreleaseserver.HashreleaseURL(p.ReleaseName),
		ReleaseName: p.ReleaseName,
		Note:        p.Note,
		Hash:        p.Hash,
		TigeraOperator: registry.Component{
			Image:    p.Operator.Image,
			Registry: p.Operator.Registry,
			Version:  p.Operator.Version,
		},
		Components: p.Components,
	}
}

// operatorComponent is the operator this build ships.
var operatorComponent = func(cfg Config, productVer string) registry.Component {
	return registry.Component{
		Image:    cmp.Or(cfg.Operator.Image, operator.DefaultImage),
		Registry: cmp.Or(cfg.Operator.Registry, operator.DefaultRegistries[0]),
		Version:  productVer,
	}
}

// componentImage maps a component name to its image name.
var componentImage = func(component string) string { return component }

// releaseImages lists the images this product releases. Each product supplies
// it, because their utils differ on whether the lookup can fail.
var releaseImages = func() ([]string, error) {
	return utils.ReleaseImages()
}

// productComponents contributes the product's own pinned components. A build
// with more of them replaces this.
var productComponents = func(cfg Config, productVer string) (map[string]registry.Component, error) {
	// Only a generated pin derives a branch; a reused one never gets here.
	if cfg.ReleaseBranchPrefix == "" {
		return nil, fmt.Errorf("release branch prefix is required to generate a pin")
	}
	components := map[string]registry.Component{
		apiComponentName:              {Version: productVer},
		calicoComponentName:           {Version: productVer},
		networkingCalicoComponentName: {Version: releaseBranch(cfg.ReleaseBranchPrefix, productVer)},
		flannelComponentName:          FlannelComponent,
	}
	imgs, err := releaseImages()
	if err != nil {
		return nil, fmt.Errorf("release images: %w", err)
	}
	for _, img := range imgs {
		components[img] = registry.Component{Version: productVer}
	}
	return components, nil
}

// releaseBranch returns the release branch for a product version.
var releaseBranch = func(prefix, productVer string) string {
	v := version.New(productVer)
	return fmt.Sprintf("%s-%s", prefix, v.Stream())
}

// productVersion returns the git-describe version of the product repository.
var productVersion = func(rootDir string) (string, error) {
	v, err := command.GitVersion(rootDir, true)
	if err != nil {
		return "", fmt.Errorf("git version: %w", err)
	}
	return v, nil
}

// repoComponents returns the components for the extra repos, and their versions for the hash.
var repoComponents = func(repos []Repo) (map[string]registry.Component, error) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	c := make(map[string]registry.Component, len(repos))
	for _, r := range repos {
		wg.Add(1)
		go func(r Repo) {
			defer wg.Done()
			if err := r.Validate(); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("%s validate: %w", r.Component, err))
				mu.Unlock()
				return
			}
			v, err := r.GitVersion()
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("%s git version: %w", r.Component, err))
				mu.Unlock()
				return
			}
			mu.Lock()
			c[r.Component] = registry.Component{Version: v}
			mu.Unlock()
		}(r)
	}
	wg.Wait()
	if len(errs) > 0 {
		return c, fmt.Errorf("repo components: %w", errors.Join(errs...))
	}
	return c, nil
}

// hash identifies the build using product version and the versions of the extra repos.
var hash = func(productVer string, repoComponents map[string]registry.Component) string {
	names := slices.Collect(maps.Keys(repoComponents))
	slices.Sort(names)

	h := productVer
	for _, name := range names {
		h = fmt.Sprintf("%s-%s", h, repoComponents[name].Version)
	}
	return h
}

var releaseName = func(branch, productVer string) string {
	name := fmt.Sprintf("%s-%s-%s",
		time.Now().Format("2006-01-02"),
		version.DeterminePublishStream(branch, productVer),
		RandomWord())
	return strings.ReplaceAll(name, ".", "-")
}

var hashreleaseNote = func(releaseName, branch string, repos []Repo) string {
	n := fmt.Sprintf("%s - generated at %s using %s release branch",
		releaseName, time.Now().Format(time.RFC1123), branch)
	for _, r := range repos {
		if r.Branch != "" {
			n = fmt.Sprintf("%s and %s %s branch", n, r.Component, r.Branch)
		}
	}
	return n
}
