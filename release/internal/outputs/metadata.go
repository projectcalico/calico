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

package outputs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sirupsen/logrus"
	"go.yaml.in/yaml/v3"

	"github.com/projectcalico/calico/release/internal/registry"
)

const metadataFileName = "metadata.yaml"

// attest validates the record before marshalling it, so an invalid record is
// never written.
type Record interface {
	describe(Describer) error
	attest() ([]byte, error)
}

func BuildMetadata(r Record, d Describer, dir string) error {
	if r == nil {
		return errors.New("metadata: no release to describe")
	}
	if dir == "" {
		return errors.New("metadata: no directory to write to")
	}
	if err := r.describe(d); err != nil {
		return fmt.Errorf("metadata: %w", err)
	}
	bs, err := r.attest()
	if err != nil {
		return fmt.Errorf("metadata: %w", err)
	}
	path := filepath.Join(dir, metadataFileName)
	if err := os.WriteFile(path, bs, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	logrus.WithField("path", path).Info("Wrote release metadata")
	return nil
}

var _ Record = (*Metadata)(nil)

type Metadata struct {
	Version string `yaml:"version"`

	// Superseded by components.operator.version; kept for older readers.
	OperatorVersion string `yaml:"operatorVersion"`

	Images []string `yaml:"images"`

	// Superseded by charts.version; kept for older readers.
	ChartVersion string `yaml:"helmChartVersion"`

	Source Source `yaml:"source"`

	Charts *Charts `yaml:"charts,omitempty"`

	Artifacts []Artifact `yaml:"artifacts,omitempty"`

	Components map[string]Component `yaml:"components"`

	Released []registry.Component `yaml:"-"`
}

type Component struct {
	Version string `yaml:"version"`
	Image   string `yaml:"image,omitempty"`
	Digest  string `yaml:"digest,omitempty"`
}

// Tag is left out of a build that is not tagged, such as a hashrelease.
type Source struct {
	Repository string `yaml:"repository"`
	Commit     string `yaml:"commit"`
	Branch     string `yaml:"branch,omitempty"`
	Tag        string `yaml:"tag,omitempty"`
}

// Charts mirrors the entries of a helm index, keyed by chart name.
type Charts struct {
	Version string           `yaml:"version"`
	Index   string           `yaml:"index,omitempty"`
	Entries map[string]Chart `yaml:"entries"`
}

type Chart struct {
	Image  string `yaml:"image"`
	Digest string `yaml:"digest,omitempty"`
	URL    string `yaml:"url"`
}

func (r *Metadata) describe(d Describer) error {
	if d.Images.Resolve == nil {
		return errors.New("no image resolver to describe with")
	}
	components, err := d.Images.describe(r.Released)
	if err != nil {
		return err
	}
	r.Components = components
	if r.Artifacts, err = d.Artifacts.describe(); err != nil {
		return err
	}
	if r.Charts == nil {
		return nil
	}
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(r.Charts.Entries)) {
		c := r.Charts.Entries[name]
		if c.Digest, err = d.Images.digest(c.Image); err != nil {
			errs = append(errs, fmt.Errorf("chart %s: %w", name, err))
			continue
		}
		r.Charts.Entries[name] = c
	}
	return errors.Join(errs...)
}

func (r Metadata) attest() ([]byte, error) {
	m, err := r.attested()
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(m)
}

func (r Metadata) attested() (Metadata, error) {
	var errs []error
	if r.Version == "" {
		errs = append(errs, fmt.Errorf("no version specified"))
	}
	if r.OperatorVersion == "" {
		errs = append(errs, fmt.Errorf("no operator version specified"))
	}
	if len(r.Components) == 0 {
		errs = append(errs, fmt.Errorf("no components specified"))
	}
	if r.Source.Repository == "" || r.Source.Commit == "" {
		errs = append(errs, fmt.Errorf("source: no repository or commit specified"))
	}
	if r.Charts != nil {
		if err := r.Charts.validate(); err != nil {
			errs = append(errs, fmt.Errorf("charts: %w", err))
		}
	}
	for _, a := range r.Artifacts {
		if err := a.validate(); err != nil {
			errs = append(errs, fmt.Errorf("artifact %s: %w", a.Name, err))
		}
	}
	r.Images = nil
	for _, key := range slices.Sorted(maps.Keys(r.Components)) {
		c := r.Components[key]
		if err := c.validate(); err != nil {
			errs = append(errs, fmt.Errorf("component %s: %w", key, err))
		}
		if c.Image != "" {
			r.Images = append(r.Images, c.Image)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return Metadata{}, err
	}
	return r, nil
}

func (c Component) validate() error {
	if c.Version == "" {
		return fmt.Errorf("no version specified")
	}
	if c.Image == "" {
		if c.Digest != "" {
			return fmt.Errorf("digest %s without an image", c.Digest)
		}
		return nil
	}
	if _, err := name.NewTag(c.Image, name.StrictValidation); err != nil {
		return fmt.Errorf("image %q: %w", c.Image, err)
	}
	return nil
}

func (c Charts) validate() error {
	var errs []error
	if c.Version == "" {
		errs = append(errs, fmt.Errorf("no version specified"))
	}
	if len(c.Entries) == 0 {
		errs = append(errs, fmt.Errorf("no charts specified"))
	}
	for _, key := range slices.Sorted(maps.Keys(c.Entries)) {
		if err := c.Entries[key].validate(); err != nil {
			errs = append(errs, fmt.Errorf("chart %s: %w", key, err))
		}
	}
	return errors.Join(errs...)
}

func (c Chart) validate() error {
	var errs []error
	if _, err := name.NewTag(c.Image, name.StrictValidation); err != nil {
		errs = append(errs, fmt.Errorf("image %q: %w", c.Image, err))
	}
	if u, err := url.Parse(c.URL); err != nil || !u.IsAbs() {
		errs = append(errs, fmt.Errorf("url %q is not absolute", c.URL))
	}
	return errors.Join(errs...)
}

type Artifact struct {
	Name   string `yaml:"name"`
	Size   int64  `yaml:"size"`
	SHA256 string `yaml:"sha256"`
	URL    string `yaml:"url"`
}

func (a Artifact) validate() error {
	var errs []error
	if a.SHA256 == "" {
		errs = append(errs, fmt.Errorf("no sha256 specified"))
	}
	if u, err := url.Parse(a.URL); err != nil || !u.IsAbs() {
		errs = append(errs, fmt.Errorf("url %q is not absolute", a.URL))
	}
	return errors.Join(errs...)
}

type Describer struct {
	Images    ImageDescriber
	Artifacts ArtifactDescriber
}

type ImageDescriber struct {
	Sources []registry.DigestSource
	Resolve registry.DigestResolver
}

func (d ImageDescriber) describe(released []registry.Component) (map[string]Component, error) {
	out := make(map[string]Component, len(released))
	var errs []error
	for _, c := range released {
		if _, dup := out[c.Image]; dup {
			errs = append(errs, fmt.Errorf("component %s is listed twice", c.Image))
			continue
		}
		ref := c.String()
		digest, err := d.digest(ref)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out[c.Image] = Component{Version: c.Version, Image: ref, Digest: digest}
	}
	return out, errors.Join(errs...)
}

func (d ImageDescriber) digest(ref string) (string, error) {
	for _, src := range d.Sources {
		if digest, ok := src.Digest(ref); ok {
			return digest, nil
		}
	}
	digest, exists, err := d.Resolve(ref)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", ref, err)
	}
	if !exists {
		logrus.WithField("image", ref).Debug("Not published, leaving its digest out")
	}
	return digest, nil
}

type ArtifactDescriber struct {
	Files []ArtifactFile
}

type ArtifactFile struct {
	Path string
	URL  string
}

// The metadata file is left out because it cannot carry its own hash.
func (d ArtifactDescriber) describe() ([]Artifact, error) {
	var out []Artifact
	for _, file := range d.Files {
		name := filepath.Base(file.Path)
		if name == metadataFileName {
			continue
		}
		f, err := os.Open(file.Path)
		if err != nil {
			return nil, fmt.Errorf("artifact %s: %w", name, err)
		}
		h := sha256.New()
		size, err := io.Copy(h, f)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("hashing artifact %s: %w", name, err)
		}
		out = append(out, Artifact{Name: name, Size: size, SHA256: hex.EncodeToString(h.Sum(nil)), URL: file.URL})
	}
	return out, nil
}
