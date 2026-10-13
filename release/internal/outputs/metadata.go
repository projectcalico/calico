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

type Record interface {
	// attest validates the record before marshalling it, so an invalid record
	// is never written.
	attest() ([]byte, error)
}

func BuildMetadata(r Record, dir string) error {
	if r == nil {
		return errors.New("metadata: no release to describe")
	}
	if dir == "" {
		return errors.New("metadata: no directory to write to")
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

	OperatorVersion string `yaml:"operatorVersion"`

	Images []string `yaml:"images"`

	ChartVersion string `yaml:"helmChartVersion"`

	Source Source `yaml:"source"`

	Charts *Charts `yaml:"charts,omitempty"`

	Artifacts []Artifact `yaml:"artifacts,omitempty"`

	Components map[string]Component `yaml:"components"`
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

// Older readers still parse these keys, so they stay, marked for new readers.
var deprecatedKeys = map[string]string{
	"operatorVersion":  "Deprecated, use components.operator.version instead.",
	"images":           "Deprecated, use components instead.",
	"helmChartVersion": "Deprecated, use charts.version instead.",
}

func marshalMarked(v any) ([]byte, error) {
	var doc yaml.Node
	if err := doc.Encode(v); err != nil {
		return nil, fmt.Errorf("encoding metadata: %w", err)
	}
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if c, ok := deprecatedKeys[doc.Content[i].Value]; ok {
			doc.Content[i].HeadComment = c
		}
	}
	return yaml.Marshal(&doc)
}

func (r Metadata) attest() ([]byte, error) {
	m, err := r.attested()
	if err != nil {
		return nil, err
	}
	return marshalMarked(m)
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

// Digests finds the digest an image was published at: from a step's record,
// else from the registry.
type Digests struct {
	Resolve registry.DigestResolver

	// Require makes an unpublished image an error rather than a warning.
	Require bool
}

func (d Digests) Of(src registry.DigestSource, ref string) (string, error) {
	if digest, ok := src.Digest(ref); ok {
		return digest, nil
	}
	if d.Resolve == nil {
		return "", fmt.Errorf("no resolver to find the digest of %s", ref)
	}
	digest, exists, err := d.Resolve(ref)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", ref, err)
	}
	if !exists {
		if d.Require {
			return "", fmt.Errorf("%s is not published", ref)
		}
		logrus.WithField("image", ref).Warn("Not published, leaving its digest out")
		return "", nil
	}
	return digest, nil
}

// DescribeComponents records a component with no image by version alone.
func DescribeComponents(src registry.DigestSource, released map[string]registry.Component, d Digests) (map[string]Component, error) {
	out := make(map[string]Component, len(released))
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(released)) {
		c := released[name]
		if c.Image == "" {
			out[name] = Component{Version: c.Version}
			continue
		}
		ref := c.String()
		digest, err := d.Of(src, ref)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out[name] = Component{Version: c.Version, Image: ref, Digest: digest}
	}
	return out, errors.Join(errs...)
}

type ArtifactFile struct {
	Name string
	Path string
	URL  string
}

// DescribeArtifacts leaves out the metadata file, because it cannot carry its
// own hash.
func DescribeArtifacts(files []ArtifactFile) ([]Artifact, error) {
	var out []Artifact
	for _, file := range files {
		name := file.Name
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
