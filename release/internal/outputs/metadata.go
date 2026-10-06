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
	"errors"
	"fmt"
	"maps"
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

	Components map[string]Component `yaml:"components"`

	Released []registry.Component `yaml:"-"`
}

type Component struct {
	Version string `yaml:"version"`
	Image   string `yaml:"image,omitempty"`
	Digest  string `yaml:"digest,omitempty"`
}

func (r *Metadata) describe(d Describer) error {
	components, err := d.describe(r.Released)
	if err != nil {
		return err
	}
	r.Components = components
	return nil
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

type Describer struct {
	Sources []registry.DigestSource
	Resolve registry.DigestResolver
}

func (d Describer) describe(released []registry.Component) (map[string]Component, error) {
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

func (d Describer) digest(ref string) (string, error) {
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
