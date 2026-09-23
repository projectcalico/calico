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

// Package operator builds and publishes the operator image.
package operator

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/steps"
)

const (
	buildStep  = "operator-build"
	branchStep = "operator-publish-branch"

	PublishStep = "operator-publish"
)

const (
	buildTarget   = "release-build"
	publishTarget = "release-publish"

	branchTagTarget = "retag-build-images-with-registries push-images-to-registries push-manifests"
)

const standardVariant = "standard"

const DirName = "operator"

var Variants = func() []Variant {
	return []Variant{{Name: standardVariant}}
}

type Variant struct {
	Name string

	Image string

	Env []string
}

func Narrow(variants []Variant, names []string) []Variant {
	if len(names) == 0 {
		return variants
	}
	out := make([]Variant, 0, len(variants))
	for _, v := range variants {
		if slices.Contains(names, v.Name) {
			out = append(out, v)
		}
	}
	return out
}

type Operator struct {
	RepoRoot string

	Version string

	Image string

	// The first names the image in the pin file and the release output.
	Registries []string

	ProductVersion string

	ProductRegistry string
}

func Registry(o Operator) string {
	if len(o.Registries) == 0 {
		return ""
	}
	return o.Registries[0]
}

func Dir(o Operator) string {
	if o.RepoRoot == "" {
		return ""
	}
	return filepath.Join(o.RepoRoot, DirName)
}

func Component(o Operator, v Variant) registry.Component {
	return registry.Component{
		Registry: Registry(o),
		Image:    image(o, v),
		Version:  o.Version,
	}
}

func image(o Operator, v Variant) string {
	if v.Image != "" {
		return v.Image
	}
	return o.Image
}

func validate(o Operator) error {
	var errs []error
	if Dir(o) == "" {
		errs = append(errs, fmt.Errorf("no repository root specified"))
	}
	if o.Version == "" {
		errs = append(errs, fmt.Errorf("no version specified"))
	}
	return errors.Join(errs...)
}

// The operator bakes in the tags of the images it deploys, so a build that
// guessed them would name images that were never published.
func validateBuild(hashrelease bool) func(Operator) error {
	return func(o Operator) error {
		errs := []error{validate(o)}
		if o.ProductRegistry == "" {
			errs = append(errs, fmt.Errorf("no product registry specified"))
		}
		if hashrelease && o.ProductVersion == "" {
			errs = append(errs, fmt.Errorf("hashrelease requires the product version to be specified"))
		}
		return errors.Join(errs...)
	}
}

var validatePublish = func(o Operator) error {
	errs := []error{validate(o)}
	errs = append(errs, validateImage(o))
	return errors.Join(errs...)
}

// The branch chain retags local images under IMAGETAG, so it needs the image
// and its registries but never the version.
var validateBranch = func(o Operator) error {
	var errs []error
	if Dir(o) == "" {
		errs = append(errs, fmt.Errorf("no repository root specified"))
	}
	errs = append(errs, validateImage(o))
	return errors.Join(errs...)
}

func validateImage(o Operator) error {
	var errs []error
	if o.Image == "" {
		errs = append(errs, fmt.Errorf("no operator image specified"))
	}
	if len(o.Registries) == 0 || slices.Contains(o.Registries, "") {
		errs = append(errs, fmt.Errorf("no operator registries specified"))
	}
	return errors.Join(errs...)
}

// Both parts keep the trailing slash the make targets join on.
func productRegistryParts(productRegistry string) (reg string, imagePath string, err error) {
	var parts []string
	for _, part := range strings.Split(productRegistry, "/") {
		if part != "" {
			parts = append(parts, part)
		}
	}
	if len(parts) < 2 {
		return "", "", fmt.Errorf("failed to parse product registry: %s", productRegistry)
	}
	return strings.Join(parts[:len(parts)-1], "/") + "/", parts[len(parts)-1] + "/", nil
}

type settings struct {
	Operator

	dryRun bool

	validate bool

	arches []string

	refs steps.RefRecorder

	steps.Step
}

type (
	BuildOption   interface{ applyBuild(*settings) error }
	PublishOption interface{ applyPublish(*settings) error }

	Option interface {
		applyBuild(*settings) error
		applyPublish(*settings) error
	}
)

var (
	_ Option        = setting(nil)
	_ BuildOption   = buildSetting(nil)
	_ PublishOption = publishSetting(nil)
)

type setting func(*settings) error

func (f setting) applyBuild(s *settings) error   { return f(s) }
func (f setting) applyPublish(s *settings) error { return f(s) }

type buildSetting func(*settings) error

func (f buildSetting) applyBuild(s *settings) error { return f(s) }

type publishSetting func(*settings) error

func (f publishSetting) applyPublish(s *settings) error { return f(s) }

func WithRunner(r command.CommandRunner) Option {
	return setting(func(s *settings) error {
		s.Apply([]steps.Option{steps.WithRunner(r)})
		return nil
	})
}

func WithLogsDir(dir string) Option {
	return setting(func(s *settings) error {
		s.Apply([]steps.Option{steps.WithLogsDir(dir)})
		return nil
	})
}

func WithArches(arches ...string) Option {
	return setting(func(s *settings) error {
		s.arches = arches
		return nil
	})
}

// Gates the pre-build checks only; the verbs always validate their config.
func WithValidation(validate bool) BuildOption {
	return buildSetting(func(s *settings) error {
		s.validate = validate
		return nil
	})
}

func WithDryRun(dryRun bool) PublishOption {
	return publishSetting(func(s *settings) error {
		s.dryRun = dryRun
		return nil
	})
}

func WithRecord(rec steps.RefRecorder) PublishOption {
	return publishSetting(func(s *settings) error {
		if rec == nil {
			return fmt.Errorf("no recorder given")
		}
		s.refs = rec
		return nil
	})
}
