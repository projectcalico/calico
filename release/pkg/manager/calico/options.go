// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package calico

import (
	"github.com/projectcalico/calico/release/internal/version"
)

type Option func(*CalicoController) error

func WithRepoRoot(root string) Option {
	return func(r *CalicoController) error {
		r.repoRoot = root
		return nil
	}
}

func IsHashRelease() Option {
	return func(r *CalicoController) error {
		r.isHashRelease = true
		return nil
	}
}

func WithValidate(validate bool) Option {
	return func(r *CalicoController) error {
		r.validate = validate
		return nil
	}
}

func WithReleaseBranchValidation(validate bool) Option {
	return func(o *CalicoController) error {
		o.validateBranch = validate
		return nil
	}
}

func WithVersions(versions *version.Data) Option {
	return func(r *CalicoController) error {
		r.calicoVersion = versions.ProductVersion.FormattedString()
		r.operatorVersion = versions.OperatorVersion.FormattedString()
		r.chartVersion = versions.ChartVersion
		return nil
	}
}

func WithOutputDir(outputDir string) Option {
	return func(r *CalicoController) error {
		r.outputDir = outputDir
		return nil
	}
}

func WithPublishOptions(images, tag, github bool) Option {
	return func(r *CalicoController) error {
		r.publishImages = images
		r.publishTag = tag
		r.publishGithub = github
		return nil
	}
}

func WithBuildImages(buildImages bool) Option {
	return func(r *CalicoController) error {
		r.buildImages = buildImages
		return nil
	}
}

func WithImageRegistries(registries []string) Option {
	return func(r *CalicoController) error {
		r.imageRegistries = registries
		return nil
	}
}

func WithArchitectures(architectures []string) Option {
	return func(r *CalicoController) error {
		r.architectures = architectures
		return nil
	}
}

func WithGithubOrg(org string) Option {
	return func(r *CalicoController) error {
		r.githubOrg = org
		return nil
	}
}

func WithReleaseBranchPrefix(prefix string) Option {
	return func(r *CalicoController) error {
		r.releaseBranchPrefix = prefix
		return nil
	}
}
