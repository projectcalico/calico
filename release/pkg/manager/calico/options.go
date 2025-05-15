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
	"fmt"

	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/registry"
)

type Option func(*CalicoManager) error

func WithRepoRoot(root string) Option {
	return func(r *CalicoManager) error {
		r.repoRoot = root
		return nil
	}
}

func IsHashRelease() Option {
	return func(r *CalicoManager) error {
		r.isHashRelease = true
		return nil
	}
}

func WithValidate(validate bool) Option {
	return func(r *CalicoManager) error {
		r.validate = validate
		return nil
	}
}

func WithReleaseBranchValidation(validate bool) Option {
	return func(o *CalicoManager) error {
		o.validateBranch = validate
		return nil
	}
}

func WithVersion(version string) Option {
	return func(r *CalicoManager) error {
		r.calicoVersion = version
		return nil
	}
}

func WithOperator(registry, image, version string) Option {
	return func(r *CalicoManager) error {
		if image == "" {
			return fmt.Errorf("operator image cannot be blank")
		}
		if registry == "" {
			return fmt.Errorf("operator registry cannot be blank")
		}
		r.operatorImage = image
		r.operatorVersion = version
		r.operatorRegistry = registry
		return nil
	}
}

func WithOperatorVersion(version string) Option {
	return func(r *CalicoManager) error {
		r.operatorVersion = version
		return nil
	}
}

func WithOutputDir(outputDir string) Option {
	return func(r *CalicoManager) error {
		r.outputDir = outputDir
		return nil
	}
}

func WithPublishImages(publish bool) Option {
	return func(r *CalicoManager) error {
		r.publishImages = publish
		return nil
	}
}

func WithPublishGitTag(publish bool) Option {
	return func(r *CalicoManager) error {
		r.publishTag = publish
		return nil
	}
}

func WithPublishGithubRelease(publish bool) Option {
	return func(r *CalicoManager) error {
		r.publishGithub = publish
		return nil
	}
}

func WithPublishHashrelease(publish bool) Option {
	return func(r *CalicoManager) error {
		r.publishHashrelease = publish
		return nil
	}
}

func WithBuildImages(buildImages bool) Option {
	return func(r *CalicoManager) error {
		r.buildImages = buildImages
		return nil
	}
}

func WithImageRegistries(registries []string) Option {
	return func(r *CalicoManager) error {
		r.imageRegistries = registries
		return nil
	}
}

func WithArchitectures(architectures []string) Option {
	return func(r *CalicoManager) error {
		r.architectures = architectures
		return nil
	}
}

func WithGithubOrg(org string) Option {
	return func(r *CalicoManager) error {
		r.githubOrg = org
		return nil
	}
}

func WithRepoRemote(remote string) Option {
	return func(o *CalicoManager) error {
		o.remote = remote
		return nil
	}
}

func WithRepoName(name string) Option {
	return func(o *CalicoManager) error {
		o.repo = name
		return nil
	}
}

func WithReleaseBranchPrefix(prefix string) Option {
	return func(r *CalicoManager) error {
		r.releaseBranchPrefix = prefix
		return nil
	}
}

func WithTmpDir(tmpDir string) Option {
	return func(r *CalicoManager) error {
		r.tmpDir = tmpDir
		return nil
	}
}

func WithHashrelease(hashrelease hashreleaseserver.Hashrelease, cfg hashreleaseserver.Config) Option {
	return func(r *CalicoManager) error {
		r.hashrelease = hashrelease
		r.hashreleaseConfig = cfg
		return nil
	}
}

func WithImageScanning(scanning bool, cfg imagescanner.Config) Option {
	return func(r *CalicoManager) error {
		r.imageScanning = scanning
		r.imageScanningConfig = cfg
		return nil
	}
}

func WithComponents(components map[string]registry.Component) Option {
	return func(r *CalicoManager) error {
		r.imageComponents = components
		return nil
	}
}

func WithGithubToken(token string) Option {
	return func(r *CalicoManager) error {
		r.githubToken = token
		return nil
	}
}
