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

package operator

type Option func(*OperatorManager) error

func WithOperatorDirectory(root string) Option {
	return func(o *OperatorManager) error {
		o.dir = root
		return nil
	}
}

func WithCalicoDirectory(dir string) Option {
	return func(o *OperatorManager) error {
		o.calicoDir = dir
		return nil
	}
}

func WithRepoRemote(remote string) Option {
	return func(o *OperatorManager) error {
		o.remote = remote
		return nil
	}
}

func WithGithubOrg(org string) Option {
	return func(o *OperatorManager) error {
		o.githubOrg = org
		return nil
	}
}

func WithRepoName(name string) Option {
	return func(o *OperatorManager) error {
		o.repoName = name
		return nil
	}
}

func WithBranch(branch string) Option {
	return func(o *OperatorManager) error {
		o.branch = branch
		return nil
	}
}

func WithDevTagIdentifier(devTag string) Option {
	return func(o *OperatorManager) error {
		o.devTagIdentifier = devTag
		return nil
	}
}

func WithReleaseBranchPrefix(prefix string) Option {
	return func(o *OperatorManager) error {
		o.releaseBranchPrefix = prefix
		return nil
	}
}

func WithValidate(validate bool) Option {
	return func(o *OperatorManager) error {
		o.validate = validate
		return nil
	}
}

func WithReleaseBranchValidation(validate bool) Option {
	return func(o *OperatorManager) error {
		o.validateBranch = validate
		return nil
	}
}

func WithPublish(publish bool) Option {
	return func(o *OperatorManager) error {
		o.publish = publish
		return nil
	}
}

func WithArchitectures(architectures []string) Option {
	return func(o *OperatorManager) error {
		o.architectures = architectures
		return nil
	}
}

func IsHashRelease() Option {
	return func(o *OperatorManager) error {
		o.isHashRelease = true
		return nil
	}
}

func WithVersion(version string) Option {
	return func(o *OperatorManager) error {
		o.version = version
		return nil
	}
}
