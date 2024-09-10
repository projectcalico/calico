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

package builder

type Option func(*ReleaseBuilder) error

func WithRepoRoot(root string) Option {
	return func(r *ReleaseBuilder) error {
		r.repoRoot = root
		return nil
	}
}

func IsHashRelease() Option {
	return func(r *ReleaseBuilder) error {
		r.isHashRelease = true
		return nil
	}
}

func WithPreReleaseValidation(validate bool) Option {
	return func(r *ReleaseBuilder) error {
		r.validate = validate
		return nil
	}
}

func WithVersions(calicoVersion, operatorVersion string) Option {
	return func(r *ReleaseBuilder) error {
		r.calicoVersion = calicoVersion
		r.operatorVersion = operatorVersion
		return nil
	}
}

func WithOutputDir(outputDir string) Option {
	return func(r *ReleaseBuilder) error {
		r.outputDir = outputDir
		return nil
	}
}
