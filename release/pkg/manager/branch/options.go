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

package branch

type Option func(*BranchManager) error

func WithRepoRemote(remote string) Option {
	return func(b *BranchManager) error {
		b.remote = remote
		return nil
	}
}

func WithRepoRoot(root string) Option {
	return func(b *BranchManager) error {
		b.repoRoot = root
		return nil
	}
}

func WithMainBranch(branch string) Option {
	return func(b *BranchManager) error {
		b.mainBranch = branch
		return nil
	}
}

func WithDevTagIdentifier(devTag string) Option {
	return func(b *BranchManager) error {
		b.devTagIdentifier = devTag
		return nil
	}
}

func WithReleaseBranchPrefix(prefix string) Option {
	return func(b *BranchManager) error {
		b.releaseBranchPrefix = prefix
		return nil
	}
}

func WithValidate(validate bool) Option {
	return func(b *BranchManager) error {
		b.validate = validate
		return nil
	}
}

func WithPublish(publish bool) Option {
	return func(b *BranchManager) error {
		b.publish = publish
		return nil
	}
}
