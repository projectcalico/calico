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

func WithCalicoVersion(version string) Option {
	return func(o *OperatorManager) error {
		o.calicoVersion = version
		return nil
	}
}

func WithValidate(validate bool) Option {
	return func(o *OperatorManager) error {
		o.validate = validate
		return nil
	}
}

func IsDryRun() Option {
	return func(o *OperatorManager) error {
		o.dryRun = true
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

func WithRegistry(registry string) Option {
	return WithRegistries([]string{registry})
}

func WithRegistries(registries []string) Option {
	return func(o *OperatorManager) error {
		// An unset flag reaches here as an empty string, which would otherwise leave the
		// image published nowhere.
		var named []string
		for _, r := range registries {
			if r != "" {
				named = append(named, r)
			}
		}
		if len(named) == 0 {
			return nil
		}
		o.registries = named
		return nil
	}
}

func WithProductRegistry(registry string) Option {
	return func(o *OperatorManager) error {
		o.productRegistry = registry
		return nil
	}
}

func WithImage(image string) Option {
	return func(o *OperatorManager) error {
		o.image = image
		return nil
	}
}
