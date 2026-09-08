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

// WithRegistry names the one registry the image is published to, which is what a
// hashrelease sending it somewhere other than the release registries needs.
func WithRegistry(registry string) Option {
	return func(o *OperatorManager) error {
		o.registry = registry
		o.registries = []string{registry}
		return nil
	}
}

func WithRegistries(registries []string) Option {
	return func(o *OperatorManager) error {
		if len(registries) == 0 {
			return nil
		}
		o.registry = registries[0]
		o.registries = registries
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
