// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package components

import (
	"fmt"
	"path"

	operator "github.com/projectcalico/calico/operator/api/v1"
)

// variant is where a product variant's images resolve, the defaults its components
// fall back to when the installation names no registry or image path of its own.
type variant struct {
	registry  string
	imagePath string
}

var calicoVariant = &variant{registry: CalicoRegistry, imagePath: CalicoImagePath}

type Component struct {
	// Image is the image name for this component (e.g., node, cni)
	Image string

	// Version is the image version for this component (e.g., v3.8.1)
	Version string

	// imagePath is only used for developer workflows. For production builds, the imagePath
	// is always determined from user configuration. This field can be overridden
	// as part of a developer workflow to deploy custom dev images on an individual basis.
	imagePath string

	// Registry is only used for developer workflows. For production builds, the registry
	// is always determined from user configuration. This field can be overridden
	// as part of a developer workflow to deploy custom dev images on an individual basis.
	Registry string

	// variant is which product variant this component belongs to. Nil for the
	// components shared across variants, which take the operator's own defaults.
	variant *variant
}

const UseDefault = "UseDefault"

// getDefaults returns the registry and imagePath a component resolves against when the
// installation names neither.
func getDefaults(c Component) (registry string, imagePath string) {
	if c.variant == nil {
		return OperatorRegistry, OperatorImagePath
	}
	return c.variant.registry, c.variant.imagePath
}

// GetReference returns the fully qualified image to use, including registry and version.
func GetReference(c Component, registry, imagePath, imagePrefix string, is *operator.ImageSet) (string, error) {
	defaultRegistry, defaultImagePath := getDefaults(c)

	// If a user did not supply a registry, use the default registry
	if registry == "" || registry == UseDefault {
		registry = defaultRegistry
		// If the component asks for an explicit registry, and the user
		// did not provide a custom registry, use the one specified by
		// the component.
		if c.Registry != "" {
			registry = c.Registry
		}
	}

	// If a user supplies an imaagePrefix, prepend it to the image name.
	imageName := c.Image
	if imagePrefix != "" && imagePrefix != UseDefault {
		imageName = fmt.Sprintf("%s%s", imagePrefix, imageName)
	}

	// If a user did not supply an imagePath, use the default imagePath
	if imagePath == "" || imagePath == UseDefault {
		imagePath = defaultImagePath
		// If the component asks for an explicit imagePath, and the user
		// did not provide a custom imagePath, use the one specified by
		// the component.
		if c.imagePath != "" {
			imagePath = c.imagePath
		}
	}

	if is == nil {
		return fmt.Sprintf("%s:%s", path.Join(registry, imagePath, imageName), c.Version), nil
	}

	for _, img := range is.Spec.Images {
		if img.Image == path.Join(defaultImagePath, c.Image) {
			return fmt.Sprintf("%s@%s", path.Join(registry, imagePath, imageName), img.Digest), nil
		}
	}

	return "", fmt.Errorf("ImageSet did not contain image %s", fmt.Sprintf("%s%s", defaultImagePath, c.Image))
}
