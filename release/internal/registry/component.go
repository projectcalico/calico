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

package registry

import "fmt"

// Component represents a component in the pinned version file.
type Component struct {
	Version  string `yaml:"version"`
	Image    string `yaml:"image,omitempty"`
	Registry string `yaml:"registry,omitempty"`
}

// ImageRef returns the image reference of the component.
func (c Component) ImageRef() ImageRef {
	return ParseImage(c.String())
}

// String returns the string representation of the component.
// The string representation is in the format of registry/image:version.
func (c Component) String() string {
	if c.Registry == "" {
		return fmt.Sprintf("%s:%s", c.Image, c.Version)
	}
	return fmt.Sprintf("%s/%s:%s", c.Registry, c.Image, c.Version)
}

type OperatorComponent struct {
	Component
}

func (c OperatorComponent) InitImage() Component {
	return Component{
		Version:  c.Version,
		Image:    fmt.Sprintf("%s-init", c.Image),
		Registry: c.Registry,
	}
}
