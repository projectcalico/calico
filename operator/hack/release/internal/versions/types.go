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

package versions

import (
	"fmt"

	"go.yaml.in/yaml/v3"
)

// Component represents a versioned component in a versions YAML file.
type Component struct {
	Version string `yaml:"version"`
	Image   string `yaml:"image,omitempty"`
}

// CalicoVersion represents a config/calico_versions.yml or enterprise_versions.yml.
type CalicoVersion struct {
	Title      string               `yaml:"title"`
	Components map[string]Component `yaml:"components"`
}

// ParseConfigVersions parses a versions YAML file content.
func ParseConfigVersions(content []byte) (*CalicoVersion, error) {
	var cv CalicoVersion
	if err := yaml.Unmarshal(content, &cv); err != nil {
		return nil, fmt.Errorf("parsing config versions YAML: %w", err)
	}
	return &cv, nil
}
